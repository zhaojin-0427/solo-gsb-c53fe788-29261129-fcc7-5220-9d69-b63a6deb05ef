"""Worker 出站传输：策略校验 + 固定已校验地址 + 逐跳重定向校验。

防止校验后 DNS 重绑定的关键：

- 每次请求（包含每次重试）都**重新解析**主机并重新执行策略；
- 校验通过后，把“本次允许的地址”直接交给自定义网络后端建立 TCP 连接，
  httpcore 不再自行做 DNS，因此连接的对端必然是本次校验过的地址；
- 请求 URL 保持原主机名，故 HTTP `Host` 头不变（httpcore 按 origin host
  自动生成）；HTTPS 的 SNI 与证书校验也仍以原主机名进行（仅 TCP 层连
  固定 IP，`server_hostname` 取 origin host）；
- 关闭自动重定向：收到 3xx 时对 Location 指向的下一跳重新执行
  parse_target → 重新解析 → 地址校验，任何一跳命中阻止类别即整体失败。
"""
from __future__ import annotations

import ipaddress
import ssl
from urllib.parse import urlsplit

import httpcore
import httpx
from httpx._transports.default import (
    AsyncResponseStream,
    create_ssl_context,
    map_httpcore_exceptions,
)

from app.egress_policy import (
    EgressPolicy,
    EgressPolicyError,
    UrlTarget,
    parse_target,
    resolve_and_check,
)

# 与常见浏览器/HTTP 库一致的重定向上限，防止重定向环
DEFAULT_MAX_REDIRECTS = 5

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
# 这几个状态码按 RFC 9110 改写为 GET 并丢弃请求体；307/308 保留方法与请求体
_FORCE_GET_STATUSES = frozenset({301, 302, 303})
# 改为 GET 时需要剥离的载荷相关头
_BODY_HEADERS = frozenset({b"content-length", b"content-type", b"transfer-encoding"})


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """把对 origin 主机的 TCP 连接重定向到已校验的固定 IP。

    httpcore 建立连接时以 URL 中的主机名调用 connect_tcp；这里替换为策略
    校验时选定的地址，使“校验的地址”与“实际连接的地址”严格一致——
    校验与连接之间不存在第二次 DNS 查询。
    """

    def __init__(self, pinned_ip: ipaddress._BaseAddress, port: int):
        self._pinned = str(pinned_ip)
        self._port = port
        self._delegate = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options=None,
    ) -> httpcore.AsyncNetworkStream:
        return await self._delegate.connect_tcp(
            self._pinned,
            self._port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(self, *args, **kwargs):
        raise EgressPolicyError("invalid_url", "Unix domain socket 目标不被允许")

    async def sleep(self, seconds: float) -> None:
        import asyncio

        await asyncio.sleep(seconds)


class _PoolClosingStream(httpx.AsyncByteStream):
    """响应流关闭时同时归还/关闭本跳绑定固定 IP 的连接池。"""

    def __init__(self, stream: httpx.AsyncByteStream, pool: httpcore.AsyncConnectionPool):
        self._stream = stream
        self._pool = pool

    async def __aiter__(self):
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        try:
            await self._stream.aclose()
        finally:
            await self._pool.aclose()


class PolicyAsyncTransport(httpx.AsyncBaseTransport):
    """逐跳执行出站策略的 httpx 传输。

    每个跳步新建独立连接池（绑定本次校验通过的 IP），跳步结束即关闭，
    不做跨跳连接复用，避免连到后续可能已变化的解析结果。
    """

    def __init__(
        self,
        policy: EgressPolicy,
        *,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        verify: ssl.SSLContext | str | bool = True,
    ):
        self._policy = policy
        self._max_redirects = max_redirects
        self._ssl_context = create_ssl_context(verify=verify)

    async def handle_async_request(
        self, request: httpx.Request
    ) -> httpx.Response:
        # 读取并缓存请求体：307/308 重放时需要重新发送同一载荷
        body = await request.aread()

        method = request.method
        url = str(request.url)
        headers = list(request.headers.raw)
        redirects = 0

        while True:
            target = parse_target(url)
            addresses = await resolve_and_check(self._policy, target)
            pinned = addresses[0]

            pool = httpcore.AsyncConnectionPool(
                ssl_context=self._ssl_context,
                network_backend=_PinnedBackend(pinned, target.port),
            )
            core_req = httpcore.Request(
                method=method,
                url=httpcore.URL(
                    scheme=target.scheme.encode("ascii"),
                    # 仍以原主机名作为 Host / SNI / 证书校验名
                    host=_encode_host(target),
                    port=target.port,
                    target=_target_of(url),
                ),
                headers=headers,
                content=body,
                # 透传 httpx 计算出的超时扩展；故意不透传/设置 sni_hostname，
                # httpcore 即以 origin host（原主机名）做 SNI 与证书校验。
                extensions={"timeout": request.extensions.get("timeout", {})},
            )
            try:
                response = await pool.handle_async_request(core_req)
            except EgressPolicyError:
                await pool.aclose()
                raise
            except Exception:
                await pool.aclose()
                # 映射成 httpx 异常，保持 worker 现有超时/网络错误分类有效
                with map_httpcore_exceptions():
                    raise

            status = response.status
            location = _header_value(response.headers, b"location")
            if status in _REDIRECT_STATUSES and location is not None:
                # 读完并丢弃本跳响应体（这会归还连接），再关闭本跳连接池
                await response.aread()
                await pool.aclose()
                if redirects >= self._max_redirects:
                    raise EgressPolicyError(
                        "too_many_redirects",
                        f"重定向次数超过上限 {self._max_redirects}",
                        host=target.host,
                    )
                next_url = httpx.URL(url).join(location.decode("ascii"))
                url = str(next_url)
                redirects += 1
                if status in _FORCE_GET_STATUSES:
                    method = "GET"
                    body = b""
                    headers = [
                        (k, v) for k, v in headers if k.lower() not in _BODY_HEADERS
                    ]
                # 307/308：保留方法、请求体与请求头，下一跳重新做完整策略校验
                continue

            return httpx.Response(
                status_code=status,
                headers=response.headers,
                stream=_PoolClosingStream(AsyncResponseStream(response.stream), pool),
                request=request,
                extensions=response.extensions,
            )

    async def aclose(self) -> None:
        return None


def _encode_host(target: UrlTarget) -> bytes:
    host = target.host
    # IPv6 字面量在 URL 里带方括号，httpcore origin host 不带方括号
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return host.encode("ascii")
    except UnicodeEncodeError:
        return host.encode("idna")


def _target_of(url: str) -> bytes:
    parts = urlsplit(url)
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    return target.encode("ascii")


def _header_value(
    headers: list[tuple[bytes, bytes]], name: bytes
) -> bytes | None:
    for key, value in headers:
        if key.lower() == name:
            return value
    return None
