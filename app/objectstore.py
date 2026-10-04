"""事件载荷对象存储：内容寻址 + S3 兼容客户端 + 本地文件系统后端。

内容寻址约定（全局唯一，与存储后端无关）：

- 规范化（canonical）序列化：`json.dumps(payload, sort_keys=True,
  separators=(",", ":"), ensure_ascii=False)`，与 HMAC 签名所用紧凑 JSON 完全一致；
- 对象键 = 规范化字节的 SHA-256 hex（64 个小写十六进制字符）；
- 对象一旦写入即不可变：同一键的字节永远相同，因此 PUT 天然幂等、可安全去重，
  也可在“数据库事务与对象上传交错”的任意崩溃点重放（见 repository.py 的
  提交状态机）。

后端：

- `S3ObjectStore`：仅依赖 httpx 的最小 S3 客户端（AWS Signature V4，
  path-style），可对接 MinIO 以及任何 S3 兼容服务；
- `LocalObjectStore`：把对象存为本地目录下的文件（原子 rename），仅用于
  离线联调/测试，语义与 S3 一致（不可变、幂等、404 即不存在）。

Worker 取回载荷后必须以 `verify_bytes` 复核摘要（防存储侧损坏/被篡改），
摘要与事件引用不一致时拒绝签名，记为 payload_integrity 失败。
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import hmac
import json
import logging
import os
from typing import Any, AsyncIterator
from urllib.parse import quote, urlsplit

import httpx

from app.config import settings

log = logging.getLogger("webhook.objectstore")

# 空载荷体的 SHA-256（SigV4 无符号体时也用 UNSIGNED-PAYLOAD 标记）
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
_UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"
_ALGORITHM = "AWS4-HMAC-SHA256"
_SERVICE = "s3"


class ObjectStoreError(Exception):
    """对象存储操作失败（网络/5xx/非预期状态码）；404 由 ObjectNotFound 表达。"""

    def __init__(self, message: str, *, status: int | None = None, key: str | None = None):
        super().__init__(message)
        self.status = status
        self.key = key


class ObjectNotFound(ObjectStoreError):
    def __init__(self, key: str):
        super().__init__(f"对象不存在: {key}", status=404, key=key)


# -- 规范化 / 摘要 ---------------------------------------------------------------

def canonical_payload_bytes(payload: Any) -> bytes:
    """规范化 JSON 字节：键排序、无空白、不转义非 ASCII（与签名体一致）。"""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def content_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_payload(payload: Any) -> tuple[str, bytes]:
    """返回 (SHA-256 hex, 规范化字节)。"""
    data = canonical_payload_bytes(payload)
    return content_digest(data), data


def verify_bytes(data: bytes, expected_digest: str) -> bool:
    """常量时间比较取回字节与事件引用的摘要。"""
    actual = content_digest(data)
    return hmac.compare_digest(actual, expected_digest.lower())


def is_valid_digest(digest: str) -> bool:
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest.lower())


# -- 抽象接口 ---------------------------------------------------------------------

class ObjectStore:
    mode = "abstract"

    async def ensure_bucket(self) -> None:
        """桶/目录不存在则创建（启动时调用一次）。"""

    async def put_object(self, key: str, data: bytes) -> None:
        """幂等上传不可变对象（同键同内容）；失败抛 ObjectStoreError。"""
        raise NotImplementedError

    async def get_object(self, key: str) -> bytes:
        """取对象；不存在抛 ObjectNotFound。Worker 取回后须再 verify_bytes。"""
        raise NotImplementedError

    async def head_object(self, key: str) -> bool:
        """对象是否存在。"""
        raise NotImplementedError

    async def delete_object(self, key: str) -> None:
        """删除对象；对象已存在与否都视为成功（幂等）。"""
        raise NotImplementedError

    def iter_all_keys(self, prefix: str = "") -> AsyncIterator[str]:
        """枚举键（GC 孤儿扫描；仅管理命令使用，内部翻页）。"""
        raise NotImplementedError


# -- 本地文件系统后端 --------------------------------------------------------------

class LocalObjectStore(ObjectStore):
    """对象即文件：<root>/<key>。仅供离线联调/测试。

    写为临时文件后原子 rename；内容寻址保证不会出现“半对象”被读到。
    """

    mode = "local"

    def __init__(self, root: str):
        self._root = root

    def _path(self, key: str) -> str:
        if not is_valid_digest(key):
            raise ObjectStoreError(f"非法对象键: {key!r}", key=key)
        return os.path.join(self._root, key)

    async def ensure_bucket(self) -> None:
        await asyncio.to_thread(os.makedirs, self._root, exist_ok=True)

    async def put_object(self, key: str, data: bytes) -> None:
        path = self._path(key)

        def _write() -> None:
            if os.path.exists(path):
                return  # 不可变对象：已存在即同一内容（内容寻址），跳过
            tmp = f"{path}.tmp-{os.getpid()}-{id(data) & 0xffff}"
            with open(tmp, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)

        await asyncio.to_thread(_write)

    async def get_object(self, key: str) -> bytes:
        path = self._path(key)
        try:
            return await asyncio.to_thread(_read_file, path)
        except FileNotFoundError:
            raise ObjectNotFound(key) from None

    async def head_object(self, key: str) -> bool:
        return await asyncio.to_thread(os.path.exists, self._path(key))

    async def delete_object(self, key: str) -> None:
        def _unlink() -> None:
            try:
                os.unlink(self._path(key))
            except FileNotFoundError:
                pass

        await asyncio.to_thread(_unlink)

    async def iter_all_keys(self, prefix: str = "") -> AsyncIterator[str]:
        try:
            names = await asyncio.to_thread(os.listdir, self._root)
        except FileNotFoundError:
            return
        for name in sorted(names):
            if name.startswith(prefix) and is_valid_digest(name):
                yield name


def _read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


# -- S3 兼容客户端（AWS SigV4，path-style） -----------------------------------------

class S3ObjectStore(ObjectStore):
    mode = "s3"

    def __init__(
        self,
        *,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        bucket: str,
        region: str = "us-east-1",
        timeout: float = 10.0,
    ):
        parts = urlsplit(endpoint_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ObjectStoreError(
                f"S3_ENDPOINT_URL 非法: {endpoint_url!r}（需形如 http://host:9000）"
            )
        self._scheme = parts.scheme
        self._host = parts.netloc
        self._access_key = access_key
        self._secret_key = secret_key
        self._bucket = bucket
        self._region = region
        self._timeout = timeout

    @property
    def bucket(self) -> str:
        return self._bucket

    def _url(self, key: str = "", *, query: str | None = None, bucket: str | None = None) -> str:
        """拼 URL。query 必须是原始（未百分号编码）的 `k=v&k=v`，
        编码在本方法与签名规范化处统一完成。"""
        bucket = bucket or self._bucket
        path = f"/{quote(bucket, safe='')}"
        if key:
            path += "/" + quote(key, safe="/")
        if query:
            path += "?" + _encode_query(query)
        return f"{self._scheme}://{self._host}{path}"

    # ---- SigV4 ----
    @staticmethod
    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("ascii"), hashlib.sha256).digest()

    def _signing_key(self, date_stamp: str) -> bytes:
        k_date = self._hmac(("AWS4" + self._secret_key).encode("ascii"), date_stamp)
        k_region = self._hmac(k_date, self._region)
        k_service = self._hmac(k_region, _SERVICE)
        return self._hmac(k_service, "aws4_request")

    def _signed_headers(
        self,
        method: str,
        url: str,
        *,
        amz_content_sha256: str,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, str]:
        parts = urlsplit(url)
        now = _dt.datetime.now(_dt.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        headers: dict[str, str] = {
            "host": parts.netloc,
            "x-amz-content-sha256": amz_content_sha256,
            "x-amz-date": amz_date,
        }
        if extra_headers:
            for k, v in extra_headers.items():
                headers[k.lower().strip()] = v.strip()

        signed_names = sorted(headers)
        canonical_headers = "".join(
            f"{name}:{headers[name].strip()}\n" for name in signed_names
        )
        signed_headers = ";".join(signed_names)

        parts = urlsplit(url)
        # parts.query 已是百分号编码形式（_url 统一编码）；SigV4 要求按解码后的
        # 参数名/值排序后再编码，因此这里先 unquote 再规范化。
        from urllib.parse import unquote

        canonical_query = _canonical_query(unquote(parts.query))

        canonical_request = "\n".join(
            [
                method,
                parts.path or "/",
                canonical_query,
                canonical_headers,
                signed_headers,
                amz_content_sha256,
            ]
        )
        scope = f"{date_stamp}/{self._region}/{_SERVICE}/aws4_request"
        string_to_sign = "\n".join(
            [
                _ALGORITHM,
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode("ascii")).hexdigest(),
            ]
        )
        signature = hmac.new(
            self._signing_key(date_stamp),
            string_to_sign.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        authorization = (
            f"{_ALGORITHM} Credential={self._access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        headers["authorization"] = authorization
        return headers

    async def _request(
        self,
        method: str,
        url: str,
        *,
        content: bytes | None = None,
        content_sha256: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        if method in ("PUT", "POST"):
            # 已知体则带真实摘要（PUT 对象时即内容摘要），否则标记未签名
            sha = content_sha256 or (
                content_digest(content) if content is not None else _UNSIGNED_PAYLOAD
            )
        else:
            sha = _EMPTY_SHA256
        headers = self._signed_headers(
            method, url, amz_content_sha256=sha, extra_headers=extra_headers
        )
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                return await client.request(
                    method, url, content=content, headers=headers
                )
        except httpx.HTTPError as exc:
            raise ObjectStoreError(f"S3 请求失败 {method} {url}: {exc}") from exc

    # ---- 桶与对象 ----
    async def ensure_bucket(self) -> None:
        url = self._url()
        # HEAD bucket：200=存在，404=不存在（需创建），403=凭据/权限问题。
        resp = await self._request("HEAD", url)
        if resp.status_code == 200:
            return
        if resp.status_code == 404:
            # us-east-1 创建桶不带 location 约束；MinIO 也接受。
            resp = await self._request("PUT", url)
            if resp.status_code not in (200, 204):
                raise ObjectStoreError(
                    f"创建桶 {self._bucket!r} 失败: HTTP {resp.status_code} "
                    f"{resp.text[:300]}",
                    status=resp.status_code,
                )
            log.info("对象存储桶已创建: %s", self._bucket)
            return
        raise ObjectStoreError(
            f"检查桶 {self._bucket!r} 失败: HTTP {resp.status_code} "
            f"（请检查 S3_ENDPOINT_URL / S3_ACCESS_KEY / S3_SECRET_KEY 与权限）",
            status=resp.status_code,
        )

    async def put_object(self, key: str, data: bytes) -> None:
        if not is_valid_digest(key):
            raise ObjectStoreError(f"非法对象键: {key!r}", key=key)
        digest = content_digest(data)
        if digest != key:
            # 内容寻址铁律：键必须等于内容摘要，防止任何调用方写错对象
            raise ObjectStoreError(
                f"对象键与内容摘要不一致: key={key} actual={digest}", key=key
            )
        url = self._url(key)
        resp = await self._request(
            "PUT",
            url,
            content=data,
            content_sha256=digest,
            extra_headers={"content-type": "application/json"},
        )
        if resp.status_code not in (200, 204):
            raise ObjectStoreError(
                f"上传对象 {key} 失败: HTTP {resp.status_code} {resp.text[:300]}",
                status=resp.status_code,
                key=key,
            )

    async def get_object(self, key: str) -> bytes:
        url = self._url(key)
        resp = await self._request("GET", url)
        if resp.status_code == 404:
            raise ObjectNotFound(key)
        if not (200 <= resp.status_code < 300):
            raise ObjectStoreError(
                f"读取对象 {key} 失败: HTTP {resp.status_code} {resp.text[:300]}",
                status=resp.status_code,
                key=key,
            )
        return resp.content

    async def head_object(self, key: str) -> bool:
        url = self._url(key)
        resp = await self._request("HEAD", url)
        if resp.status_code == 404:
            return False
        if not (200 <= resp.status_code < 300):
            raise ObjectStoreError(
                f"HEAD 对象 {key} 失败: HTTP {resp.status_code}",
                status=resp.status_code,
                key=key,
            )
        return True

    async def delete_object(self, key: str) -> None:
        url = self._url(key)
        resp = await self._request("DELETE", url)
        # 幂等：404 视为成功
        if resp.status_code not in (200, 204) and resp.status_code != 404:
            raise ObjectStoreError(
                f"删除对象 {key} 失败: HTTP {resp.status_code} {resp.text[:300]}",
                status=resp.status_code,
                key=key,
            )

    async def iter_all_keys(self, prefix: str = "") -> AsyncIterator[str]:
        """ListObjectsV2 翻页枚举键（GC 孤儿扫描）。"""
        continuation: str | None = None
        while True:
            # 原始参数（不做编码）；请求 URL 与签名规范化共用同一编码逻辑。
            params = [f"list-type=2"]
            if prefix:
                params.append(f"prefix={prefix}")
            if continuation:
                params.append(f"continuation-token={continuation}")
            url = self._url(query="&".join(params))
            resp = await self._request("GET", url)
            if not (200 <= resp.status_code < 300):
                raise ObjectStoreError(
                    f"列举对象失败: HTTP {resp.status_code} {resp.text[:300]}",
                    status=resp.status_code,
                )
            keys, truncated, next_token = _parse_list_objects(resp.text)
            for key in keys:
                yield key
            if not truncated:
                return
            continuation = next_token
            if not continuation:
                return


def _split_query(raw_query: str) -> list[tuple[str, str]]:
    """把原始（未编码）查询串拆成有序 (name, value) 对。"""
    pairs: list[tuple[str, str]] = []
    if not raw_query:
        return pairs
    for piece in raw_query.split("&"):
        if not piece:
            continue
        name, _, value = piece.partition("=")
        pairs.append((name, value))
    return pairs


def _encode_pair(name: str, value: str) -> str:
    # 已编码的内容不应再传入；这里对原始值统一按 RFC3986 编码
    return f"{quote(name, safe='-_.~')}={quote(value, safe='-_.~')}"


def _encode_query(raw_query: str) -> str:
    """按原始出现顺序编码查询串（用于请求 URL）。"""
    return "&".join(_encode_pair(n, v) for n, v in _split_query(raw_query))


def _canonical_query(raw_query: str) -> str:
    """SigV4 规范查询串：按参数名（再按值）排序后 URI 编码。"""
    pairs = _split_query(raw_query)
    pairs.sort()
    return "&".join(_encode_pair(name, value) for name, value in pairs)


def _parse_list_objects(xml_text: str) -> tuple[list[str], bool, str | None]:
    """最小 XML 解析（无第三方依赖）：取 <Contents><Key>、截断标志与下一页令牌。"""
    import re
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise ObjectStoreError(f"ListObjects 返回不是合法 XML: {xml_text[:300]}")

    def _localname(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    keys: list[str] = []
    truncated = False
    next_token: str | None = None
    for child in root:
        name = _localname(child.tag)
        if name == "Contents":
            for sub in child:
                if _localname(sub.tag) == "Key" and sub.text is not None:
                    keys.append(sub.text)
        elif name == "IsTruncated":
            truncated = (child.text or "").strip().lower() == "true"
        elif name == "NextContinuationToken":
            next_token = (child.text or "").strip() or None
    return keys, truncated, next_token


# -- 工厂 / 进程级单例 --------------------------------------------------------------

_store: ObjectStore | None = None
_loaded = False


def build_object_store() -> ObjectStore:
    mode = settings.payload_store_mode.strip().lower()
    if mode == "local":
        return LocalObjectStore(settings.local_objectstore_dir)
    if mode == "s3":
        return S3ObjectStore(
            endpoint_url=settings.s3_endpoint_url,
            access_key=settings.s3_access_key,
            secret_key=settings.s3_secret_key,
            bucket=settings.s3_bucket,
            region=settings.s3_region,
        )
    raise ObjectStoreError(
        f"PAYLOAD_STORE_MODE 非法: {mode!r}（支持 's3' / 'local'）"
    )


def get_object_store() -> ObjectStore:
    global _store, _loaded
    if not _loaded:
        _store = build_object_store()
        _loaded = True
    return _store


async def init_object_store() -> ObjectStore:
    """启动时调用：构造单例并确保桶/目录就绪（S3 不可用则启动失败，避免半运行）。"""
    store = get_object_store()
    await store.ensure_bucket()
    log.info("事件载荷对象存储已就绪：mode=%s", store.mode)
    return store


def reset_object_store_cache() -> None:
    """清空进程内单例（测试用）。"""
    global _store, _loaded
    _store = None
    _loaded = False
