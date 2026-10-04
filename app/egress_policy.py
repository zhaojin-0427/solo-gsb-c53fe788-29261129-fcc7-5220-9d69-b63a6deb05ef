"""Webhook 出站目标安全策略（SSRF 防护）。

两道关卡，规则完全一致：

1. **入口校验**（API 进程）：创建订阅、发布配置版本时对 `target_url` 做一次
   完整校验——scheme 仅允许 http/https、拒绝带用户信息（userinfo）的 URL、
   解析主机并校验解析出的**全部**地址；
2. **投递校验**（Worker 进程，见 `app/egress_transport.py`）：每次尝试都重新
   解析，并把“本次校验通过的地址”固定到实际 TCP 连接（Host 头与 HTTPS SNI
   保持原主机名），从而消除“校验后 DNS 重绑定”窗口；跟随重定向时每一跳都
   重新执行同一策略，不自动放行。

默认阻止：回环、链路本地、私网（含 CGNAT/基准测试段等保留用途地址）、
组播、保留/未指定地址，以及云元数据地址（169.254.169.254、fd00:ec2::254、
metadata.google.internal 等）；IPv4-mapped IPv6 按内嵌 IPv4 地址分类。
可用 `WEBHOOK_ALLOWED_HOSTS`（精确主机名）与 `WEBHOOK_ALLOWED_CIDRS`
（CIDR）显式放行；放行优先于阻止（但 scheme/userinfo 规则不可放行）。
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# 云厂商实例元数据地址：即便将来 ipaddress 的分类变化，也始终显式拒绝
CLOUD_METADATA_IPS = (
    "169.254.169.254",  # AWS / Azure / GCE / OpenStack / 阿里云等通用元数据 IP
    "fd00:ec2::254",    # AWS IMDS over IPv6
)

# 除 ipaddress 的语义分类外，始终显式阻止的网段（跨 Python 版本一致）：
# 100.64.0.0/10 为运营商级 NAT（CGNAT），Python 3.11 的 is_private 未覆盖；
# 192.88.99.0/24 为 6to4 中继任播（已废弃，Python 3.11 分类为全局可达）。
EXTRA_BLOCKED_NETWORKS = ("100.64.0.0/10", "192.88.99.0/24")

# 云元数据主机名：在解析之前直接拒绝（防止自定义解析器把这些名字指到公网后，
# 又通过 Host/SNI 头访问到元数据服务的混淆攻击；IP 层阻止是另一道防线）
CLOUD_METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",  # GCP
        "metadata",                  # GCP 短名
        "metadata.goog",
        "metadata.google.internal.",
    }
)

ALLOWED_SCHEMES = frozenset({"http", "https"})


class EgressPolicyError(Exception):
    """目标 URL 未通过出站安全策略。

    code 为机器可读的失败分类，写入投递尝试记录（outcome=security_blocked）
    与 API 422 响应，便于检索“因安全策略失败”的订阅/投递。
    """

    def __init__(self, code: str, message: str, *, host: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.host = host


@dataclass(frozen=True)
class UrlTarget:
    """解析后的目标 URL（不含用户信息）。"""

    scheme: str
    host: str
    port: int
    # 原样重建后的 URL（用于发起请求），路径/查询等保持原样
    raw_url: str
    # 主机是否是 IP 字面量（此时无需 DNS 解析）
    ip_literal: bool


@dataclass(frozen=True)
class EgressPolicy:
    """出站策略：阻止类别固定，放行项由环境变量配置。

    - allowed_hosts：精确主机名（大小写不敏感，不做通配）；命中即放行该主机的
      全部解析地址（scheme/userinfo 仍强制校验）。
    - allowed_cidrs：IP/CIDR 白名单；地址落在其中即放行，即使属于默认阻止类别
      （例如显式放行 docker compose 的 receiver 网段）。
    """

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_networks: tuple[ipaddress._BaseNetwork, ...] = ()

    def host_allowed(self, host: str) -> bool:
        return host.rstrip(".").lower() in self.allowed_hosts

    def evaluate(self, host: str, addresses: list[ipaddress._BaseAddress]) -> None:
        """校验主机解析出的全部地址；任一不允许即拒绝。

        必须先经 `parse_target` 的 scheme/userinfo 校验；本方法只负责地址层。
        """
        if not addresses:
            raise EgressPolicyError(
                "no_address", f"主机 {host} 未解析出任何地址", host=host
            )
        if self.host_allowed(host):
            return
        blocked: list[str] = []
        for ip in addresses:
            # IPv4-mapped IPv6（::ffff:a.b.c.d）按内嵌 IPv4 分类
            unwrapped = getattr(ip, "ipv4_mapped", None) or ip
            if any(unwrapped in net for net in self.allowed_networks):
                continue
            category = classify_ip(unwrapped)
            if category is not None:
                blocked.append(f"{ip}({category})")
        if blocked:
            raise EgressPolicyError(
                "blocked_address",
                f"主机 {host} 解析到被安全策略阻止的地址: {', '.join(blocked)}"
                "（可通过 WEBHOOK_ALLOWED_HOSTS / WEBHOOK_ALLOWED_CIDRS 显式放行）",
                host=host,
            )


# -- IP 分类 --------------------------------------------------------------------

_METADATA_NETWORKS = tuple(
    ipaddress.ip_network(item) for item in CLOUD_METADATA_IPS
)
_EXTRA_BLOCKED = tuple(
    ipaddress.ip_network(item) for item in EXTRA_BLOCKED_NETWORKS
)


def classify_ip(ip: ipaddress._BaseAddress) -> str | None:
    """返回阻止类别；公网地址返回 None（允许）。

    IPv4-mapped IPv6（::ffff:a.b.c.d）按内嵌 IPv4 分类，防止用映射形式
    绕过 127/8、169.254/16 等阻止规则。

    类别在 ipaddress 中可能重叠（如 0.0.0.0 同时是 private 与 unspecified，
    169.254/16 同时是 private 与 link_local）；顺序按“更具体/更敏感优先”。
    """
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    if any(ip in net for net in _METADATA_NETWORKS):
        return "cloud_metadata"
    if any(ip in net for net in _EXTRA_BLOCKED):
        return "private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_reserved:
        return "reserved"
    if ip.is_private:
        # is_private 已覆盖 10/8、172.16/12、192.168/16、fc00::/7、
        # 100.64/10（CGNAT）及部分保留段
        return "private"
    return None


# -- URL 解析 -------------------------------------------------------------------

def parse_target(url: str) -> UrlTarget:
    """结构性校验目标 URL：仅 http/https、必须有主机、禁止 userinfo。

    不做 DNS 解析（地址校验见 resolve_and_check）。
    """
    if not isinstance(url, str) or not url.strip():
        raise EgressPolicyError("invalid_url", "target_url 不能为空")
    try:
        parts = urlsplit(url.strip())
    except ValueError as exc:
        raise EgressPolicyError("invalid_url", f"URL 无法解析: {exc}") from exc
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise EgressPolicyError(
            "invalid_scheme",
            f"仅允许 http/https 协议，收到: {parts.scheme or '空'}",
        )
    if not parts.hostname:
        raise EgressPolicyError("invalid_url", "URL 缺少主机名")
    if parts.username is not None or parts.password is not None:
        raise EgressPolicyError(
            "userinfo_forbidden",
            "URL 不允许包含用户名/密码（userinfo），请把凭据放到签名或请求头中",
        )
    # urlsplit 对非法端口会抛 ValueError；对过限主机等做一次基本长度约束
    host = parts.hostname
    if len(host) > 253:
        raise EgressPolicyError("invalid_url", "主机名过长（超过 253 字符）")
    port = parts.port
    if port is None:
        port = 443 if parts.scheme.lower() == "https" else 80
    ip_literal = _as_ip_address(host) is not None
    return UrlTarget(
        scheme=parts.scheme.lower(),
        host=host,
        port=port,
        raw_url=url.strip(),
        ip_literal=ip_literal,
    )


def _as_ip_address(host: str) -> ipaddress._BaseAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


# -- DNS 解析（每次调用都重新解析，不做跨尝试缓存）--------------------------------

async def resolve_host(host: str, port: int) -> list[ipaddress._BaseAddress]:
    """解析主机的全部地址（A + AAAA，按系统解析器顺序返回）。"""
    infos = await asyncio.get_running_loop().getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )
    addresses: list[ipaddress._BaseAddress] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip = ipaddress.ip_address(sockaddr[0])
        key = str(ip)
        if key not in seen:
            seen.add(key)
            addresses.append(ip)
    return addresses


async def resolve_and_check(
    policy: EgressPolicy, target: UrlTarget
) -> list[ipaddress._BaseAddress]:
    """解析并校验目标，返回本次允许的全部地址（调用方须固定其中之一连接）。"""
    if target.host.rstrip(".").lower() in CLOUD_METADATA_HOSTS:
        raise EgressPolicyError(
            "cloud_metadata_host",
            f"云元数据主机名 {target.host} 被安全策略禁止",
            host=target.host,
        )
    if target.ip_literal:
        addresses = [ipaddress.ip_address(target.host.strip("[]"))]
    else:
        try:
            addresses = await resolve_host(target.host, target.port)
        except socket.gaierror as exc:
            raise EgressPolicyError(
                "dns_error", f"主机 {target.host} 解析失败: {exc}", host=target.host
            ) from exc
    policy.evaluate(target.host, addresses)
    return addresses


def policy_from_env(
    allowed_hosts_env: str | None, allowed_cidrs_env: str | None
) -> EgressPolicy:
    hosts = frozenset(
        h.strip().rstrip(".").lower()
        for h in (allowed_hosts_env or "").split(",")
        if h.strip()
    )
    networks: list[ipaddress._BaseNetwork] = []
    for raw in (allowed_cidrs_env or "").split(","):
        item = raw.strip()
        if not item:
            continue
        # 单个 IP 视为 /32（v4）或 /128（v6）
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"WEBHOOK_ALLOWED_CIDRS 中的非法条目 {item!r}: {exc}") from exc
    return EgressPolicy(allowed_hosts=hosts, allowed_networks=tuple(networks))
