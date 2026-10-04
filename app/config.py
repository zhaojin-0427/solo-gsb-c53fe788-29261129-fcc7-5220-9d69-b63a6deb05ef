"""运行配置：全部来自环境变量，默认值可直接在 docker compose 中运行。"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _get_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _get_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return float(raw)


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://webhook:webhook@db:5432/webhooks"
    )
    # 租约时长：in_flight 投递超过该时间未心跳/未结算即可被其他 Worker 接管
    lease_seconds: int = _get_int("LEASE_SECONDS", 30)
    http_timeout_seconds: float = _get_float("HTTP_TIMEOUT_SECONDS", 10)
    worker_poll_seconds: float = _get_float("WORKER_POLL_SECONDS", 1)
    # 失败策略：共尝试 max_attempts 次；第 n 次失败后等待 base*2^(n-1)（封顶 cap）
    max_attempts: int = _get_int("MAX_ATTEMPTS", 6)
    backoff_base_seconds: float = _get_float("BACKOFF_BASE_SECONDS", 5)
    backoff_cap_seconds: float = _get_float("BACKOFF_CAP_SECONDS", 300)
    # 本地回调接收器
    receiver_secret: str = os.getenv("RECEIVER_SECRET", "")
    receiver_timestamp_tolerance: int = _get_int(
        "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS", 300
    )
    # 出站目标安全策略（SSRF 防护）
    # 精确主机名白名单（逗号分隔，大小写不敏感）；命中即放行其全部解析地址
    allowed_hosts: str = os.getenv("WEBHOOK_ALLOWED_HOSTS", "")
    # CIDR/IP 白名单（逗号分隔）；地址落入即放行，即使属于默认阻止类别
    allowed_cidrs: str = os.getenv("WEBHOOK_ALLOWED_CIDRS", "")
    # Worker 跟随重定向的最大跳数（每一跳都重新执行同一策略）
    max_redirects: int = _get_int("WEBHOOK_MAX_REDIRECTS", 5)
    # 订阅 HMAC 密钥信封加密的本地密钥环（主密钥不落数据库）：
    # WEBHOOK_KEYRING_JSON 非空时优先，否则读 WEBHOOK_KEYRING_FILE 指向的 JSON 文件；
    # 两者都为空表示未配置（新配置版本无法写入，已加密版本无法投递）。
    keyring_json: str = os.getenv("WEBHOOK_KEYRING_JSON", "")
    keyring_file: str = os.getenv("WEBHOOK_KEYRING_FILE", "")

    # ---- 事件载荷对象存储（S3 兼容；local 为本地文件系统后端，便于离线联调）----
    # 事件载荷以“规范化 JSON（键排序、无空白）”的 SHA-256 内容寻址，不可变对象
    # 存于对象存储，数据库只保留元数据与引用。提交经持久化状态机协调对象上传与
    # 数据库事务；见 app/objectstore.py、app/repository.py。
    payload_store_mode: str = os.getenv("PAYLOAD_STORE_MODE", "s3")
    # s3 后端：endpoint（path-style；MinIO 形如 http://minio:9000）、桶与凭据
    s3_endpoint_url: str = os.getenv("S3_ENDPOINT_URL", "http://minio:9000")
    s3_access_key: str = os.getenv("S3_ACCESS_KEY", "minioadmin")
    s3_secret_key: str = os.getenv("S3_SECRET_KEY", "minioadmin")
    s3_bucket: str = os.getenv("S3_BUCKET", "webhook-payloads")
    s3_region: str = os.getenv("S3_REGION", "us-east-1")
    # local 后端：对象文件根目录（仅建议用于离线联调/测试，语义与 S3 一致）
    local_objectstore_dir: str = os.getenv(
        "PAYLOAD_LOCAL_DIR", "/var/lib/webhook/payloads"
    )
    # 单个载荷对象大小上限（字节），提交超限直接 413 拒绝
    payload_max_bytes: int = _get_int("PAYLOAD_MAX_BYTES", 1024 * 1024)
    # GC 宽限期（秒）：引用计数归零后至少等待这么久才允许删除对象；
    # 并发提交/重放在此期间重新建立引用的对象会被标记复活而保留。
    payload_gc_grace_seconds: int = _get_int("PAYLOAD_GC_GRACE_SECONDS", 3600)
    # API 进程内崩溃残留提交状态机的后台巡检间隔（秒）：重放/清理中断的上传。
    payload_recover_interval_seconds: float = _get_float(
        "PAYLOAD_RECOVER_INTERVAL_SECONDS", 15
    )
    # 提交状态机判定为“残留（owner 已死）”前的最短年龄（秒），避免接管正在
    # 进行中的上传
    payload_stale_age_seconds: float = _get_float(
        "PAYLOAD_STALE_AGE_SECONDS", 60
    )


settings = Settings()
