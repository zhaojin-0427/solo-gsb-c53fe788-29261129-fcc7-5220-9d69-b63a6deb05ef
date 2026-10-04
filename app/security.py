"""HMAC 签名工具。

签名串：`<unix时间戳>.<紧凑 JSON 载荷>`，头为 `X-Webhook-Signature: t=<ts>,v1=<hex>`。
签名与验签均使用订阅密钥，保证生产者、投递服务、回调端约定一致。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any


def compact_json(payload: Any) -> str:
    """排序键并去空白，保证发送方与接收方序列化结果一致。"""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign(secret: str, timestamp: int, payload: Any) -> str:
    body = compact_json(payload)
    signed = f"{timestamp}.{body}".encode("utf-8")
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return digest


def build_signature_header(secret: str, timestamp: int, payload: Any) -> str:
    return f"t={timestamp},v1={sign(secret, timestamp, payload)}"


def verify(secret: str, timestamp: int, payload: Any, signature_hex: str) -> bool:
    expected = sign(secret, timestamp, payload)
    return hmac.compare_digest(expected, signature_hex)


def parse_signature_header(header: str) -> tuple[int, str] | None:
    """解析 `t=<ts>,v1=<hex>`，失败返回 None。"""
    ts: int | None = None
    sig: str | None = None
    for part in header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                ts = int(value)
            except ValueError:
                return None
        elif key == "v1":
            sig = value
    if ts is None or not sig:
        return None
    return ts, sig


def now_timestamp() -> int:
    return int(time.time())
