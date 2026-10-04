"""本地回调接收器（开发/联调用）。

端点：
- POST /receive             始终 200，记录并校验 HMAC 签名头
- POST /fail                始终 500，用于验证指数退避（可用 /control/fail 关闭）
- POST /fail/{times}        前 times 次对同一 delivery 返回 500，之后 200
- POST /slow?seconds=N      延迟 N 秒响应，用于验证租约超时接管
- POST /redirect            307 重定向到 ?to=<URL>（相对/绝对均可），用于验证
                            Worker 对重定向每一跳都执行同一出站安全策略
- POST /control/fail        开关 /fail 的失败行为，便于演示死信重放成功
- GET  /received            查看最近收到的投递
- POST /received/reset      清空内存记录
- GET  /health              健康检查
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from app import security
from app.config import settings

log = logging.getLogger("webhook.receiver")

app = FastAPI(title="本地 Webhook 回调接收器", version="1.0.0")

MAX_RECORDS = 200
received: deque[dict] = deque(maxlen=MAX_RECORDS)
fail_counts: dict[str, int] = defaultdict(int)
# /fail 端点是否真的返回 500（可用 /control/fail 关闭，便于演示重放成功）
force_fail_enabled: bool = True


def _parse_json(raw: bytes) -> tuple[dict | None, str | None]:
    import json

    if not raw:
        return {}, None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"载荷不是合法 JSON: {exc}"
    if not isinstance(data, dict):
        return None, "载荷必须是 JSON 对象"
    return data, None


def _check_signature(
    payload: dict, signature_header: str | None
) -> tuple[bool, str]:
    if not settings.receiver_secret:
        # 未配置密钥：开发模式只记录不强制
        return True, "未配置 RECEIVER_SECRET，跳过签名校验"
    if not signature_header:
        return False, "缺少 X-Webhook-Signature 头"
    parsed = security.parse_signature_header(signature_header)
    if parsed is None:
        return False, "签名头格式错误"
    timestamp, sig_hex = parsed
    tolerance = settings.receiver_timestamp_tolerance
    if tolerance > 0 and abs(time.time() - timestamp) > tolerance:
        return False, f"时间戳超出允许偏差（{tolerance}s）"
    if not security.verify(settings.receiver_secret, timestamp, payload, sig_hex):
        return False, "HMAC 签名校验失败"
    return True, "签名校验通过"


def _store(
    request: Request,
    payload: dict,
    status_code: int,
    sig_ok: bool,
    sig_message: str,
) -> None:
    record = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "path": request.url.path,
        "delivery_id": request.headers.get("x-webhook-delivery-id"),
        "event": request.headers.get("x-webhook-event"),
        "event_id": request.headers.get("x-webhook-event-id"),
        "attempt": request.headers.get("x-webhook-attempt"),
        "config_revision": request.headers.get("x-webhook-config-revision"),
        # 原始签名头，便于外部按各订阅版本密钥独立验签（接收器本身不保存订阅密钥）
        "signature_header": request.headers.get("x-webhook-signature"),
        "signature_valid": sig_ok,
        "signature_message": sig_message,
        "responded_status": status_code,
        "payload": payload,
    }
    received.append(record)
    log.info(
        "收到投递 delivery=%s event=%s attempt=%s -> HTTP %s（%s）",
        record["delivery_id"],
        record["event"],
        record["attempt"],
        status_code,
        sig_message,
    )


async def _handle(
    request: Request,
    status_code: int,
    signature_header: str | None,
    *,
    flaky_times: int | None = None,
) -> JSONResponse:
    raw = await request.body()
    payload, error = _parse_json(raw)
    if error is not None:
        raise HTTPException(status_code=400, detail=error)

    sig_ok, sig_message = _check_signature(payload, signature_header)

    if flaky_times is not None:
        delivery_id = request.headers.get("x-webhook-delivery-id", "?")
        if fail_counts[delivery_id] < flaky_times:
            fail_counts[delivery_id] += 1
            status_code = 500
    elif status_code == 500 and not force_fail_enabled:
        status_code = 200

    # 配置了密钥且签名不通过时，以 401 拒收（投递方会按失败重试）
    response_status = 401 if not sig_ok else status_code
    _store(request, payload, response_status, sig_ok, sig_message)
    return JSONResponse(
        status_code=response_status,
        content={
            "ok": 200 <= response_status < 300,
            "status": response_status,
            "signature_valid": sig_ok,
            "signature_message": sig_message,
        },
    )


@app.post("/receive", tags=["receiver"])
async def receive(
    request: Request,
    x_webhook_signature: str | None = Header(default=None),
):
    result = await _handle(request, 200, x_webhook_signature)
    return result


@app.post("/fail", tags=["receiver"])
async def fail(
    request: Request,
    x_webhook_signature: str | None = Header(default=None),
):
    result = await _handle(request, 500, x_webhook_signature)
    return result


@app.post("/fail/{times}", tags=["receiver"])
async def fail_first_n(
    times: int,
    request: Request,
    x_webhook_signature: str | None = Header(default=None),
):
    """对每个 delivery_id 的前 times 次投递返回 500，之后返回 200。"""
    if times < 1:
        raise HTTPException(status_code=400, detail="times 必须 >= 1")
    result = await _handle(
        request, 200, x_webhook_signature, flaky_times=times
    )
    return result


@app.post("/slow", tags=["receiver"])
async def slow(
    request: Request,
    x_webhook_signature: str | None = Header(default=None),
    seconds: float = 5.0,
):
    """延迟响应，用于验证租约超时后其他 Worker 接管。"""
    await asyncio.sleep(min(seconds, 30.0))
    result = await _handle(request, 200, x_webhook_signature)
    return result


@app.post("/control/fail", tags=["receiver"])
async def control_fail(enabled: bool = True):
    """开关 /fail 端点的 500 行为（关闭后重放可成功）。"""
    global force_fail_enabled
    force_fail_enabled = enabled
    return {"force_fail_enabled": force_fail_enabled}


@app.post("/redirect", tags=["receiver"])
async def redirect(request: Request, to: str):
    """307 临时重定向（保留方法与载荷），用于验证逐跳出站安全策略。

    `to` 可为相对路径（如 /receive）或绝对 URL
    （如 http://169.254.169.254/...，会被 Worker 在第二跳拒绝）。
    """
    return RedirectResponse(url=to, status_code=307)


@app.get("/received", tags=["receiver"])
async def list_received(limit: int = 100):
    items = list(received)[-limit:]
    return {"count": len(items), "items": items}


@app.post("/received/reset", tags=["receiver"])
async def reset_received():
    received.clear()
    fail_counts.clear()
    return {"ok": True}


@app.get("/health", tags=["meta"])
async def health():
    return {"status": "ok"}
