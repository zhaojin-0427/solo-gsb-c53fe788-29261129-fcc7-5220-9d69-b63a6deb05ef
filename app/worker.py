"""投递 Worker 进程。

并发模型：单进程内每轮认领一个队首任务并同步投递，可通过 docker compose
`--scale worker=N` 水平扩展；数据库行锁 + SKIP LOCKED 保证任务不被重复认领。
租约（LEASE_SECONDS）到期后，其他 Worker 可接管卡死/宕机的任务，
回写用 lease_token 栅栏丢弃过期结果（可能产生一次重复投递，这是 at-least-once
语义的正常表现）。
"""
from __future__ import annotations

import asyncio
import logging
import os
import signal
import socket
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from app import payloads, repository as repo
from app import security
from app.config import settings
from app.db import init_db, close_pool
from app.egress_policy import EgressPolicyError, policy_from_env
from app.egress_transport import PolicyAsyncTransport
from app.envelope import SecretCryptoError, resolve_secret
from app.keyring import get_keyring
from app.objectstore import init_object_store

log = logging.getLogger("webhook.worker")

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"

RESPONSE_EXCERPT_LIMIT = 2048


def compute_backoff(
    attempt_number: int, base_seconds: float, cap_seconds: float
) -> datetime:
    """第 attempt_number 次失败后，下次可投递时间（指数退避，封顶）。

    base/cap 取自该投递钉住的配置版本：旧投递即使在配置发布后重试，
    也继续沿用其创建时版本的退避参数。
    """
    delay = min(cap_seconds, base_seconds * (2 ** (attempt_number - 1)))
    return datetime.now(timezone.utc) + timedelta(seconds=delay)


async def deliver_once(
    client: httpx.AsyncClient, context: dict
) -> tuple[str, int | None, str | None, str | None, bool]:
    """执行一次 HTTP 投递。

    返回 (outcome, http_status, response_excerpt, error_message, succeeded)。
    """
    payload = dict(context["payload"])
    timestamp = security.now_timestamp()
    signature = security.build_signature_header(
        context["secret"], timestamp, payload
    )
    body = security.compact_json(payload)
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Signature": signature,
        "X-Webhook-Event": context["source"],
        "X-Webhook-Event-Id": context["event_id"],
        "X-Webhook-Delivery-Id": str(context["delivery_id"]),
        "X-Webhook-Attempt": str(context["attempt_number"]),
        # 本次投递实际使用的配置版本（钉在投递记录上，重试/接管不变）
        "X-Webhook-Config-Revision": str(context["config_revision"]),
        "User-Agent": "reliable-webhook/1.0",
    }
    try:
        response = await client.post(
            context["target_url"], content=body.encode("utf-8"), headers=headers
        )
    except EgressPolicyError as exc:
        # 出站安全策略拒绝（含重定向后任意一跳命中阻止类别）：
        # 记录为可查询的 security_blocked，并与普通失败一样参与重试/退避/死信结算。
        log.warning(
            "投递 id=%s 目标被出站安全策略拒绝（%s）: %s",
            context["delivery_id"],
            exc.code,
            exc.message,
        )
        return "security_blocked", None, None, f"安全策略拒绝[{exc.code}]: {exc.message}", False
    except httpx.TimeoutException as exc:
        return "timeout", None, None, f"请求超时: {exc}", False
    except httpx.HTTPError as exc:
        return "network_error", None, None, f"网络错误: {exc}", False

    excerpt = response.text[:RESPONSE_EXCERPT_LIMIT]
    if 200 <= response.status_code < 300:
        return "success", response.status_code, excerpt, None, True
    return (
        "http_error",
        response.status_code,
        excerpt,
        f"目标返回 HTTP {response.status_code}",
        False,
    )


async def handle_one(pool, client: httpx.AsyncClient, payload_store) -> bool:
    """认领并处理一个任务；返回本轮是否处理了任务。"""
    async with pool.acquire() as conn:
        claim = await repo.claim_delivery(conn, WORKER_ID)
    if claim is None:
        return False

    delivery = claim["delivery"]
    delivery_id = delivery["id"]
    lease_token = claim["lease_token"]
    log.info(
        "worker=%s 认领投递 id=%s event=%s attempt(即将)=%s",
        WORKER_ID,
        delivery_id,
        delivery["event_id_fk"],
        delivery["attempts_made"] + 1,
    )

    async with pool.acquire() as conn:
        context_row = await repo.load_delivery_context(conn, delivery_id)
    if context_row is None:
        return True
    context = dict(context_row)
    context["attempt_number"] = delivery["attempts_made"] + 1
    log.info(
        "worker=%s 认领投递 id=%s event=%s revision=%s attempt(即将)=%s",
        WORKER_ID,
        delivery_id,
        delivery["event_id_fk"],
        context.get("config_revision"),
        context["attempt_number"],
    )

    # 取事件载荷：新格式从对象存储取回并复核 SHA-256 摘要后才允许签名；
    # 旧 JSONB 数据（在线迁移未完成）回退读库，双读期间投递不中断。
    # 对象缺失/摘要不符（损坏或被篡改）一律拒绝投递，记为 payload_integrity，
    # 与普通失败一样参与退避/重试/死信结算。
    try:
        context["payload"] = await payloads.load_event_payload(
            payload_store, context_row
        )
    except payloads.PayloadIntegrityError as exc:
        log.error("投递 id=%s 载荷完整性校验失败: %s", delivery_id, exc)
        outcome, http_status, excerpt, error_message, succeeded = (
            "payload_integrity",
            None,
            None,
            f"载荷完整性失败: {exc}",
            False,
        )
        await _settle(
            pool,
            delivery_id=delivery_id,
            lease_token=lease_token,
            worker_id=WORKER_ID,
            claim=claim,
            outcome=outcome,
            http_status=http_status,
            excerpt=excerpt,
            error_message=error_message,
            succeeded=succeeded,
            context=context,
        )
        return True

    # 仅在签名前解密订阅密钥（信封格式解包 DEK 后解密；旧明文格式直接回退）。
    # 未知 key_id / 认证失败 / 未配置密钥环：拒绝投递并记录可查询的 crypto_error，
    # 与普通失败一样参与退避/重试/死信结算（修复密钥环后可自动恢复）。
    try:
        context["secret"] = resolve_secret(context, get_keyring())
    except SecretCryptoError as exc:
        log.warning(
            "投递 id=%s 被拒绝：密钥不可用[%s] key_id=%s",
            delivery_id,
            exc.code,
            context.get("secret_key_id"),
        )
        outcome, http_status, excerpt, error_message, succeeded = (
            "crypto_error",
            None,
            None,
            f"密钥解密失败[{exc.code}]: {exc.message}",
            False,
        )
    else:
        outcome, http_status, excerpt, error_message, succeeded = await deliver_once(
            client, context
        )

    await _settle(
        pool,
        delivery_id=delivery_id,
        lease_token=lease_token,
        worker_id=WORKER_ID,
        claim=claim,
        outcome=outcome,
        http_status=http_status,
        excerpt=excerpt,
        error_message=error_message,
        succeeded=succeeded,
        context=context,
    )
    return True


async def _settle(
    pool,
    *,
    delivery_id: int,
    lease_token: str,
    worker_id: str,
    claim: dict,
    outcome: str,
    http_status: int | None,
    excerpt: str | None,
    error_message: str | None,
    succeeded: bool,
    context: dict,
) -> None:
    """租约栅栏下记录尝试并结算（复用 worker 主循环）。"""
    async with pool.acquire() as conn:
        attempt_number = await repo.record_attempt(
            conn,
            delivery_id=delivery_id,
            lease_token=lease_token,
            worker_id=worker_id,
            outcome=outcome,
            http_status=http_status,
            response_excerpt=excerpt,
            error_message=error_message,
            leased_at=claim["leased_at"],
            lease_expires_at=claim["lease_expires_at"],
        )
        if attempt_number is None:
            log.warning(
                "投递 id=%s 的租约已被接管，本次尝试结果丢弃（outcome=%s）",
                delivery_id,
                outcome,
            )
            return

        not_before = (
            None
            if succeeded
            else compute_backoff(
                attempt_number,
                float(context["backoff_base_seconds"]),
                float(context["backoff_cap_seconds"]),
            )
        )
        new_status = await repo.settle_delivery(
            conn,
            delivery_id=delivery_id,
            lease_token=lease_token,
            succeeded=succeeded,
            not_before=not_before,
            max_attempts=int(context["max_attempts"]),
        )

    if new_status == "succeeded":
        log.info("投递 id=%s 成功（第 %s 次尝试）", delivery_id, attempt_number)
    elif new_status == "dead_lettered":
        log.error(
            "投递 id=%s 已达 %s 次尝试，进入死信",
            delivery_id,
            context["max_attempts"],
        )
    else:
        log.info(
            "投递 id=%s 第 %s 次失败（%s），退避后重试",
            delivery_id,
            attempt_number,
            outcome,
        )


async def run() -> None:
    log.info("Worker 启动 id=%s", WORKER_ID)
    pool = await init_db()
    # 对象存储：桶不存在会自动创建；不可用则启动失败（避免每个任务都失败）。
    payload_store = await init_object_store()
    # 启动时加载本地密钥环：配置非法直接退出；未配置则明文旧记录可投递、
    # 已加密记录以 crypto_error 结算（可查询），修复配置后自动恢复。
    get_keyring()
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    policy = policy_from_env(settings.allowed_hosts, settings.allowed_cidrs)
    # follow_redirects=False：重定向由 PolicyAsyncTransport 逐跳重新执行
    # 同一出站策略，不会因 3xx 自动越过策略（含固定地址防 DNS 重绑定）。
    transport = PolicyAsyncTransport(policy, max_redirects=settings.max_redirects)
    async with httpx.AsyncClient(
        timeout=settings.http_timeout_seconds,
        follow_redirects=False,
        transport=transport,
        limits=httpx.Limits(max_connections=20),
    ) as client:
        try:
            while not stop.is_set():
                try:
                    handled = await handle_one(pool, client, payload_store)
                except Exception:  # noqa: BLE001 - Worker 主循环不能因单任务退出
                    log.exception("处理投递时发生未预期错误")
                    handled = False
                if not handled:
                    try:
                        await asyncio.wait_for(
                            stop.wait(), timeout=settings.worker_poll_seconds
                        )
                    except asyncio.TimeoutError:
                        pass
        finally:
            await close_pool()
    log.info("Worker 停止 id=%s", WORKER_ID)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    asyncio.run(run())


if __name__ == "__main__":
    main()
