"""HTTP API：事件提交、订阅与配置版本管理、投递历史、死信与重放。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Response

from app import payloads, repository as repo
from app.config import settings
from app.db import get_pool
from app.egress_policy import (
    EgressPolicyError,
    parse_target,
    policy_from_env,
    resolve_and_check,
)
from app.keyring import get_keyring
from app.objectstore import (
    ObjectStoreError,
    get_object_store,
    is_valid_digest,
)
from app.schemas import (
    AttemptOut,
    CryptoStatusOut,
    DeliveryOut,
    EventCreate,
    EventOut,
    GCCandidateOut,
    GCRunOut,
    GCStatusOut,
    PayloadStorageStatusOut,
    ReplayOut,
    ReplayRequest,
    RotationRunOut,
    SubscriptionCreate,
    SubscriptionOut,
    VersionOut,
    VersionPublish,
)

router = APIRouter(prefix="/api/v1")

VALID_STATUSES = {"pending", "in_flight", "succeeded", "dead_lettered"}

# 出站目标安全策略：进程级单例，配置来自环境变量（见 app/config.py）
egress_policy = policy_from_env(settings.allowed_hosts, settings.allowed_cidrs)


async def validate_target_url(url: str) -> None:
    """创建订阅 / 发布配置版本时的入口策略校验。

    结构（scheme 白名单、禁止 userinfo）与地址（解析出的全部地址不得落在
    默认阻止类别）双重校验；失败统一返回 422，detail.code 可被调用方检索。
    """
    try:
        target = parse_target(url)
        await resolve_and_check(egress_policy, target)
    except EgressPolicyError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": exc.code,
                "message": exc.message,
                "host": exc.host,
            },
        )


def _subscription_out(row: asyncpg.Record) -> SubscriptionOut:
    return SubscriptionOut(
        id=row["id"],
        source=row["source"],
        target_url=row["target_url"],
        active=row["active"],
        paused=row["paused"],
        paused_at=row["paused_at"],
        current_revision=row["current_revision"],
        created_at=row["created_at"],
    )


def _delivery_out(row: asyncpg.Record) -> DeliveryOut:
    data = dict(row)
    return DeliveryOut(
        id=data["id"],
        event_id_fk=data["event_id_fk"],
        subscription_id=data["subscription_id"],
        event_source=data.get("event_source"),
        source_event_id=data.get("source_event_id"),
        target_url=data.get("target_url"),
        config_version_id=data["config_version_id"],
        config_revision=data["config_revision"],
        config_effective_at=data["config_effective_at"],
        chain_id=data["chain_id"],
        chain_seq=data["chain_seq"],
        status=data["status"],
        attempts_made=data["attempts_made"],
        not_before=data["not_before"],
        leased_at=data["leased_at"],
        lease_expires_at=data.get("lease_expires_at"),
        leased_by=data.get("leased_by"),
        created_at=data["created_at"],
        updated_at=data["updated_at"],
    )


# -- 事件 ----------------------------------------------------------------------

# 提交状态机 owner 标识（仅用于恢复接管的可观测性）
_OWNER_ID = "api"


async def _event_out(row: asyncpg.Record, *, duplicate: bool) -> EventOut:
    """构造事件响应：payload 双读（对象存储优先，旧 JSONB 回退）。"""
    payload: dict
    digest = row["payload_digest"]
    if digest is not None:
        store = get_object_store()
        data = await store.get_object(digest)
        import json as _json

        payload = _json.loads(data.decode("utf-8"))
    else:
        payload = dict(row["payload"]) if row["payload"] is not None else {}
    return EventOut(
        id=row["id"],
        source=row["source"],
        event_id=row["event_id"],
        payload=payload,
        payload_digest=digest,
        created_at=row["created_at"],
        duplicate=duplicate,
    )


@router.post("/events", response_model=EventOut, status_code=201, tags=["events"])
async def submit_event(body: EventCreate, response: Response) -> EventOut:
    """提交事件。(source, event_id) 重复时返回原事件且不新增投递（HTTP 200）。

    载荷以规范化 JSON 的 SHA-256 内容寻址存入对象存储；提交由持久化状态机
    协调对象上传与数据库事务（失败/崩溃无半成品、无悬空引用、无重复投递）。
    """
    pool = get_pool()
    store = get_object_store()
    try:
        async with pool.acquire() as conn:
            row, duplicate = await payloads.submit_event_payload(
                conn,
                store,
                source=body.source,
                event_id=body.event_id,
                payload=body.payload,
                owner_id=_OWNER_ID,
            )
    except payloads.PayloadTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except payloads.PayloadSubmitConflict as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "event_submission_in_progress", "message": str(exc)},
        )
    except ObjectStoreError as exc:
        # 对象存储不可用：提交未完成（状态机行已持久化，恢复/重试可续跑）。
        raise HTTPException(
            status_code=503,
            detail={
                "code": "payload_store_unavailable",
                "message": f"事件载荷对象存储暂不可用，请稍后重试: {exc}",
            },
        )
    if duplicate:
        response.status_code = 200
    return await _event_out(row, duplicate=duplicate)


@router.get("/events/{event_pk}", response_model=EventOut, tags=["events"])
async def get_event(event_pk: int) -> EventOut:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await repo.get_event(conn, event_pk)
    if row is None:
        raise HTTPException(status_code=404, detail="事件不存在")
    try:
        return await _event_out(row, duplicate=False)
    except ObjectStoreError as exc:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "payload_store_unavailable",
                "message": f"事件载荷对象存储暂不可用: {exc}",
            },
        )


@router.get(
    "/events/{event_pk}/deliveries",
    response_model=list[DeliveryOut],
    tags=["events"],
)
async def list_event_deliveries(event_pk: int) -> list[DeliveryOut]:
    pool = get_pool()
    async with pool.acquire() as conn:
        event = await repo.get_event(conn, event_pk)
        if event is None:
            raise HTTPException(status_code=404, detail="事件不存在")
        rows = await repo.list_deliveries_for_event(conn, event_pk)
    return [_delivery_out(r) for r in rows]


# -- 订阅 ----------------------------------------------------------------------

@router.post(
    "/subscriptions",
    response_model=SubscriptionOut,
    status_code=201,
    tags=["subscriptions"],
)
async def create_subscription(body: SubscriptionCreate) -> SubscriptionOut:
    pool = get_pool()
    target = body.target_url.strip()
    # 入口安全校验：scheme 白名单、禁止 userinfo、解析地址全量校验。
    # （Worker 每次尝试还会重新解析并固定地址，防校验后 DNS 重绑定。）
    await validate_target_url(target)
    keyring = get_keyring()
    if keyring is None:
        # 未配置密钥环时拒绝写入（绝不落明文），读接口不受影响。
        raise HTTPException(
            status_code=503,
            detail={
                "code": "keyring_not_configured",
                "message": "服务端未配置本地密钥环，无法加密保存订阅密钥",
            },
        )
    async with pool.acquire() as conn:
        row = await repo.create_subscription(
            conn,
            body.source,
            target,
            body.secret,
            keyring=keyring,
            max_attempts=(
                body.max_attempts
                if body.max_attempts is not None
                else settings.max_attempts
            ),
            backoff_base_seconds=(
                body.backoff_base_seconds
                if body.backoff_base_seconds is not None
                else settings.backoff_base_seconds
            ),
            backoff_cap_seconds=(
                body.backoff_cap_seconds
                if body.backoff_cap_seconds is not None
                else settings.backoff_cap_seconds
            ),
        )
    return _subscription_out(row)


@router.get(
    "/subscriptions", response_model=list[SubscriptionOut], tags=["subscriptions"]
)
async def list_subscriptions(
    source: str | None = Query(default=None),
) -> list[SubscriptionOut]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await repo.list_subscriptions(conn, source)
    return [_subscription_out(r) for r in rows]


@router.get(
    "/subscriptions/{subscription_id}",
    response_model=SubscriptionOut,
    tags=["subscriptions"],
)
async def get_subscription(subscription_id: int) -> SubscriptionOut:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await repo.get_subscription_by_id(conn, subscription_id)
    if row is None:
        raise HTTPException(status_code=404, detail="订阅不存在")
    return _subscription_out(row)


@router.post(
    "/subscriptions/{subscription_id}/pause",
    response_model=SubscriptionOut,
    tags=["subscriptions"],
)
async def pause_subscription(subscription_id: int) -> SubscriptionOut:
    """暂停订阅投递（幂等）。

    暂停与 Worker 认领在数据库订阅行锁上串行：本接口事务提交成功后，该订阅
    不会再被认领产生新租约；暂停前已认领（在途）的尝试不受影响，照常结算。
    暂停期间 `POST /events` 仍为该订阅建立 pending 投递并钉住当时的配置版本；
    投递的 seq、not_before、attempts_made 全部保留，恢复后原样继续。
    对已暂停的订阅重复暂停为幂等操作（返回 200 与当前状态）。
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await repo.set_subscription_paused(conn, subscription_id, True)
    if row is None:
        raise HTTPException(status_code=404, detail="订阅不存在")
    return _subscription_out(row)


@router.post(
    "/subscriptions/{subscription_id}/resume",
    response_model=SubscriptionOut,
    tags=["subscriptions"],
)
async def resume_subscription(subscription_id: int) -> SubscriptionOut:
    """恢复订阅投递（幂等）。

    只清除暂停闸门：不重置任何投递状态，Worker 沿原 seq、退避时刻
    （not_before）与尝试次数（attempts_made）继续；钉住的配置版本不变。
    对投递中的订阅重复恢复为幂等操作（返回 200 与当前状态）。
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await repo.set_subscription_paused(conn, subscription_id, False)
    if row is None:
        raise HTTPException(status_code=404, detail="订阅不存在")
    return _subscription_out(row)


# -- 订阅配置版本 / 无损切换 -----------------------------------------------------

def _version_out(row: asyncpg.Record) -> VersionOut:
    return VersionOut(
        version_id=row["version_id"],
        subscription_id=row["subscription_id"],
        revision=row["revision"],
        target_url=row["target_url"],
        max_attempts=row["max_attempts"],
        backoff_base_seconds=row["backoff_base_seconds"],
        backoff_cap_seconds=row["backoff_cap_seconds"],
        secret_key_id=row["secret_key_id"],
        created_at=row["created_at"],
        superseded_at=row["superseded_at"],
        is_current=row["is_current"],
    )


@router.post(
    "/subscriptions/{subscription_id}/versions",
    response_model=VersionOut,
    status_code=201,
    tags=["subscriptions"],
)
async def publish_version(
    subscription_id: int, body: VersionPublish
) -> VersionOut:
    """发布新的不可变配置版本（CAS）。

    必须携带 `expected_revision`（调用方当前所见版本）。与当前版本不一致时
    返回 409（并发发布只有一个成功）。切换边界与发布事务原子提交：边界前
    已创建的投递及其重试始终使用旧版本，边界后的投递使用新版本。
    """
    pool = get_pool()
    target_url = body.target_url.strip()
    # 入口安全校验（与创建订阅同一规则；不随发布事务放宽）
    await validate_target_url(target_url)
    keyring = get_keyring()
    if keyring is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "keyring_not_configured",
                "message": "服务端未配置本地密钥环，无法加密保存订阅密钥",
            },
        )
    async with pool.acquire() as conn:
        async with conn.transaction():
            sub = await repo.get_subscription_by_id(conn, subscription_id)
            if sub is None:
                raise HTTPException(status_code=404, detail="订阅不存在")
            current = await repo.get_current_version(conn, subscription_id)
            if current is None:  # 理论上不可能
                raise HTTPException(status_code=404, detail="当前配置版本不存在")
            try:
                row, _revision = await repo.publish_version(
                    conn,
                    keyring=keyring,
                    subscription_id=subscription_id,
                    target_url=target_url,
                    secret=body.secret,
                    max_attempts=(
                        body.max_attempts
                        if body.max_attempts is not None
                        else current["max_attempts"]
                    ),
                    backoff_base_seconds=(
                        body.backoff_base_seconds
                        if body.backoff_base_seconds is not None
                        else float(current["backoff_base_seconds"])
                    ),
                    backoff_cap_seconds=(
                        body.backoff_cap_seconds
                        if body.backoff_cap_seconds is not None
                        else float(current["backoff_cap_seconds"])
                    ),
                    expected_revision=body.expected_revision,
                )
            except repo.ConfigConflictError as exc:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": exc.code,
                        "message": str(exc),
                        "current_revision": exc.current_revision,
                    },
                )
            except asyncpg.UniqueViolationError:
                # 竞态兜底：expected_revision 校验通过但插入新版本时，
                # 另一个并发发布已先提交（同 revision 唯一约束，事务随之回滚）。
                # CAS 语义下这同样是一次失败的并发发布 -> 409；调用方重新获取
                # 当前 revision 后重试。
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "revision_conflict",
                        "message": "并发发布冲突：该 expected_revision 已被其他发布抢先提交",
                    },
                )
    return _version_out({**row, "is_current": True})


@router.get(
    "/subscriptions/{subscription_id}/versions",
    response_model=list[VersionOut],
    tags=["subscriptions"],
)
async def list_versions(subscription_id: int) -> list[VersionOut]:
    """列出订阅全部配置版本（含切换边界），不返回密钥。"""
    pool = get_pool()
    async with pool.acquire() as conn:
        if await repo.get_subscription_by_id(conn, subscription_id) is None:
            raise HTTPException(status_code=404, detail="订阅不存在")
        rows = await repo.list_versions(conn, subscription_id)
    return [_version_out(r) for r in rows]


# -- 投递历史 / 死信 -------------------------------------------------------------

@router.get(
    "/deliveries", response_model=list[DeliveryOut], tags=["deliveries"]
)
async def list_deliveries(
    status: str | None = Query(default=None),
    subscription_id: int | None = Query(default=None),
    source: str | None = Query(default=None),
    config_revision: int | None = Query(
        default=None, ge=1, description="只返回使用指定配置版本的投递"
    ),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[DeliveryOut]:
    if status is not None and status not in VALID_STATUSES:
        raise HTTPException(
            status_code=400, detail=f"status 必须是 {sorted(VALID_STATUSES)} 之一"
        )
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await repo.list_deliveries(
            conn,
            status=status,
            subscription_id=subscription_id,
            source=source,
            config_revision=config_revision,
            limit=limit,
            offset=offset,
        )
    return [_delivery_out(r) for r in rows]


@router.get(
    "/deliveries/{delivery_id}", response_model=DeliveryOut, tags=["deliveries"]
)
async def get_delivery(delivery_id: int) -> DeliveryOut:
    pool = get_pool()
    async with pool.acquire() as conn:
        row = await repo.get_delivery(conn, delivery_id)
    if row is None:
        raise HTTPException(status_code=404, detail="投递不存在")
    return _delivery_out(row)


@router.get(
    "/deliveries/{delivery_id}/attempts",
    response_model=list[AttemptOut],
    tags=["deliveries"],
)
async def list_delivery_attempts(delivery_id: int) -> list[AttemptOut]:
    pool = get_pool()
    async with pool.acquire() as conn:
        if await repo.get_delivery(conn, delivery_id) is None:
            raise HTTPException(status_code=404, detail="投递不存在")
        rows = await repo.list_attempts(conn, delivery_id)
    return [
        AttemptOut(
            id=r["id"],
            attempt_number=r["attempt_number"],
            worker_id=r["worker_id"],
            started_at=r["started_at"],
            finished_at=r["finished_at"],
            outcome=r["outcome"],
            http_status=r["http_status"],
            response_excerpt=r["response_excerpt"],
            error_message=r["error_message"],
            leased_at=r["leased_at"],
            lease_expires_at=r["lease_expires_at"],
        )
        for r in rows
    ]


@router.get(
    "/dead-letters", response_model=list[DeliveryOut], tags=["dead-letters"]
)
async def list_dead_letters(
    subscription_id: int | None = Query(default=None),
    source: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[DeliveryOut]:
    pool = get_pool()
    async with pool.acquire() as conn:
        rows = await repo.list_deliveries(
            conn,
            status="dead_lettered",
            subscription_id=subscription_id,
            source=source,
            limit=limit,
            offset=offset,
        )
    return [_delivery_out(r) for r in rows]


@router.post(
    "/dead-letters/{delivery_id}/replay",
    response_model=ReplayOut,
    status_code=201,
    tags=["dead-letters"],
)
async def replay_dead_letter(
    delivery_id: int, body: ReplayRequest | None = None
) -> ReplayOut:
    """重放死信：在同一条投递链上新建投递，旧记录完整保留。

    默认沿用原投递的配置版本（`config_revision` 与原记录相同）；
    请求体传 `{"use_current_version": true}` 可显式选用订阅当前版本。
    选择结果固化在新投递记录上。
    """
    use_current = bool(body.use_current_version) if body is not None else False
    pool = get_pool()
    async with pool.acquire() as conn:
        try:
            new_row, config_revision = await repo.replay_dead_letter(
                conn, delivery_id, use_current_version=use_current
            )
        except LookupError:
            raise HTTPException(status_code=404, detail="投递不存在")
        except repo.ReplayError as exc:
            status_code = 409 if exc.code in {"not_dead_lettered", "chain_busy"} else 400
            raise HTTPException(status_code=status_code, detail=str(exc))
    return ReplayOut(
        replayed_from_delivery_id=delivery_id,
        new_delivery_id=new_row["id"],
        chain_id=new_row["chain_id"],
        chain_seq=new_row["chain_seq"],
        status=new_row["status"],
        config_revision=config_revision,
    )


# -- 密钥信封加密 / 轮换状态 ---------------------------------------------------------


@router.get("/crypto/status", response_model=CryptoStatusOut, tags=["crypto"])
async def crypto_status() -> CryptoStatusOut:
    """密钥环与信封加密状态（只含 key_id 标识符，绝不含密钥材料/明文）。"""
    keyring = get_keyring()
    pool = get_pool()
    async with pool.acquire() as conn:
        plaintext = await repo.count_plaintext_versions(conn)
        by_key = await repo.count_versions_by_key_id(conn)
        rotations = await repo.list_rotations(conn)
    known = set(keyring.key_ids) if keyring is not None else set()
    in_use = {row["key_id"]: row["n"] for row in by_key}
    return CryptoStatusOut(
        keyring_configured=keyring is not None,
        active_key_id=keyring.active_key_id if keyring is not None else None,
        key_ids=sorted(known),
        plaintext_versions_pending=plaintext,
        encrypted_versions_by_key_id=in_use,
        unknown_key_ids_in_use=sorted(k for k in in_use if k not in known),
        rotations=[RotationRunOut(**dict(r)) for r in rotations],
    )


# -- 事件载荷对象存储状态 -------------------------------------------------------------


@router.get("/payloads/status", response_model=PayloadStorageStatusOut, tags=["payloads"])
async def payload_storage_status() -> PayloadStorageStatusOut:
    """事件载荷对象存储 / 在线迁移 / GC 状态（只含计数，绝不含载荷内容）。

    一致性读：状态行、legacy_events_pending 与 migration.remaining 等全部读
    操作在**同一个只读 REPEATABLE READ 快照**内完成，因此同次响应对应同一
    数据库视图——两个剩余数恒等；除持久化 failed 外，快照中仍可见旧行即
    running、清零即 completed（见 payloads.build_migration_status）。本接口
    只读，不会重开/推进迁移进度；最后一批旧载荷在查询间并发提交时，提交前
    的请求看到 running/N、提交后的请求看到 completed/0，各自自洽。
    """
    pool = get_pool()
    store = get_object_store()
    async with pool.acquire() as conn:
        async with payloads.payload_status_snapshot(conn):
            total_events = await conn.fetchval("SELECT COUNT(*) FROM events")
            # 剩余集合只 COUNT 这一次：外层字段与 migration.remaining 共用同一
            # 快照下的同一个值，绝不可能出现两个不同的剩余数。
            legacy = await repo.count_legacy_events(conn)
            objects = await repo.count_payload_objects(conn)
            candidates = await repo.count_payload_candidates(conn)
            pending = await repo.count_pending_submissions(conn)
            state = await repo.get_migration_state(conn)
            migration = payloads.build_migration_status(state, legacy)
            gc_runs = await repo.list_gc_runs(conn)
            ref_sum = await conn.fetchval(
                "SELECT COALESCE(SUM(ref_count), 0) FROM event_payload_objects"
            )
            bytes_sum = await conn.fetchval(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM event_payload_objects"
            )
    return PayloadStorageStatusOut(
        store_mode=store.mode,
        bucket=getattr(store, "bucket", None),
        total_events=total_events,
        legacy_events_pending=legacy,
        payload_objects=objects,
        total_references=ref_sum,
        total_object_bytes=bytes_sum,
        pending_submissions=pending,
        gc_candidates=candidates,
        gc_grace_seconds=settings.payload_gc_grace_seconds,
        migration={
            "status": migration["status"],
            "processed": migration["processed"],
            "remaining": migration["remaining"],
            "last_event_id": migration["last_event_id"],
            "last_error": migration["last_error"],
            "updated_at": migration["updated_at"].isoformat()
            if migration["updated_at"] is not None
            else None,
        },
        gc_runs=[GCRunOut(**dict(r)) for r in gc_runs],
    )


# -- 垃圾回收状态 -------------------------------------------------------------------


@router.get("/payloads/gc", response_model=GCStatusOut, tags=["payloads"])
async def payload_gc_status() -> GCStatusOut:
    """垃圾回收状态总览（候选数、到期数、最近运行；只含计数，不含载荷内容）。

    - `candidates`：当前 GC 候选（零引用标记或 --rescan-store 登记的存储孤儿）；
    - `due_candidates`：已超过宽限期、下一轮 gc 将进入“最终复核→删除”的数量；
    - 进行中提交（`pending_submissions`）引用的对象绝不会被删除。
    物理回收仍由管理命令 `python -m app.payloadadmin gc` 触发（本接口只读）。
    """
    pool = get_pool()
    async with pool.acquire() as conn:
        overview = await repo.gc_candidate_overview(conn)
        pending = await repo.count_pending_submissions(conn)
        gc_runs = await repo.list_gc_runs(conn, limit=10)
    return GCStatusOut(
        gc_grace_seconds=settings.payload_gc_grace_seconds,
        candidates=overview["candidates"],
        due_candidates=overview["due"],
        oldest_candidate_age_seconds=float(overview["oldest_age_seconds"] or 0),
        pending_submissions=pending,
        recent_runs=[GCRunOut(**dict(r)) for r in gc_runs],
    )


@router.get(
    "/payloads/gc/{digest}",
    response_model=GCCandidateOut,
    tags=["payloads"],
)
async def payload_gc_digest_status(digest: str) -> GCCandidateOut:
    """查询单个对象摘要的回收状态（候选标记、到期时刻、引用计数、进行中提交）。

    对象被任一事件引用（或存在引用该摘要的进行中提交）时不会被删除；
    无元数据行的存储孤儿也可经此查询其候选与到期状态。摘要必须是 64 位
    小写十六进制 SHA-256，否则 400。
    """
    if not is_valid_digest(digest):
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_digest", "message": "摘要必须是 64 位十六进制 SHA-256"},
        )
    pool = get_pool()
    async with pool.acquire() as conn:
        candidate = await repo.get_gc_candidate(conn, digest)
        obj = await repo.get_payload_object(conn, digest)
        in_flight = await repo.pending_exists_for_digest(conn, digest)
    grace = settings.payload_gc_grace_seconds
    first_seen = candidate["first_seen_at"] if candidate is not None else None
    eligible_at = (
        first_seen + timedelta(seconds=grace) if first_seen is not None else None
    )
    return GCCandidateOut(
        digest=digest,
        is_candidate=candidate is not None,
        first_seen_at=first_seen,
        eligible_at=eligible_at,
        eligible_now=(
            eligible_at is not None
            and eligible_at <= datetime.now(timezone.utc)
        ),
        size_bytes=obj["size_bytes"] if obj is not None else None,
        ref_count=obj["ref_count"] if obj is not None else None,
        object_metadata_exists=obj is not None,
        pending_submission=in_flight,
        gc_grace_seconds=grace,
    )
