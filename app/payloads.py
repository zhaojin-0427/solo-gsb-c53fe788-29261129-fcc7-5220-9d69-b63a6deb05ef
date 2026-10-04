"""事件载荷提交状态机、崩溃恢复、在线迁移与垃圾回收的编排层。

提交（submit_event_payload）：
  见 repository.py 文件头的五步状态机。本模块负责事务边界与对象存储调用的
  交错；任何抛出异常的位置之后，状态都可由 recover_pending 断点续跑。

恢复（recover_pending）：
  扫描 payload_upload_pending 中超过 stale 阈值的残留行（崩溃于“登记后/
  上传失败/终结事务失败”的提交），幂等补传对象并重放终结事务；
  事件已存在（重复提交完成）的残留行直接清除。

在线迁移（migrate_legacy_payloads）：
  旧 JSONB 事件按批链接到（必要时上传的）内容寻址对象，双读不中断，
  进度持久化、可断点续跑、可并发；最后可用 clear_legacy_payloads 回收
  JSONB 空间（此时所有读路径都已只认对象）。

  并发漏行修复（SKIP LOCKED + 空/短批裁决）：取批不使用单调 id 游标——
  否则一方锁住较早事件后上传失败回滚、另一方跳锁处理较晚事件并遇空批/短批
  时会把状态写成 completed，游标还会越过回滚行使其永不可再领取。每批都从
  “仍待迁移集合”重新领取（部分索引，行迁移成功即出集合），进度可回访被
  跳过的旧行。空批/短批都不代表完成：只有在“无任何事务持锁、确无旧载荷”
  （COUNT(payload_digest IS NULL)=0）时才在批内标记 completed；空批但
  剩余>0（剩余行正被别的迁移者持锁）只返回 0、状态保持 running，由调用方
  稍后重跑。挂引用是“仅当 payload_digest 为空”的防卫性条件更新，重复
  运行不重复计数、不新增引用。

  并发死锁修复：批次先在事务内锁定本批旧事件行（SKIP LOCKED，互不分批），
  在内存中算出全部所需摘要；随后按咨询锁实际键 (classid,objid) 的全局统一
  顺序一次性取齐本批全部摘要锁（同一把锁只取一次），再幂等上传对象、逐事件
  挂引用。任意并发批次取锁顺序一致，不会因“两批含相同摘要 X/Y 而事件顺序
  相反”形成 AB-BA 死锁；锁贯穿上传与挂引用全程，与 GC 删除对同一摘要互斥。
  对象上传失败时整批回滚（进度不前、可重跑），失败状态在批次事务之外的
  独立事务持久化（事务内写 failed 会随批次一并回滚，无法落库）。

垃圾回收（run_gc）：
  标记（零引用且无进行中提交）→ 宽限期 → 逐对象在“按摘要的咨询锁 +
  元数据行锁”内复核引用（防并发提交/恢复/迁移复用同一内容对象）→
  删对象 → 删元数据；
  --rescan-store 额外清理“对象存储里有、元数据里没有”的孤儿（崩溃于上传后、
  终结前的对象，或手工残留），同样先过宽限候选。

引用互斥（与 GC 的竞态修复）：
  所有建立对象引用的路径（新提交终结、崩溃恢复、旧数据在线迁移）都在同一
  数据库事务、同一把按摘要的事务级咨询锁内完成“锁 → 幂等 PUT 对象 →
  建元数据与引用”；GC 的最终复核与物理删除持有同一把锁。锁的粒度是摘要，
  因而即使对象在存储中存在而数据库尚无元数据行（--rescan-store 登记的孤儿），
  并发的新提交/恢复/迁移也会与删除严格串行：对象一旦被引用就绝不可能被删。
  在线迁移一次处理整批事件、可能需要多把摘要锁；为避免并发批次因取锁顺序
  相反形成 AB-BA 死锁，迁移先汇总本批全部摘要并按咨询锁实际键的统一顺序
  一次取齐（同键去重），再上传与挂引用（见 payload_object_xact_locks_ordered）。
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator

import asyncpg

from app import objectstore, repository as repo
from app.config import settings
from app.objectstore import (
    ObjectNotFound,
    ObjectStore,
    ObjectStoreError,
    canonical_payload,
    canonical_payload_bytes,
    content_digest,
    verify_bytes,
)

log = logging.getLogger("webhook.payloads")


class PayloadSubmitConflict(Exception):
    """同一 (source, event_id) 正以另一载荷提交中（并发且内容不同）。"""


class PayloadTooLarge(Exception):
    def __init__(self, size: int, limit: int):
        super().__init__(f"事件载荷 {size} 字节超过上限 {limit}")
        self.size = size
        self.limit = limit


# -- 提交状态机 -------------------------------------------------------------------

async def submit_event_payload(
    conn: asyncpg.Connection,
    store: ObjectStore,
    *,
    source: str,
    event_id: str,
    payload: dict[str, Any],
    owner_id: str,
) -> tuple[asyncpg.Record, bool]:
    """执行一次提交，返回 (event 行, 是否重复)。

    成功返回时对象与数据库引用均已就绪；任何失败都不产生可见半成品。
    `conn` 由调用方提供；对象上传在终结事务、按摘要咨询锁内完成
    （见模块/仓库文件头的状态机说明），与 GC 的物理删除互斥。
    """
    # 第 1 步：快速查重（常见路径，零对象存储调用）。
    existing = await repo.find_event_by_key(conn, source, event_id)
    if existing is not None:
        return existing, True

    digest, data = canonical_payload(payload)
    if len(data) > settings.payload_max_bytes:
        raise PayloadTooLarge(len(data), settings.payload_max_bytes)

    # 第 2 步：登记持久化状态机行（独立事务，确保崩溃后字节不丢）。
    async with conn.transaction():
        # 再查一次（事务内拿到提交顺序视图）+ 检查进行中的同键提交。
        existing = await repo.find_event_by_key(conn, source, event_id)
        if existing is not None:
            return existing, True
        in_flight = await repo.get_pending_submission_for_event(conn, source, event_id)
        if in_flight is not None:
            # 同键已有进行中提交：内容一致则等其完成后按重复返回原事件
            # （极端情况下它崩溃了会由后台恢复接管，调用方稍后重试即可）；
            # 内容不一致 -> 明确冲突（业务键不能同时是两个载荷）。
            if in_flight["digest"] == digest:
                row = await _wait_for_event(conn, source, event_id)
                return row, True
            raise PayloadSubmitConflict(
                f"事件 ({source}, {event_id}) 正以不同载荷提交中"
            )
        try:
            await repo.register_pending_submission(
                conn,
                digest=digest,
                source=source,
                event_id=event_id,
                payload_bytes=data,
                owner_id=owner_id,
            )
        except asyncpg.UniqueViolationError as exc:
            # 与上面的检查并发：另一个同键提交刚插入。按提交冲突返回，调用方可重试。
            raise PayloadSubmitConflict(
                f"事件 ({source}, {event_id}) 正并发提交，请稍后重试"
            ) from exc

    # 第 3+4 步：在“持有按摘要咨询锁的终结事务”内幂等上传对象并建引用。
    #
    # 关键：对象 PUT 必须在锁内（而不是事务外先传），否则 GC 可在“对象已
    # 传、元数据/引用尚不可见”的窗口把对象删掉（元数据行尚不存在时行锁也
    # 拦不住）。内容寻址对象不可变，锁内重复 PUT 天然幂等；对象存储失败时
    # 事务回滚（无元数据/引用变更），pending 行保留，可安全重试/恢复。
    try:
        return await _put_and_finalize(
            conn,
            store,
            source=source,
            event_id=event_id,
            digest=digest,
            data=data,
        )
    except Exception:
        # 终结失败：pending 行保留，由 recover_pending 续跑；对象即便已上传
        # 但事务回滚，也是零引用孤儿，最终由 GC 的 --rescan-store 清理。
        log.exception(
            "提交终结失败，保留状态机行待恢复: source=%s event_id=%s digest=%s",
            source, event_id, digest,
        )
        raise


async def _put_and_finalize(
    conn: asyncpg.Connection,
    store: ObjectStore,
    *,
    source: str,
    event_id: str,
    digest: str,
    data: bytes,
) -> tuple[asyncpg.Record, bool]:
    """锁内“确保对象存在 → 终结（元数据/引用/事件/投递/清 pending）”。

    终结事务先获取按摘要的事务级咨询锁（finalize_event_submission 内部再次
    可重入获取同一把），与 GC 的“最终复核 → 物理删除”严格互斥。拿到锁后
    幂等 PUT：若 GC 刚刚删除了该对象，这里会把同一内容重新写回再建引用，
    因此不存在悬空引用；PUT 已存在的同键对象是内容寻址下的空操作。
    """
    async with conn.transaction():
        await repo.payload_object_xact_lock(conn, digest)
        await store.put_object(digest, data)
        return await repo.finalize_event_submission(
            conn,
            source=source,
            event_id=event_id,
            digest=digest,
            size_bytes=len(data),
        )


async def _wait_for_event(
    conn: asyncpg.Connection, source: str, event_id: str, *, timeout: float = 10.0
) -> asyncpg.Record:
    """并发同内容提交时等待进行者把事件提交出来。"""
    deadline = datetime.now(timezone.utc) + timedelta(seconds=timeout)
    while True:
        row = await repo.find_event_by_key(conn, source, event_id)
        if row is not None:
            return row
        if datetime.now(timezone.utc) >= deadline:
            # 进行者疑似崩溃：交给恢复流程；本次按冲突返回（调用方 409，可重试）。
            raise PayloadSubmitConflict(
                f"事件 ({source}, {event_id}) 的并发提交尚未完成，请稍后重试"
            )
        await asyncio.sleep(0.05)


# -- Worker 读路径：取对象 + 摘要校验 ----------------------------------------------

class PayloadIntegrityError(Exception):
    """对象取回失败或摘要复核不通过；Worker 据此拒绝签名。"""


async def load_event_payload(
    store: ObjectStore,
    row: dict[str, Any] | asyncpg.Record,
) -> dict[str, Any]:
    """解析投递上下文中的事件载荷（双读 + 摘要复核）。

    - 新格式（payload_digest 非空）：从对象存储取回，先比对摘要再 JSON 解析；
      对象缺失或摘要不符抛 PayloadIntegrityError（绝不签名/投递坏数据）。
    - 旧格式（迁移未完成，payload_digest 为空）：回退读 JSONB 列。
    """
    digest = row["payload_digest"]
    if digest is None:
        payload = row["payload"]
        return dict(payload) if payload is not None else {}
    try:
        data = await store.get_object(digest)
    except ObjectNotFound as exc:
        raise PayloadIntegrityError(
            f"载荷对象缺失（digest={digest}）：拒绝签名"
        ) from exc
    except ObjectStoreError as exc:
        raise PayloadIntegrityError(f"读取载荷对象失败: {exc}") from exc
    if not verify_bytes(data, digest):
        raise PayloadIntegrityError(
            f"载荷摘要复核失败（期望 {digest}，实际 {content_digest(data)}）："
            "对象可能损坏或被篡改，拒绝签名"
        )
    try:
        payload = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PayloadIntegrityError(f"载荷对象不是合法 UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PayloadIntegrityError("载荷对象不是 JSON 对象")
    return payload


# -- 崩溃恢复 ----------------------------------------------------------------------

async def recover_pending(
    conn: asyncpg.Connection,
    store: ObjectStore,
    *,
    owner_id: str,
    stale_age_seconds: float | None = None,
    batch_size: int = 100,
) -> int:
    """续跑/清理残留的提交状态机行，返回本轮处理行数。

    - 事件已存在（别的进程已完成或重复提交）：直接删除 pending；
    - 其余：必要时幂等补传对象，再重放终结事务。
    """
    age = (
        settings.payload_stale_age_seconds
        if stale_age_seconds is None
        else stale_age_seconds
    )
    stale_before = datetime.now(timezone.utc) - timedelta(seconds=age)
    rows = await repo.list_stale_pending(
        conn, stale_before=stale_before, limit=batch_size
    )
    handled = 0
    for row in rows:
        digest = row["digest"]
        data = bytes(row["payload_bytes"])
        # 内容寻址校验：pending 行内字节必须与其键一致（防任何不一致状态）。
        if content_digest(data) != digest:
            log.error(
                "丢弃损坏的提交状态机行 source=%s event_id=%s digest=%s"
                "（字节与摘要不符）",
                row["source"], row["event_id"], digest,
            )
            await repo.delete_pending_submission(
                conn, row["source"], row["event_id"]
            )
            handled += 1
            continue
        try:
            existing = await repo.find_event_by_key(
                conn, row["source"], row["event_id"]
            )
            if existing is not None:
                await repo.delete_pending_submission(
                    conn, row["source"], row["event_id"]
                )
                handled += 1
                continue
            await repo.adopt_pending_submission(conn, row["id"], owner_id)
            # 与新提交共用同一把“锁内 PUT + 终结”路径：恢复期间同摘要的
            # GC 删除被咨询锁挡住，杜绝“恢复上传中对象被删”的悬空引用。
            await _put_and_finalize(
                conn,
                store,
                source=row["source"],
                event_id=row["event_id"],
                digest=digest,
                data=data,
            )
            handled += 1
        except ObjectStoreError:
            # 对象存储暂不可用：保留该行，下轮/下个进程继续。
            log.warning("恢复提交 digest=%s 时对象存储不可用，稍后重试", digest)
            continue
        except Exception:  # noqa: BLE001 - 单条恢复失败不能拖垮整轮
            log.exception(
                "恢复提交状态机行失败 source=%s event_id=%s",
                row["source"], row["event_id"],
            )
            continue
    return handled


async def recovery_loop(owner_id: str) -> None:
    """API 进程后台任务：周期接管崩溃残留的提交。"""
    store = objectstore.get_object_store()
    pool = None
    from app.db import get_pool

    try:
        pool = get_pool()
    except RuntimeError:
        return
    interval = settings.payload_recover_interval_seconds
    log.info("提交状态机后台恢复任务已启动（间隔 %ss）", interval)
    while True:
        await asyncio.sleep(interval)
        try:
            async with pool.acquire() as conn:
                n = await recover_pending(conn, store, owner_id=owner_id)
            if n:
                log.info("后台恢复处理了 %s 条残留提交", n)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("后台恢复轮询失败")


# -- 在线迁移（旧 JSONB -> 对象引用） -----------------------------------------------

async def migrate_legacy_payloads(
    conn: asyncpg.Connection,
    store: ObjectStore,
    *,
    batch_size: int = 200,
) -> int:
    """跑一批旧事件迁移并推进持久化进度；返回本批实际挂接行数。

    返回 0 有两种截然不同的情形，调用方必须区分：
    - 确无旧载荷（全库 COUNT 剩余 = 0，completed）：迁移真正完成；
    - 空批但剩余 > 0：剩余行正被并发迁移者持锁（SKIP LOCKED 跳过），
      它们可能正在提交也可能即将整批回滚——保持 running，稍后重跑即可
      回访这些行（回滚释放的行仍在剩余集合内，无游标挡路）。

    每个事件：规范化旧 JSONB -> 摘要 -> 幂等上传对象 -> 同事务挂引用并计数。
    双读期间新旧数据都可投递（Worker 的 load_event_payload 自动选择）。

    并发安全（死锁修复）：整批一个事务——先取批（FOR UPDATE SKIP LOCKED，
    各迁移者领取互不相交的事件行），在内存中汇总本批所需的全部摘要，然后按
    咨询锁实际键的统一顺序一次取齐（同键去重，只取一次），再上传对象、挂
    事件引用。所有并发批次取锁顺序相同，杜绝反向持锁导致的 AB-BA 死锁。
    锁在整个上传+挂引用期间持有，与 GC 的“最终复核+物理删除”对同一摘要严格
    互斥。上传失败整批回滚、进度不前，重跑即断点续跑；failed 状态在批次事务
    之外的独立事务持久化（批次事务内的写入会随回滚丢失）。
    """
    await repo.reopen_migration_if_legacy_remaining(conn)
    state = await repo.get_migration_state(conn)
    if state["status"] == "completed":
        return 0

    # 第 1 步：批次事务内领取事件行，并在内存中算出全部规范化载荷与摘要。
    # 这一步不触摘要咨询锁、不触对象存储；持有的只是本批事件行锁（SKIP LOCKED
    # 保证并发迁移者领取不同批次）。每批都从剩余集合领取，不使用单调游标，
    # 故别批回滚释放的较早行在重跑时仍可被领取。
    try:
        async with conn.transaction():
            rows = await repo.fetch_legacy_events_batch(conn, limit=batch_size)
            if not rows:
                # 空批不代表完成：剩余行可能正被并发迁移者持锁（未提交）。
                # 只有此刻全库确无旧载荷（没有任何持锁者还留着旧行）才裁决
                # completed；否则保持 running 返回 0，由调用方稍后重跑。
                remaining = await repo.count_legacy_events(conn)
                if remaining == 0:
                    await repo.set_migration_status(conn, "completed")
                return 0

            # item: (事件行 id, 规范化字节, 摘要)。保留重复摘要（不同事件可共享
            # 同一去重对象），但取锁/上传按摘要去重。
            items: list[tuple[int, bytes, str]] = []
            for row in rows:
                payload = row["payload"] if row["payload"] is not None else {}
                data = canonical_payload_bytes(payload)
                items.append((row["id"], data, content_digest(data)))

            # 第 2 步：按咨询锁实际键 (classid,objid) 的全局统一顺序取齐本批全部
            # 摘要锁（同一把锁只取一次）。这样并发批次即便事件顺序相反，持锁顺序
            # 也完全一致，不可能成环（修复两批 X/Y 顺序相反而互相等待的死锁）。
            # 锁在事务结束前一直持有，贯穿上传与挂引用，与 GC 的删除互斥。
            await repo.payload_object_xact_locks_ordered(
                conn, [digest for _id, _data, digest in items]
            )

            # 第 3 步：锁齐后幂等上传去重对象（同一摘要只传一次）。内容寻址对象
            # 不可变，重复 PUT 是空操作；若 GC 刚删过对象，这里把同一内容写回。
            sizes: dict[str, int] = {}
            for _id, data, digest in items:
                if digest in sizes:
                    continue
                sizes[digest] = len(data)
                # 抛出即整批回滚：无元数据/引用变更，进度不前；已 PUT 的对象是
                # 零引用孤儿，由 GC 的 --rescan-store 清理。failed 状态在下面
                # except 里以独立事务持久化（事务内写状态会随回滚一起丢失）。
                await store.put_object(digest, data)

            # 第 4 步：逐事件挂引用（attach 内部可重入地再取同一把咨询锁）。
            # 防卫性条件更新保证只有实际挂接的行才计数（重复运行不重复计数、
            # 不新增引用）。last_event_id 只是观测高水位，不再用于领取过滤。
            last_id = state["last_event_id"]
            attached_count = 0
            for event_pk, _data, digest in items:
                attached = await repo.attach_payload_object_to_event(
                    conn,
                    event_id_fk=event_pk,
                    digest=digest,
                    size_bytes=sizes[digest],
                )
                if attached:
                    attached_count += 1
                    last_id = max(last_id, event_pk)
            await repo.update_migration_progress(
                conn,
                last_event_id=last_id,
                processed_delta=attached_count,
            )

            # 短批同样不代表完成：未领到的行可能只是被并发迁移者持锁。提交本批
            # 后（READ COMMITTED 下 COUNT 取语句级新快照，能见到已提交的他批）
            # 再做权威裁决：仅当全库确无旧载荷时才 completed；否则保持 running。
            remaining = await repo.count_legacy_events(conn)
            if remaining == 0:
                await repo.set_migration_status(conn, "completed")
            return attached_count
    except ObjectStoreError as exc:
        # 批次事务已整批回滚（引用/进度均未落库），连接仍可复用：在独立事务把
        # 运行标记 failed 并落库错误，供 status/HTTP 查询；重跑时剩余集合不变、
        # 自动续跑（下一批成功 update_migration_progress 会清回 running）。
        try:
            await repo.set_migration_status(
                conn,
                "failed",
                f"对象上传失败（整批已回滚，重跑自动续跑）: {exc}",
            )
        except Exception:  # noqa: BLE001 - 持久化失败不应掩盖原始上传错误
            log.exception("持久化迁移失败状态失败")
        raise


async def migration_status(conn: asyncpg.Connection) -> dict[str, Any]:
    """迁移状态（独立快照读，供 CLI / 单调用方使用）。

    状态行与剩余计数在同一个 read_only REPEATABLE READ 快照内读取，二者
    必然对应同一数据库视图；状态再由该视图按 build_migration_status
    规则裁决（failed 持久保留，有旧行 running，清零 completed）。
    """
    async with payload_status_snapshot(conn):
        state = await repo.get_migration_state(conn)
        remaining = await repo.count_legacy_events(conn)
        return build_migration_status(state, remaining)


@contextlib.asynccontextmanager
async def payload_status_snapshot(
    conn: asyncpg.Connection,
) -> AsyncIterator[None]:
    """状态查询的一致性只读快照（REPEATABLE READ READ ONLY）。

    GET /payloads/status 的修复：旧实现把 COUNT 旧行与读 payload_migration_state
    放在 READ COMMITTED 的不同语句里，每条语句各自取语句级快照——最后一批旧
    JSONB 在两次查询之间提交时，响应可能同时给出 legacy_events_pending=0 而
    migration.remaining>0（或反过来），甚至 status=running 而 remaining=0。

    本上下文把同一次状态响应所需的全部读操作包进单个 REPEATABLE READ 只读
    事务：事务内所有语句共享**同一个快照**，因此迁移状态行、剩余计数与各处
    统计都来自一致的数据库视图，两个剩余数恒等、status 与 remaining 自洽。
    READ ONLY 保证状态查询绝不写入、绝不推进迁移进度（并发提交前看到旧视图
    报 running/N、提交后看到新视图报 completed/0，两种响应各自自洽）。
    外层已有事务（如迁移批次内）则退化为保存点，不改变外层隔离级别。
    """
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        yield


def build_migration_status(state: Any, remaining: int) -> dict[str, Any]:
    """按同一快照内的持久化状态行与剩余计数裁决响应状态（纯函数，不触库）。

    裁决规则（不写库，只影响本次响应；迁移命令如何落状态完全不变）：
    - 持久化 `failed` 一律保留（哪怕 remaining=0，那是失败前已迁完的视图），
      last_error 原样带出，由下次成功批次/重跑清回 running；
    - 其余状态下以同快照的剩余集合为准：仍可见旧行（remaining>0）报
      running；清零（remaining=0）报 completed。这样陈旧的 “completed 但
      仍有旧行” 状态在被 reopen 持久化纠正之前，读侧也不会谎报完成；
      而 running/0（最后一批刚提交、completed 尚未落库的瞬间）直接按
      completed 呈现，与 remaining=0 自洽，不等待任何写入。
    """
    raw_status = state["status"]
    if raw_status == "failed":
        status = "failed"
    elif remaining > 0:
        status = "running"
    else:
        status = "completed"
    return {
        "status": status,
        "processed": state["processed"],
        "last_event_id": state["last_event_id"],
        "remaining": remaining,
        "last_error": state["last_error"],
        "updated_at": state["updated_at"],
    }


# -- 垃圾回收 ----------------------------------------------------------------------

async def run_gc(
    conn: asyncpg.Connection,
    store: ObjectStore,
    *,
    grace_seconds: int | None = None,
    batch_size: int = 100,
    rescan_store: bool = False,
) -> dict[str, int]:
    """执行一轮 GC：标记 -> 宽限复核 -> 删除。返回统计。

    幂等：候选表记录 first_seen_at，重复运行只推进真正过期的对象；
    删除前在按摘要的咨询锁与候选/元数据行锁内复核 ref_count 与进行中提交，
    与并发的新提交/恢复/迁移互斥，防误删（含无元数据行的存储孤儿）。
    """
    grace = settings.payload_gc_grace_seconds if grace_seconds is None else grace_seconds
    run_id = await repo.start_gc_run(conn, rescanned_store=rescan_store)
    deleted = 0
    candidates = 0
    try:
        candidates = await repo.mark_gc_candidates(conn, grace)
        grace_before = datetime.now(timezone.utc) - timedelta(seconds=grace)
        digests = await repo.list_gc_candidates(
            conn, grace_before=grace_before, limit=batch_size
        )
        for digest in digests:
            deleted += await _delete_one_guarded(conn, store, digest)

        if rescan_store:
            deleted += await _sweep_store_orphans(conn, store)

        await repo.update_gc_run(
            conn, run_id,
            candidates=candidates, deleted=deleted, status="completed",
        )
    except Exception as exc:  # noqa: BLE001
        await repo.update_gc_run(
            conn, run_id,
            candidates=candidates, deleted=deleted, status="failed", error=str(exc),
        )
        raise
    return {"candidates": candidates, "deleted": deleted}


async def _delete_one_guarded(conn, store: ObjectStore, digest: str) -> int:
    """在单个数据库事务内完成“锁定复核 → 删对象 → 删元数据”。

    复核先取按摘要的事务级咨询锁并锁定候选行：
    - 咨询锁贯穿物理删除全程，并发提交/恢复/迁移的“锁内 PUT + 建引用”必须
      等到本事务提交（对象与元数据一起消失）或回滚（对象仍在），不存在
      “复核零引用后、删除前被并发建引用”而误删在用对象的窗口；元数据行
      尚不存在的存储孤儿同样受该锁保护（候选行本身也 FOR UPDATE 锁定）；
    - 复核为 reanimate（引用已重建或有进行中提交）：移除候选、对象保留；
    - 候选已被并发 GC 处理（gone）：跳过，不重复计数；
    - 对象物理删除失败：宽限重新计时并提交本事务（下轮 GC 幂等重试），
      不拖垮整轮回收，也不改变任何引用/提交状态。
    """
    async with conn.transaction():
        verdict = await repo.recheck_gc_candidate(conn, digest)
        if verdict == "gone":
            return 0
        if verdict == "reanimate":
            await repo.remove_gc_candidate(conn, digest)
            return 0
        try:
            await store.delete_object(digest)
        except ObjectStoreError:
            # 对象删除失败：宽限重新计时并提交本事务（下轮 GC 重试），
            # 不拖垮整轮回收。对象存储删除本身幂等，重试不破坏任何状态。
            log.warning("GC 删除对象失败，宽限重置，下轮重试: %s", digest)
            await repo.rollback_gc_candidate(conn, digest)
            return 0
        await repo.delete_payload_metadata_locked(conn, digest)
        return 1


async def _sweep_store_orphans(conn, store: ObjectStore) -> int:
    """登记“存储里存在、元数据里不存在”的对象（上传后崩溃的残留）。

    本函数只登记候选（first_seen_at 起算宽限期）；真正的删除由下一轮 GC 的
    主 sweep 在咨询锁 + 行锁复核后统一完成——并发提交、恢复或迁移重新建立
    引用的对象会被复活而不会被误删。已有元数据、或存在进行中提交状态机行
    （对象可能正处于“先上传、后终结”窗口）的键一律跳过。本函数始终返回 0
    （本轮不直接产生删除）。
    """
    registered = 0
    skipped_metadata = 0
    skipped_pending = 0
    seen = 0
    async for key in store.iter_all_keys():
        seen += 1
        obj = await repo.get_payload_object(conn, key)
        if obj is not None:
            skipped_metadata += 1
            continue  # 元数据存在：正常对象（零引用由主 sweep 处理）
        if await repo.pending_exists_for_digest(conn, key):
            skipped_pending += 1
            continue  # 进行中提交：终结事务会在锁内重建元数据与引用
        await conn.execute(
            """
            INSERT INTO payload_gc_candidates (digest)
            VALUES ($1) ON CONFLICT (digest) DO NOTHING
            """,
            key,
        )
        registered += 1
    log.info(
        "存储孤儿扫描完成：枚举 %s 个对象，新登记孤儿候选 %s 个"
        "（跳过有元数据 %s、有进行中提交 %s；过宽限期后由下一轮 GC 删除）",
        seen, registered, skipped_metadata, skipped_pending,
    )
    return 0
