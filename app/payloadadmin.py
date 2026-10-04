"""事件载荷对象存储管理命令行：在线迁移、垃圾回收、崩溃恢复与状态查看。

用法（容器内）：

    python -m app.payloadadmin status [--verbose]
        # 查看对象/引用/待迁移/待恢复/GC 运行状态

    python -m app.payloadadmin recover [--batch-size N]
        # 立即续跑崩溃/中断残留的提交状态机行（API 进程也会后台自动执行）

    python -m app.payloadadmin migrate [--batch-size N] [--wait-seconds N]
        # 把旧 JSONB 事件在线链接到内容寻址对象（幂等、断点续跑、可并发）；
        # 迁移期间双读，投递不中断。空批/短批不代表完成（可能只是并发迁移者
        # 持锁）：仅在全库确无旧载荷时才标记 completed；--wait-seconds 控制
        # 无进展时在本次运行内等待对端提交/回滚并重试回访的最长时间
        # （默认 30 秒；超时保持 running 退出，重跑即续完）。

    python -m app.payloadadmin clear-legacy [--batch-size N]
        # 迁移完成后清空事件行内冗余 JSONB（分批，可重复运行直到为 0）

    python -m app.payloadadmin gc [--grace-seconds N] [--rescan-store] [--batch-size N]
        # 一阶段标记 + 宽限复核的幂等垃圾回收：
        # 首次运行标记零引用候选；超过宽限期后再次运行才真正删除对象。
        # --rescan-store 同时登记对象存储里有、数据库元数据里没有的孤儿
        # （同样需要再过一轮宽限才会删除）。

所有命令与在线提交/投递并发安全：标记不阻塞写入；删除前在“按摘要的事务级
咨询锁 + 候选/元数据行锁”内复核引用与进行中的提交状态机，并发提交、崩溃
恢复或在线迁移正在复用的对象会被复活——即使对象在存储中已存在而数据库尚无
元数据行（--rescan-store 登记的孤儿），咨询锁同样提供互斥。HTTP 侧可经
GET /api/v1/payloads/gc 与 /api/v1/payloads/gc/{digest} 查询回收状态。
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from app import payloads, repository as repo
from app.config import settings
from app.db import close_pool, init_db
from app.objectstore import init_object_store

log = logging.getLogger("webhook.payloadadmin")


# -- status ----------------------------------------------------------------------

async def _status(verbose: bool) -> int:
    pool = await init_db()
    store = await init_object_store()
    try:
        async with pool.acquire() as conn:
            # 与 GET /payloads/status 同一套一致性读：状态行与所有计数在单个
            # 只读 REPEATABLE READ 快照内取得，CLI 打印的“待迁移”数与迁移状态
            # 的 remaining 恒等，查询不写库、不推进迁移。
            async with payloads.payload_status_snapshot(conn):
                total_events = await conn.fetchval("SELECT COUNT(*) FROM events")
                legacy = await repo.count_legacy_events(conn)
                objects = await repo.count_payload_objects(conn)
                candidates = await repo.count_payload_candidates(conn)
                gc_overview = await repo.gc_candidate_overview(conn)
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
    finally:
        await close_pool()

    print(f"对象存储后端：mode={store.mode}")
    if store.mode == "s3":
        print(f"桶：{settings.s3_bucket}（endpoint={settings.s3_endpoint_url}）")
    else:
        print(f"目录：{settings.local_objectstore_dir}")
    print(
        f"事件总数={total_events}，待迁移(仍只在 JSONB)={legacy}，"
        f"去重对象数={objects}，引用总数={ref_sum}，对象总字节={bytes_sum}"
    )
    print(
        f"提交状态机残留={pending}，GC 候选={candidates}"
        f"（已过宽限期 {gc_overview['due']} 个，"
        f"最老候选 {float(gc_overview['oldest_age_seconds']):.0f}s），"
        f"GC 宽限期={settings.payload_gc_grace_seconds}s"
    )
    print(
        "迁移状态：status={status} processed={processed} "
        "last_event_id={last_event_id} remaining={remaining}".format(**migration)
    )
    if migration["last_error"]:
        print(f"  last_error: {migration['last_error']}")
    if gc_runs:
        print("最近 GC 运行：")
        for r in gc_runs:
            print(
                f"  #{r['id']} [{r['status']}] candidates={r['candidates']} "
                f"deleted={r['deleted_objects']} rescan_store={r['rescanned_store']}"
                + (f" error={r['last_error']}" if r["last_error"] else "")
            )
    else:
        print("GC 运行：无")
    return 0


# -- recover ---------------------------------------------------------------------

async def _recover(batch_size: int) -> int:
    pool = await init_db()
    store = await init_object_store()
    total = 0
    try:
        while True:
            async with pool.acquire() as conn:
                # CLI 立即接管：stale 年龄给 0（显式人工恢复，不等后台阈值）。
                n = await payloads.recover_pending(
                    conn, store, owner_id="payloadadmin-recover",
                    stale_age_seconds=0, batch_size=batch_size,
                )
            total += n
            if n < batch_size:
                break
        print(f"恢复完成：处理残留提交 {total} 条")
        return 0
    finally:
        await close_pool()


# -- migrate ---------------------------------------------------------------------

async def _migrate(batch_size: int, wait_seconds: float) -> int:
    pool = await init_db()
    store = await init_object_store()
    total = 0
    idle_since: float | None = None
    try:
        loop = asyncio.get_running_loop()
        while True:
            async with pool.acquire() as conn:
                try:
                    n = await payloads.migrate_legacy_payloads(
                        conn, store, batch_size=batch_size
                    )
                    status = await payloads.migration_status(conn)
                except Exception:  # noqa: BLE001 - 进度已持久化为 failed
                    log.exception("迁移批次失败（已持久化进度，重跑续跑）")
                    return 1
            if n:
                total += n
                idle_since = None
                log.info("本批迁移 %d 个事件（累计 %d）", n, total)
            if status["status"] == "completed":
                # 权威裁决：completed 只可能在全库确无旧载荷时写入。
                break
            # 剩余 > 0 但本批未领到行：空批/短批是被并发迁移者的行锁挡住
            # （SKIP LOCKED），对端可能正在提交，也可能上传失败后整批回滚。
            # 不能据此退出（旧实现会误写 completed 并漏行）；等待并重试回访
            # 这些行，直到它们提交或回滚释放。仅在长期无进展（疑似对端僵死
            # 持锁）时停下并保持 running，提示稍后重跑（不标记 completed）。
            now = loop.time()
            if idle_since is None:
                idle_since = now
            if now - idle_since >= wait_seconds:
                print(
                    f"迁移等待超时：剩余待迁移 {status['remaining']} 个事件"
                    f"持续被其他迁移进程锁定（{wait_seconds:.0f}s 无进展）；"
                    "未标记 completed，待对端提交/回滚后重跑本命令即可续完。"
                )
                return 0
            await asyncio.sleep(0.2)
        print(
            f"迁移完成：共链接 {total} 个事件到对象存储；"
            f"状态={status['status']}，剩余待迁移={status['remaining']}"
        )
        if status["remaining"] == 0:
            print("提示：可运行 'clear-legacy' 回收事件行内的旧 JSONB 字节")
        return 0
    finally:
        await close_pool()


# -- clear-legacy ----------------------------------------------------------------

async def _clear_legacy(batch_size: int) -> int:
    pool = await init_db()
    total = 0
    try:
        while True:
            async with pool.acquire() as conn:
                n = await repo.clear_legacy_payloads(conn, batch_size)
            total += n
            if n < batch_size:
                break
        async with pool.acquire() as conn:
            remaining = await repo.count_legacy_events(conn)
        print(f"清理完成：本命令清空 {total} 行旧 JSONB；仍待迁移事件={remaining}")
        if remaining:
            print("提示：仍有事件未迁移，请先运行 'migrate'")
        return 0
    finally:
        await close_pool()


# -- gc --------------------------------------------------------------------------

async def _gc(grace_seconds: int, rescan_store: bool, batch_size: int) -> int:
    pool = await init_db()
    store = await init_object_store()
    try:
        async with pool.acquire() as conn:
            stats = await payloads.run_gc(
                conn,
                store,
                grace_seconds=grace_seconds,
                batch_size=batch_size,
                rescan_store=rescan_store,
            )
        print(
            f"GC 完成：本轮标记候选 {stats['candidates']} 个，"
            f"删除过期对象 {stats['deleted']} 个"
            + ("（已扫描对象存储孤儿，下一轮 GC 过宽限后删除）" if rescan_store else "")
        )
        print(
            "提示：新标记的候选需超过宽限期 "
            f"{grace_seconds}s 后再次运行 gc 才会被删除（防并发提交/重放误删）"
        )
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"GC 失败（已记录运行，重跑幂等）: {exc}", file=sys.stderr)
        return 1
    finally:
        await close_pool()


# -- entrypoint ------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(
        prog="payloadadmin", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_status = sub.add_parser("status", help="对象存储/迁移/GC 状态")
    p_status.add_argument("--verbose", action="store_true")

    p_recover = sub.add_parser("recover", help="续跑崩溃残留的提交状态机")
    p_recover.add_argument("--batch-size", type=int, default=100)

    p_migrate = sub.add_parser("migrate", help="旧 JSONB 事件在线迁移到对象引用")
    p_migrate.add_argument("--batch-size", type=int, default=200)
    p_migrate.add_argument(
        "--wait-seconds", type=float, default=30.0,
        help=(
            "空批/短批因并发迁移者持锁而无进展时，最多等待多久后停下"
            "（保持 running、不标记 completed；默认 30 秒，重跑即续完）"
        ),
    )

    p_clear = sub.add_parser(
        "clear-legacy", help="迁移完成后清空事件行内旧 JSONB"
    )
    p_clear.add_argument("--batch-size", type=int, default=500)

    p_gc = sub.add_parser("gc", help="标记/回收零引用载荷对象（宽限+复核）")
    p_gc.add_argument(
        "--grace-seconds", type=int, default=settings.payload_gc_grace_seconds,
        help="引用归零后至少等待多久才删除（默认取 PAYLOAD_GC_GRACE_SECONDS）",
    )
    p_gc.add_argument(
        "--rescan-store", action="store_true",
        help="同时登记对象存储中存在但数据库无元数据的孤儿（下一轮过宽限删除）",
    )
    p_gc.add_argument("--batch-size", type=int, default=100)

    args = parser.parse_args()
    if args.command == "status":
        code = asyncio.run(_status(args.verbose))
    elif args.command == "recover":
        code = asyncio.run(_recover(args.batch_size))
    elif args.command == "migrate":
        code = asyncio.run(_migrate(args.batch_size, args.wait_seconds))
    elif args.command == "clear-legacy":
        code = asyncio.run(_clear_legacy(args.batch_size))
    elif args.command == "gc":
        code = asyncio.run(_gc(args.grace_seconds, args.rescan_store, args.batch_size))
    else:  # pragma: no cover
        parser.error("未知命令")
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
