"""竞态聚焦验证：载荷对象垃圾回收 vs 并发提交/恢复/迁移的引用互斥。

背景缺陷：对象存储里已有某 SHA-256 对象、但数据库尚无元数据行时
（--rescan-store 登记的孤儿；或 GC 已删元数据只剩候选行），原有行锁
保护不存在的行，GC“最终复核→物理删除”与并发“PUT 对象→建引用”之间
存在窗口，可产生悬空引用（事件引用了已删除对象）。

本测试用真实 PostgreSQL（pgserver）+ 本地文件对象后端，在进程内以带
屏障的 ObjectStore 确定性地交错两侧操作，覆盖：

1. GC 先持锁删除孤儿对象，并发提交在锁等待；删除提交后提交方重建同一
   内容寻址对象并建引用——不悬空，对象可按摘要取回且摘要复核通过；
2. 提交方先持锁（锁内 PUT），GC 复核等待；提交提交后复核见引用而复活；
3. 对象删除失败：候选保留、宽限重置，重试幂等成功，不破坏任何引用；
4. 候选存在但有进行中提交（payload_upload_pending）：复核复活；
5. 在线迁移（旧 JSONB 事件）与 GC 并发：迁移锁内 PUT，GC 等待后复活；
6. 压力：大量同摘要并发提交与多轮 GC 交错，无悬空引用，引用计数精确。

非 Docker：自动拉起便携 PostgreSQL + 本地文件对象后端（PAYLOAD_STORE_MODE=local）。
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pgserver

ROOT = Path(__file__).resolve().parent

# 必须在导入 app.* 之前就绪（app.config 在导入时读取环境变量）。
os.environ["LEASE_SECONDS"] = "30"
os.environ["MAX_ATTEMPTS"] = "6"
os.environ["WEBHOOK_ALLOWED_HOSTS"] = "127.0.0.1,localhost"
os.environ["WEBHOOK_KEYRING_JSON"] = (
    '{"active_key_id":"k1","keys":'
    '{"k1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}'
)
os.environ["PAYLOAD_STORE_MODE"] = "local"
os.environ["PAYLOAD_GC_GRACE_SECONDS"] = "0"
os.environ["PAYLOAD_STALE_AGE_SECONDS"] = "0"

# app.payloads / app.repository 在各 case 内延迟导入；_run 导入后绑定到全局。
payloads = None
repo = None

# DATABASE_URL / PAYLOAD_LOCAL_DIR 在 main 中按临时目录分配：app.config 在
# 导入时固化 settings，必须先拿到 DSN 再导入 app.*。
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        failures.append(name)


def canon(payload: dict) -> tuple[str, bytes]:
    data = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    import hashlib

    return hashlib.sha256(data).hexdigest(), data


class HookLocalStore:
    """LocalObjectStore 的屏障包装：可在 PUT/DELETE 的持锁点挂起，制造交错。"""

    def __init__(self, root: str):
        from app.objectstore import LocalObjectStore

        self._inner = LocalObjectStore(root)
        self.put_hook = None
        self.delete_hook = None

    @property
    def mode(self) -> str:
        return self._inner.mode

    async def ensure_bucket(self):
        return await self._inner.ensure_bucket()

    async def put_object(self, key, data):
        if self.put_hook is not None:
            await self.put_hook(key)
        return await self._inner.put_object(key, data)

    async def get_object(self, key):
        return await self._inner.get_object(key)

    async def head_object(self, key):
        return await self._inner.head_object(key)

    async def delete_object(self, key):
        if self.delete_hook is not None:
            await self.delete_hook(key)
        return await self._inner.delete_object(key)

    def iter_all_keys(self, prefix=""):
        return self._inner.iter_all_keys(prefix)


async def seed_orphan(conn, store, digest, data) -> None:
    """存储里有对象、数据库无元数据；直接插一条（已过宽限的）GC 候选。"""
    await store.ensure_bucket()
    (Path(os.environ["PAYLOAD_LOCAL_DIR"]) / digest).write_bytes(data)
    await conn.execute(
        """
        INSERT INTO payload_gc_candidates (digest, first_seen_at)
        VALUES ($1, now() - interval '2 hour')
        ON CONFLICT (digest) DO NOTHING
        """,
        digest,
    )
    assert await store.head_object(digest)


async def seed_zero_ref_meta(conn, store, digest, data) -> None:
    """存储有对象、元数据 ref_count=0、候选已过宽限。"""
    await seed_orphan(conn, store, digest, data)
    await conn.execute(
        """
        INSERT INTO event_payload_objects (digest, size_bytes, ref_count)
        VALUES ($1, $2, 0)
        ON CONFLICT (digest) DO NOTHING
        """,
        digest,
        len(data),
    )


async def register_pending(conn, digest, source, event_id, data, owner="test"):
    async with conn.transaction():
        return await repo.register_pending_submission(
            conn,
            digest=digest,
            source=source,
            event_id=event_id,
            payload_bytes=data,
            owner_id=owner,
        )


async def case1_gc_deletes_first_submitter_recreates(pool, store, digest, data) -> None:
    """GC 先拿到锁并物理删孤儿；提交方等锁后重建对象再建引用。"""
    async with pool.acquire() as gc_conn, pool.acquire() as sub_conn:
        await seed_orphan(gc_conn, store, digest, data)
        delete_started = asyncio.Event()
        release_delete = asyncio.Event()

        async def delete_hook(key):
            if key == digest:
                delete_started.set()
                await release_delete.wait()

        store.delete_hook = delete_hook
        gc_task = asyncio.create_task(
            payloads._delete_one_guarded(gc_conn, store, digest)
        )
        await delete_started.wait()
        # GC 正持锁删除：登记进行中提交（不触咨询锁，立即可见），终结应等待。
        await register_pending(sub_conn, digest, "gcase", "e-1", data)
        sub_task = asyncio.create_task(
            payloads._put_and_finalize(
                sub_conn, store,
                source="gcase", event_id="e-1", digest=digest, data=data,
            )
        )
        await asyncio.sleep(0.3)
        check("1 GC 删除期间并发终结在咨询锁上等待", not sub_task.done())

        release_delete.set()
        deleted = await gc_task
        check("1 GC 本轮删除了无引用孤儿", deleted == 1, f"deleted={deleted}")
        row, duplicate = await sub_task
        store.delete_hook = None

        check("1 提交完成且非重复", duplicate is False and row is not None)
    async with pool.acquire() as conn:
        exists = await conn.fetchval(
            "SELECT 1 FROM event_payload_objects WHERE digest=$1 AND ref_count=1",
            digest,
        )
        candidate = await conn.fetchval(
            "SELECT 1 FROM payload_gc_candidates WHERE digest=$1", digest
        )
        got = await store.get_object(digest)
    check("1 删除提交后对象被重建、元数据 ref_count=1", exists is not None)
    check("1 候选已随成功提交清除", candidate is None)
    check("1 对象可按摘要取回且字节一致（无悬空引用）", got == data)


async def case2_submitter_first_gc_reanimates(pool, store) -> None:
    """提交方先持锁 PUT；GC 复核等锁，提交后见引用 -> 复活。"""
    digest, data = canon({"case": 2})
    async with pool.acquire() as gc_conn, pool.acquire() as sub_conn:
        await seed_zero_ref_meta(sub_conn, store, digest, data)
        await register_pending(sub_conn, digest, "gcase", "e-2", data)
        put_started = asyncio.Event()
        release_put = asyncio.Event()

        async def put_hook(key):
            if key == digest:
                put_started.set()
                await release_put.wait()

        store.put_hook = put_hook
        sub_task = asyncio.create_task(
            payloads._put_and_finalize(
                sub_conn, store,
                source="gcase", event_id="e-2", digest=digest, data=data,
            )
        )
        await put_started.wait()
        gc_task = asyncio.create_task(
            payloads._delete_one_guarded(gc_conn, store, digest)
        )
        await asyncio.sleep(0.3)
        check("2 提交持锁 PUT 期间 GC 复核等待", not gc_task.done())

        release_put.set()
        deleted = await gc_task
        _, duplicate = await sub_task
        store.put_hook = None
        check("2 GC 未删除已被引用的对象", deleted == 0, f"deleted={deleted}")
        check("2 提交完成非重复", duplicate is False)
    async with pool.acquire() as conn:
        rc = await conn.fetchval(
            "SELECT ref_count FROM event_payload_objects WHERE digest=$1", digest
        )
        candidate = await conn.fetchval(
            "SELECT 1 FROM payload_gc_candidates WHERE digest=$1", digest
        )
    check("2 对象复活：ref_count=1、候选移除、对象仍在",
          rc == 1 and candidate is None and await store.head_object(digest))


async def case3_delete_failure_is_retryable(pool, store) -> None:
    """对象删除失败：候选保留、宽限重置、对象/元数据不动；重试成功。"""
    from app.objectstore import ObjectStoreError

    digest, data = canon({"case": 3})
    async with pool.acquire() as conn:
        await seed_zero_ref_meta(conn, store, digest, data)

        async def failing_delete(key):
            if key == digest:
                store.delete_hook = None
                raise ObjectStoreError("注入：S3 500", status=500, key=key)

        store.delete_hook = failing_delete
        deleted = await payloads._delete_one_guarded(conn, store, digest)
        check("3 删除失败本轮不计数", deleted == 0)
        cand = await conn.fetchrow(
            "SELECT digest, first_seen_at FROM payload_gc_candidates WHERE digest=$1",
            digest,
        )
        meta = await conn.fetchval(
            "SELECT ref_count FROM event_payload_objects WHERE digest=$1", digest
        )
        check("3 失败后候选保留、元数据仍在、对象未删",
              cand is not None and meta == 0 and await store.head_object(digest))

        # 宽限被重置到 now：把候选调回过去模拟“下一轮 GC 之后”，重试应成功。
        await conn.execute(
            "UPDATE payload_gc_candidates SET first_seen_at=now()-interval '1 hour'"
            " WHERE digest=$1", digest,
        )
        deleted = await payloads._delete_one_guarded(conn, store, digest)
        meta_after = await conn.fetchval(
            "SELECT 1 FROM event_payload_objects WHERE digest=$1", digest
        )
    check("3 重试幂等删除成功（对象+元数据+候选全部清除）",
          deleted == 1 and meta_after is None
          and not await store.head_object(digest))


async def case4_pending_inflight_is_reanimated(pool, store) -> None:
    """存储孤儿候选 + 同摘要进行中提交（尚未终结）：复核必须复活。"""
    digest, data = canon({"case": 4})
    async with pool.acquire() as conn:
        await seed_orphan(conn, store, digest, data)
        await register_pending(conn, digest, "gcase", "e-4", data)
        deleted = await payloads._delete_one_guarded(conn, store, digest)
        candidate = await conn.fetchval(
            "SELECT 1 FROM payload_gc_candidates WHERE digest=$1", digest
        )
    check("4 进行中提交使孤儿候选复活（不计数、移除候选、保留对象）",
          deleted == 0 and candidate is None and await store.head_object(digest))


async def case5_migration_vs_gc(pool, store) -> None:
    """旧 JSONB 事件迁移与 GC 并发：迁移锁内 PUT，GC 等待后复活、不悬空。"""
    digest, data = canon({"legacy": 5})
    async with pool.acquire() as mig_conn, pool.acquire() as gc_conn:
        # 全新库的迁移状态会自动标记 completed：重置为 running 以驱动本批迁移。
        await mig_conn.execute(
            "UPDATE payload_migration_state SET status='running', last_event_id=0"
        )
        # 直接种一条旧格式事件（payload_digest 为空），存储里恰好已有同摘要孤儿。
        await mig_conn.execute(
            "INSERT INTO events (source, event_id, payload) VALUES ('gcase','e-5',$1::jsonb)",
            {"legacy": 5},
        )
        await seed_orphan(mig_conn, store, digest, data)
        put_started = asyncio.Event()
        release_put = asyncio.Event()

        async def put_hook(key):
            if key == digest:
                put_started.set()
                await release_put.wait()

        store.put_hook = put_hook
        mig_task = asyncio.create_task(
            payloads.migrate_legacy_payloads(mig_conn, store, batch_size=100)
        )
        await put_started.wait()
        gc_task = asyncio.create_task(
            payloads._delete_one_guarded(gc_conn, store, digest)
        )
        await asyncio.sleep(0.3)
        check("5 迁移持锁 PUT 期间 GC 等待", not gc_task.done())
        release_put.set()
        migrated = await mig_task
        deleted = await gc_task
        store.put_hook = None
        check("5 迁移完成 1 行且 GC 未删对象", migrated == 1 and deleted == 0,
              f"migrated={migrated} deleted={deleted}")
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT payload_digest FROM events WHERE source='gcase' AND event_id='e-5'"
        )
        rc = await conn.fetchval(
            "SELECT ref_count FROM event_payload_objects WHERE digest=$1", digest
        )
        got = await store.get_object(digest)
    check("5 迁移后事件挂正确摘要、引用计数=1、对象可取回（无悬空引用）",
          row["payload_digest"] == digest and rc == 1 and got == data)


async def case6_stress(pool, store) -> None:
    """20 个同摘要并发提交与 3 个并发 GC 循环交错：无悬空引用、计数精确。"""
    from app.keyring import get_keyring

    digest, data = canon({"stress": "same-body", "n": 1})
    n = 20
    async with pool.acquire() as conn:
        await repo.create_subscription(
            conn, "gstress", "http://127.0.0.1:9/receive", "dev-signing-secret",
            keyring=get_keyring(),
            max_attempts=6, backoff_base_seconds=1.0, backoff_cap_seconds=2.0,
        )

    async def submit(i: int) -> None:
        async with pool.acquire() as c:
            await payloads.submit_event_payload(
                c, store,
                source="gstress", event_id=f"s-{i}",
                payload={"stress": "same-body", "n": 1},
                owner_id=f"stress-{i}",
            )

    async def gc_loop(k: int) -> None:
        async with pool.acquire() as c:
            for _ in range(5):
                await payloads.run_gc(c, store, grace_seconds=0, batch_size=500)
                await asyncio.sleep(0)

    results = await asyncio.gather(
        *(submit(i) for i in range(n)),
        *(gc_loop(k) for k in range(3)),
        return_exceptions=True,
    )
    errs = [repr(r) for r in results if isinstance(r, Exception)]
    check("6 全部并发提交/GC 无异常", not errs, str(errs[:3]))

    async with pool.acquire() as conn:
        ev_count = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE source='gstress' "
            "AND payload_digest=$1", digest,
        )
        rc = await conn.fetchval(
            "SELECT ref_count FROM event_payload_objects WHERE digest=$1", digest
        )
        pending = await conn.fetchval(
            "SELECT COUNT(*) FROM payload_upload_pending WHERE digest=$1", digest
        )
        candidates = await conn.fetchval(
            "SELECT COUNT(*) FROM payload_gc_candidates WHERE digest=$1", digest
        )
        # 每个事件经正式读路径都必须取回对象并通过摘要复核（悬空引用会在此炸）
        bad = 0
        rows = await conn.fetch(
            "SELECT payload_digest FROM events WHERE source='gstress'"
        )
        for r in rows:
            try:
                payload = await payloads.load_event_payload(store, r)
                if canon(payload)[0] != digest:
                    bad += 1
            except Exception:  # noqa: BLE001
                bad += 1
    check("6 20 个事件全部建成且共享对象 ref_count=20",
          ev_count == n and rc == n, f"events={ev_count} rc={rc}")
    check("6 无残留 pending/候选，正式读路径零悬空引用",
          pending == 0 and candidates == 0 and bad == 0,
          f"pending={pending} candidates={candidates} bad={bad}")


def main() -> int:
    # 先起库拿 DSN，再设置环境并导入 app（settings 在导入时固化）。
    pg_root = tempfile.mkdtemp(prefix=".gc-pgdata-", dir=str(ROOT))
    obj_dir = tempfile.mkdtemp(prefix=".gc-store-", dir=str(ROOT))
    pg = pgserver.get_server(pg_root, cleanup_mode="stop")
    os.environ["DATABASE_URL"] = pg.get_uri()
    os.environ["PAYLOAD_LOCAL_DIR"] = obj_dir
    try:
        rc = asyncio.run(_run())
    finally:
        try:
            pg.cleanup()
        except Exception:  # noqa: BLE001
            pass
        shutil.rmtree(pg_root, ignore_errors=True)
        shutil.rmtree(obj_dir, ignore_errors=True)
    return rc


async def _run() -> int:
    global payloads, repo
    from app import payloads as _payloads, repository as _repo
    from app.db import close_pool, get_pool, init_db

    payloads = _payloads
    repo = _repo

    await init_db()
    store = HookLocalStore(os.environ["PAYLOAD_LOCAL_DIR"])
    await store.ensure_bucket()
    pool = get_pool()

    d1, b1 = canon({"orphan": 1})
    try:
        await case1_gc_deletes_first_submitter_recreates(pool, store, d1, b1)
        await case2_submitter_first_gc_reanimates(pool, store)
        await case3_delete_failure_is_retryable(pool, store)
        await case4_pending_inflight_is_reanimated(pool, store)
        await case5_migration_vs_gc(pool, store)
        await case6_stress(pool, store)
    except Exception:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        failures.append("异常")
    finally:
        await close_pool()

    print()
    if failures:
        print(f"失败 {len(failures)} 项: {failures}")
        return 1
    print("GC × 并发提交/恢复/迁移 引用互斥检查全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
