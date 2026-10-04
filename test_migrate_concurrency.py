"""并发迁移死锁修复专项验证（旧 JSONB -> 对象引用，migrate_legacy_payloads）。

背景缺陷（一）：两个 payloadadmin migrate 进程经 FOR UPDATE SKIP LOCKED 领取
互不相交的事件批次，但若两批都含相同摘要 X、Y 且事件顺序相反（A 批 X→Y、
B 批 Y→X），旧代码在同一事务内“按事件顺序逐把持摘要咨询锁、锁内上传”，
两边互相等待对方持有的锁 -> AB-BA 死锁，Postgres 回滚其中一批。

背景缺陷（二，本文件 case5）：一方锁住较早事件后上传失败整批回滚，另一方
SKIP LOCKED 跳锁处理较晚事件并拿到空批/短批；旧代码据“空批/短批”直接写
completed，且单调 id 游标（id > last_event_id 领取）越过回滚行，重跑也
永远领取不到较早的旧行 -> 漏迁移 + completed 谎报。

修复后契约（本测试验证）：
1. 取锁顺序：批次先汇总所需摘要，按咨询锁实际键 (classid,objid) 全局统一
   顺序取齐；同一 objid（不同摘要前 8 hex 碰撞时）只取一次；
2. 确定性反序批次不再死锁：两批 [X,Y] / [Y,X] 并发，含真实持锁等待交错，
   均成功提交；对象去重（2 个对象）、ref_count 各 2、摘要正确；
3. 压力：多个迁移者不同批次大小并发 + GC 同时跑，全部完成、无死锁异常，
   对象去重 / 引用计数 / 迁移进度精确，正式读路径零悬空引用、无残留候选；
4. 上传失败：整批回滚（引用/游标均不落库），failed 状态在批次事务外持久化，
   双读仍可读旧 JSONB；修复后重跑幂等成功，failed 错误被清除。
5. 空批/短批裁决（case5）：并发下空批/短批绝不谎报 completed；失败批次
   释放后重跑必须迁完较早事件；仅在确无旧载荷时才 completed；重复运行不
   重复计数/不新增引用；旧库残留的“completed 但仍有旧行”状态会被重开。

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

payloads = None
repo = None

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
    """LocalObjectStore 的薄包装：多个实例可共享同一内部存储与磁盘目录。"""

    def __init__(self, inner):
        self._inner = inner
        self.put_hook = None
        # 始终抛错的摘要集合（上传失败注入用）
        self.fail_put: set[str] = set()

    @property
    def mode(self) -> str:
        return self._inner.mode

    @property
    def root(self) -> str:
        return self._inner._root

    async def ensure_bucket(self):
        return await self._inner.ensure_bucket()

    async def put_object(self, key, data):
        if self.put_hook is not None:
            await self.put_hook(key)
        if key in self.fail_put:
            from app.objectstore import ObjectStoreError

            raise ObjectStoreError("注入：对象上传失败", status=500, key=key)
        return await self._inner.put_object(key, data)

    async def get_object(self, key):
        return await self._inner.get_object(key)

    async def head_object(self, key):
        return await self._inner.head_object(key)

    async def delete_object(self, key):
        return await self._inner.delete_object(key)

    def iter_all_keys(self, prefix=""):
        return self._inner.iter_all_keys(prefix)


async def reset_migration_running(conn) -> None:
    await conn.execute(
        "UPDATE payload_migration_state "
        "SET status='running', last_event_id=0, processed=0, last_error=NULL "
        "WHERE id=1"
    )


async def seed_legacy_events(
    conn, payloads_in_order: list[dict], *, source: str = "mig",
    id_prefix: str = "e-",
) -> list[int]:
    ids = []
    for i, payload in enumerate(payloads_in_order):
        row = await conn.fetchrow(
            "INSERT INTO events (source, event_id, payload) "
            "VALUES ($1, $2, $3::jsonb) RETURNING id",
            source, f"{id_prefix}{i}", payload,
        )
        ids.append(row["id"])
    return ids


# -- case 1：统一顺序取锁 + 同键去重（单元级，不依赖数据库） ---------------------------


class FakeConn:
    def __init__(self):
        self.calls: list[tuple[int, int]] = []

    async def fetchval(self, sql, classid, objid):
        assert sql.startswith("SELECT pg_advisory_xact_lock")
        self.calls.append((classid, objid))
        return None


async def case1_lock_ordering_and_dedup() -> None:
    import app.repository as r

    # 前 8 hex 决定 objid：两个不同摘要故意共用同一 objid（00000005），
    # 另一个用 00000002；传入乱序，期望按 objid 升序、且 00000005 只取一次。
    d_a = "00000005" + "0" * 56
    d_b = "00000002" + "f" * 56
    d_c = "00000005" + "a" * 56
    assert d_a != d_c
    assert r._digest_lock_key(d_a) == r._digest_lock_key(d_c) == 0x00000005
    assert r._digest_lock_key(d_b) == 0x00000002

    fake = FakeConn()
    await r.payload_object_xact_locks_ordered(fake, [d_a, d_b, d_c])
    objids = [objid for _classid, objid in fake.calls]
    check("1 统一顺序取锁：按 objid 升序", objids == [2, 5], str(objids))
    check("1 同一锁键只取一次（去重）", len(fake.calls) == 2, str(fake.calls))
    check("1 classid 为载荷锁固定值",
          all(c[0] == r._PAYLOAD_LOCK_CLASSID for c in fake.calls))

    # 有符号 int32 映射：大 objid（>=2^31）与小 objid 混排顺序必须与实际键一致。
    d_hi = "ffffffff" + "0" * 56  # objid = -1
    d_mid = "80000000" + "0" * 56  # objid = -2^31
    d_lo = "00000001" + "0" * 56   # objid = 1
    fake2 = FakeConn()
    await r.payload_object_xact_locks_ordered(fake2, [d_hi, d_lo, d_mid])
    got = [objid for _c, objid in fake2.calls]
    check("1 有符号 int32 映射下顺序仍与实际键一致",
          got == sorted([-1, 1, -(2 ** 31)]) and got[0] == -(2 ** 31), str(got))


# -- case 2：确定性反序批次并发不死锁 --------------------------------------------------


async def wait_for_other_waiting_advisory(conn, holder_pid: int, timeout: float = 10.0):
    """等到另一个会话在载荷咨询锁上等待（granted=false）。"""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        waiting = await conn.fetchval(
            """
            SELECT 1 FROM pg_locks
            WHERE locktype='advisory' AND classid=$1
              AND NOT granted AND pid <> $2
            LIMIT 1
            """,
            repo._PAYLOAD_LOCK_CLASSID, holder_pid,
        )
        if waiting is not None:
            return
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError("未观察到并发迁移者在咨询锁上等待")
        await asyncio.sleep(0.02)


async def case2_reverse_ordered_batches_no_deadlock(pool, inner_store) -> None:
    """两批事件顺序相反 [X,Y]/[Y,X]，在真实持锁等待交错下并发迁移。"""
    from app.objectstore import LocalObjectStore

    async with pool.acquire() as seed:
        await reset_migration_running(seed)
        ids = await seed_legacy_events(
            seed, [{"v": "X"}, {"v": "Y"}, {"v": "Y"}, {"v": "X"}]
        )
        dig_x, _ = canon({"v": "X"})
        dig_y, _ = canon({"v": "Y"})

    store_a = HookLocalStore(LocalObjectStore(inner_store._root))
    store_b = HookLocalStore(LocalObjectStore(inner_store._root))

    async def put_gate_a(key):
        # A 批在持有“已取齐的全部锁”后、上传第一个对象时挂起，直到确认 B 批
        # 已在咨询锁上等待再放行：这精确重现“两批都持锁并互等”的交错。
        # 旧实现此时 A 只持 X、B 只持 Y 且都在等对方 -> PG 死锁检测中止其一；
        # 新实现 A 已持 X+Y，B 只是普通等待，A 提交后 B 顺序继续，无环。
        if key == dig_x:
            async with pool.acquire() as watcher:
                pid = await watcher.fetchval("SELECT pg_backend_pid()")
                await wait_for_other_waiting_advisory(watcher, pid)

    store_a.put_hook = put_gate_a

    async with pool.acquire() as conn_a, pool.acquire() as conn_b:
        task_a = asyncio.create_task(
            payloads.migrate_legacy_payloads(conn_a, store_a, batch_size=2)
        )
        task_b = asyncio.create_task(
            payloads.migrate_legacy_payloads(conn_b, store_b, batch_size=2)
        )
        results = await asyncio.gather(task_a, task_b, return_exceptions=True)
        store_a.put_hook = None
        store_b.put_hook = None

    errs = [repr(r) for r in results if isinstance(r, Exception)]
    check("2 反序批次并发无死锁/无异常（均本批 2 行）",
          not errs and results == [2, 2], f"results={results} errs={errs}")

    async with pool.acquire() as conn:
        n = await payloads.migrate_legacy_payloads(conn, store_a, batch_size=50)
        state = await repo.get_migration_state(conn)
        remaining = await repo.count_legacy_events(conn)
        rows = await conn.fetch(
            "SELECT id, payload_digest FROM events "
            "WHERE id = ANY($1::bigint[]) ORDER BY id", ids
        )
        objs = await conn.fetch(
            "SELECT digest, ref_count, size_bytes FROM event_payload_objects "
            "WHERE digest = ANY($1::text[]) ORDER BY digest",
            [dig_x, dig_y],
        )
    check("2 再跑一批为 0 且迁移 completed",
          n == 0 and state["status"] == "completed" and remaining == 0,
          f"n={n} state={state['status']} remaining={remaining}")
    expect_digests = [dig_x, dig_y, dig_y, dig_x]
    check("2 四个事件挂到正确摘要（X,Y,Y,X）",
          [r["payload_digest"] for r in rows] == expect_digests)
    rc_map = {o["digest"]: o["ref_count"] for o in objs}
    check("2 去重对象 2 个、ref_count 各为 2",
          len(objs) == 2 and rc_map == {dig_x: 2, dig_y: 2},
          str([(o["digest"][:8], o["ref_count"]) for o in objs]))

    async with pool.acquire() as conn:
        bad = 0
        for pk in ids:
            row = await conn.fetchrow(
                "SELECT payload, payload_digest FROM events WHERE id=$1", pk
            )
            try:
                payload = await payloads.load_event_payload(store_a, row)
                if canon(payload)[0] != row["payload_digest"]:
                    bad += 1
            except Exception:  # noqa: BLE001
                bad += 1
    check("2 正式读路径取回对象并复核摘要通过（无悬空引用）", bad == 0)


# -- case 3：多迁移者 + GC 并发压力 ----------------------------------------------------


async def case3_stress(pool, inner_store) -> None:
    from app.objectstore import LocalObjectStore

    distinct = 10
    repeat = 8
    seed_payloads = [{"p": i % distinct} for i in range(distinct * repeat)]  # 80 个
    digest_of = {i: canon({"p": i})[0] for i in range(distinct)}

    async with pool.acquire() as seed:
        await reset_migration_running(seed)
        ids = await seed_legacy_events(seed, seed_payloads, source="migs")

    def make_store():
        return HookLocalStore(LocalObjectStore(inner_store._root))

    async def migrator(name: str, batch_size: int) -> list[Exception]:
        local_errs: list[Exception] = []
        async with pool.acquire() as conn:
            store = make_store()
            rounds = 0
            while rounds < 200:
                try:
                    n = await payloads.migrate_legacy_payloads(
                        conn, store, batch_size=batch_size
                    )
                except Exception as exc:  # noqa: BLE001
                    local_errs.append(exc)
                    await asyncio.sleep(0.01)
                    rounds += 1
                    continue
                rounds += 1
                if n == 0:
                    break
                # 让出事件循环，制造批次间交错
                await asyncio.sleep(0.005)
        return local_errs

    async def gc_loop() -> None:
        async with pool.acquire() as conn:
            store = make_store()
            for _ in range(30):
                await payloads.run_gc(
                    conn, store, grace_seconds=0, batch_size=200,
                    rescan_store=True,
                )
                await asyncio.sleep(0.002)

    results = await asyncio.gather(
        migrator("m1", 1), migrator("m2", 3), migrator("m3", 7),
        migrator("m4", 13), migrator("m5", 29), migrator("m6", 50),
        gc_loop(), gc_loop(),
        return_exceptions=True,
    )
    errs = []
    for r in results:
        if isinstance(r, Exception):
            errs.append(repr(r))
        elif isinstance(r, list):
            errs.extend(repr(e) for e in r)
    check("3 并发迁移/GC 全程无死锁、无异常", not errs, str(errs[:5]))

    # 收尾：再补一轮 migrate + gc，使 completed/候选全部稳定。
    async with pool.acquire() as conn:
        store = make_store()
        tail = await payloads.migrate_legacy_payloads(conn, store, batch_size=100)
        state = await repo.get_migration_state(conn)
        await payloads.run_gc(conn, store, grace_seconds=0, batch_size=500,
                              rescan_store=True)
        remaining = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE payload_digest IS NULL "
            "AND id = ANY($1::bigint[])", ids
        )
        migrated = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE payload_digest IS NOT NULL "
            "AND id = ANY($1::bigint[])", ids
        )
        ref_sum = await conn.fetchval(
            "SELECT COALESCE(SUM(ref_count),0) FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])",
            list(digest_of.values()),
        )
        obj_count = await conn.fetchval(
            "SELECT COUNT(*) FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])", list(digest_of.values())
        )
        candidates = await conn.fetchval("SELECT COUNT(*) FROM payload_gc_candidates")
        rows = await conn.fetch(
            "SELECT payload_digest FROM events WHERE id = ANY($1::bigint[])", ids
        )
        per_digest = {i: 0 for i in range(distinct)}
        for i in range(distinct * repeat):
            per_digest[i % distinct] += 1
        rc_rows = await conn.fetch(
            "SELECT digest, ref_count FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])", list(digest_of.values())
        )
        rc_map = {r["digest"]: r["ref_count"] for r in rc_rows}
        bad = 0
        for r in rows:
            try:
                got = await store.get_object(r["payload_digest"])
                import hashlib

                if hashlib.sha256(got).hexdigest() != r["payload_digest"]:
                    bad += 1
            except Exception:  # noqa: BLE001
                bad += 1

    expect_rc = {digest_of[i]: repeat for i in range(distinct)}
    check("3 收尾后 status=completed、剩余 0、processed=80、尾批 0",
          tail == 0 and state["status"] == "completed"
          and remaining == 0 and migrated == len(ids)
          and state["processed"] == len(ids),
          f"tail={tail} state={dict(state)} remaining={remaining} migrated={migrated}")
    check("3 对象去重（10 个）、引用总数 80、每对象 ref_count=8",
          obj_count == distinct and ref_sum == len(ids) and rc_map == expect_rc,
          f"objects={obj_count} ref_sum={ref_sum}")
    check("3 GC 后无残留候选", candidates == 0, f"candidates={candidates}")
    check("3 全部对象可按摘要取回且复核通过（无悬空引用）", bad == 0, f"bad={bad}")


# -- case 4：上传失败整批回滚 + failed 持久化 + 重跑恢复 -------------------------------


async def case4_upload_failure_rollback_and_rerun(pool, inner_store) -> None:
    from app.objectstore import LocalObjectStore, ObjectStoreError

    async with pool.acquire() as seed:
        await reset_migration_running(seed)
        payloads_in_order = [{"f": i} for i in range(5)]
        ids = await seed_legacy_events(seed, payloads_in_order, source="migf")
        digests = [canon(p)[0] for p in payloads_in_order]

    store = HookLocalStore(LocalObjectStore(inner_store._root))
    fail_digest = digests[2]
    store.fail_put = {fail_digest}

    async with pool.acquire() as conn:
        raised: Exception | None = None
        try:
            await payloads.migrate_legacy_payloads(conn, store, batch_size=50)
        except ObjectStoreError as exc:
            raised = exc
        state = await repo.get_migration_state(conn)
        still_legacy = await conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE payload_digest IS NULL "
            "AND id = ANY($1::bigint[])", ids
        )
        meta_for_batch = await conn.fetchval(
            "SELECT COUNT(*) FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])", digests
        )

    check("4 上传失败向上抛出 ObjectStoreError（CLI 据此返回非 0）",
          isinstance(raised, ObjectStoreError))
    check("4 failed 状态在批次事务外持久化（未随回滚丢失）",
          state["status"] == "failed"
          and state["last_error"] is not None and "重跑" in state["last_error"]
          and state["last_event_id"] == 0 and state["processed"] == 0,
          f"state={dict(state)}")
    check("4 整批回滚：5 个事件仍全部为旧 JSONB、无对象元数据",
          still_legacy == 5 and meta_for_batch == 0,
          f"legacy={still_legacy} meta={meta_for_batch}")

    # 双读不受影响：未迁移事件仍可从 JSONB 列读出原始载荷。
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT payload, payload_digest FROM events WHERE id=$1", ids[0]
        )
        dual = await payloads.load_event_payload(store, row)
    check("4 失败后双读仍可从旧 JSONB 取到载荷", dual == payloads_in_order[0])

    # 恢复对象存储后重跑：幂等成功（先前已 PUT 的对象按内容寻址直接复用）。
    store.fail_put = set()
    async with pool.acquire() as conn:
        n1 = await payloads.migrate_legacy_payloads(conn, store, batch_size=50)
        state1 = await repo.get_migration_state(conn)
        n2 = await payloads.migrate_legacy_payloads(conn, store, batch_size=50)
        state2 = await repo.get_migration_state(conn)
        ref_sum = await conn.fetchval(
            "SELECT COALESCE(SUM(ref_count),0) FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])", digests
        )
        obj_count = await conn.fetchval(
            "SELECT COUNT(*) FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])", digests
        )
        rows = await conn.fetch(
            "SELECT payload_digest FROM events WHERE id = ANY($1::bigint[]) "
            "ORDER BY id", ids
        )
        bad = 0
        for i, r in enumerate(rows):
            if r["payload_digest"] != digests[i]:
                bad += 1
        for d in digests:
            if canon(json.loads((await store.get_object(d)).decode("utf-8")))[0] != d:
                bad += 1

    check("4 重跑整批成功 5 行、再跑 0、completed 且 last_error 已清除",
          n1 == 5 and n2 == 0 and state1["status"] == "completed"
          and state2["status"] == "completed" and state2["last_error"] is None
          and state2["processed"] == 5,
          f"n1={n1} n2={n2} state={dict(state2)}")
    check("4 重跑后 5 个去重对象、ref_count 合计 5、摘要全部正确、对象可读",
          obj_count == 5 and ref_sum == 5 and bad == 0,
          f"objects={obj_count} ref_sum={ref_sum} bad={bad}")


# -- case 5：空批/短批不误判 completed + 回滚行可回访（漏行修复） ----------------------


async def _rows_are_locked(conn, ids: list[int]) -> bool:
    """给定事件行是否已被别的事务用行锁持有（NOWAIT 探测）。"""
    import asyncpg

    try:
        async with conn.transaction():
            await conn.execute(
                "SELECT id FROM events WHERE id = ANY($1::bigint[]) "
                "FOR UPDATE NOWAIT",
                ids,
            )
    except asyncpg.LockNotAvailableError:
        return True
    return False


async def case5_short_empty_batch_not_completed_and_rollback_revisited(
    pool, inner_store
) -> None:
    """一方锁较早行后上传失败回滚，另一方跳锁处理较晚行：不得谎报 completed。

    复现旧缺陷：A 持 [0,1,2] 行锁后上传挂起 -> B SKIP LOCKED 只领到短批 [3,4]
    （旧代码短批即写 completed）；B 再跑得到空批（旧代码空批也写 completed）。
    A 随后上传失败整批回滚 -> 旧实现单调游标已越过 id=4，[0,1,2] 重跑永不可
    领取。修复后：短批/空批都只按“全库确无旧载荷”裁决，A 回滚后重跑必须
    从剩余集合回访 [0,1,2] 并迁完；重复运行不重复计数、不新增引用。
    """
    from app.objectstore import LocalObjectStore, ObjectStoreError

    async with pool.acquire() as seed:
        await reset_migration_running(seed)
        payloads_in_order = [{"u": i} for i in range(5)]
        ids = await seed_legacy_events(seed, payloads_in_order, source="migr")
        digests = [canon(p)[0] for p in payloads_in_order]

    store_a = HookLocalStore(LocalObjectStore(inner_store._root))
    store_b = HookLocalStore(LocalObjectStore(inner_store._root))

    a_entered = asyncio.Event()
    release_a = asyncio.Event()

    async def gate_a(key):
        # 行锁在取摘要咨询锁之前已持有；进入首个 PUT 即说明 [0,1,2] 已锁定。
        a_entered.set()
        await release_a.wait()

    store_a.put_hook = gate_a
    store_a.fail_put = set(digests)  # 放行后 A 的首个上传即失败 -> 整批回滚

    async with pool.acquire() as conn_a, pool.acquire() as conn_b, \
            pool.acquire() as watcher:
        task_a = asyncio.create_task(
            payloads.migrate_legacy_payloads(conn_a, store_a, batch_size=3)
        )
        await a_entered.wait()
        # 确认 A 的事务确实持有最早 3 行的行锁，再启动 B（确定性复现跳锁）。
        for _ in range(200):
            if await _rows_are_locked(watcher, ids[:3]):
                break
            await asyncio.sleep(0.02)
        else:  # pragma: no cover - 仅在极端调度下可能未观察到
            raise AssertionError("未观察到 A 持有最早 3 行行锁")

        # B 跳锁只领到 [3,4]（短批）：剩余 3 行仍被 A 持锁，不得 completed。
        n_short = await payloads.migrate_legacy_payloads(
            conn_b, store_b, batch_size=3
        )
        state_short = await repo.get_migration_state(conn_b)
        remain_short = await repo.count_legacy_events(conn_b)

        # B 再跑：[0,1,2] 仍被 A 锁定并跳过后空批；同样不得 completed。
        n_empty = await payloads.migrate_legacy_payloads(
            conn_b, store_b, batch_size=3
        )
        state_empty = await repo.get_migration_state(conn_b)
        remain_empty = await repo.count_legacy_events(conn_b)

        # 放行 A -> 上传失败 -> 整批回滚、failed 落库（独立事务）。
        release_a.set()
        a_result = await asyncio.gather(task_a, return_exceptions=True)

        state_failed = await repo.get_migration_state(conn_b)
        remain_failed = await repo.count_legacy_events(conn_b)
        early_still_legacy = await conn_b.fetchval(
            "SELECT COUNT(*) FROM events WHERE payload_digest IS NULL "
            "AND id = ANY($1::bigint[])", ids[:3]
        )
        late_attached = await conn_b.fetch(
            "SELECT id, payload_digest FROM events WHERE id = ANY($1::bigint[]) "
            "ORDER BY id",
            ids[3:],
        )

    check("5 B 短批处理 2 行但状态仍 running（不谎报完成）",
          n_short == 2 and state_short["status"] == "running"
          and remain_short == 3,
          f"n={n_short} state={state_short['status']} remain={remain_short}")
    check("5 B 空批返回 0 且状态仍 running（剩余行被并发持锁）",
          n_empty == 0 and state_empty["status"] == "running"
          and remain_empty == 3,
          f"n={n_empty} state={state_empty['status']} remain={remain_empty}")
    check("5 A 放行后上传失败向上抛出并整批回滚",
          isinstance(a_result[0], ObjectStoreError), repr(a_result[0]))
    check("5 A 回滚后状态 failed、较早 3 行仍为旧 JSONB、B 的 2 行已挂引用",
          state_failed["status"] == "failed" and remain_failed == 3
          and early_still_legacy == 3
          and [r["payload_digest"] for r in late_attached] == digests[3:],
          f"state={dict(state_failed)} remain={remain_failed} "
          f"early={early_still_legacy}")

    # 对象存储恢复后重跑：必须回访高水位“之前”的 [0,1,2]（旧游标会漏掉），
    # 本批 3 行、剩余 0 -> completed；累计 processed=5 而非重复计数。
    store_a.fail_put = set()
    store_a.put_hook = None
    async with pool.acquire() as conn:
        n_rerun = await payloads.migrate_legacy_payloads(
            conn, store_a, batch_size=50
        )
        state_run = await repo.get_migration_state(conn)
        n_again = await payloads.migrate_legacy_payloads(
            conn, store_a, batch_size=50
        )
        state_again = await repo.get_migration_state(conn)
        remaining = await repo.count_legacy_events(conn)
        ref_sum = await conn.fetchval(
            "SELECT COALESCE(SUM(ref_count),0) FROM event_payload_objects "
            "WHERE digest = ANY($1::text[])", digests
        )
        rows = await conn.fetch(
            "SELECT payload_digest FROM events WHERE id = ANY($1::bigint[]) "
            "ORDER BY id", ids
        )

    check("5 重跑回访较早 3 行、仅确无旧载荷时 completed、再跑为 0",
          n_rerun == 3 and n_again == 0 and remaining == 0
          and state_run["status"] == "completed"
          and state_again["status"] == "completed"
          and state_again["processed"] == 5,
          f"rerun={n_rerun} again={n_again} state={dict(state_again)}")
    check("5 重复运行不重复计数/不新增引用：5 摘要各 ref_count=1、合计 5",
          ref_sum == 5 and [r["payload_digest"] for r in rows] == digests,
          f"ref_sum={ref_sum}")

    # 双读投递可用：每个事件从对象取回并复核摘要通过。
    async with pool.acquire() as conn:
        bad = 0
        for pk, want in zip(ids, payloads_in_order):
            row = await conn.fetchrow(
                "SELECT payload, payload_digest FROM events WHERE id=$1", pk
            )
            try:
                got = await payloads.load_event_payload(store_a, row)
                if got != want or canon(got)[0] != row["payload_digest"]:
                    bad += 1
            except Exception:  # noqa: BLE001
                bad += 1
    check("5 双读/对象读路径全部可取回且摘要正确", bad == 0, f"bad={bad}")

    # 旧库残留修复：状态被（旧实现）误置 completed 但仍有旧行时，重跑须
    # 自动重开为 running 并迁完（启动 SQL 也做同一裁决）。
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE payload_migration_state SET status='completed' WHERE id=1"
        )
        extra_ids = await seed_legacy_events(
            conn, [{"late": 1}], source="migr", id_prefix="late-"
        )
        n_reopen = await payloads.migrate_legacy_payloads(
            conn, store_a, batch_size=50
        )
        state_reopen = await repo.get_migration_state(conn)
        extra_digest = canon({"late": 1})[0]
        extra_row = await conn.fetchrow(
            "SELECT payload_digest FROM events WHERE id=$1", extra_ids[0]
        )
        extra_rc = await conn.fetchval(
            "SELECT ref_count FROM event_payload_objects WHERE digest=$1",
            extra_digest,
        )
    check("5 completed 但仍有旧行时重跑自动重开并迁完（processed 精确 +1）",
          n_reopen == 1 and state_reopen["status"] == "completed"
          and state_reopen["processed"] == 6 and extra_row["payload_digest"]
          == extra_digest and extra_rc == 1,
          f"n={n_reopen} state={dict(state_reopen)} rc={extra_rc}")


def main() -> int:
    pg_root = tempfile.mkdtemp(prefix=".mig-pgdata-", dir=str(ROOT))
    obj_dir = tempfile.mkdtemp(prefix=".mig-store-", dir=str(ROOT))
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
    from app.objectstore import LocalObjectStore

    payloads = _payloads
    repo = _repo

    await init_db()
    pool = get_pool()
    inner_store = LocalObjectStore(os.environ["PAYLOAD_LOCAL_DIR"])
    await inner_store.ensure_bucket()

    try:
        await case1_lock_ordering_and_dedup()
        await case2_reverse_ordered_batches_no_deadlock(pool, inner_store)
        await case3_stress(pool, inner_store)
        await case4_upload_failure_rollback_and_rerun(pool, inner_store)
        await case5_short_empty_batch_not_completed_and_rollback_revisited(
            pool, inner_store
        )
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
    print("并发迁移死锁修复检查全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
