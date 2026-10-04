"""端到端验证：事件载荷对象存储重构（内容寻址/去重/状态机/迁移/GC/摘要校验）。

覆盖：
1. 提交后事件只引用不可变对象（events.payload 为 NULL，payload_digest 为
   规范化 JSON 的 SHA-256），API/Worker 经对象存储取回，签名与送达正常；
2. 相同载荷去重：多个事件共享同一对象，event_payload_objects 只有 1 行、
   ref_count 正确；不同 JSON 键序归一为同一摘要；
3. 提交状态机崩溃恢复：制造 payload_upload_pending 残留 + 缺失对象，
   recover 补传对象并完成提交，无悬空引用、无重复投递；
4. 在线迁移：直接写旧 JSONB 事件 -> migrate 链接对象、双读投递不中断 ->
   clear-legacy 清空 JSONB；进度持久化、幂等可重跑；
5. Worker 摘要校验：篡改对象内容后投递被拒绝（payload_integrity），
   恢复对象后重试成功（幂等/顺序/死信重放语义不变）；
6. 垃圾回收：零引用对象经“标记 -> 宽限 -> 行锁复核”后删除；
   宽限期内/被重新引用的对象被复活不误删；--rescan-store 登记存储孤儿；
7. payloadadmin status / API /api/v1/payloads/status 可观测；迁移状态读一致性：
   同次响应 legacy_events_pending == migration.remaining（同一只读快照），
   除持久化 failed 外有旧行 running、清零 completed，只读不改进度；
   慢迁移者并发提交期间反复采样无自相矛盾响应。

非 Docker：自动拉起便携 PostgreSQL + 本地文件对象后端（PAYLOAD_STORE_MODE=local）。
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pgserver

ROOT = Path(__file__).resolve().parent
VENV_PY = os.environ.get("VENV_PY", "/tmp/venv/bin/python")
PAYLOAD_DIR = ROOT / ".test-payloads-store"

COMMON_ENV = {
    "LEASE_SECONDS": "3",
    "HTTP_TIMEOUT_SECONDS": "2",
    "WORKER_POLL_SECONDS": "0.1",
    "MAX_ATTEMPTS": "6",
    "BACKOFF_BASE_SECONDS": "1",
    "BACKOFF_CAP_SECONDS": "8",
    "RECEIVER_SECRET": "dev-signing-secret",
    "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS": "600",
    "WEBHOOK_ALLOWED_HOSTS": "127.0.0.1,localhost",
    "WEBHOOK_KEYRING_JSON": '{"active_key_id":"k1","keys":{"k1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}',
    "PAYLOAD_STORE_MODE": "local",
    "PAYLOAD_LOCAL_DIR": str(PAYLOAD_DIR),
    "PAYLOAD_STALE_AGE_SECONDS": "0",
    "PAYLOAD_RECOVER_INTERVAL_SECONDS": "3600",  # 测试中手动 recover，避免后台抢
    "PAYLOAD_GC_GRACE_SECONDS": "0",
    "PYTHONUNBUFFERED": "1",
}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_http(url, timeout=20):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.25)
    raise RuntimeError(f"not ready: {url} ({last})")


def wait_for(cond, desc, timeout=60, interval=0.3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = cond()
        if r:
            return r
        time.sleep(interval)
    raise AssertionError(f"timeout: {desc}")


def canon_digest(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


class Harness:
    def __init__(self):
        self.procs = []

    def spawn(self, mod, port, name):
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        log = open(ROOT / f"test-store-{name}.log", "w")
        p = subprocess.Popen(
            [VENV_PY, "-m", *mod], cwd=ROOT, env=env,
            stdout=log, stderr=subprocess.STDOUT,
        )
        self.procs.append(p)
        return p

    def admin(self, *args):
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        return subprocess.run(
            [VENV_PY, "-m", "app.payloadadmin", *args],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
        )

    def start(self):
        self.pg = pgserver.get_server(str(ROOT / ".test-store-pgdata"),
                                      cleanup_mode="stop")
        self.dsn = self.pg.get_uri()
        PAYLOAD_DIR.mkdir(exist_ok=True)
        api_port, rcv_port = free_port(), free_port()
        self.api = f"http://127.0.0.1:{api_port}"
        self.rcv = f"http://127.0.0.1:{rcv_port}"
        self.spawn(["uvicorn", "app.main:app", "--host", "127.0.0.1",
                    "--port", str(api_port)], api_port, "api")
        self.spawn(["uvicorn", "app.receiver:app", "--host", "127.0.0.1",
                    "--port", str(rcv_port)], rcv_port, "receiver")
        self.spawn(["app.worker"], None, "worker")
        wait_http(f"{self.api}/health")
        wait_http(f"{self.rcv}/health")

    def stop(self):
        for p in self.procs:
            p.send_signal(signal.SIGTERM)
        for p in self.procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
        try:
            self.pg.cleanup()
        except Exception:  # noqa: BLE001
            pass


async def _pg(dsn):
    import asyncpg
    conn = await asyncpg.connect(dsn)
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads,
                              schema="pg_catalog")
    return conn


def main() -> int:
    h = Harness()
    h.start()
    failures = []

    def check(name, ok, detail=""):
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    try:
        api = httpx.Client(base_url=h.api, timeout=10)
        rcv = httpx.Client(base_url=h.rcv, timeout=10)
        rcv.post("/received/reset")

        sub = api.post("/api/v1/subscriptions", json={
            "source": "ord", "target_url": f"{h.rcv}/receive",
            "secret": "dev-signing-secret",
        })
        check("订阅创建", sub.status_code in (200, 201), sub.text)

        # 1) 内容寻址：提交后数据库只挂摘要，对象在文件后端
        payload_a = {"b": 2, "a": 1, "nested": {"z": 0, "y": 9}}
        dig_a = canon_digest(payload_a)
        r = api.post("/api/v1/events", json={
            "source": "ord", "event_id": "e-1", "payload": payload_a})
        check("提交 201", r.status_code == 201 and r.json()["duplicate"] is False,
              r.text)
        check("响应含 payload_digest（规范化摘要）",
              r.json()["payload_digest"] == dig_a,
              f"{r.json().get('payload_digest')} != {dig_a}")
        # 键序归一：同内容不同写法同摘要、且为幂等重复
        r2 = api.post("/api/v1/events", json={
            "source": "ord", "event_id": "e-1",
            "payload": {"nested": {"y": 9, "z": 0}, "a": 1, "b": 2}})
        check("键序归一 + 幂等重复 200",
              r2.status_code == 200 and r2.json()["duplicate"] is True
              and r2.json()["payload_digest"] == dig_a, r2.text)
        check("对象文件存在于本地后端", (PAYLOAD_DIR / dig_a).exists())

        # 数据库侧：events.payload 为 NULL，只引用摘要
        async def inspect_1():
            conn = await _pg(h.dsn)
            row = await conn.fetchrow(
                "SELECT payload, payload_digest FROM events "
                "WHERE source='ord' AND event_id='e-1'")
            obj = await conn.fetchrow(
                "SELECT ref_count, size_bytes FROM event_payload_objects "
                "WHERE digest=$1", dig_a)
            await conn.close()
            return row, obj
        ev_row, obj_row = asyncio.run(inspect_1())
        check("events.payload 不再保存字节（NULL）", ev_row["payload"] is None)
        check("payload_digest 引用对象", ev_row["payload_digest"] == dig_a)
        check("对象元数据 ref_count=1", obj_row["ref_count"] == 1
              and obj_row["size_bytes"] > 0, str(dict(obj_row)))

        # 送达 + 验签（Worker 经对象存储取回）
        def delivery_of(event_id):
            return next((d for d in api.get("/api/v1/deliveries",
                         params={"source": "ord"}).json()
                         if d["source_event_id"] == event_id), None)
        d = wait_for(lambda: delivery_of("e-1"), "e-1 投递")
        wait_for(lambda: api.get(f"/api/v1/deliveries/{d['id']}").json()
                 ["status"] == "succeeded", "e-1 成功")
        rec = next(x for x in rcv.get("/received").json()["items"]
                   if x["event_id"] == "e-1")
        check("对象载荷送达且签名校验通过", rec["signature_valid"] is True,
              rec.get("signature_message"))

        # 2) 去重：两个不同事件，同内容 -> 同一对象 ref_count=2
        api.post("/api/v1/events", json={
            "source": "ord", "event_id": "e-2", "payload": payload_a})
        wait_for(lambda: delivery_of("e-2"), "e-2 投递")
        wait_for(lambda: api.get(
            f"/api/v1/deliveries/{delivery_of('e-2')['id']}").json()
            ["status"] == "succeeded", "e-2 成功")

        async def inspect_2():
            conn = await _pg(h.dsn)
            n = await conn.fetchval(
                "SELECT ref_count FROM event_payload_objects WHERE digest=$1", dig_a)
            cnt = await conn.fetchval("SELECT COUNT(*) FROM event_payload_objects")
            await conn.close()
            return n, cnt
        rc, total_obj = asyncio.run(inspect_2())
        check("同内容跨事件去重：共享对象 ref_count=2", rc == 2, f"rc={rc}")
        check("去重后对象表仅 1 行", total_obj == 1, f"total={total_obj}")

        # 3) 提交状态机崩溃恢复：插一条 pending 残留且对象缺失
        async def seed_crash():
            conn = await _pg(h.dsn)
            data = json.dumps({"crash": True, "n": 7}, sort_keys=True,
                              separators=(",", ":")).encode()
            dig = hashlib.sha256(data).hexdigest()
            await conn.execute(
                """INSERT INTO payload_upload_pending
                   (digest, source, event_id, payload_bytes, owner_id, updated_at)
                   VALUES ($1,'ord','e-crash',$2,'dead', now() - interval '1 hour')""",
                dig, data)
            await conn.close()
            return dig
        dig_crash = asyncio.run(seed_crash())
        check("崩溃场景：对象初始缺失", not (PAYLOAD_DIR / dig_crash).exists())
        out = h.admin("recover")
        check("payloadadmin recover 成功", out.returncode == 0, out.stderr)
        check("recover 后对象已补传", (PAYLOAD_DIR / dig_crash).exists())
        crash_ev = wait_for(
            lambda: asyncio.run(_event_row(h.dsn, "ord", "e-crash")),
            "崩溃事件被提交")
        check("恢复后事件挂正确摘要且 payload 为 NULL",
              crash_ev["payload_digest"] == dig_crash
              and crash_ev["payload"] is None)
        d3 = wait_for(lambda: delivery_of("e-crash"), "崩溃事件投递")
        wait_for(lambda: api.get(f"/api/v1/deliveries/{d3['id']}").json()
                 ["status"] == "succeeded", "崩溃事件送达")
        check("崩溃恢复只投递一次",
              api.get(f"/api/v1/deliveries/{d3['id']}").json()["attempts_made"] == 1)
        # recover 幂等：再跑无残留
        out2 = h.admin("recover")
        check("recover 幂等", out2.returncode == 0 and "0 条" in out2.stdout,
              out2.stdout)

        # 4) 在线迁移：直接写一条旧 JSONB 事件（无摘要），需可投递（双读）
        async def seed_legacy():
            conn = await _pg(h.dsn)
            e = await conn.fetchrow(
                "INSERT INTO events (source,event_id,payload) "
                "VALUES ('ord','e-legacy',$1::jsonb) RETURNING id",
                {"legacy": 1})
            # 该旧事件插入在建表“无旧数据即 completed”自动标记之后；真实旧库
            # 升级时状态应为 running。重置迁移状态以模拟待迁移的存量库。
            await conn.execute(
                "UPDATE payload_migration_state "
                "SET status='running', last_event_id=0, last_error=NULL WHERE id=1"
            )
            # 为该事件手工建投递（沿用 e-1 的订阅/版本/链规则）
            await conn.execute(
                """INSERT INTO deliveries
                   (event_id_fk, subscription_id, config_version_id,
                    chain_id, chain_seq, status)
                   SELECT $1, s.id, v.id, nextval('delivery_chain_seq'),1,'pending'
                   FROM subscriptions s
                   JOIN subscription_versions v ON v.subscription_id=s.id
                        AND v.revision=s.current_revision
                   WHERE s.source='ord' LIMIT 1""",
                e["id"])
            await conn.close()
        asyncio.run(seed_legacy())
        d4 = wait_for(lambda: delivery_of("e-legacy"), "旧 JSONB 事件投递创建")
        wait_for(lambda: api.get(f"/api/v1/deliveries/{d4['id']}").json()
                 ["status"] == "succeeded", "双读：迁移前旧事件也能送达")
        check("双读迁移不中断", True)

        # migrate（幂等、断点续跑）
        st0 = h.admin("status")
        out = h.admin("migrate")
        check("migrate 成功", out.returncode == 0, out.stderr + out.stdout)
        dig_legacy = canon_digest({"legacy": 1})

        async def inspect_legacy():
            conn = await _pg(h.dsn)
            row = await conn.fetchrow(
                "SELECT payload, payload_digest FROM events "
                "WHERE source='ord' AND event_id='e-legacy'")
            rem = await conn.fetchval(
                "SELECT COUNT(*) FROM events WHERE payload_digest IS NULL")
            rc = await conn.fetchval(
                "SELECT ref_count FROM event_payload_objects WHERE digest=$1",
                dig_legacy)
            await conn.close()
            return row, rem, rc
        lr, remaining, lrc = asyncio.run(inspect_legacy())
        check("迁移后旧事件挂摘要（JSONB 暂保留为双读兜底）",
              lr["payload_digest"] == dig_legacy and lr["payload"] == {"legacy": 1})
        check("无剩余待迁移事件", remaining == 0, f"remaining={remaining}")
        check("迁移对象引用计数=1", lrc == 1)
        out = h.admin("migrate")
        check("migrate 幂等重跑完成", out.returncode == 0 and "0 个事件" in out.stdout,
              out.stdout)

        # clear-legacy：清空已迁移行的 JSONB
        out = h.admin("clear-legacy")
        check("clear-legacy 成功", out.returncode == 0, out.stderr)

        async def inspect_cleared():
            conn = await _pg(h.dsn)
            n = await conn.fetchval(
                "SELECT COUNT(*) FROM events WHERE payload_digest IS NOT NULL "
                "AND payload IS NOT NULL")
            await conn.close()
            return n
        check("旧 JSONB 已清空（只留对象引用）",
              asyncio.run(inspect_cleared()) == 0)
        # 清空后 API 仍能返回 payload（从对象读）
        legacy_pk = d4["event_id_fk"]
        ev_after = api.get(f"/api/v1/events/{legacy_pk}").json()
        check("清空 JSONB 后 API 仍返回载荷（对象读）",
              ev_after["payload"] == {"legacy": 1}
              and ev_after["payload_digest"] == dig_legacy)

        # 5) Worker 摘要校验：篡改对象 -> payload_integrity；恢复后重试成功
        # 造一个会死信前持续重试的投递：用 /fail，max_attempts 较大；
        # 先提交事件，暂停 worker 不易，改为直接篡改 e-2 已成功对象会影响别的，
        # 故新建专用事件，投递到 /fail，期间篡改其对象。
        api.post("/api/v1/subscriptions", json={
            "source": "tamper", "target_url": f"{h.rcv}/fail",
            "secret": "dev-signing-secret", "max_attempts": 6,
            "backoff_base_seconds": 1, "backoff_cap_seconds": 1})
        payload_t = {"tamper": 1}
        dig_t = canon_digest(payload_t)
        api.post("/api/v1/events", json={
            "source": "tamper", "event_id": "t-1", "payload": payload_t})
        dt = wait_for(lambda: delivery_of_t(api, "t-1"), "t-1 投递")["id"]
        wait_for(lambda: api.get(f"/api/v1/deliveries/{dt}").json()
                 ["attempts_made"] >= 1, "t-1 已首次尝试")
        # 篡改对象内容（键保持不变）
        obj_path = PAYLOAD_DIR / dig_t
        obj_path.write_bytes(b'{"tamper": 999}')  # 内容与摘要不符
        wait_for(lambda: any(
            a["outcome"] == "payload_integrity"
            for a in api.get(f"/api/v1/deliveries/{dt}/attempts").json()),
            "篡改对象后出现 payload_integrity", timeout=20)
        check("摘要校验失败被拒绝并可查询", True)
        # 恢复正确对象 -> 后续重试成功（关闭 /fail）
        rcv.post("/control/fail", params={"enabled": False})
        correct = json.dumps(payload_t, sort_keys=True,
                             separators=(",", ":")).encode()
        obj_path.write_bytes(correct)
        wait_for(lambda: api.get(f"/api/v1/deliveries/{dt}").json()
                 ["status"] == "succeeded", "恢复对象后重试成功", timeout=30)
        check("完整性恢复后投递成功（语义不变）", True)
        rcv.post("/control/fail", params={"enabled": True})

        # 6) GC：零引用对象经宽限复核删除；被重新引用则复活
        # 先造一个只被一个事件引用的对象，然后“制造零引用”——通过删除其唯一事件
        # 在真实系统事件不会被删；这里直接用 SQL 释放引用来验证 GC 机制。
        payload_g = {"gc": "me"}
        dig_g = canon_digest(payload_g)
        api.post("/api/v1/events", json={
            "source": "ord", "event_id": "e-gc", "payload": payload_g})
        dg = wait_for(lambda: delivery_of("e-gc"), "e-gc 投递")
        wait_for(lambda: api.get(f"/api/v1/deliveries/{dg['id']}").json()
                 ["status"] == "succeeded", "e-gc 成功")

        async def ref(digest):
            conn = await _pg(h.dsn)
            r = await conn.fetchval(
                "SELECT ref_count FROM event_payload_objects WHERE digest=$1", digest)
            await conn.close()
            return r
        check("GC 对象初始 ref_count=1", asyncio.run(ref(dig_g)) == 1)

        # 第一轮 GC：对象仍有引用，不标记
        out = h.admin("gc")
        check("有引用时 GC 不删除", out.returncode == 0)
        check("对象仍在", asyncio.run(ref(dig_g)) == 1)

        # 直接 SQL 释放引用并移除元数据引用（模拟该载荷不再被任何事件引用）：
        # 通过新建“引用归零”：把事件改指到另一摘要不现实；改为删除关联事件行
        # （测试专用），并手动把 ref_count 调到真实无引用值。
        async def drop_ref(digest):
            conn = await _pg(h.dsn)
            await conn.execute(
                "DELETE FROM deliveries WHERE event_id_fk IN "
                "(SELECT id FROM events WHERE source='ord' AND event_id='e-gc')")
            await conn.execute(
                "DELETE FROM events WHERE source='ord' AND event_id='e-gc'")
            await conn.execute(
                "UPDATE event_payload_objects SET ref_count=0 WHERE digest=$1",
                digest)
            await conn.close()
        asyncio.run(drop_ref(dig_g))

        # 宽限期=0：第一次 gc 标记+（grace_before=now）候选 first_seen 可能
        # 略晚于 now，故允许第二次 gc 完成删除。
        h.admin("gc")
        h.admin("gc")

        async def gone(digest):
            conn = await _pg(h.dsn)
            m = await conn.fetchval(
                "SELECT 1 FROM event_payload_objects WHERE digest=$1", digest)
            await conn.close()
            return m is None and not (PAYLOAD_DIR / digest).exists()
        check("零引用对象过宽限复核后对象与元数据均删除",
              wait_for(lambda: asyncio.run(gone(dig_g)), "GC 删除", timeout=10))

        # 复活场景：零引用对象在候选期内被重新引用 -> 不删
        payload_r = {"reanimate": 1}
        dig_r = canon_digest(payload_r)
        api.post("/api/v1/events", json={
            "source": "ord", "event_id": "e-r1", "payload": payload_r})
        dr = wait_for(lambda: delivery_of("e-r1"), "e-r1 投递")
        wait_for(lambda: api.get(f"/api/v1/deliveries/{dr['id']}").json()
                 ["status"] == "succeeded", "e-r1 成功")
        asyncio.run(drop_ref(dig_r))
        h.admin("gc")  # 标记候选
        # 在删除前重新建立引用（模拟并发提交/重放复用同一内容对象）
        async def revive(digest):
            conn = await _pg(h.dsn)
            e = await conn.fetchrow(
                "INSERT INTO events (source,event_id,payload,payload_digest) "
                "VALUES ('ord','e-r2',NULL,$1) ON CONFLICT DO NOTHING RETURNING id",
                digest)
            if e is not None:
                await conn.execute(
                    "UPDATE event_payload_objects SET ref_count=ref_count+1 "
                    "WHERE digest=$1", digest)
            await conn.close()
        asyncio.run(revive(dig_r))
        h.admin("gc")  # 复核时引用已重建 -> 复活

        async def survived(digest):
            conn = await _pg(h.dsn)
            r = await conn.fetchval(
                "SELECT ref_count FROM event_payload_objects WHERE digest=$1", digest)
            await conn.close()
            return r
        check("重新引用的对象被复活不误删",
              asyncio.run(survived(dig_r)) == 1 and (PAYLOAD_DIR / dig_r).exists())

        # 存储孤儿扫描：放一个无元数据对象，--rescan-store 先登记，再过一轮删除
        orphan = hashlib.sha256(b'{"orphan":1}').hexdigest()
        (PAYLOAD_DIR / orphan).write_bytes(b'{"orphan":1}')
        out = h.admin("gc", "--rescan-store")
        check("rescan-store 成功登记", out.returncode == 0, out.stderr)
        check("孤儿首轮保留（宽限）", (PAYLOAD_DIR / orphan).exists())
        h.admin("gc", "--rescan-store")
        h.admin("gc")
        check("存储孤儿过宽限后删除", not (PAYLOAD_DIR / orphan).exists())

        # 6.5) GET /payloads/status 迁移状态读竞态修复：同次响应必须来自一致
        # 的数据库视图（legacy_events_pending == migration.remaining），且
        # 除持久化 failed 外，有可见旧行报 running、清零报 completed；只读不改进度。
        async def seed_legacy_status(n, status):
            """造 n 行旧 JSONB 事件（唯一键）并把迁移状态行置为 status。"""
            conn = await _pg(h.dsn)
            ts = time.time_ns()
            for i in range(n):
                await conn.execute(
                    "INSERT INTO events (source,event_id,payload) "
                    "VALUES ('statchk',$1,$2::jsonb)",
                    f"e-{ts}-{i}", {"i": ts % 100000, "n": i},
                )
            await conn.execute(
                "UPDATE payload_migration_state SET status=$1,"
                "last_error=NULL, updated_at=now() WHERE id=1",
                status,
            )
            await conn.close()

        async def get_state_row():
            conn = await _pg(h.dsn)
            row = await conn.fetchrow(
                "SELECT status, last_error, processed FROM payload_migration_state "
                "WHERE id=1"
            )
            await conn.close()
            return dict(row)

        def assert_coherent(body, expect_status, expect_remaining):
            mig = body["migration"]
            return (
                body["legacy_events_pending"] == expect_remaining
                and mig["remaining"] == expect_remaining
                and mig["status"] == expect_status
            )

        # (a) running/0：最后一批已提交、completed 尚未落库的瞬间 -> completed。
        #     此刻全库无旧行（前面的迁移已完成），单独把状态行置 running 即可。
        async def set_state(status, error=None):
            conn = await _pg(h.dsn)
            await conn.execute(
                "UPDATE payload_migration_state SET status=$1,"
                "last_error=$2, updated_at=now() WHERE id=1",
                status, error,
            )
            await conn.close()

        asyncio.run(set_state("running"))
        body = api.get("/api/v1/payloads/status").json()
        check("状态读一致：清零后报 completed（不出现 running/0）",
              assert_coherent(body, "completed", 0),
              json.dumps(body["migration"], ensure_ascii=False))

        # (b) 持久化 failed 一律保留并带出 last_error，即使 remaining=0
        asyncio.run(set_state("failed", "boom（一致性测试）"))
        body = api.get("/api/v1/payloads/status").json()
        check("状态读一致：remaining=0 时持久化 failed 仍保留",
              body["migration"]["status"] == "failed"
              and body["migration"]["remaining"] == 0
              and body["legacy_events_pending"] == 0
              and body["migration"]["last_error"] == "boom（一致性测试）",
              json.dumps(body["migration"], ensure_ascii=False))
        check("只读查询不清 failed/last_error",
              asyncio.run(get_state_row())["status"] == "failed")

        # (c) 有可见旧行 + 状态行 running -> running 且两个剩余数相等。
        #     后续用例继续追加旧行，记录基线后按增量断言。
        asyncio.run(seed_legacy_status(3, "running"))
        body = api.get("/api/v1/payloads/status").json()
        check("状态读一致：有旧行报 running 且两个剩余数相等(=3)",
              assert_coherent(body, "running", 3),
              json.dumps({"legacy": body["legacy_events_pending"],
                          "migration": body["migration"]}, ensure_ascii=False))

        # (d) 陈旧状态：状态行误标 completed 但仍有旧行 -> 读侧即报 running，
        # 剩余数仍相等（不等持久化写入纠正，且只读查询不改状态行）。
        asyncio.run(seed_legacy_status(2, "completed"))
        before = asyncio.run(get_state_row())
        body = api.get("/api/v1/payloads/status").json()
        after = asyncio.run(get_state_row())
        check("状态读一致：completed 但有旧行时报 running（不谎报完成）",
              assert_coherent(body, "running", 5),
              json.dumps({"legacy": body["legacy_events_pending"],
                          "migration": body["migration"]}, ensure_ascii=False))
        check("只读查询不改变迁移状态行（不重开/不推进）",
              before["status"] == after["status"] == "completed"
              and before["processed"] == after["processed"],
              f"before={before} after={after}")

        # (e) failed 且有旧行：failed 保留、两剩余数相等
        asyncio.run(seed_legacy_status(2, "failed"))
        body = api.get("/api/v1/payloads/status").json()
        check("状态读一致：failed 且有旧行时 failed 保留、两个剩余数相等(=7)",
              body["migration"]["status"] == "failed"
              and assert_coherent(body, "failed", 7),
              json.dumps({"legacy": body["legacy_events_pending"],
                          "migration": body["migration"]}, ensure_ascii=False))

        # (f) 并发：迁移批次持续提交期间反复查询，每次响应都必须自洽
        #     （两剩余数相等；running 时 >0、completed 时 ==0；failed 保留）。
        # 用后台子进程迁移，并把本地对象存储的 put 人为放慢，把“批次提交
        # 正好落在 API 两次读取之间”的窗口放大，稳定复现旧实现的读竞态。
        asyncio.run(seed_legacy_status(60, "running"))

        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = h.dsn
        # 预置一个“慢迁移者”脚本：每个对象上传前 sleep，放大批次提交窗口。
        slow_script = ROOT / ".test-slow-migrator.py"
        slow_script.write_text(
            "import asyncio, sys\n"
            "from app.objectstore import LocalObjectStore\n"
            "_orig = LocalObjectStore.put_object\n"
            "async def slow(self, digest, data):\n"
            "    await asyncio.sleep(0.05)\n"
            "    return await _orig(self, digest, data)\n"
            "LocalObjectStore.put_object = slow\n"
            "from app.payloadadmin import _migrate\n"
            "sys.exit(asyncio.run(_migrate(5, 60.0)))\n",
            encoding="utf-8",
        )
        migrator = subprocess.Popen(
            [VENV_PY, str(slow_script)], cwd=ROOT, env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.time() + 40
            incoherent: list = []
            probes = 0
            while time.time() < deadline:
                b = api.get("/api/v1/payloads/status").json()
                probes += 1
                m = b["migration"]
                ok = b["legacy_events_pending"] == m["remaining"]
                if m["status"] == "running":
                    ok = ok and m["remaining"] > 0
                elif m["status"] == "completed":
                    ok = ok and m["remaining"] == 0
                # failed 允许任意 remaining，但本场景不应出现
                if not ok:
                    incoherent.append({"legacy": b["legacy_events_pending"],
                                       "migration": m})
                if migrator.poll() is not None:
                    break
                time.sleep(0.01)
            migrator.wait(timeout=20)
        finally:
            if migrator.poll() is None:
                migrator.terminate()
                migrator.wait(timeout=10)
        check(f"并发迁移中每次状态响应自洽（采样 {probes} 次，无矛盾）",
              migrator.returncode == 0 and not incoherent,
              json.dumps({"rc": migrator.returncode,
                          "bad": incoherent[:3]}, ensure_ascii=False))
        # 收尾：把可能剩余的 statchk 旧行全部迁完，failed 状态由成功批次清回
        out_final = h.admin("migrate")
        body = api.get("/api/v1/payloads/status").json()
        check("并发收尾后迁移完成、两剩余数为 0",
              out_final.returncode == 0
              and assert_coherent(body, "completed", 0),
              json.dumps({"legacy": body["legacy_events_pending"],
                          "migration": body["migration"]}, ensure_ascii=False))

        # 7) 状态可观测
        st = api.get("/api/v1/payloads/status")
        check("GET /payloads/status 200", st.status_code == 200, st.text)
        body = st.json()
        check("状态含去重对象数与迁移完成",
              body["payload_objects"] >= 1
              and body["legacy_events_pending"] == 0
              and body["migration"]["status"] == "completed",
              json.dumps(body["migration"], ensure_ascii=False))
        check("status CLI 可运行", st0.returncode == 0, st0.stderr)

    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append("异常")
    finally:
        h.stop()

    print()
    if failures:
        print(f"失败 {len(failures)} 项: {failures}")
        return 1
    print("载荷对象存储全部检查通过 ✅")
    return 0


async def _event_row(dsn, source, event_id):
    conn = await _pg(dsn)
    row = await conn.fetchrow(
        "SELECT id, payload, payload_digest FROM events "
        "WHERE source=$1 AND event_id=$2", source, event_id)
    await conn.close()
    return dict(row) if row else None


def delivery_of_t(api, event_id):
    return next((d for d in api.get("/api/v1/deliveries",
                 params={"source": "tamper"}).json()
                 if d["source_event_id"] == event_id), None)


if __name__ == "__main__":
    sys.exit(main())
