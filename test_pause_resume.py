"""订阅暂停/恢复专项验证（非 Docker 环境使用）：启动便携 Postgres、API、
Receiver 与两个 Worker，覆盖：

1. HTTP：暂停/查询/恢复，重复操作幂等，未知订阅 404，订阅视图含暂停状态；
2. 暂停成功后 Worker 不再为该订阅产生新租约（pending 投递不被认领，过期租约
   也不被接管）；暂停前已认领的在途尝试照常结算（用 /slow 确定性验证）；
3. 暂停期间 POST /events 仍建立 pending 投递并钉住当时配置版本（不复用
   active 标志阻止建投递）；恢复后沿原 seq、not_before、attempts_made 继续；
4. 暂停期间发布新版本：暂停前已 pending 的投递钉旧版本，恢复后的新投递钉
   新版本（版本固定与严格顺序语义不变）；
5. 暂停期间死信重放仍可在同一 chain 上新建投递记录（语义不变），恢复后续跑；
6. 事务边界（仓库层直接验证）：暂停写入与 claim_delivery 在同一订阅行锁上
   串行——暂停先提交则等待中的认领读到新状态放弃；认领先提交则暂停等待认领
   完成，该在途租约有效（不会出现读到旧状态的认领越过边界）。
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncpg
import httpx
import pgserver

ROOT = Path(__file__).resolve().parent
VENV_PY = os.environ.get("VENV_PY", sys.executable)

# 长租约 + 长退避，保证“暂停期间不被认领/接管”的观察窗口确定。
COMMON_ENV = {
    "LEASE_SECONDS": "60",
    "HTTP_TIMEOUT_SECONDS": "10",
    "WORKER_POLL_SECONDS": "0.1",
    "MAX_ATTEMPTS": "6",
    "BACKOFF_BASE_SECONDS": "30",
    "BACKOFF_CAP_SECONDS": "300",
    "RECEIVER_SECRET": "dev-signing-secret",
    "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS": "600",
    "WEBHOOK_ALLOWED_HOSTS": "127.0.0.1,localhost",
    "WEBHOOK_ALLOWED_CIDRS": "",
    "WEBHOOK_MAX_REDIRECTS": "5",
    "WEBHOOK_KEYRING_JSON": '{"active_key_id":"k1","keys":{"k1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}',
    "PAYLOAD_STORE_MODE": "local",
    "PAYLOAD_LOCAL_DIR": str(ROOT / ".test-payloads-pause"),
    "PYTHONUNBUFFERED": "1",
}


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_http(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(0.3)
    raise RuntimeError(f"服务未就绪: {url} ({last})")


def wait_for(condition, desc: str, timeout: float = 30.0, interval: float = 0.2):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = condition()
        if result:
            return result
        time.sleep(interval)
    raise AssertionError(f"等待超时: {desc}")


class Harness:
    def __init__(self) -> None:
        self.procs: list[subprocess.Popen] = []

    def spawn(self, module_cmd: list[str], name: str):
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        log = open(ROOT / f"test-pause-{name}.log", "w")
        proc = subprocess.Popen(
            [VENV_PY, "-m", *module_cmd],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.procs.append(proc)
        return proc

    def start(self):
        self.pg = pgserver.get_server(
            str(ROOT / ".test-pgdata-pause"), cleanup_mode="stop"
        )
        self.dsn = self.pg.get_uri()
        print("Postgres DSN:", self.dsn)

        api_port = free_port()
        rcv_port = free_port()
        self.api = f"http://127.0.0.1:{api_port}"
        self.rcv = f"http://127.0.0.1:{rcv_port}"

        self.spawn(
            ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
            "api",
        )
        self.spawn(
            ["uvicorn", "app.receiver:app", "--host", "127.0.0.1", "--port", str(rcv_port)],
            "receiver",
        )
        self.spawn(["app.worker"], "worker1")
        self.spawn(["app.worker"], "worker2")
        wait_http(f"{self.api}/health")
        wait_http(f"{self.rcv}/health")
        print("API/Receiver/Workers 已启动")

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


# -- 仓库层事务边界测试 -------------------------------------------------------------


async def repo_boundary_test(dsn: str) -> list[tuple[str, bool, str]]:
    """直接对 repository 层验证暂停/认领的行锁串行语义。"""
    from app import repository as repo

    results: list[tuple[str, bool, str]] = []

    def check(name, ok, detail=""):
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
        results.append((name, ok, detail))

    conn_a = await asyncpg.connect(dsn)  # 模拟 Worker
    conn_b = await asyncpg.connect(dsn)  # 模拟 API（暂停）
    conn_c = await asyncpg.connect(dsn)  # 旁观者
    for c in (conn_a, conn_b, conn_c):
        await c.set_type_codec(
            "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
        )

    async def make_sub(source: str, target: str) -> int:
        async with conn_c.transaction():
            sub = await conn_c.fetchrow(
                """
                INSERT INTO subscriptions (source, target_url, secret, current_revision)
                VALUES ($1, $2, '', 1) RETURNING id
                """,
                source, target,
            )
            ver = await conn_c.fetchval(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret, max_attempts,
                     backoff_base_seconds, backoff_cap_seconds)
                VALUES ($1, 1, $2, '', 6, 30.0, 300.0) RETURNING id
                """,
                sub["id"], target,
            )
            ev = await conn_c.fetchval(
                """
                INSERT INTO events (source, event_id, payload)
                VALUES ($1, $2, NULL) RETURNING id
                """,
                source, f"{source}-e1",
            )
            await conn_c.execute(
                """
                INSERT INTO deliveries
                    (event_id_fk, subscription_id, config_version_id,
                     chain_id, chain_seq, status, not_before)
                VALUES ($1, $2, $3, nextval('delivery_chain_seq'), 1,
                        'pending', now() - interval '1 second')
                """,
                ev, sub["id"], ver,
            )
        return sub["id"]

    worker_id = "boundary-worker"

    # 场景 A：认领先锁住投递行；暂停先提交（先拿到订阅行锁并提交）；认领随后
    # 锁订阅行时读到 paused=TRUE，必须放弃（返回 None，无新租约）。
    sid_a = await make_sub("pausefirst", "http://127.0.0.1/x")
    tx_a = conn_a.transaction()
    await tx_a.start()
    cand = await conn_a.fetchrow(
        """
        SELECT d.id FROM deliveries d
        WHERE d.subscription_id = $1
          AND d.status = 'pending' AND d.not_before <= now()
        ORDER BY d.seq LIMIT 1
        FOR UPDATE OF d SKIP LOCKED
        """,
        sid_a,
    )
    check("场景A：认领事务已锁投递行", cand is not None)
    # API 暂停事务在认领尚未锁订阅行时抢先提交。
    await conn_b.execute(
        "UPDATE subscriptions SET paused = TRUE, paused_at = now() WHERE id = $1",
        sid_a,
    )
    # 认领继续执行：锁订阅行 -> 复核 -> 放弃。
    sub_row = await conn_a.fetchrow(
        "SELECT paused FROM subscriptions WHERE id = $1 FOR UPDATE", sid_a
    )
    crossed = sub_row["paused"] is False
    if crossed:
        await conn_a.fetchrow(
            """
            UPDATE deliveries SET status = 'in_flight', leased_at = now(),
                lease_expires_at = now() + interval '60 seconds', leased_by = 'w'
            WHERE id = $1 RETURNING id
            """,
            cand["id"],
        )
    await tx_a.commit()
    state = await conn_c.fetchrow(
        "SELECT status, leased_by, paused FROM deliveries d JOIN subscriptions s ON s.id = d.subscription_id WHERE d.subscription_id = $1",
        sid_a,
    )
    check(
        "场景A：暂停先提交后，等待中的认领读到新状态、未越过边界",
        not crossed and state["status"] == "pending" and state["leased_by"] is None,
        f"status={state['status']} leased_by={state['leased_by']}",
    )

    # 场景 B：认领先完成（锁住订阅行并写入租约）；暂停必须等认领提交后才生效，
    # 租约保持有效——暂停前已认领的尝试照常结算。
    sid_b = await make_sub("claimfirst", "http://127.0.0.1/y")
    tx_b = conn_b.transaction()
    await tx_b.start()
    cand_b = await conn_b.fetchrow(
        """
        SELECT d.id FROM deliveries d
        WHERE d.subscription_id = $1
          AND d.status = 'pending' AND d.not_before <= now()
        ORDER BY d.seq LIMIT 1
        FOR UPDATE OF d SKIP LOCKED
        """,
        sid_b,
    )
    sub_b = await conn_b.fetchrow(
        "SELECT paused FROM subscriptions WHERE id = $1 FOR UPDATE", sid_b
    )
    leased = await conn_b.fetchrow(
        """
        UPDATE deliveries SET status = 'in_flight', leased_at = now(),
            lease_expires_at = now() + interval '60 seconds', leased_by = $2
        WHERE id = $1 RETURNING id, leased_by
        """,
        cand_b["id"], worker_id,
    )

    async def pause_after_claim():
        await asyncio.sleep(0.3)
        # set_subscription_paused 与 API 完全同一条加锁更新路径。
        async with conn_a.transaction():
            await repo.set_subscription_paused(conn_a, sid_b, True)

    pause_task = asyncio.create_task(pause_after_claim())
    await asyncio.sleep(0.1)
    await tx_b.commit()  # 认领先提交
    await pause_task
    state_b = await conn_c.fetchrow(
        "SELECT status, leased_by, paused FROM deliveries d JOIN subscriptions s ON s.id = d.subscription_id WHERE d.subscription_id = $1",
        sid_b,
    )
    check(
        "场景B：认领先提交则暂停等待其完成，在途租约有效（暂停只阻断新租约）",
        state_b["status"] == "in_flight"
        and state_b["leased_by"] == worker_id
        and state_b["paused"] is True,
        f"status={state_b['status']} leased_by={state_b['leased_by']} paused={state_b['paused']}",
    )

    # 暂停后：真实 claim_delivery 对该订阅返回 None（即便存在到期 pending）。
    async with conn_a.transaction():
        claim = await repo.claim_delivery(conn_a, worker_id)
        claimed_paused_id = claim["delivery"]["subscription_id"] if claim else None
    check(
        "场景B：暂停生效后 claim_delivery 不再认领该订阅",
        claim is None or claimed_paused_id not in (sid_a, sid_b),
        f"claimed_sub={claimed_paused_id}",
    )

    # 恢复：幂等，且 claim_delivery 立即可以重新认领（场景 A 的投递仍 pending）。
    async with conn_c.transaction():
        row = await repo.set_subscription_paused(conn_c, sid_a, False)
        row2 = await repo.set_subscription_paused(conn_c, sid_a, False)
    check(
        "恢复幂等（paused=FALSE, paused_at=NULL）",
        row["paused"] is False and row["paused_at"] is None
        and row2["paused"] is False and row2["paused_at"] is None,
    )
    async with conn_a.transaction():
        claim2 = await repo.claim_delivery(conn_a, worker_id)
    check(
        "恢复后 claim_delivery 可认领原暂停订阅（seq 最小者优先）",
        claim2 is not None and claim2["delivery"]["subscription_id"] == sid_a,
        str(claim2["delivery"]["subscription_id"] if claim2 else None),
    )

    # 未知订阅返回 None（API 层映射为 404）。
    async with conn_c.transaction():
        missing = await repo.set_subscription_paused(conn_c, 999999, True)
    check("未知订阅暂停返回 None", missing is None)

    for c in (conn_a, conn_b, conn_c):
        await c.close()
    return results


def main() -> int:
    failures: list[str] = []

    def check(name, ok, detail=""):
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    # 1) 仓库层边界测试（独立便携 Postgres，快速确定性验证）
    pg = pgserver.get_server(str(ROOT / ".test-pgdata-pause-repo"), cleanup_mode="stop")
    dsn = pg.get_uri()
    try:

        async def setup():
            c = await asyncpg.connect(dsn)
            await c.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            from app.db import init_schema
            await init_schema(c)
            await c.close()

        asyncio.run(setup())
        repo_results = asyncio.run(repo_boundary_test(dsn))
        failures.extend(n for n, ok, _ in repo_results if not ok)
    finally:
        pg.cleanup()

    # 2) 端到端 HTTP/Worker 测试
    h = Harness()
    h.start()
    try:
        api = httpx.Client(base_url=h.api, timeout=10)
        rcv = httpx.Client(base_url=h.rcv, timeout=10)
        rcv.post("/received/reset")
        rcv.post("/control/fail", params={"enabled": False})

        # ---- 2.1 API：暂停/查询/恢复/幂等/404 ----
        sub = api.post("/api/v1/subscriptions", json={
            "source": "pause-demo",
            "target_url": f"{h.rcv}/receive",
            "secret": "dev-signing-secret",
        })
        check("创建订阅 201 且初始 paused=false",
              sub.status_code == 201 and sub.json()["paused"] is False
              and sub.json()["paused_at"] is None, sub.text)
        sid = sub.json()["id"]

        missing = api.post("/api/v1/subscriptions/999999/pause")
        check("暂停未知订阅 404", missing.status_code == 404)
        missing2 = api.post("/api/v1/subscriptions/999999/resume")
        check("恢复未知订阅 404", missing2.status_code == 404)
        missing3 = api.get("/api/v1/subscriptions/999999")
        check("查询未知订阅 404", missing3.status_code == 404)

        pr = api.post(f"/api/v1/subscriptions/{sid}/pause")
        check("暂停返回 200 且 paused=true + paused_at",
              pr.status_code == 200 and pr.json()["paused"] is True
              and pr.json()["paused_at"] is not None, pr.text)
        paused_at_1 = pr.json()["paused_at"]
        time.sleep(0.01)
        pr2 = api.post(f"/api/v1/subscriptions/{sid}/pause")
        check("重复暂停幂等（仍 200，仍 paused=true）",
              pr2.status_code == 200 and pr2.json()["paused"] is True, pr2.text)

        got = api.get(f"/api/v1/subscriptions/{sid}")
        check("GET 订阅显示暂停状态",
              got.status_code == 200 and got.json()["paused"] is True
              and got.json()["paused_at"] is not None)
        listed = api.get("/api/v1/subscriptions", params={"source": "pause-demo"})
        check("GET 订阅列表显示暂停状态",
              listed.status_code == 200 and listed.json()[0]["paused"] is True)

        # ---- 2.2 暂停期间：事件仍建 pending 投递、钉住版本，且无新租约 ----
        e1 = api.post("/api/v1/events", json={
            "source": "pause-demo", "event_id": "pd-1", "payload": {"n": 1},
        })
        check("暂停期间提交事件仍 201", e1.status_code == 201)
        d1 = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                         params={"source": "pause-demo"}).json()
                         if x["source_event_id"] == "pd-1"), None),
            "暂停期间 pd-1 投递仍被创建",
        )
        check("暂停期间新投递为 pending 且钉住 revision=1",
              d1["status"] == "pending" and d1["config_revision"] == 1)
        time.sleep(2.0)  # 远超 worker 轮询间隔
        d1 = api.get(f"/api/v1/deliveries/{d1['id']}").json()
        check("暂停 2s 后投递仍 pending、零尝试、无租约（不产生新租约）",
              d1["status"] == "pending" and d1["attempts_made"] == 0
              and d1["leased_by"] is None,
              f"status={d1['status']} attempts={d1['attempts_made']} leased={d1['leased_by']}")
        check("暂停期间接收器未收到该事件",
              all(x["event_id"] != "pd-1"
                  for x in rcv.get("/received").json()["items"]))

        # ---- 2.3 暂停期间发布 rev2：pending 的 pd-1 仍钉 rev1 ----
        pub = api.post(f"/api/v1/subscriptions/{sid}/versions", json={
            "target_url": f"{h.rcv}/receive",
            "secret": "dev-signing-secret",
            "expected_revision": 1,
        })
        check("暂停期间发布新版本 201", pub.status_code == 201, pub.text)
        d1 = api.get(f"/api/v1/deliveries/{d1['id']}").json()
        check("暂停前/暂停中已建投递继续钉住 rev1（无损切换语义不变）",
              d1["config_revision"] == 1)

        # ---- 2.4 恢复：沿原 seq/尝试次数继续；暂停后的新事件用 rev2 ----
        rr = api.post(f"/api/v1/subscriptions/{sid}/resume")
        check("恢复返回 200 且 paused=false、paused_at=null",
              rr.status_code == 200 and rr.json()["paused"] is False
              and rr.json()["paused_at"] is None, rr.text)
        rr2 = api.post(f"/api/v1/subscriptions/{sid}/resume")
        check("重复恢复幂等", rr2.status_code == 200 and rr2.json()["paused"] is False)

        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{d1['id']}").json()["status"] == "succeeded",
            "恢复后原 pending 投递沿原 seq 续跑成功", timeout=15,
        )
        d1f = api.get(f"/api/v1/deliveries/{d1['id']}").json()
        check("pd-1 恢复后一次成功、仍为 rev1、尝试次数从 0 正常累计到 1",
              d1f["status"] == "succeeded" and d1f["config_revision"] == 1
              and d1f["attempts_made"] == 1)

        e2 = api.post("/api/v1/events", json={
            "source": "pause-demo", "event_id": "pd-2", "payload": {"n": 2},
        })
        d2 = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                         params={"source": "pause-demo"}).json()
                         if x["source_event_id"] == "pd-2"), None),
            "pd-2 投递创建",
        )
        wait_for(lambda: api.get(f"/api/v1/deliveries/{d2['id']}").json()["status"] == "succeeded",
                 "pd-2 成功", timeout=15)
        d2f = api.get(f"/api/v1/deliveries/{d2['id']}").json()
        check("恢复后新投递使用暂停期间发布的 rev2", d2f["config_revision"] == 2)

        # ---- 2.5 在途尝试：暂停前已认领的尝试照常结算（/slow 确定性）----
        slow_sub = api.post("/api/v1/subscriptions", json={
            "source": "slow-demo",
            "target_url": f"{h.rcv}/slow?seconds=4",
            "secret": "dev-signing-secret",
        }).json()
        ssid = slow_sub["id"]
        api.post("/api/v1/events", json={
            "source": "slow-demo", "event_id": "slow-1", "payload": {},
        })
        sd = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                         params={"source": "slow-demo"}).json()
                         if x["source_event_id"] == "slow-1"), None),
            "slow-1 投递创建",
        )
        # 等 Worker 认领（进入在途，请求飞行中），然后立即暂停。
        wait_for(lambda: api.get(f"/api/v1/deliveries/{sd['id']}").json()["status"] == "in_flight",
                 "slow-1 已被认领（在途）")
        pslow = api.post(f"/api/v1/subscriptions/{ssid}/pause")
        check("在途期间暂停成功", pslow.status_code == 200 and pslow.json()["paused"] is True)
        wait_for(lambda: api.get(f"/api/v1/deliveries/{sd['id']}").json()["status"] == "succeeded",
                 "暂停前已认领的在途尝试照常结算为成功", timeout=15)
        sdf = api.get(f"/api/v1/deliveries/{sd['id']}").json()
        check("在途尝试成功且只尝试 1 次（暂停不取消在途投递）",
              sdf["status"] == "succeeded" and sdf["attempts_made"] == 1)

        # ---- 2.6 not_before / attempts_made 跨暂停保留 + 严格顺序 ----
        flaky = api.post("/api/v1/subscriptions", json={
            "source": "retry-demo",
            "target_url": f"{h.rcv}/fail/1",
            "secret": "dev-signing-secret",
            "backoff_base_seconds": 1.0,
            "backoff_cap_seconds": 1.0,
        }).json()
        fsid = flaky["id"]
        api.post("/api/v1/events", json={
            "source": "retry-demo", "event_id": "rt-1", "payload": {},
        })
        api.post("/api/v1/events", json={
            "source": "retry-demo", "event_id": "rt-2", "payload": {},
        })
        rd1 = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                         params={"source": "retry-demo"}).json()
                         if x["source_event_id"] == "rt-1"), None),
            "rt-1 投递创建",
        )
        rd2 = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                         params={"source": "retry-demo"}).json()
                         if x["source_event_id"] == "rt-2"), None),
            "rt-2 投递创建",
        )
        wait_for(lambda: api.get(f"/api/v1/deliveries/{rd1['id']}").json()["attempts_made"] >= 1,
                 "rt-1 已失败 1 次")
        # 第一次失败后它回到 pending（not_before=未来 ~1s）；此刻暂停。
        api.post(f"/api/v1/subscriptions/{fsid}/pause").raise_for_status()
        time.sleep(2.5)  # 超过 not_before 但保持暂停
        rd1_paused = api.get(f"/api/v1/deliveries/{rd1['id']}").json()
        rd2_paused = api.get(f"/api/v1/deliveries/{rd2['id']}").json()
        check("暂停期间退避已到点也不重试（attempts_made 保留为 1）",
              rd1_paused["attempts_made"] == 1 and rd1_paused["status"] == "pending",
              f"attempts={rd1_paused['attempts_made']} status={rd1_paused['status']}")
        check("严格顺序：rt-2 在暂停期间仍未开始",
              rd2_paused["attempts_made"] == 0 and rd2_paused["status"] == "pending")
        api.post(f"/api/v1/subscriptions/{fsid}/resume").raise_for_status()
        wait_for(lambda: api.get(f"/api/v1/deliveries/{rd1['id']}").json()["status"] == "succeeded",
                 "恢复后 rt-1 沿原尝试次数（第 2 次）成功", timeout=15)
        rd1f = api.get(f"/api/v1/deliveries/{rd1['id']}").json()
        check("rt-1 总尝试恰好 2 次（暂停不重置 attempts_made/not_before）",
              rd1f["attempts_made"] == 2)
        wait_for(lambda: api.get(f"/api/v1/deliveries/{rd2['id']}").json()["status"] == "succeeded",
                 "恢复后 rt-2 按严格顺序随后成功", timeout=15)

        # ---- 2.7 暂停期间死信重放仍可建链记录，恢复后续跑 ----
        rcv.post("/control/fail", params={"enabled": True}).raise_for_status()
        dlsub = api.post("/api/v1/subscriptions", json={
            "source": "dl-demo",
            "target_url": f"{h.rcv}/fail",
            "secret": "dev-signing-secret",
            "max_attempts": 1,
            "backoff_base_seconds": 1.0,
            "backoff_cap_seconds": 1.0,
        }).json()
        dsid = dlsub["id"]
        api.post("/api/v1/events", json={
            "source": "dl-demo", "event_id": "dl-1", "payload": {},
        })
        dld = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                         params={"source": "dl-demo"}).json()
                         if x["source_event_id"] == "dl-1"), None),
            "dl-1 投递创建",
        )
        wait_for(lambda: api.get(f"/api/v1/deliveries/{dld['id']}").json()["status"] == "dead_lettered",
                 "dl-1 进入死信", timeout=20)
        api.post(f"/api/v1/subscriptions/{dsid}/pause").raise_for_status()
        rcv.post("/control/fail", params={"enabled": False}).raise_for_status()
        rp = api.post(f"/api/v1/dead-letters/{dld['id']}/replay")
        check("暂停期间死信重放仍 201（语义不变）", rp.status_code == 201, rp.text)
        new_id = rp.json()["new_delivery_id"]
        time.sleep(2.0)
        rp_paused = api.get(f"/api/v1/deliveries/{new_id}").json()
        check("暂停期间重放投递保持 pending、不被认领",
              rp_paused["status"] == "pending" and rp_paused["attempts_made"] == 0
              and rp_paused["chain_id"] == dld["chain_id"]
              and rp_paused["chain_seq"] == dld["chain_seq"] + 1)
        api.post(f"/api/v1/subscriptions/{dsid}/resume").raise_for_status()
        wait_for(lambda: api.get(f"/api/v1/deliveries/{new_id}").json()["status"] == "succeeded",
                 "恢复后重放投递成功", timeout=15)

    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append("异常退出")
    finally:
        h.stop()

    print()
    if failures:
        print(f"失败 {len(failures)} 项: {failures}")
        return 1
    print("暂停/恢复全部检查通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
