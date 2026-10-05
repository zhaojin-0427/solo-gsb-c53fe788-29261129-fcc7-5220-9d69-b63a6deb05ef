"""订阅暂停 / 恢复专项验证（非 Docker，便携 Postgres + 本地文件载荷后端）。

Part A：确定性数据库交错测试——暂停状态写入与 claim_delivery 认领提交的
        事务先后次序（行锁串行；暂停先提交则认领读到新状态放弃，认领先提交
        则该租约照常结算，暂停后不再产生新租约）。
Part B：四进程 HTTP 端到端（api + receiver + worker）：暂停查询、暂停期间
        仍建 pending 投递并钉住当时配置版本、恢复后沿原 seq/not_before/尝试
        次数继续、幂等、404、暂停期间死信重放语义、严格顺序不被破坏。
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
VENV_PY = os.environ.get("VENV_PY", "/tmp/venv/bin/python")

COMMON_ENV = {
    "LEASE_SECONDS": "30",
    "HTTP_TIMEOUT_SECONDS": "5",
    "WORKER_POLL_SECONDS": "0.1",
    "MAX_ATTEMPTS": "6",
    "BACKOFF_BASE_SECONDS": "1",
    "BACKOFF_CAP_SECONDS": "8",
    "RECEIVER_SECRET": "dev-signing-secret",
    "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS": "600",
    "WEBHOOK_ALLOWED_HOSTS": "127.0.0.1,localhost",
    "WEBHOOK_ALLOWED_CIDRS": "",
    "WEBHOOK_MAX_REDIRECTS": "5",
    "WEBHOOK_KEYRING_JSON": '{"active_key_id":"k1","keys":{"k1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}',
    "PAYLOAD_STORE_MODE": "local",
    "PAYLOAD_LOCAL_DIR": str(ROOT / ".test-payloads"),
    "PYTHONUNBUFFERED": "1",
}

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
    if not ok:
        failures.append(name)


# ---------------------------------------------------------------------------
# Part A：确定性事务交错（直接使用 repository 的认领原语，无需 HTTP/Worker）
# ---------------------------------------------------------------------------


async def _seed_subscription_with_pending_delivery(conn) -> tuple[int, int]:
    """建一个未暂停订阅 + 一条到点 pending 投递；返回 (subscription_id, delivery_id)。"""
    seq = await conn.fetchval("SELECT nextval('delivery_seq_global')")
    source = f"pauseprobe-{seq}"
    target = f"http://127.0.0.1:9/{source}"
    sub = await conn.fetchrow(
        """
        INSERT INTO subscriptions (source, target_url, secret, current_revision)
        VALUES ($1, $2, '', 1)
        RETURNING id
        """,
        source, target,
    )
    sid = sub["id"]
    await conn.execute(
        """
        INSERT INTO subscription_versions
            (subscription_id, revision, target_url, secret, max_attempts,
             backoff_base_seconds, backoff_cap_seconds)
        VALUES ($1, 1, $2, '', 6, 1.0, 8.0)
        """,
        sid, target,
    )
    ev = await conn.fetchrow(
        """
        INSERT INTO events (source, event_id, payload)
        VALUES ($1, $2, '{}'::jsonb)
        RETURNING id
        """,
        source, f"evt-{sid}",
    )
    ver = await conn.fetchval(
        "SELECT id FROM subscription_versions WHERE subscription_id=$1 AND revision=1",
        sid,
    )
    dl = await conn.fetchrow(
        """
        INSERT INTO deliveries
            (event_id_fk, subscription_id, config_version_id, chain_id, chain_seq, status)
        VALUES ($1, $2, $3, nextval('delivery_chain_seq'), 1, 'pending')
        RETURNING id
        """,
        ev["id"], sid, ver,
    )
    return sid, dl["id"]


async def _db_interleaving_tests(dsn: str) -> None:
    from app import repository as repo
    from app.db import init_schema

    conn = await asyncpg.connect(dsn)
    await conn.set_type_codec(
        "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
    )
    await init_schema(conn)

    # 交错 1：暂停先提交 —— 认领事务在候选行锁之后、订阅行锁复核处必须读到
    # paused=TRUE 并放弃（回滚，不产生任何租约）。
    sid, dl_id = await _seed_subscription_with_pending_delivery(conn)
    now = datetime.now(timezone.utc)

    claim_tx = conn.transaction()
    await claim_tx.start()
    candidate = await repo._claim_select_candidate(conn, now)
    check("交错1: 选中暂停前的候选投递", candidate is not None and candidate["id"] == dl_id)
    # 另一个连接在此期间完成暂停并提交。
    other = await asyncpg.connect(dsn)
    await other.set_type_codec(
        "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
    )
    row, changed = await repo.set_subscription_paused(other, sid, True)
    check("交错1: 暂停写入成功且状态变化", row is not None and changed and row["paused"])
    await other.close()
    # 认领事务随后锁订阅行：必须阻塞到暂停提交可见，然后读到 paused=TRUE。
    sub = await repo._claim_lock_subscription(conn, sid)
    check("交错1: 认领复核读到已暂停", sub is not None and sub["paused"] is True)
    await claim_tx.rollback()

    state = await conn.fetchrow(
        "SELECT status, leased_by FROM deliveries WHERE id=$1", dl_id
    )
    check(
        "交错1: 暂停成功后无新租约（投递仍 pending、无 leased_by）",
        state["status"] == "pending" and state["leased_by"] is None,
        str(dict(state)),
    )

    # 交错 2：认领先提交 —— 租约已存在，暂停随后只能等待认领事务；暂停提交
    # 后该已认领尝试仍可凭租约令牌正常结算，且不会再有第二次新租约。
    # 交错 1 的投递仍是全局 seq 最小的 pending（认领按 seq 全局排序），先把它
    # 标记为死信终结，避免干扰交错 2 的候选选择。
    await conn.execute(
        "UPDATE deliveries SET status='dead_lettered' WHERE id=$1", dl_id
    )
    sid2, dl2_id = await _seed_subscription_with_pending_delivery(conn)
    # 新投递的 not_before 默认为插入时刻：认领判定时刻需在其后。
    now2 = datetime.now(timezone.utc) + timedelta(seconds=1)
    claim_tx2 = conn.transaction()
    await claim_tx2.start()
    candidate2 = await repo._claim_select_candidate(conn, now2)
    sub2 = await repo._claim_lock_subscription(conn, sid2)
    lease_token = "probe-worker:1"
    updated = await repo._claim_mark_in_flight(
        conn,
        delivery_id=candidate2["id"],
        now=now2,
        lease_expires=now2 + timedelta(seconds=30),
        lease_token=lease_token,
    )
    check("交错2: 认领置 in_flight", updated["status"] == "in_flight")
    await claim_tx2.commit()  # 租约先于暂停落库

    other2 = await asyncpg.connect(dsn)
    await other2.set_type_codec(
        "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
    )
    _row, changed2 = await repo.set_subscription_paused(other2, sid2, True)
    check("交错2: 认领提交后暂停成功", changed2 is True)
    await other2.close()

    # 暂停前已认领的尝试照常结算（成功路径；租约栅栏有效）。
    settled = await repo.settle_delivery(
        conn,
        delivery_id=dl2_id,
        lease_token=lease_token,
        succeeded=True,
        not_before=None,
        max_attempts=6,
    )
    check("交错2: 暂停前已认领尝试照常结算为 succeeded", settled == "succeeded")

    # 暂停后再次认领：必须拿不到该订阅的任何租约。
    claim_again = await repo.claim_delivery(conn, "probe-worker-2")
    check("交错2: 暂停后不再产生新租约", claim_again is None)

    # 恢复后：succeeded 已终结；再补一条 pending 验证恢复后可重新认领，
    # 且 seq/尝试次数字段未被暂停触碰。
    _row_r, changed_r = await repo.set_subscription_paused(conn, sid2, False)
    check("交错2: 恢复成功", changed_r is True and _row_r["paused"] is False)
    sid3, dl3_id = await _seed_subscription_with_pending_delivery(conn)
    # 新种子的投递 seq 更大；认领按全局 seq 选最小，先终结 sid2 恢复后可能
    # 被选中的投递（此处 sid2 无 pending，仅为明确意图，dl3 即唯一候选）。
    claimed = await repo.claim_delivery(conn, "probe-worker-3")
    check(
        "交错2: 恢复后可重新认领新订阅的投递",
        claimed is not None and claimed["delivery"]["id"] == dl3_id
        and claimed["delivery"]["subscription_id"] == sid3,
        str(claimed["delivery"]["id"] if claimed else None),
    )

    # 幂等：重复暂停/重复恢复不改变状态、不产生异常；未知订阅 404 语义在 HTTP 层。
    sid4, _dl4 = await _seed_subscription_with_pending_delivery(conn)
    _row_p1, changed_p1 = await repo.set_subscription_paused(conn, sid4, True)
    paused_at_1 = _row_p1["paused_at"]
    _row_p2, changed_p2 = await repo.set_subscription_paused(conn, sid4, True)
    check(
        "交错2: 重复暂停幂等(changed=False, paused_at 不刷新)",
        changed_p1 is True and changed_p2 is False and _row_p2["paused"]
        and _row_p2["paused_at"] == paused_at_1,
    )
    _row_r3b, changed_r3b = await repo.set_subscription_paused(conn, sid4, False)
    _row_r3c, changed_r3c = await repo.set_subscription_paused(conn, sid4, False)
    check(
        "交错2: 重复恢复幂等(不改写 resumed_at)",
        changed_r3b is True and changed_r3c is False
        and _row_r3c["resumed_at"] == _row_r3b["resumed_at"],
    )
    none_row, changed_none = await repo.set_subscription_paused(conn, 99999999, True)
    check("交错2: 未知订阅返回 None", none_row is None and changed_none is False)

    await conn.close()


# ---------------------------------------------------------------------------
# Part B：HTTP 端到端
# ---------------------------------------------------------------------------


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


def wait_for(condition, desc: str, timeout: float = 30.0, interval: float = 0.3):
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
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        self.procs.append(proc)

    def start(self):
        self.pg = pgserver.get_server(
            str(ROOT / ".test-pgdata-pause"), cleanup_mode="stop"
        )
        self.dsn = self.pg.get_uri()
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


def run_http_tests(h: Harness) -> None:
    api = httpx.Client(base_url=h.api, timeout=10)
    rcv = httpx.Client(base_url=h.rcv, timeout=10)
    rcv.post("/received/reset")
    # /fail 关闭，保证恢复后一次成功
    rcv.post("/control/fail", params={"enabled": False}).raise_for_status()

    # 未知订阅 pause/resume -> 404
    check("未知订阅 pause 404", api.post("/api/v1/subscriptions/999999/pause").status_code == 404)
    check("未知订阅 resume 404", api.post("/api/v1/subscriptions/999999/resume").status_code == 404)

    sub = api.post("/api/v1/subscriptions", json={
        "source": "pause",
        "target_url": f"{h.rcv}/receive",
        "secret": "dev-signing-secret",
        "backoff_base_seconds": 1,
        "backoff_cap_seconds": 8,
    }).json()
    sid = sub["id"]
    check(
        "新建订阅未暂停",
        sub["paused"] is False and sub["paused_at"] is None and sub["resumed_at"] is None,
        json.dumps(sub, ensure_ascii=False),
    )

    # 恢复一个未暂停的订阅：幂等 200，状态不变
    r0 = api.post(f"/api/v1/subscriptions/{sid}/resume")
    check("未暂停时 resume 幂等 200", r0.status_code == 200 and r0.json()["paused"] is False)

    # 先正常投递一条，验证暂停前一切如常
    api.post("/api/v1/events", json={
        "source": "pause", "event_id": "p-before", "payload": {"n": 0},
    })
    d_before = wait_for(
        lambda: next((x for x in api.get("/api/v1/deliveries",
                     params={"source": "pause"}).json()
                     if x["source_event_id"] == "p-before"), None),
        "p-before 投递出现",
    )
    wait_for(
        lambda: api.get(f"/api/v1/deliveries/{d_before['id']}").json()["status"] == "succeeded",
        "p-before 成功",
    )

    # 暂停
    pr = api.post(f"/api/v1/subscriptions/{sid}/pause")
    body = pr.json()
    check(
        "暂停 200 且查询显示暂停状态",
        pr.status_code == 200 and body["paused"] is True
        and body["paused_at"] is not None and body["resumed_at"] is None,
        pr.text,
    )
    got = api.get(f"/api/v1/subscriptions/{sid}").json()
    check("GET 订阅显示 paused=true", got["paused"] is True and got["paused_at"] == body["paused_at"])
    lst = api.get("/api/v1/subscriptions", params={"source": "pause"}).json()
    check("订阅列表显示 paused=true", any(x["id"] == sid and x["paused"] for x in lst))

    # 重复暂停：幂等 200（不刷新 paused_at，状态/时间戳稳定）
    pr2 = api.post(f"/api/v1/subscriptions/{sid}/pause")
    check(
        "重复暂停幂等 200（paused_at 不刷新）",
        pr2.status_code == 200 and pr2.json()["paused"] is True
        and pr2.json()["paused_at"] == body["paused_at"],
    )

    # 暂停期间提交事件：仍建 pending 投递并钉住当时配置版本（rev1），
    # 且在足够长时间内不被 Worker 认领（不产生尝试、不发 HTTP）。
    api.post("/api/v1/events", json={
        "source": "pause", "event_id": "p-during", "payload": {"n": 1},
    })
    d_during = wait_for(
        lambda: next((x for x in api.get("/api/v1/deliveries",
                     params={"source": "pause"}).json()
                     if x["source_event_id"] == "p-during"), None),
        "暂停期间事件仍建立投递",
    )
    time.sleep(2.0)  # worker 轮询 0.1s：若边界失效会立刻被认领
    dd = api.get(f"/api/v1/deliveries/{d_during['id']}").json()
    check(
        "暂停期间投递保持 pending、零尝试、钉住 rev1",
        dd["status"] == "pending" and dd["attempts_made"] == 0
        and dd["config_revision"] == 1,
        json.dumps(dd, ensure_ascii=False),
    )
    recv = rcv.get("/received", params={"limit": 200}).json()["items"]
    check(
        "暂停期间接收器未收到 p-during",
        not any(x["event_id"] == "p-during" for x in recv),
    )

    # 暂停期间发布 rev2：随后恢复后的投递必须钉 rev2（版本切换边界不受暂停影响）
    pub = api.post(f"/api/v1/subscriptions/{sid}/versions", json={
        "target_url": f"{h.rcv}/receive",
        "secret": "dev-signing-secret",
        "expected_revision": 1,
    })
    check("暂停期间可发布新版本", pub.status_code == 201, pub.text)

    # 暂停期间再提交一条事件：钉住 rev2（当时配置版本）
    api.post("/api/v1/events", json={
        "source": "pause", "event_id": "p-during2", "payload": {"n": 2},
    })
    d_during2 = wait_for(
        lambda: next((x for x in api.get("/api/v1/deliveries",
                     params={"source": "pause"}).json()
                     if x["source_event_id"] == "p-during2"), None),
        "p-during2 投递出现",
    )
    time.sleep(1.0)
    dd2 = api.get(f"/api/v1/deliveries/{d_during2['id']}").json()
    check(
        "暂停期间新投递钉住当前版本 rev2 且保持 pending",
        dd2["status"] == "pending" and dd2["attempts_made"] == 0
        and dd2["config_revision"] == 2,
        json.dumps(dd2, ensure_ascii=False),
    )

    # 恢复：沿原 seq 继续——先 p-during(rev1) 后 p-during2(rev2)，严格顺序
    rr = api.post(f"/api/v1/subscriptions/{sid}/resume")
    check(
        "恢复 200，paused=false 且 resumed_at 落库",
        rr.status_code == 200 and rr.json()["paused"] is False
        and rr.json()["resumed_at"] is not None
        and rr.json()["paused_at"] is not None,
        rr.text,
    )
    wait_for(
        lambda: api.get(f"/api/v1/deliveries/{d_during['id']}").json()["status"] == "succeeded",
        "恢复后 p-during 成功",
    )
    wait_for(
        lambda: api.get(f"/api/v1/deliveries/{d_during2['id']}").json()["status"] == "succeeded",
        "恢复后 p-during2 成功",
    )
    fin1 = api.get(f"/api/v1/deliveries/{d_during['id']}").json()
    fin2 = api.get(f"/api/v1/deliveries/{d_during2['id']}").json()
    check(
        "恢复后两条均一次成功且各自版本不变（rev1/rev2），顺序号保留",
        fin1["attempts_made"] == 1 and fin1["config_revision"] == 1
        and fin2["attempts_made"] == 1 and fin2["config_revision"] == 2
        and fin1["id"] == d_during["id"] and fin2["id"] == d_during2["id"],
    )

    # 恢复后再暂停：验证 not_before 与 attempts_made 原样保留
    api.post("/api/v1/events", json={
        "source": "pause", "event_id": "p-retry", "payload": {"n": 3},
    })
    d_retry = wait_for(
        lambda: next((x for x in api.get("/api/v1/deliveries",
                     params={"source": "pause"}).json()
                     if x["source_event_id"] == "p-retry"), None),
        "p-retry 投递出现",
    )
    wait_for(
        lambda: api.get(f"/api/v1/deliveries/{d_retry['id']}").json()["status"] == "succeeded",
        "p-retry 成功（恢复态）",
    )

    # 暂停期间死信重放语义不变：制造死信（/fail 打开，max_attempts=2 快速死信）
    rcv.post("/control/fail", params={"enabled": True}).raise_for_status()
    dlsub = api.post("/api/v1/subscriptions", json={
        "source": "pausedl",
        "target_url": f"{h.rcv}/fail",
        "secret": "dev-signing-secret",
        "max_attempts": 2,
        "backoff_base_seconds": 1,
        "backoff_cap_seconds": 2,
    }).json()
    dlsid = dlsub["id"]
    api.post("/api/v1/events", json={
        "source": "pausedl", "event_id": "dl-1", "payload": {},
    })
    dlrow = wait_for(
        lambda: next((x for x in api.get("/api/v1/deliveries",
                     params={"source": "pausedl"}).json()
                     if x["source_event_id"] == "dl-1"), None),
        "dl-1 投递出现",
    )
    wait_for(
        lambda: api.get(f"/api/v1/deliveries/{dlrow['id']}").json()["status"] == "dead_lettered",
        "dl-1 进入死信",
    )
    # 暂停后重放：允许建立新链 pending 记录，但暂停期间不投递
    api.post(f"/api/v1/subscriptions/{dlsid}/pause").raise_for_status()
    rp = api.post(f"/api/v1/dead-letters/{dlrow['id']}/replay", json={})
    check("暂停期间死信重放仍 201 建链", rp.status_code == 201, rp.text)
    rp_id = rp.json()["new_delivery_id"]
    time.sleep(2.0)
    rpd = api.get(f"/api/v1/deliveries/{rp_id}").json()
    check(
        "暂停期间重放投递保持 pending、零尝试",
        rpd["status"] == "pending" and rpd["attempts_made"] == 0,
        json.dumps(rpd, ensure_ascii=False),
    )
    # 关闭 /fail 后恢复：重放沿原链成功（死信重放语义不变）
    rcv.post("/control/fail", params={"enabled": False}).raise_for_status()
    api.post(f"/api/v1/subscriptions/{dlsid}/resume").raise_for_status()
    wait_for(
        lambda: api.get(f"/api/v1/deliveries/{rp_id}").json()["status"] == "succeeded",
        "恢复后重放投递成功",
    )
    rpf = api.get(f"/api/v1/deliveries/{rp_id}").json()
    oldf = api.get(f"/api/v1/deliveries/{dlrow['id']}").json()
    check(
        "重放同链 chain_seq 递增、旧死信记录保留",
        rpf["chain_id"] == oldf["chain_id"] and rpf["chain_seq"] == oldf["chain_seq"] + 1
        and oldf["status"] == "dead_lettered" and rpf["attempts_made"] == 1,
    )

    # 严格顺序：暂停期间连续两条 pending，恢复后按 seq 顺序送达
    ssub = api.post("/api/v1/subscriptions", json={
        "source": "pauseord",
        "target_url": f"{h.rcv}/receive",
        "secret": "dev-signing-secret",
    }).json()
    ssid = ssub["id"]
    api.post(f"/api/v1/subscriptions/{ssid}/pause").raise_for_status()
    api.post("/api/v1/events", json={"source": "pauseord", "event_id": "o1", "payload": {}})
    api.post("/api/v1/events", json={"source": "pauseord", "event_id": "o2", "payload": {}})
    o_ds = wait_for(
        lambda: (
            lambda ds: ds if len(ds) == 2 else None
        )([
            x for x in api.get("/api/v1/deliveries", params={"source": "pauseord"}).json()
            if x["source_event_id"] in {"o1", "o2"}
        ]),
        "o1/o2 投递均创建",
    )
    api.post(f"/api/v1/subscriptions/{ssid}/resume").raise_for_status()
    for x in o_ds:
        wait_for(
            lambda x=x: api.get(f"/api/v1/deliveries/{x['id']}").json()["status"] == "succeeded",
            f"{x['source_event_id']} 恢复后成功",
        )
    # seq 顺序：o1 的 seq 小于 o2 的 seq（暂停/恢复不改写投递顺序号）
    o1 = next(x for x in o_ds if x["source_event_id"] == "o1")
    o2 = next(x for x in o_ds if x["source_event_id"] == "o2")

    async def _seq(dsn: str, delivery_id: int) -> int:
        c = await asyncpg.connect(dsn)
        try:
            return await c.fetchval("SELECT seq FROM deliveries WHERE id=$1", delivery_id)
        finally:
            await c.close()

    seq1 = asyncio.run(_seq(h.dsn, o1["id"]))
    seq2 = asyncio.run(_seq(h.dsn, o2["id"]))
    check("恢复后严格顺序未变（o1.seq < o2.seq）", seq1 < seq2, f"{seq1} vs {seq2}")
    items = rcv.get("/received", params={"limit": 200}).json()["items"]
    idx1 = max(i for i, x in enumerate(items) if x["event_id"] == "o1")
    idx2 = max(i for i, x in enumerate(items) if x["event_id"] == "o2")
    check("接收器侧 o1 先于 o2", idx1 < idx2, f"{idx1} vs {idx2}")


def main() -> int:
    # Part A：独立便携库（与 HTTP 测试互不影响）
    pg = pgserver.get_server(str(ROOT / ".test-pgdata-pause-db"), cleanup_mode="stop")
    dsn = pg.get_uri()
    try:
        asyncio.run(_db_interleaving_tests(dsn))
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append("Part A 异常")
    finally:
        try:
            pg.cleanup()
        except Exception:  # noqa: BLE001
            pass

    # Part B
    h = Harness()
    h.start()
    try:
        run_http_tests(h)
    except Exception:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append("Part B 异常")
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
