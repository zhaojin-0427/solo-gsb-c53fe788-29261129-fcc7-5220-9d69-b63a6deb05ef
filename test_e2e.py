"""端到端验证脚本（非 Docker 环境使用）：启动便携 Postgres、API、Receiver、
两个 Worker，覆盖：
1. 事件幂等（重复提交返回原事件且不新增投递）
2. 成功投递 + HMAC 校验
3. 严格顺序（失败阻塞时后一事件不被发送）
4. 6 次尝试后死信（指数退避）
5. 死信重放生成新链记录、旧记录保留
6. 租约超时接管
7. 配置版本 CAS 发布、无损切换、按钉住版本的重试参数结算与死信重放版本选择
8. 出站目标安全策略：入口 422（scheme/userinfo/元数据/私网）、
   Worker security_blocked 失败按退避/死信结算、重定向逐跳校验
"""
from __future__ import annotations

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

# 用极短退避加速测试：1s, 2s, 4s, 8s, 8s(cap)
COMMON_ENV = {
    "LEASE_SECONDS": "3",
    "HTTP_TIMEOUT_SECONDS": "2",
    "WORKER_POLL_SECONDS": "0.2",
    "MAX_ATTEMPTS": "6",
    "BACKOFF_BASE_SECONDS": "1",
    "BACKOFF_CAP_SECONDS": "8",
    "RECEIVER_SECRET": "dev-signing-secret",
    "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS": "600",
    # 出站安全策略：本地联调目标为 127.0.0.1（回环），显式加入精确主机白名单
    "WEBHOOK_ALLOWED_HOSTS": "127.0.0.1,localhost",
    "WEBHOOK_ALLOWED_CIDRS": "",
    "WEBHOOK_MAX_REDIRECTS": "5",
    # 订阅密钥信封加密的本地密钥环（测试主密钥）
    "WEBHOOK_KEYRING_JSON": '{"active_key_id":"k1","keys":{"k1":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}',
    # 事件载荷对象存储：测试用本地文件后端（无需 MinIO）
    "PAYLOAD_STORE_MODE": "local",
    "PAYLOAD_LOCAL_DIR": str(ROOT / ".test-payloads"),
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


def wait_for(condition, desc: str, timeout: float = 60.0, interval: float = 0.5):
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

    def spawn(self, module_cmd: list[str], port: int | None, name: str, extra_env: dict | None = None):
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        if extra_env:
            env.update(extra_env)
        log = open(ROOT / f"test-{name}.log", "w")
        proc = subprocess.Popen(
            [VENV_PY, "-m", *module_cmd],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        proc.name = name  # type: ignore[attr-defined]
        self.procs.append(proc)
        return proc

    def start(self):
        self.pg = pgserver.get_server(
            str(ROOT / ".test-pgdata"), cleanup_mode="stop"
        )
        self.dsn = self.pg.get_uri()
        print("Postgres DSN:", self.dsn)

        api_port = free_port()
        rcv_port = free_port()
        self.api = f"http://127.0.0.1:{api_port}"
        self.rcv = f"http://127.0.0.1:{rcv_port}"

        self.spawn(
            ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
            api_port, "api",
        )
        self.spawn(
            ["uvicorn", "app.receiver:app", "--host", "127.0.0.1", "--port", str(rcv_port)],
            rcv_port, "receiver",
        )
        self.spawn(["app.worker"], None, "worker1")
        self.spawn(["app.worker"], None, "worker2")
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


def main() -> int:
    h = Harness()
    h.start()
    failures = []

    def check(name: str, ok: bool, detail: str = ""):
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    try:
        api = httpx.Client(base_url=h.api, timeout=5)
        rcv = httpx.Client(base_url=h.rcv, timeout=10)

        rcv.post("/received/reset")

        # 1) 幂等：先建订阅，再重复提交同一事件
        sub = api.post("/api/v1/subscriptions", json={
            "source": "orders",
            "target_url": f"{h.rcv}/receive",
            "secret": "dev-signing-secret",
        }).json()
        check("创建订阅", sub["active"] is True, json.dumps(sub, ensure_ascii=False))

        ev1 = api.post("/api/v1/events", json={
            "source": "orders", "event_id": "evt-1", "payload": {"n": 1},
        })
        check("首次提交事件 201", ev1.status_code == 201 and ev1.json()["duplicate"] is False)
        ev1b = api.post("/api/v1/events", json={
            "source": "orders", "event_id": "evt-1", "payload": {"n": 999},
        })
        check("重复提交 200 + duplicate", ev1b.status_code == 200 and ev1b.json()["duplicate"] is True)
        check(
            "重复提交返回原事件且不覆盖 payload",
            ev1b.json()["payload"] == {"n": 1} and ev1b.json()["id"] == ev1.json()["id"],
        )

        # 2) 成功投递
        d = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                        params={"source": "orders"}).json()
                         if x["source_event_id"] == "evt-1"), None),
            "evt-1 投递出现",
        )
        wait_for(lambda: api.get(f"/api/v1/deliveries/{d['id']}").json()["status"] == "succeeded",
                 "evt-1 投递成功")
        d = api.get(f"/api/v1/deliveries/{d['id']}").json()
        check("evt-1 一次成功", d["attempts_made"] == 1 and d["status"] == "succeeded")

        recv_items = rcv.get("/received").json()["items"]
        evt1_rec = next(x for x in recv_items if x["event_id"] == "evt-1")
        check("Receiver 校验签名通过", evt1_rec["signature_valid"] is True, evt1_rec["signature_message"])

        # 3) 严格顺序：/block 对 evt-seq-1 始终 500；evt-seq-2 不能在其终结前发出
        api.post("/api/v1/subscriptions", json={
            "source": "seq",
            "target_url": f"{h.rcv}/fail",
            "secret": "dev-signing-secret",
        })
        r1 = api.post("/api/v1/events", json={
            "source": "seq", "event_id": "seq-1", "payload": {},
        }).json()
        r2 = api.post("/api/v1/events", json={
            "source": "seq", "event_id": "seq-2", "payload": {},
        }).json()

        def deliveries_of(event_pk):
            return api.get(f"/api/v1/events/{event_pk}/deliveries").json()

        def dl1_dl2():
            dl1 = deliveries_of(r1["id"])
            dl2 = deliveries_of(r2["id"])
            return (dl1[0] if dl1 else None), (dl2[0] if dl2 else None)

        dl1, dl2 = wait_for(lambda: dl1_dl2() if all(dl1_dl2()) else None, "两条投递均创建")

        # 等 dl1 出现多次尝试（说明它在反复失败），期间 dl2 必须保持 pending/0 次
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl1['id']}").json()["attempts_made"] >= 2,
            "seq-1 已失败 >=2 次", timeout=30,
        )
        dl2_now = api.get(f"/api/v1/deliveries/{dl2['id']}").json()
        check(
            "严格顺序：前序未终结时后序不发送",
            dl2_now["attempts_made"] == 0 and dl2_now["status"] == "pending",
            f"seq-2 status={dl2_now['status']} attempts={dl2_now['attempts_made']}",
        )

        # 4) 6 次尝试后死信（1,2,4,8,8 退避 ≈ 23s）
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl1['id']}").json()["status"] == "dead_lettered",
            "seq-1 进入死信", timeout=90,
        )
        dl1_final = api.get(f"/api/v1/deliveries/{dl1['id']}").json()
        check("死信恰好 6 次尝试", dl1_final["attempts_made"] == 6)
        attempts = api.get(f"/api/v1/deliveries/{dl1['id']}/attempts").json()
        check("历史含 6 条尝试记录", len(attempts) == 6 and attempts[0]["attempt_number"] == 1)

        # 前序进入死信后，seq-2 才开始处理并同样最终进死信
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl2['id']}").json()["attempts_made"] >= 1,
            "前序死信后 seq-2 才开始", timeout=10,
        )
        check("严格顺序：前序死信后后序才开始", True)

        # 5) 死信列表 + 重放（关闭 /fail 后重放成功，生成新链记录）
        dls = api.get("/api/v1/dead-letters", params={"source": "seq"}).json()
        check("死信列表可查", any(x["id"] == dl1["id"] for x in dls))

        bad = api.post(f"/api/v1/dead-letters/{d['id']}/replay")
        check("非死信重放返回 409", bad.status_code == 409)

        ctl = rcv.post("/control/fail", params={"enabled": False})
        ctl.raise_for_status()
        replay = api.post(f"/api/v1/dead-letters/{dl1['id']}/replay")
        check("重放返回 201", replay.status_code == 201, replay.text)
        new_id = replay.json()["new_delivery_id"]
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{new_id}").json()["status"] == "succeeded",
            "重放投递成功", timeout=20,
        )
        old = api.get(f"/api/v1/deliveries/{dl1['id']}").json()
        new = api.get(f"/api/v1/deliveries/{new_id}").json()
        check("重放为同链新记录(chain_seq+1)且旧记录保留",
              old["status"] == "dead_lettered"
              and new["chain_id"] == old["chain_id"]
              and new["chain_seq"] == old["chain_seq"] + 1
              and new["attempts_made"] == 1)

        # 链忙时重复重放 -> 409（先制造一个死信：seq-2 此刻可能仍在失败；
        # 用它在 pending 窗口小概率，改做直接规则校验：对成功的新记录重放 -> 409）
        again = api.post(f"/api/v1/dead-letters/{new_id}/replay")
        check("重放非死信记录返回 409", again.status_code == 409)

        # 6) 租约接管：模拟宕机 Worker——直接写入一条 in_flight 且租约已过期的投递。
        # 存活 Worker 应在 lease 过期后接管并完成投递。
        import asyncio

        import asyncpg

        async def seed_stale_lease():
            conn = await asyncpg.connect(h.dsn)
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            ev = await conn.fetchrow(
                """
                INSERT INTO events (source, event_id, payload)
                VALUES ('lease', 'lease-1', '{}'::jsonb)
                RETURNING id
                """
            )
            sub = await conn.fetchrow(
                """
                INSERT INTO subscriptions (source, target_url, secret, current_revision)
                VALUES ('lease', $1, 'dev-signing-secret', 1)
                ON CONFLICT (source, target_url) DO UPDATE SET active = TRUE
                RETURNING id
                """,
                f"{h.rcv}/receive",
            )
            ver = await conn.fetchrow(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret,
                     max_attempts, backoff_base_seconds, backoff_cap_seconds)
                SELECT $1, 1, target_url, secret, 6, 1.0, 8.0
                FROM subscriptions WHERE id = $1
                ON CONFLICT (subscription_id, revision) DO NOTHING
                RETURNING id
                """,
                sub["id"],
            )
            if ver is None:
                ver = await conn.fetchrow(
                    "SELECT id FROM subscription_versions WHERE subscription_id=$1 AND revision=1",
                    sub["id"],
                )
            row = await conn.fetchrow(
                """
                INSERT INTO deliveries
                    (event_id_fk, subscription_id, config_version_id, chain_id, chain_seq,
                     status, attempts_made, not_before,
                     leased_at, lease_expires_at, leased_by)
                VALUES ($1, $2, $3, nextval('delivery_chain_seq'), 1,
                        'in_flight', 0, now() - interval '1 hour',
                        now() - interval '1 minute',
                        now() - interval '57 seconds',
                        'dead-worker')
                RETURNING id
                """,
                ev["id"],
                sub["id"],
                ver["id"],
            )
            await conn.close()
            return ev["id"], row["id"]

        lease_event, dl_lease = asyncio.run(seed_stale_lease())
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl_lease}").json()["status"] == "succeeded",
            "过期租约被接管并成功", timeout=30,
        )
        lease_d = api.get(f"/api/v1/deliveries/{dl_lease}").json()
        lease_attempts = api.get(f"/api/v1/deliveries/{dl_lease}/attempts").json()
        check("租约超时后被存活 Worker 接管",
              lease_d["status"] == "succeeded"
              and lease_attempts
              and lease_attempts[0]["worker_id"] != "dead-worker",
              f"worker={lease_attempts[0]['worker_id'] if lease_attempts else None}")

        # 7) 订阅配置版本与无损切换
        # 7.1 初始订阅 revision=1，携带按订阅的重试参数
        versub = api.post("/api/v1/subscriptions", json={
            "source": "ver",
            "target_url": f"{h.rcv}/fail/2",
            "secret": "dev-signing-secret",
            "max_attempts": 3,
            "backoff_base_seconds": 1,
            "backoff_cap_seconds": 2,
        }).json()
        sid = versub["id"]
        check("新订阅 current_revision=1", versub["current_revision"] == 1)
        vlist = api.get(f"/api/v1/subscriptions/{sid}/versions").json()
        check(
            "版本列表初始 1 条且无密钥泄露",
            len(vlist) == 1
            and vlist[0]["revision"] == 1
            and vlist[0]["is_current"] is True
            and vlist[0]["max_attempts"] == 3
            and "secret" not in vlist[0],
        )

        # 7.2 边界前创建的投递钉在 revision 1（/fail/2：前两次失败后成功）
        api.post("/api/v1/events", json={
            "source": "ver", "event_id": "ver-old", "payload": {},
        })
        old_delivery = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                        params={"source": "ver"}).json()
                         if x["source_event_id"] == "ver-old"), None),
            "ver-old 投递创建",
        )
        check("边界前投递钉在 revision 1", old_delivery["config_revision"] == 1)
        # 等它失败一次（证明此刻还在用旧版本 URL /fail/2），再发布 rev2
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{old_delivery['id']}").json()["attempts_made"] >= 1,
            "ver-old 已按旧版本失败 >=1 次", timeout=20,
        )

        # 7.3 CAS：错误的 expected_revision 必须 409
        bad_cas = api.post(f"/api/v1/subscriptions/{sid}/versions", json={
            "target_url": f"{h.rcv}/receive",
            "secret": "dev-signing-secret",
            "expected_revision": 99,
        })
        check("CAS expected_revision 不匹配返回 409", bad_cas.status_code == 409)

        # 7.4 并发发布：携带相同 expected_revision，只能有一个成功
        import concurrent.futures

        def publish(rev):
            return httpx.post(
                f"{h.api}/api/v1/subscriptions/{sid}/versions",
                json={
                    "target_url": f"{h.rcv}/receive",
                    "secret": "dev-signing-secret",
                    "expected_revision": rev,
                },
                timeout=10,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(publish, 1), ex.submit(publish, 1)]
            codes = sorted(f.result().status_code for f in futs)
        check("并发发布只有一个成功", codes == [201, 409], str(codes))

        vlist = api.get(f"/api/v1/subscriptions/{sid}/versions").json()
        check(
            "发布后 rev2 为当前、rev1 有切换边界 superseded_at",
            [v["revision"] for v in vlist] == [1, 2]
            and vlist[1]["is_current"] is True
            and vlist[1]["target_url"].endswith("/receive")
            and vlist[0]["superseded_at"] is not None
            and vlist[1]["superseded_at"] is None,
        )
        check(
            "重试参数缺省继承当前版本",
            vlist[1]["max_attempts"] == 3
            and vlist[1]["backoff_base_seconds"] == 1.0
            and vlist[1]["backoff_cap_seconds"] == 2.0,
        )

        # 7.5 边界前的投递重试始终使用旧版本：最终经 /fail/2 成功，且 revision 仍为 1
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{old_delivery['id']}").json()["status"] == "succeeded",
            "旧投递按旧版本重试成功", timeout=30,
        )
        old_final = api.get(f"/api/v1/deliveries/{old_delivery['id']}").json()
        check(
            "边界前投递重试不改版本（仍 rev1，走 /fail/2）",
            old_final["config_revision"] == 1
            and old_final["target_url"].endswith("/fail/2"),
        )

        # 7.6 边界后的投递使用新版本（rev2，/receive）
        api.post("/api/v1/events", json={
            "source": "ver", "event_id": "ver-new", "payload": {},
        })
        new_delivery = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                        params={"source": "ver"}).json()
                         if x["source_event_id"] == "ver-new"), None),
            "ver-new 投递创建",
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{new_delivery['id']}").json()["status"] == "succeeded",
            "边界后投递成功", timeout=15,
        )
        new_final = api.get(f"/api/v1/deliveries/{new_delivery['id']}").json()
        check(
            "边界后投递使用 rev2 与新 URL，一次成功",
            new_final["config_revision"] == 2
            and new_final["target_url"].endswith("/receive")
            and new_final["attempts_made"] == 1,
        )

        # 7.7 按钉住版本的 max_attempts 结算 + 死信重放版本选择
        # 步骤 5 曾关闭 /fail；这里重新打开以制造死信
        rcv.post("/control/fail", params={"enabled": True}).raise_for_status()
        dlsub = api.post("/api/v1/subscriptions", json={
            "source": "verdl",
            "target_url": f"{h.rcv}/fail",
            "secret": "dev-signing-secret",
            "max_attempts": 2,
            "backoff_base_seconds": 1,
            "backoff_cap_seconds": 2,
        }).json()
        dlsid = dlsub["id"]
        api.post("/api/v1/events", json={
            "source": "verdl", "event_id": "ver-dl-1", "payload": {},
        })
        dl_old = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                        params={"source": "verdl"}).json()
                         if x["source_event_id"] == "ver-dl-1"), None),
            "ver-dl-1 投递创建",
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl_old['id']}").json()["status"] == "dead_lettered",
            "旧版本 max_attempts=2 -> 死信", timeout=30,
        )
        dl_old = api.get(f"/api/v1/deliveries/{dl_old['id']}").json()
        check(
            "投递按其版本 max_attempts=2 进死信（非全局 6）",
            dl_old["attempts_made"] == 2 and dl_old["config_revision"] == 1,
        )

        # 发布 rev2：改到 /receive（始终 200）
        pub2 = api.post(f"/api/v1/subscriptions/{dlsid}/versions", json={
            "target_url": f"{h.rcv}/receive",
            "secret": "dev-signing-secret",
            "expected_revision": 1,
        })
        check("verdl 发布 rev2 成功", pub2.status_code == 201, pub2.text)

        # 默认重放沿用原版本 rev1：关闭 /fail 使其成功，但记录仍钉 rev1
        rcv.post("/control/fail", params={"enabled": False}).raise_for_status()
        rp1 = api.post(f"/api/v1/dead-letters/{dl_old['id']}/replay", json={})
        check("默认重放 201", rp1.status_code == 201, rp1.text)
        rp1_id = rp1.json()["new_delivery_id"]
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{rp1_id}").json()["status"] == "succeeded",
            "重放(旧版本)成功", timeout=15,
        )
        rp1_d = api.get(f"/api/v1/deliveries/{rp1_id}").json()
        check(
            "默认重放沿用原版本 rev1 且同链 chain_seq 递增",
            rp1.json()["config_revision"] == 1
            and rp1_d["config_revision"] == 1
            and rp1_d["chain_id"] == dl_old["chain_id"]
            and rp1_d["chain_seq"] == dl_old["chain_seq"] + 1,
        )

        # 显式当前版本重放：use_current_version=true -> rev2
        rp2 = api.post(
            f"/api/v1/dead-letters/{dl_old['id']}/replay",
            json={"use_current_version": True},
        )
        check("当前版本重放 201", rp2.status_code == 201, rp2.text)
        rp2_id = rp2.json()["new_delivery_id"]
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{rp2_id}").json()["status"] == "succeeded",
            "重放(当前版本)成功", timeout=15,
        )
        rp2_d = api.get(f"/api/v1/deliveries/{rp2_id}").json()
        check(
            "显式当前版本重放钉在 rev2 与新 URL，且 chain_seq 继续递增",
            rp2.json()["config_revision"] == 2
            and rp2_d["config_revision"] == 2
            and rp2_d["target_url"].endswith("/receive")
            and rp2_d["chain_seq"] == rp1_d["chain_seq"] + 1,
        )

        # 8) 出站目标安全策略（SSRF 防护）
        # 8.1 入口校验：创建订阅时拒绝非法 scheme / userinfo / 云元数据 / 私网
        def expect_422_policy(payload, expected_code):
            r = api.post("/api/v1/subscriptions", json=payload)
            ok = (
                r.status_code == 422
                and isinstance(r.json().get("detail"), dict)
                and r.json()["detail"].get("code") == expected_code
            )
            return ok, r.status_code, r.text

        ok, code, text = expect_422_policy(
            {"source": "ssrf1", "target_url": "ftp://example.com/x",
             "secret": "dev-signing-secret"}, "invalid_scheme")
        check("入口拒绝非 http/https", ok, f"{code} {text}")

        ok, code, text = expect_422_policy(
            {"source": "ssrf2", "target_url": "http://user:pass@example.com/x",
             "secret": "dev-signing-secret"}, "userinfo_forbidden")
        check("入口拒绝带用户信息的 URL", ok, f"{code} {text}")

        ok, code, text = expect_422_policy(
            {"source": "ssrf3", "target_url": "http://169.254.169.254/latest/meta-data/",
             "secret": "dev-signing-secret"}, "blocked_address")
        check("入口拒绝云元数据地址", ok, f"{code} {text}")

        ok, code, text = expect_422_policy(
            {"source": "ssrf4", "target_url": "http://10.0.0.5/x",
             "secret": "dev-signing-secret"}, "blocked_address")
        check("入口拒绝私网地址", ok, f"{code} {text}")

        ok, code, text = expect_422_policy(
            {"source": "ssrf5", "target_url": "http://[::1]/x",
             "secret": "dev-signing-secret"}, "blocked_address")
        check("入口拒绝 IPv6 回环", ok, f"{code} {text}")

        # 8.2 发布配置版本时同样执行入口校验（CAS 之前，422 优先）
        r = api.post(f"/api/v1/subscriptions/{sid}/versions", json={
            "target_url": "http://169.254.169.254/x",
            "secret": "dev-signing-secret",
            "expected_revision": 2,
        })
        check("发布版本拒绝云元数据 URL（422，不落入 CAS）",
              r.status_code == 422
              and r.json()["detail"]["code"] == "blocked_address",
              f"{r.status_code} {r.text}")

        # 8.3 Worker 投递期阻止：直接写入一条钉到云元数据 IP 的投递链。
        # 既无法创建订阅（入口拒绝），也必须在 Worker 每次尝试时被阻止，
        # 记录为 security_blocked，并按现有退避/死信语义结算。
        import asyncio

        import asyncpg

        async def seed_blocked_delivery():
            conn = await asyncpg.connect(h.dsn)
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            ev = await conn.fetchrow(
                """
                INSERT INTO events (source, event_id, payload)
                VALUES ('ssrfw', 'ssrfw-1', '{}'::jsonb)
                RETURNING id
                """
            )
            sub = await conn.fetchrow(
                """
                INSERT INTO subscriptions (source, target_url, secret, current_revision)
                VALUES ('ssrfw', 'http://169.254.169.254/latest/meta-data/',
                        'dev-signing-secret', 1)
                RETURNING id
                """
            )
            ver = await conn.fetchrow(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret,
                     max_attempts, backoff_base_seconds, backoff_cap_seconds)
                VALUES ($1, 1,
                        'http://169.254.169.254/latest/meta-data/',
                        'dev-signing-secret', 2, 1, 2)
                RETURNING id
                """,
                sub["id"],
            )
            row = await conn.fetchrow(
                """
                INSERT INTO deliveries
                    (event_id_fk, subscription_id, config_version_id,
                     chain_id, chain_seq, status)
                VALUES ($1, $2, $3, nextval('delivery_chain_seq'), 1, 'pending')
                RETURNING id
                """,
                ev["id"], sub["id"], ver["id"],
            )
            await conn.close()
            return row["id"]

        blocked_id = asyncio.run(seed_blocked_delivery())
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{blocked_id}").json()["attempts_made"] >= 1,
            "被策略阻止的投递出现首次尝试", timeout=15,
        )
        attempts = api.get(f"/api/v1/deliveries/{blocked_id}/attempts").json()
        check(
            "Worker 尝试明细记录 security_blocked 且错误可检索",
            attempts[0]["outcome"] == "security_blocked"
            and "安全策略拒绝" in (attempts[0]["error_message"] or ""),
            json.dumps(attempts[0], ensure_ascii=False),
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{blocked_id}").json()["status"] == "dead_lettered",
            "被阻止投递按钉住版本 max_attempts=2 进入死信", timeout=30,
        )
        bd = api.get(f"/api/v1/deliveries/{blocked_id}").json()
        attempts = api.get(f"/api/v1/deliveries/{blocked_id}/attempts").json()
        check(
            "安全失败按现有重试/死信语义结算（2 次均 security_blocked）",
            bd["status"] == "dead_lettered"
            and bd["attempts_made"] == 2
            and all(a["outcome"] == "security_blocked" for a in attempts),
        )
        check(
            "可按结果检索安全失败尝试",
            all(
                a["outcome"] == "security_blocked"
                for a in api.get(f"/api/v1/deliveries/{blocked_id}/attempts").json()
            ),
        )

        # 8.4 重定向逐跳校验：第一跳是放行的 receiver（相对路径），成功；
        # 指向云元数据的重定向在第二跳被 Worker 拒绝（security_blocked）。
        redsub = api.post("/api/v1/subscriptions", json={
            "source": "redir",
            "target_url": f"{h.rcv}/redirect?to=/receive",
            "secret": "dev-signing-secret",
            "max_attempts": 1,
        }).json()
        check("放行主机上的重定向目标订阅创建成功", redsub.get("active") is True,
              json.dumps(redsub, ensure_ascii=False))
        api.post("/api/v1/events", json={
            "source": "redir", "event_id": "redir-ok", "payload": {},
        })
        rd_ok = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                        params={"source": "redir"}).json()
                         if x["source_event_id"] == "redir-ok"), None),
            "redir-ok 投递创建",
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{rd_ok['id']}").json()["status"] == "succeeded",
            "逐跳校验通过的相对重定向最终成功", timeout=15,
        )
        check("重定向每跳经策略校验：相对重定向 200",
              api.get(f"/api/v1/deliveries/{rd_ok['id']}").json()["attempts_made"] == 1)

        # 第二跳跳到云元数据：直接写库构造订阅（入口会拦），max_attempts=1 快速死信
        async def seed_redirect_to_metadata():
            conn = await asyncpg.connect(h.dsn)
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            ev = await conn.fetchrow(
                """
                INSERT INTO events (source, event_id, payload)
                VALUES ('redirb', 'redir-bad', '{}'::jsonb)
                RETURNING id
                """
            )
            sub = await conn.fetchrow(
                """
                INSERT INTO subscriptions (source, target_url, secret, current_revision)
                VALUES ('redirb', $1, 'dev-signing-secret', 1)
                RETURNING id
                """,
                f"{h.rcv}/redirect?to=http://169.254.169.254/latest/meta-data/",
            )
            ver = await conn.fetchrow(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret,
                     max_attempts, backoff_base_seconds, backoff_cap_seconds)
                VALUES ($1, 1, $2, 'dev-signing-secret', 1, 1, 2)
                RETURNING id
                """,
                sub["id"],
                f"{h.rcv}/redirect?to=http://169.254.169.254/latest/meta-data/",
            )
            row = await conn.fetchrow(
                """
                INSERT INTO deliveries
                    (event_id_fk, subscription_id, config_version_id,
                     chain_id, chain_seq, status)
                VALUES ($1, $2, $3, nextval('delivery_chain_seq'), 1, 'pending')
                RETURNING id
                """,
                ev["id"], sub["id"], ver["id"],
            )
            await conn.close()
            return row["id"]

        rb_id = asyncio.run(seed_redirect_to_metadata())
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{rb_id}").json()["status"] == "dead_lettered",
            "重定向到元数据的投递死信", timeout=20,
        )
        rb_attempts = api.get(f"/api/v1/deliveries/{rb_id}/attempts").json()
        check(
            "重定向不越过策略：第二跳云元数据 -> security_blocked",
            len(rb_attempts) == 1 and rb_attempts[0]["outcome"] == "security_blocked",
            json.dumps(rb_attempts, ensure_ascii=False),
        )

    except Exception as exc:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        failures.append(f"异常: {exc}")
    finally:
        h.stop()

    print()
    if failures:
        print(f"失败 {len(failures)} 项: {failures}")
        return 1
    print("全部端到端检查通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
