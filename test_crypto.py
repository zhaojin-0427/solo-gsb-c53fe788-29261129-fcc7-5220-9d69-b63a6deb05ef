"""端到端验证：订阅 HMAC 密钥的信封加密与在线主密钥轮换。

覆盖：
1. 新版本密钥信封加密落库（无明文），API/查询不暴露明文；
2. Worker 签名前解密，投递签名与明文密钥一致；
3. 旧明文记录迁移期间可读（投递不中断），keyadmin migrate 幂等、断点续跑；
4. 主密钥轮换只重包裹 DEK，进度持久化，失败可恢复，可并发；
5. 尚有记录引用旧 key_id 时禁止移除旧密钥；
6. 未知 key_id / 认证失败 -> 拒绝投递并记录可查询 crypto_error；
7. 修复后死信重放恢复（版本固定与重放语义不变）；
8. 未配置密钥环时写入接口 503、读取接口可用。
"""
from __future__ import annotations

import asyncio
import base64
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

K1_B64 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
K2_B64 = base64.b64encode(b"fedcba9876543210fedcba9876543210").decode()

KR_K1 = json.dumps({"active_key_id": "k1", "keys": {"k1": K1_B64}})
KR_BOTH = json.dumps(
    {"active_key_id": "k1", "keys": {"k1": K1_B64, "k2": K2_B64}}
)
KR_BOTH_K2 = json.dumps(
    {"active_key_id": "k2", "keys": {"k1": K1_B64, "k2": K2_B64}}
)
KR_K2 = json.dumps({"active_key_id": "k2", "keys": {"k2": K2_B64}})

SECRET_A = "crypto-secret-A"
SECRET_LEGACY = "legacy-plaintext-secret"

COMMON_ENV = {
    "LEASE_SECONDS": "3",
    "HTTP_TIMEOUT_SECONDS": "2",
    "WORKER_POLL_SECONDS": "0.2",
    "MAX_ATTEMPTS": "6",
    "BACKOFF_BASE_SECONDS": "1",
    "BACKOFF_CAP_SECONDS": "8",
    "RECEIVER_SECRET": "",  # 测试自行按投递验签
    "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS": "600",
    "WEBHOOK_ALLOWED_HOSTS": "127.0.0.1,localhost",
    "WEBHOOK_ALLOWED_CIDRS": "",
    "WEBHOOK_MAX_REDIRECTS": "5",
    # 事件载荷对象存储：测试用本地文件后端（无需 MinIO）
    "PAYLOAD_STORE_MODE": "local",
    "PAYLOAD_LOCAL_DIR": str(ROOT / ".test-payloads-crypto"),
    "PAYLOAD_STALE_AGE_SECONDS": "0.2",
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


def wait_for(condition, desc: str, timeout: float = 60.0, interval: float = 0.4):
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = condition()
        if result:
            return result
        time.sleep(interval)
    raise AssertionError(f"等待超时: {desc}")


class Harness:
    def __init__(self) -> None:
        self.procs: dict[str, subprocess.Popen] = {}

    def spawn(self, module_cmd: list[str], name: str, extra_env: dict | None = None):
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        if extra_env:
            env.update(extra_env)
        log = open(ROOT / f"test-crypto-{name}.log", "w")
        proc = subprocess.Popen(
            [VENV_PY, "-m", *module_cmd],
            cwd=ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.procs[name] = proc
        return proc

    def kill(self, name: str):
        proc = self.procs.pop(name, None)
        if proc is None:
            return
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()

    def start(self, keyring_json: str):
        import shutil

        # 每次运行从全新数据库开始（pgserver 的 stop 清理模式会保留数据目录）
        shutil.rmtree(ROOT / ".test-crypto-pgdata", ignore_errors=True)
        self.pg = pgserver.get_server(
            str(ROOT / ".test-crypto-pgdata"), cleanup_mode="stop"
        )
        self.dsn = self.pg.get_uri()
        print("Postgres DSN:", self.dsn)
        self.api_port = free_port()
        self.rcv_port = free_port()
        self.api = f"http://127.0.0.1:{self.api_port}"
        self.rcv = f"http://127.0.0.1:{self.rcv_port}"
        self.keyring_json = keyring_json
        self.start_api_worker(keyring_json)
        self.spawn(
            ["uvicorn", "app.receiver:app", "--host", "127.0.0.1",
             "--port", str(self.rcv_port)],
            "receiver",
        )
        wait_http(f"{self.api}/health")
        wait_http(f"{self.rcv}/health")
        print("API/Receiver/Worker 已启动")

    def start_api_worker(self, keyring_json: str):
        env = {"WEBHOOK_KEYRING_JSON": keyring_json, "WEBHOOK_KEYRING_FILE": ""}
        self.spawn(
            ["uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", str(self.api_port)],
            "api",
            env,
        )
        self.spawn(["app.worker"], "worker1", env)
        self.spawn(["app.worker"], "worker2", env)

    def restart_api_worker(self, keyring_json: str):
        for name in ("api", "worker1", "worker2"):
            self.kill(name)
        self.start_api_worker(keyring_json)
        wait_http(f"{self.api}/health")

    def keyadmin(self, *argv: str, keyring_json: str | None = None) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        env["WEBHOOK_KEYRING_JSON"] = keyring_json or self.keyring_json
        env["WEBHOOK_KEYRING_FILE"] = ""
        return subprocess.run(
            [VENV_PY, "-m", "app.keyadmin", *argv],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def stop(self):
        for name in list(self.procs):
            self.kill(name)
        try:
            self.pg.cleanup()
        except Exception:  # noqa: BLE001
            pass


def db_query(dsn: str, sql: str, *args):
    import asyncpg

    async def _run():
        conn = await asyncpg.connect(dsn)
        try:
            return await conn.fetch(sql, *args)
        finally:
            await conn.close()

    return asyncio.run(_run())


def db_execute(dsn: str, sql: str, *args):
    import asyncpg

    async def _run():
        conn = await asyncpg.connect(dsn)
        try:
            return await conn.execute(sql, *args)
        finally:
            await conn.close()

    return asyncio.run(_run())


def main() -> int:
    sys.path.insert(0, str(ROOT))
    h = Harness()
    failures = []

    def check(name: str, ok: bool, detail: str = ""):
        print(f"[{'PASS' if ok else 'FAIL'}] {name} {detail}")
        if not ok:
            failures.append(name)

    h.start(KR_BOTH)
    try:
        api = httpx.Client(base_url=h.api, timeout=5)
        rcv = httpx.Client(base_url=h.rcv, timeout=10)
        rcv.post("/received/reset")

        # -- 0) 信封加密的单元级性质（不依赖服务） -------------------------------
        from app import envelope
        from app.keyring import Keyring, KeyUnwrapError

        kr = Keyring.from_dict(json.loads(KR_BOTH))
        ct, wrapped, kid = envelope.encrypt_new_secret(kr, 10, 20, "s3cret")
        dek = kr.unwrap_dek(kid, wrapped)
        check("信封单元：加密->解包->解密还原",
              envelope.decrypt_secret(dek, 10, 20, ct) == "s3cret" and kid == "k1")
        tampered = bytearray(ct)
        tampered[-1] ^= 0x01
        try:
            envelope.decrypt_secret(dek, 10, 20, bytes(tampered))
            check("信封单元：篡改密文认证失败", False)
        except envelope.SecretCryptoError:
            check("信封单元：篡改密文认证失败", True)
        try:
            envelope.decrypt_secret(dek, 10, 21, ct)  # version_id 不同（AAD 绑定）
            check("信封单元：AAD 绑定行（换 version_id 解密失败）", False)
        except envelope.SecretCryptoError:
            check("信封单元：AAD 绑定行（换 version_id 解密失败）", True)
        try:
            kr.unwrap_dek("k2", wrapped)  # k1 包裹的 DEK 用 k2 解
            check("信封单元：错误主密钥解包失败", False)
        except KeyUnwrapError:
            check("信封单元：错误主密钥解包失败", True)

        # -- 1) 新订阅：密钥信封加密落库，API 不暴露明文 --------------------------
        sub = api.post("/api/v1/subscriptions", json={
            "source": "crypto", "target_url": f"{h.rcv}/receive",
            "secret": SECRET_A,
        })
        check("创建订阅 201", sub.status_code == 201, sub.text)
        sid = sub.json()["id"]
        check("订阅响应不含密钥", "secret" not in sub.json(), sub.text)

        rows = db_query(
            h.dsn,
            "SELECT secret, secret_ciphertext, secret_dek_wrapped, secret_key_id "
            "FROM subscription_versions WHERE subscription_id=$1",
            sid,
        )
        v = rows[0]
        check(
            "版本行无明文：secret 置空、密文/包裹 DEK/key_id 齐全",
            v["secret"] == ""
            and bytes(v["secret_ciphertext"]).startswith(b"SC1")
            and bytes(v["secret_dek_wrapped"]).startswith(b"WK1")
            and v["secret_key_id"] == "k1",
        )
        rows = db_query(h.dsn, "SELECT secret FROM subscriptions WHERE id=$1", sid)
        check("subscriptions 冗余列不存明文", rows[0]["secret"] == "")

        vlist = api.get(f"/api/v1/subscriptions/{sid}/versions").json()
        check(
            "版本列表无密钥明文、可见 key_id",
            "secret" not in vlist[0] and vlist[0]["secret_key_id"] == "k1",
            json.dumps(vlist, ensure_ascii=False),
        )

        # -- 2) 加密版本投递：Worker 签名前解密，签名与明文密钥一致 -----------------
        api.post("/api/v1/events", json={
            "source": "crypto", "event_id": "c-1", "payload": {"x": 1},
        })
        d1 = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                          params={"source": "crypto"}).json()
                          if x["source_event_id"] == "c-1"), None),
            "c-1 投递创建",
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{d1['id']}").json()["status"] == "succeeded",
            "c-1 投递成功", timeout=20,
        )

        from app import security

        def received_sig_ok(event_id: str, secret: str) -> bool:
            items = rcv.get("/received", params={"limit": 500}).json()["items"]
            hits = [x for x in items if x["event_id"] == event_id]
            if not hits:
                return False
            parsed = security.parse_signature_header(hits[-1]["signature_header"] or "")
            if parsed is None:
                return False
            ts, sig = parsed
            return security.verify(secret, ts, hits[-1]["payload"], sig)

        check("加密版本投递签名与明文密钥一致", received_sig_ok("c-1", SECRET_A))

        # -- 3) 旧明文记录：迁移期间仍可投递（新旧格式均可读） ----------------------
        async def seed_legacy():
            import asyncpg

            conn = await asyncpg.connect(h.dsn)
            await conn.set_type_codec(
                "jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog"
            )
            sub = await conn.fetchrow(
                """
                INSERT INTO subscriptions (source, target_url, secret, current_revision)
                VALUES ('legacysrc', $1, $2, 1) RETURNING id
                """,
                f"{h.rcv}/receive", SECRET_LEGACY,
            )
            ver = await conn.fetchrow(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret,
                     max_attempts, backoff_base_seconds, backoff_cap_seconds)
                VALUES ($1, 1, $2, $3, 6, 1.0, 8.0) RETURNING id
                """,
                sub["id"], f"{h.rcv}/receive", SECRET_LEGACY,
            )
            await conn.close()
            return sub["id"], ver["id"]

        legacy_sub, legacy_ver = asyncio.run(seed_legacy())
        api.post("/api/v1/events", json={
            "source": "legacysrc", "event_id": "lg-1", "payload": {"n": 1},
        })
        dl_legacy = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                          params={"source": "legacysrc"}).json()
                          if x["source_event_id"] == "lg-1"), None),
            "lg-1 投递创建",
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl_legacy['id']}").json()["status"] == "succeeded",
            "明文旧记录投递成功（迁移前可读）", timeout=20,
        )
        check("明文旧记录签名正确", received_sig_ok("lg-1", SECRET_LEGACY))

        # -- 4) 尚有引用时禁止移除旧密钥 -------------------------------------------
        r = h.keyadmin("remove-key", "k1")
        check("有引用时 remove-key 拒绝", r.returncode != 0 and "拒绝移除" in r.stderr,
              (r.stderr or r.stdout).strip())

        # -- 5) 明文批量迁移：幂等、断点续跑 ---------------------------------------
        r = h.keyadmin("migrate", "--batch-size", "1")  # 小批次模拟断点续跑
        check("migrate 成功", r.returncode == 0, (r.stdout + r.stderr).strip())
        rows = db_query(
            h.dsn,
            "SELECT secret, secret_key_id, secret_ciphertext IS NOT NULL AS enc "
            "FROM subscription_versions WHERE id=$1",
            legacy_ver,
        )
        check(
            "旧明文版本已加密且明文清空",
            rows[0]["enc"] and rows[0]["secret"] == "" and rows[0]["secret_key_id"] == "k1",
        )
        rows = db_query(h.dsn, "SELECT COUNT(*) AS n FROM subscriptions WHERE secret <> ''")
        check("subscriptions 冗余明文已清空", rows[0]["n"] == 0)
        r2 = h.keyadmin("migrate")
        check("migrate 幂等（重跑处理 0 条）",
              r2.returncode == 0 and "共加密 0 个" in r2.stdout, r2.stdout.strip())

        # 迁移后旧订阅新事件仍投递成功且签名密钥不变
        api.post("/api/v1/events", json={
            "source": "legacysrc", "event_id": "lg-2", "payload": {"n": 2},
        })
        wait_for(
            lambda: any(x["source_event_id"] == "lg-2" and x["status"] == "succeeded"
                        for x in api.get("/api/v1/deliveries",
                                         params={"source": "legacysrc"}).json()),
            "迁移后 lg-2 投递成功", timeout=20,
        )
        check("迁移后投递签名仍用原密钥", received_sig_ok("lg-2", SECRET_LEGACY))

        # -- 6) 在线主密钥轮换：只重包裹 DEK，进度持久化 ----------------------------
        before = db_query(
            h.dsn,
            "SELECT id, secret_ciphertext FROM subscription_versions ORDER BY id",
        )
        r = h.keyadmin("rotate", "--to", "k2", "--batch-size", "1")
        check("rotate 成功", r.returncode == 0, (r.stdout + r.stderr).strip())
        rows = db_query(
            h.dsn,
            "SELECT COUNT(*) FILTER (WHERE secret_key_id = 'k2') AS k2, "
            "COUNT(*) FILTER (WHERE secret_key_id <> 'k2' OR secret_key_id IS NULL) AS other "
            "FROM subscription_versions WHERE secret_ciphertext IS NOT NULL",
        )
        check("全部信封版本已重包裹到 k2", rows[0]["other"] == 0 and rows[0]["k2"] >= 2,
              f"k2={rows[0]['k2']} other={rows[0]['other']}")
        after = db_query(
            h.dsn,
            "SELECT id, secret_ciphertext FROM subscription_versions ORDER BY id",
        )
        check("轮换只重包裹 DEK（密钥密文不变）",
              [bytes(x["secret_ciphertext"]) for x in before]
              == [bytes(x["secret_ciphertext"]) for x in after])
        runs = db_query(h.dsn, "SELECT status, processed_count FROM key_rotations")
        check("轮换进度已持久化且完成",
              len(runs) == 1 and runs[0]["status"] == "completed"
              and runs[0]["processed_count"] >= 2,
              json.dumps([dict(x) for x in runs], default=str))
        r = h.keyadmin("rotate", "--to", "k2")
        check("rotate 幂等（重跑 0 条）", r.returncode == 0 and "共重包裹 0 个" in r.stdout,
              r.stdout.strip())

        # 轮换后（Worker 密钥环同时持有 k1/k2）投递不中断
        api.post("/api/v1/events", json={
            "source": "crypto", "event_id": "c-2", "payload": {"x": 2},
        })
        wait_for(
            lambda: any(x["source_event_id"] == "c-2" and x["status"] == "succeeded"
                        for x in api.get("/api/v1/deliveries",
                                         params={"source": "crypto"}).json()),
            "轮换后 c-2 投递成功", timeout=20,
        )
        check("轮换后投递签名仍正确", received_sig_ok("c-2", SECRET_A))

        # -- 7) 无引用后可移除旧密钥（需先把活跃密钥切到 k2） ------------------------
        r = h.keyadmin("remove-key", "k1", keyring_json=KR_BOTH_K2)
        check("无引用后 remove-key 放行", r.returncode == 0, (r.stdout + r.stderr).strip())

        # -- 8) 切换到仅 k2 的密钥环：滚动重启后一切正常 -----------------------------
        h.restart_api_worker(KR_K2)
        api.post("/api/v1/events", json={
            "source": "crypto", "event_id": "c-3", "payload": {"x": 3},
        })
        wait_for(
            lambda: any(x["source_event_id"] == "c-3" and x["status"] == "succeeded"
                        for x in api.get("/api/v1/deliveries",
                                         params={"source": "crypto"}).json()),
            "仅 k2 密钥环下 c-3 投递成功", timeout=20,
        )
        check("仅 k2 密钥环投递签名正确", received_sig_ok("c-3", SECRET_A))
        sub2 = api.post("/api/v1/subscriptions", json={
            "source": "crypto2", "target_url": f"{h.rcv}/receive",
            "secret": "crypto-secret-B", "max_attempts": 1,
        }).json()
        rows = db_query(
            h.dsn,
            "SELECT secret_key_id FROM subscription_versions WHERE subscription_id=$1",
            sub2["id"],
        )
        check("新订阅以 k2 包裹", rows[0]["secret_key_id"] == "k2")

        # -- 9) 未知 key_id：拒绝投递并记录可查询错误 --------------------------------
        db_execute(
            h.dsn,
            "UPDATE subscription_versions SET secret_key_id='ghost' "
            "WHERE subscription_id=$1",
            sub2["id"],
        )
        api.post("/api/v1/events", json={
            "source": "crypto2", "event_id": "bad-1", "payload": {},
        })
        dl_bad = wait_for(
            lambda: next((x for x in api.get("/api/v1/deliveries",
                          params={"source": "crypto2"}).json()
                          if x["source_event_id"] == "bad-1"), None),
            "bad-1 投递创建",
        )
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{dl_bad['id']}").json()["status"] == "dead_lettered",
            "未知 key_id 投递进入死信（max_attempts=1）", timeout=20,
        )
        attempts = api.get(f"/api/v1/deliveries/{dl_bad['id']}/attempts").json()
        check(
            "拒绝投递并记录 crypto_error（含 key_id，可查询）",
            len(attempts) == 1
            and attempts[0]["outcome"] == "crypto_error"
            and "ghost" in (attempts[0]["error_message"] or ""),
            json.dumps(attempts, ensure_ascii=False),
        )
        items = rcv.get("/received", params={"limit": 500}).json()["items"]
        check("未知 key_id 未发出任何 HTTP 投递",
              not any(x["event_id"] == "bad-1" for x in items))
        status = api.get("/api/v1/crypto/status").json()
        check("crypto/status 暴露未知 key_id",
              "ghost" in status["unknown_key_ids_in_use"],
              json.dumps(status, ensure_ascii=False))

        # 修复 key_id 后重放恢复（重放语义不变）
        db_execute(
            h.dsn,
            "UPDATE subscription_versions SET secret_key_id='k2' "
            "WHERE subscription_id=$1",
            sub2["id"],
        )
        rp = api.post(f"/api/v1/dead-letters/{dl_bad['id']}/replay")
        check("修复后死信重放 201", rp.status_code == 201, rp.text)
        new_id = rp.json()["new_delivery_id"]
        wait_for(
            lambda: api.get(f"/api/v1/deliveries/{new_id}").json()["status"] == "succeeded",
            "重放投递成功", timeout=20,
        )
        check("重放沿用原版本（config_revision=1）", rp.json()["config_revision"] == 1)

        # -- 10) crypto/status 总览 -------------------------------------------------
        status = api.get("/api/v1/crypto/status").json()
        check(
            "crypto/status 汇总正确",
            status["keyring_configured"] is True
            and status["active_key_id"] == "k2"
            and status["plaintext_versions_pending"] == 0
            and status["encrypted_versions_by_key_id"].get("k2", 0) >= 3
            and status["unknown_key_ids_in_use"] == []
            and any(r["status"] == "completed" for r in status["rotations"]),
            json.dumps(status, ensure_ascii=False),
        )

        # -- 11) 未配置密钥环：写入 503、读取可用 ------------------------------------
        nokey_port = free_port()
        h.spawn(
            ["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(nokey_port)],
            "api-nokey",
            {"WEBHOOK_KEYRING_JSON": "", "WEBHOOK_KEYRING_FILE": ""},
        )
        wait_http(f"http://127.0.0.1:{nokey_port}/health")
        nokey = httpx.Client(base_url=f"http://127.0.0.1:{nokey_port}", timeout=5)
        r = nokey.post("/api/v1/subscriptions", json={
            "source": "nokey", "target_url": f"{h.rcv}/receive",
            "secret": "nokey-secret-1",
        })
        check("未配置密钥环创建订阅 503",
              r.status_code == 503 and r.json()["detail"]["code"] == "keyring_not_configured",
              f"{r.status_code} {r.text}")
        r = nokey.get("/api/v1/subscriptions")
        check("未配置密钥环读取接口仍可用", r.status_code == 200)
        h.kill("api-nokey")

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
    print("密钥信封加密与轮换检查全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
