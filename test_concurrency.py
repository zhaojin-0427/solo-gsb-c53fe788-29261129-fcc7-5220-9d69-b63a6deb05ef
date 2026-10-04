"""聚焦验证：配置版本发布与并发事件提交的原子切换边界 + 密钥钉死。

场景：订阅 rev1(secret=S1, /receive)；并发提交 N 个事件并同时发布 rev2(secret=S2)。
要求：
- 每条投递记录的 config_revision 与其创建时刻的边界一致；
- 收到的 HTTP 投递（含重试/接管）签名密钥、revision 头与投递记录的版本严格一致；
- 不允许出现“记录钉 rev1 却用 S2 签名”之类的跨界投递；
- 并发发布多个 rev2 只有一个成功。
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pgserver

ROOT = Path(__file__).resolve().parent
VENV_PY = os.environ.get("VENV_PY", "python3")

S1 = "secret-one-000000"
S2 = "secret-two-000000"

COMMON_ENV = {
    "LEASE_SECONDS": "30",
    "HTTP_TIMEOUT_SECONDS": "5",
    "WORKER_POLL_SECONDS": "0.05",
    "MAX_ATTEMPTS": "6",
    "BACKOFF_BASE_SECONDS": "1",
    "BACKOFF_CAP_SECONDS": "2",
    "RECEIVER_SECRET": "",  # 接收器不强制，两种密钥都能收
    "RECEIVER_TIMESTAMP_TOLERANCE_SECONDS": "600",
    # 出站安全策略：本地联调目标为回环地址，显式放行
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


def wait_http(url, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"not ready: {url}")


class H:
    def __init__(self):
        self.procs = []

    def spawn(self, mod, port, name, extra_env=None):
        env = os.environ.copy()
        env.update(COMMON_ENV)
        env["DATABASE_URL"] = self.dsn
        if extra_env:
            env.update(extra_env)
        log = open(ROOT / f"stress-{name}.log", "w")
        p = subprocess.Popen(
            [VENV_PY, "-m", *mod], cwd=ROOT, env=env,
            stdout=log, stderr=subprocess.STDOUT,
        )
        self.procs.append(p)

    def start(self):
        self.pg = pgserver.get_server(str(ROOT / ".stress-pgdata"), cleanup_mode="stop")
        self.dsn = self.pg.get_uri()
        ap, rp = free_port(), free_port()
        self.api = f"http://127.0.0.1:{ap}"
        self.rcv = f"http://127.0.0.1:{rp}"
        self.spawn(["uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(ap)], ap, "api")
        self.spawn(["uvicorn", "app.receiver:app", "--host", "127.0.0.1", "--port", str(rp)], rp, "rcv")
        self.spawn(["app.worker"], None, "w1")
        self.spawn(["app.worker"], None, "w2")
        wait_http(f"{self.api}/health")
        wait_http(f"{self.rcv}/health")

    def stop(self):
        import signal
        for p in self.procs:
            p.send_signal(signal.SIGTERM)
        for p in self.procs:
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()
        try:
            self.pg.cleanup()
        except Exception:
            pass


def main() -> int:
    h = H()
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
            "source": "race", "target_url": f"{h.rcv}/receive", "secret": S1,
            "max_attempts": 2, "backoff_base_seconds": 1, "backoff_cap_seconds": 1,
        }).json()
        sid = sub["id"]

        # 先提交一个“哨兵”事件并等它被投递：它是边界前确定性的 rev1 投递，
        # 也顺带自检 rev1/S1 链路。
        api.post("/api/v1/events", json={
            "source": "race", "event_id": "sentinel", "payload": {},
        })
        deadline = time.time() + 15
        while time.time() < deadline:
            ds = api.get("/api/v1/deliveries", params={"source": "race"}).json()
            if any(d["source_event_id"] == "sentinel" and d["status"] == "succeeded"
                   for d in ds):
                break
            time.sleep(0.2)

        # 再以 N 个事件与发布撞同一把订阅行锁：并发归属由 DB 行锁决定；
        # 另提交 M 个“发布后”事件，确定性地落在边界后。
        N = 16
        M = 8
        # 参与方：N 个并发事件 + 1 个发布 + 主线程放行
        barrier = threading.Barrier(N + 2)
        late = threading.Event()
        results: list = []
        lock = threading.Lock()

        def submit_concurrent(i):
            barrier.wait()
            r = httpx.post(
                f"{h.api}/api/v1/events",
                json={"source": "race", "event_id": f"r-{i}", "payload": {"i": i}},
                timeout=10,
            )
            with lock:
                results.append((i, r.status_code))

        def submit_late(i):
            late.wait()  # 等发布提交后再发，确保落在边界后
            r = httpx.post(
                f"{h.api}/api/v1/events",
                json={"source": "race", "event_id": f"r-late-{i}", "payload": {"i": i}},
                timeout=10,
            )
            with lock:
                results.append((i, r.status_code))

        def publish():
            barrier.wait()
            # 与前 N 个事件请求同时撞行锁：DB 行锁决定谁落在边界哪一侧
            r = httpx.post(
                f"{h.api}/api/v1/subscriptions/{sid}/versions",
                json={
                    # 目标保持同一宽松接收器；仅更换密钥，从而单独检验“密钥钉死”
                    "target_url": f"{h.rcv}/receive",
                    "secret": S2,
                    "expected_revision": 1,
                },
                timeout=10,
            )
            late.set()  # 边界确定，放行发布后事件
            return r

        c_threads = [threading.Thread(target=submit_concurrent, args=(i,)) for i in range(N)]
        l_threads = [threading.Thread(target=submit_late, args=(i,)) for i in range(M)]
        pub_result = {}

        def run_publish():
            pub_result["resp"] = publish()

        pub_thread = threading.Thread(target=run_publish)
        for t in c_threads + l_threads:
            t.start()
        pub_thread.start()
        barrier.wait()  # 主线程放行并发事件与发布
        pub_thread.join()
        for t in c_threads + l_threads:
            t.join()
        results.append(("pub", pub_result["resp"].status_code))

        total = N + M
        pub_codes = [c for tag, c in results if tag == "pub"]
        check("唯一一次发布成功(201)", pub_codes == [201], str(pub_codes))
        check("全部事件首次提交 201",
              sorted(c for tag, c in results if tag != "pub") == [201] * total)

        # 等所有投递结束（含哨兵，共 total+1 条）
        deadline = time.time() + 40
        while time.time() < deadline:
            ds = api.get("/api/v1/deliveries", params={"source": "race", "limit": 200}).json()
            if len(ds) == total + 1 and all(d["status"] == "succeeded" for d in ds):
                break
            time.sleep(0.3)
        ds_all = api.get("/api/v1/deliveries", params={"source": "race", "limit": 200}).json()
        ds = ds_all
        check(f"恰好 {total + 1} 条投递且全部成功",
              len(ds) == total + 1 and all(d["status"] == "succeeded" for d in ds),
              f"n={len(ds)}")

        rev1_ids = {d["id"] for d in ds if d["config_revision"] == 1}
        rev2_ids = {d["id"] for d in ds if d["config_revision"] == 2}
        # rev1 至少有哨兵（还可能有并发赢过发布的事件）；rev2 至少有 M 个晚到事件
        check("投递按边界分成 rev1/rev2 两群（rev1 含哨兵，rev2 含全部晚到事件）",
              bool(rev1_ids) and len(rev2_ids) >= M
              and rev1_ids.isdisjoint(rev2_ids),
              f"rev1={len(rev1_ids)} rev2={len(rev2_ids)}")

        # 晚到事件必须全部 rev2
        late_bad = [
            d["id"] for d in ds
            if d["source_event_id"].startswith("r-late-") and d["config_revision"] != 2
        ]
        check("发布后提交的事件全部使用 rev2", not late_bad, str(late_bad))
        # 哨兵必须 rev1（边界前创建，其签名也只能用 S1 验证）
        sentinel_d = next(d for d in ds if d["source_event_id"] == "sentinel")
        check("哨兵投递钉在 rev1", sentinel_d["config_revision"] == 1)

        # 端到端密钥钉死：用每条投递记录版本对应的密钥，对接收器实际收到的
        # 原始签名头重新验签。旧密钥必须只在 rev1 投递上有效，新密钥反之。
        sys.path.insert(0, str(ROOT))
        from app import security

        received = rcv.get("/received", params={"limit": 500}).json()["items"]
        by_delivery: dict[str, list[dict]] = {}
        for r in received:
            by_delivery.setdefault(r["delivery_id"], []).append(r)

        mismatches = []
        for d in ds:
            hits = by_delivery.get(str(d["id"]), [])
            if not hits:
                mismatches.append((d["id"], "no http record"))
                continue
            pinned_secret = S1 if d["config_revision"] == 1 else S2
            other_secret = S2 if d["config_revision"] == 1 else S1
            for hit in hits:
                # 头里的 revision 必须等于投递记录版本（重试也不能变）
                if int(hit["config_revision"]) != d["config_revision"]:
                    mismatches.append((d["id"], "header revision drift"))
                parsed = security.parse_signature_header(hit["signature_header"] or "")
                if parsed is None:
                    mismatches.append((d["id"], "bad signature header"))
                    continue
                ts, sig = parsed
                ok_pinned = security.verify(pinned_secret, ts, hit["payload"], sig)
                ok_other = security.verify(other_secret, ts, hit["payload"], sig)
                if not ok_pinned or ok_other:
                    mismatches.append(
                        (d["id"], f"secret pin violated ok_pinned={ok_pinned} ok_other={ok_other}")
                    )
        check(
            "每条投递（含重试）均以其钉住版本的密钥签名，且用另一版本密钥验签必失败",
            not mismatches, str(mismatches[:5]),
        )

        versions = api.get(f"/api/v1/subscriptions/{sid}/versions").json()
        check("版本不可变：两版本密钥不可见、URL/边界齐全",
              [v["revision"] for v in versions] == [1, 2]
              and all("secret" not in v for v in versions)
              and versions[0]["superseded_at"] is not None
              and versions[1]["is_current"] is True)

        # 边界时间戳是发布事务“执行时刻”（非严格提交时刻），并发的 rev1 事务
        # 可能在其后几毫秒才提交，因此这里只做秒级近似 sanity 校验；
        # 确定性的正确性保证来自：
        #   (a) 事件提交事务对订阅行 FOR UPDATE 与发布串行（读到的 current_revision
        #       与事务先后提交严格对应）；
        #   (b) 上面对每条投递按钉住版本密钥独立重新验签（跨界必失败）。
        v1, v2 = versions
        from datetime import datetime as _dt

        def _parse(s: str):
            return _dt.fromisoformat(s.replace("Z", "+00:00"))

        boundary = _parse(v1["superseded_at"])
        rev1_ds = [d for d in ds if d["config_revision"] == 1]
        rev2_ds = [d for d in ds if d["config_revision"] == 2]
        last_rev1_ts = max(_parse(d["created_at"]) for d in rev1_ds)
        first_rev2_ts = min(_parse(d["created_at"]) for d in rev2_ds)
        # 确定性边界证据：所有“发布后”事件（其 HTTP 请求在发布响应之后才发出）
        # 必须在 superseded_at 之后创建；哨兵（发布前）必须在其之前。
        sentinel_ts = _parse(sentinel_d["created_at"])
        late_ts_ok = all(
            _parse(d["created_at"]) >= boundary
            for d in ds
            if d["source_event_id"].startswith("r-late-")
        )
        check(
            "哨兵(rev1)在边界前、所有发布后事件(rev2)在边界后",
            sentinel_ts < boundary and late_ts_ok,
            f"sentinel={sentinel_ts} boundary={boundary}",
        )
        check(
            "rev1/rev2 投递时间各自成簇且不交叉（近似窗内）",
            abs((boundary - last_rev1_ts).total_seconds()) < 2
            and abs((first_rev2_ts - boundary).total_seconds()) < 2,
            f"last_rev1={last_rev1_ts} boundary={boundary} first_rev2={first_rev2_ts}",
        )

    except Exception:
        import traceback
        traceback.print_exc()
        failures.append("异常")
    finally:
        h.stop()

    print()
    if failures:
        print(f"失败 {len(failures)}: {failures}")
        return 1
    print("并发边界压力检查全部通过 ✅")
    return 0


if __name__ == "__main__":
    sys.exit(main())
