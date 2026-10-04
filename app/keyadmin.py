"""密钥管理命令行：明文迁移、主密钥轮换、密钥移除守卫、状态查看。

用法（容器内）：

    python -m app.keyadmin generate-key            # 生成一把新主密钥（JSON 片段）
    python -m app.keyadmin status                  # 密钥环与加密/轮换状态
    python -m app.keyadmin migrate [--batch-size N]   # 明文版本 -> 信封加密（幂等/断点续跑）
    python -m app.keyadmin rotate --to KEY_ID [--batch-size N]   # 重包裹 DEK 到新主密钥
    python -m app.keyadmin remove-key KEY_ID       # 无引用校验后移除旧主密钥

所有批处理命令幂等、可断点续跑、可并发执行，与在线投递 Worker 互不阻塞。
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import sys

from app import envelope, repository as repo
from app.config import settings
from app.db import close_pool, init_db
from app.keyring import (
    KeyringConfigError,
    KeyUnwrapError,
    UnknownKeyIdError,
    get_keyring,
    require_keyring,
)

log = logging.getLogger("webhook.keyadmin")


# -- generate-key ---------------------------------------------------------------

def cmd_generate_key(_args: argparse.Namespace) -> int:
    import secrets

    key_id = "k-" + secrets.token_hex(4)
    key_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    print("新主密钥（把它并入密钥环的 keys，并把 active_key_id 指向它以启用）：")
    print(
        json.dumps(
            {"active_key_id": key_id, "keys": {key_id: key_b64}},
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


# -- status -------------------------------------------------------------------------

async def _status() -> int:
    keyring = get_keyring()
    pool = await init_db()
    try:
        async with pool.acquire() as conn:
            plaintext = await repo.count_plaintext_versions(conn)
            by_key = await repo.count_versions_by_key_id(conn)
            rotations = await repo.list_rotations(conn)
    finally:
        await close_pool()

    if keyring is None:
        print("密钥环：未配置（WEBHOOK_KEYRING_JSON / WEBHOOK_KEYRING_FILE 均为空）")
        known_ids: set[str] = set()
        active = None
    else:
        active = keyring.active_key_id
        known_ids = set(keyring.key_ids)
        print(f"密钥环：active_key_id={active}，keys={keyring.key_ids}")

    print(f"明文待迁移配置版本：{plaintext}")
    in_use = {row["key_id"]: row["n"] for row in by_key}
    if in_use:
        print("信封版本按 key_id 分布：")
        for key_id, n in sorted(in_use.items()):
            marker = ""
            if key_id not in known_ids:
                marker = "  ⚠️ 本地密钥环中不存在该 key_id，相关投递将被拒绝"
            print(f"  {key_id}: {n}{marker}")
    else:
        print("信封版本：无")
    unknown = sorted(k for k in in_use if k not in known_ids)
    if unknown:
        print(f"⚠️ 数据库引用了密钥环中不存在的 key_id: {unknown}")

    if rotations:
        print("最近轮换运行：")
        for r in rotations:
            line = (
                f"  #{r['id']} -> {r['new_key_id']} [{r['status']}] "
                f"processed={r['processed_count']} last_version_id={r['last_version_id']}"
            )
            if r["last_error"]:
                line += f" error={r['last_error']}"
            print(line)
    else:
        print("轮换运行：无")
    return 0


# -- migrate（明文 -> 信封） ----------------------------------------------------------

async def _migrate(batch_size: int) -> int:
    keyring = require_keyring()
    pool = await init_db()
    total = 0
    try:
        while True:
            async with pool.acquire() as conn:
                async with conn.transaction():
                    rows = await repo.fetch_plaintext_versions_batch(conn, batch_size)
                    for row in rows:
                        ciphertext, wrapped, key_id = envelope.encrypt_new_secret(
                            keyring,
                            row["subscription_id"],
                            row["id"],
                            row["secret"],
                        )
                        await repo.mark_version_encrypted(
                            conn, row["id"], ciphertext, wrapped, key_id
                        )
            total += len(rows)
            if rows:
                log.info("已加密 %d 个配置版本（累计 %d）", len(rows), total)
            if len(rows) < batch_size:
                break
        async with pool.acquire() as conn:
            cleared = await repo.clear_subscription_secret_cache(conn)
        print(
            f"迁移完成：共加密 {total} 个配置版本；"
            f"清理 subscriptions 冗余明文 {cleared} 行"
        )
        return 0
    finally:
        await close_pool()


# -- rotate（重包裹 DEK） -------------------------------------------------------------

async def _rotate(to_key_id: str, from_key_id: str | None, batch_size: int) -> int:
    keyring = require_keyring()
    if to_key_id not in keyring.keys:
        print(
            f"错误：目标 key_id={to_key_id!r} 不在本地密钥环中"
            f"（现有: {keyring.key_ids}）",
            file=sys.stderr,
        )
        return 2
    pool = await init_db()
    total = 0
    try:
        async with pool.acquire() as conn:
            run, adopted = await repo.start_or_adopt_rotation(
                conn, new_key_id=to_key_id, old_key_id=from_key_id or ""
            )
        rotation_id = run["id"]
        if adopted:
            print(
                f"接续轮换运行 #{rotation_id}（此前状态 {run['status']}，"
                f"已完成 {run['processed_count']} 条），断点续跑"
            )
        try:
            while True:
                async with pool.acquire() as conn:
                    async with conn.transaction():
                        rows = await repo.fetch_rewrap_batch(
                            conn, to_key_id, batch_size, from_key_id
                        )
                        for row in rows:
                            # 只重包裹 DEK：解包 -> 用新主密钥重新包裹，
                            # 密钥密文（secret_ciphertext）保持不变。
                            dek = keyring.unwrap_dek(
                                row["secret_key_id"], bytes(row["secret_dek_wrapped"])
                            )
                            new_blob = keyring.wrap_dek_with(to_key_id, dek)
                            await repo.apply_rewrap(
                                conn, row["id"], new_blob, to_key_id
                            )
                        last_id = max((r["id"] for r in rows), default=0)
                        await repo.update_rotation_progress(
                            conn, rotation_id, len(rows), last_id
                        )
                total += len(rows)
                if rows:
                    log.info(
                        "已重包裹 %d 个 DEK（累计 %d）", len(rows), total
                    )
                if len(rows) < batch_size:
                    break
        except (UnknownKeyIdError, KeyUnwrapError) as exc:
            async with pool.acquire() as conn:
                await repo.finish_rotation(conn, rotation_id, "failed", str(exc))
            print(f"轮换失败（可修复后重跑，将断点续跑）: {exc}", file=sys.stderr)
            return 1
        async with pool.acquire() as conn:
            await repo.finish_rotation(conn, rotation_id, "completed")
            remaining_plain = await repo.count_plaintext_versions(conn)
        print(f"轮换完成：共重包裹 {total} 个 DEK 到 key_id={to_key_id}")
        if remaining_plain:
            print(
                f"提示：仍有 {remaining_plain} 个明文版本未迁移"
                "（先运行 migrate，再执行 rotate 才会覆盖它们）"
            )
        return 0
    finally:
        await close_pool()


# -- remove-key ---------------------------------------------------------------------

async def _remove_key(key_id: str, assume_yes: bool) -> int:
    keyring = require_keyring()
    pool = await init_db()
    try:
        async with pool.acquire() as conn:
            refs = await repo.count_references_to_key(conn, key_id)
    finally:
        await close_pool()

    if refs > 0:
        print(
            f"拒绝移除：仍有 {refs} 个配置版本引用 key_id={key_id!r}。"
            "请先完成轮换（rotate）并确认无引用后再移除。",
            file=sys.stderr,
        )
        return 1
    if key_id == keyring.active_key_id:
        print(
            f"拒绝移除：key_id={key_id!r} 是当前活跃主密钥，"
            "请先把 active_key_id 切换到其他密钥。",
            file=sys.stderr,
        )
        return 1
    if key_id not in keyring.keys:
        print(f"key_id={key_id!r} 不在本地密钥环中，无需移除。")
        return 0

    path = settings.keyring_file.strip()
    if path and not settings.keyring_json.strip():
        # 文件型密钥环：原地改写（兼容 Docker 单文件 bind mount，不能 rename），
        # 旧内容先写入 .bak 备份。
        with open(path, "r", encoding="utf-8") as fh:
            original = fh.read()
        data = json.loads(original)
        data["keys"].pop(key_id, None)
        with open(path + ".bak", "w", encoding="utf-8") as fh:
            fh.write(original)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        print(
            f"已从密钥环文件 {path} 移除 {key_id!r}（备份：{path}.bak）。"
            "请重启 api/worker 使新密钥环生效。"
        )
    else:
        print(
            f"数据库中已无对 {key_id!r} 的引用，可安全地从 "
            "WEBHOOK_KEYRING_JSON 中删除该密钥并重启 api/worker。"
        )
    return 0


# -- 入口 -----------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(prog="keyadmin", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("generate-key", help="生成一把新主密钥（JSON 片段）")
    sub.add_parser("status", help="查看密钥环/迁移/轮换状态")

    p_migrate = sub.add_parser("migrate", help="明文配置版本批量迁移为信封加密")
    p_migrate.add_argument("--batch-size", type=int, default=200)

    p_rotate = sub.add_parser("rotate", help="把 DEK 重包裹到新的主密钥")
    p_rotate.add_argument("--to", required=True, help="目标 key_id")
    p_rotate.add_argument("--from", dest="from_key", default=None,
                          help="只轮换该来源 key_id（默认全部非目标 key）")
    p_rotate.add_argument("--batch-size", type=int, default=200)

    p_remove = sub.add_parser("remove-key", help="无引用校验后移除旧主密钥")
    p_remove.add_argument("key_id")
    p_remove.add_argument("--yes", action="store_true", help="跳过交互确认")

    args = parser.parse_args()
    try:
        if args.command == "generate-key":
            code = cmd_generate_key(args)
        elif args.command == "status":
            code = asyncio.run(_status())
        elif args.command == "migrate":
            code = asyncio.run(_migrate(args.batch_size))
        elif args.command == "rotate":
            code = asyncio.run(_rotate(args.to, args.from_key, args.batch_size))
        elif args.command == "remove-key":
            code = asyncio.run(_remove_key(args.key_id, args.yes))
        else:  # pragma: no cover
            parser.error("未知命令")
            code = 2
    except KeyringConfigError as exc:
        print(f"密钥环配置错误: {exc}", file=sys.stderr)
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
