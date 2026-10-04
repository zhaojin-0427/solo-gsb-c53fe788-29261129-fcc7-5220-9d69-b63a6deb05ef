"""领域数据访问：事件、订阅、订阅配置版本、投递、投递尝试。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg

from app import envelope
from app.config import settings
from app.keyring import Keyring


class ReplayError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ConfigConflictError(Exception):
    """发布新版本时 expected_revision 与当前版本不一致（CAS 失败）。"""

    def __init__(self, current_revision: int):
        super().__init__(
            f"配置版本已变更：expected_revision 已过期，当前版本为 {current_revision}"
        )
        self.code = "revision_conflict"
        self.current_revision = current_revision


# -- 行 -> dict 映射 -----------------------------------------------------------

DELIVERY_COLUMNS = """
    d.id, d.event_id_fk, d.subscription_id, d.config_version_id,
    d.chain_id, d.chain_seq, d.status, d.attempts_made, d.not_before,
    d.leased_at, d.lease_expires_at, d.leased_by,
    d.created_at, d.updated_at
"""

# 版本查询返回的非敏感字段（绝不包含 secret 明文，也不包含密文/包裹的 DEK）
VERSION_COLUMNS = """
    v.id AS version_id, v.subscription_id, v.revision, v.target_url,
    v.max_attempts, v.backoff_base_seconds, v.backoff_cap_seconds,
    v.created_at, v.superseded_at, v.secret_key_id
"""


def delivery_to_dict(row: asyncpg.Record) -> dict[str, Any]:
    data = dict(row)
    # JOIN 出来的展示字段（可能不存在）
    return data


# -- 订阅 ----------------------------------------------------------------------

async def _encrypt_version_secret(
    conn: asyncpg.Connection,
    keyring: Keyring,
    subscription_id: int,
    version_id: int,
    secret: str,
) -> None:
    """为刚插入的配置版本生成随机 DEK 并信封加密其 HMAC 密钥。

    AAD 绑定 (subscription_id, version_id)；只写密文/包裹的 DEK/key_id，
    secret 明文列保持空串，明文不落盘。与插入版本行处于同一事务。
    """
    ciphertext, wrapped_dek, key_id = envelope.encrypt_new_secret(
        keyring, subscription_id, version_id, secret
    )
    await conn.execute(
        """
        UPDATE subscription_versions
        SET secret_ciphertext = $2,
            secret_dek_wrapped = $3,
            secret_key_id = $4
        WHERE id = $1
        """,
        version_id,
        ciphertext,
        wrapped_dek,
        key_id,
    )


async def create_subscription(
    conn: asyncpg.Connection,
    source: str,
    target_url: str,
    secret: str,
    *,
    keyring: Keyring,
    max_attempts: int,
    backoff_base_seconds: float,
    backoff_cap_seconds: float,
) -> asyncpg.Record:
    """新建订阅并原子写入不可变的初始配置版本 revision=1（密钥信封加密）。

    (source, target_url) 已存在时仅重新激活（配置不变，沿用其当前版本）。
    返回订阅行（含 current_revision）。
    """
    async with conn.transaction():
        sub = await conn.fetchrow(
            """
            INSERT INTO subscriptions (source, target_url, secret, current_revision)
            VALUES ($1, $2, '', 1)
            ON CONFLICT (source, target_url) DO UPDATE
                SET active = TRUE
            RETURNING id, source, target_url, active, created_at, current_revision,
                      (xmax = 0) AS inserted
            """,
            source,
            target_url,
        )
        # 仅对真正新建的订阅追加 revision=1；已存在的订阅其版本历史保持不变。
        if sub["inserted"]:
            version_id = await conn.fetchval(
                """
                INSERT INTO subscription_versions
                    (subscription_id, revision, target_url, secret, max_attempts,
                     backoff_base_seconds, backoff_cap_seconds)
                VALUES ($1, 1, $2, '', $3, $4, $5)
                RETURNING id
                """,
                sub["id"],
                target_url,
                max_attempts,
                backoff_base_seconds,
                backoff_cap_seconds,
            )
            await _encrypt_version_secret(
                conn, keyring, sub["id"], version_id, secret
            )
        return sub


async def get_subscription_by_id(
    conn: asyncpg.Connection, subscription_id: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT id, source, target_url, active, current_revision, created_at
        FROM subscriptions WHERE id = $1
        """,
        subscription_id,
    )


async def find_subscription(
    conn: asyncpg.Connection, source: str, target_url: str
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT id, source, target_url, active, current_revision, created_at
        FROM subscriptions WHERE source = $1 AND target_url = $2
        """,
        source,
        target_url,
    )


async def list_subscriptions(
    conn: asyncpg.Connection, source: str | None
) -> list[asyncpg.Record]:
    if source is not None:
        rows = await conn.fetch(
            """
            SELECT id, source, target_url, active, current_revision, created_at
            FROM subscriptions WHERE source = $1 ORDER BY id
            """,
            source,
        )
    else:
        rows = await conn.fetch(
            """
            SELECT id, source, target_url, active, current_revision, created_at
            FROM subscriptions ORDER BY id
            """
        )
    return list(rows)


# -- 订阅配置版本 / CAS 发布 ----------------------------------------------------

async def publish_version(
    conn: asyncpg.Connection,
    *,
    keyring: Keyring,
    subscription_id: int,
    target_url: str,
    secret: str,
    max_attempts: int,
    backoff_base_seconds: float,
    backoff_cap_seconds: float,
    expected_revision: int,
) -> tuple[asyncpg.Record, int]:
    """以 CAS 方式发布新的不可变配置版本，并原子确定切换边界。

    - 必须携带 expected_revision；与 subscriptions.current_revision 不一致则抛
      ConfigConflictError（并发发布只有一个能成功）。
    - 同一事务内：关闭旧版本边界（superseded_at=now）、追加新版本（密钥信封
      加密，AAD 绑定新 version_id）、推进 current_revision。事件提交事务会先锁
      订阅行，因此与发布竞争的事件要么在边界前（钉旧版本）、要么在边界后
      （用新版本），不存在跨界。
    - 不修改任何旧版本行；已存在的投递永远引用各自创建时的版本。

    返回 (新版本行, 新 revision)。
    """
    async with conn.transaction():
        # 行锁串行化同一订阅上的所有发布与事件提交，保证唯一切换边界。
        sub = await conn.fetchrow(
            """
            SELECT id, current_revision
            FROM subscriptions
            WHERE id = $1
            FOR UPDATE
            """,
            subscription_id,
        )
        if sub is None:
            raise LookupError("subscription not found")
        if sub["current_revision"] != expected_revision:
            raise ConfigConflictError(sub["current_revision"])

        new_revision = expected_revision + 1
        await conn.execute(
            """
            UPDATE subscription_versions
            SET superseded_at = now()
            WHERE subscription_id = $1
              AND revision = $2
              AND superseded_at IS NULL
            """,
            subscription_id,
            expected_revision,
        )
        version_id = await conn.fetchval(
            """
            INSERT INTO subscription_versions
                (subscription_id, revision, target_url, secret, max_attempts,
                 backoff_base_seconds, backoff_cap_seconds)
            VALUES ($1, $2, $3, '', $4, $5, $6)
            RETURNING id
            """,
            subscription_id,
            new_revision,
            target_url,
            max_attempts,
            backoff_base_seconds,
            backoff_cap_seconds,
        )
        await _encrypt_version_secret(
            conn, keyring, subscription_id, version_id, secret
        )
        version = await conn.fetchrow(
            f"""
            SELECT {VERSION_COLUMNS}
            FROM subscription_versions v
            WHERE v.id = $1
            """,
            version_id,
        )
        # 冗余的 subscriptions.target_url 仅为兼容旧列随当前版本同步；
        # secret 冗余列不再保存明文（统一置空，权威密钥在版本表的密文列中）。
        await conn.execute(
            """
            UPDATE subscriptions
            SET current_revision = $2, target_url = $3, secret = ''
            WHERE id = $1
            """,
            subscription_id,
            new_revision,
            target_url,
        )
        return version, new_revision


async def list_versions(
    conn: asyncpg.Connection, subscription_id: int
) -> list[asyncpg.Record]:
    """列出某订阅全部配置版本（按 revision 升序）；不返回 secret。"""
    rows = await conn.fetch(
        f"""
        SELECT {VERSION_COLUMNS},
               (v.revision = s.current_revision) AS is_current
        FROM subscription_versions v
        JOIN subscriptions s ON s.id = v.subscription_id
        WHERE v.subscription_id = $1
        ORDER BY v.revision
        """,
        subscription_id,
    )
    return list(rows)


async def get_current_version(
    conn: asyncpg.Connection, subscription_id: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        f"""
        SELECT {VERSION_COLUMNS}, TRUE AS is_current
        FROM subscription_versions v
        JOIN subscriptions s ON s.id = v.subscription_id
        WHERE v.subscription_id = $1 AND v.revision = s.current_revision
        """,
        subscription_id,
    )


# -- 事件与投递创建（载荷内容寻址 + 提交状态机） -----------------------------------
#
# 载荷不再直接写入 events.payload（该 JSONB 列只承载迁移前的旧数据）：
# 规范化 JSON 的 SHA-256 是对象键，字节本体在 S3 兼容对象存储中，
# event_payload_objects 保存元数据与引用计数，events.payload_digest 只做引用。
#
# “对象上传”与“数据库事务”无法用单一原子事务覆盖，因此提交由持久化状态机
# （payload_upload_pending）协调，崩溃恢复见 app/payloads.py:recover_pending：
#
#   1. 快速查重（(source,event_id) 已存在 -> 幂等返回，不触对象存储）；
#   2. 事务内登记 payload_upload_pending（含规范化字节，崩溃后可重放）：
#      - 已有别的进程为同一事件登记 -> 其进行中/残留，交由恢复流程，本次报冲突；
#   3. 终结事务（按摘要咨询锁内幂等 PUT 对象，再 upsert 对象元数据并维护引用
#      计数、插入事件（payload 置 NULL，只挂摘要）、建投递、删除 pending 行）：
#      单事务原子，外部只能看到“完全没有该事件”或“事件+投递+对象引用齐备”，
#      无半成品；PUT 与建引用同在与 GC 互斥的锁内，对象不会被并发 GC 删除；
#   4. 任一步失败：pending 行保留（字节就在行内，不依赖对象存储），恢复或
#      重试从第 3 步继续；终结事务回滚则没有悬空引用，重放整步即可。
#
# 同一 (source,event_id) 的并发提交由 events 唯一约束兜底；重复提交不新增投递
# 的幂等语义不变（第 1 步命中即直接返回原事件）。
#
# 与 GC 的引用互斥（关键）：
# “引用建立”与“对象物理删除”均持有按摘要划分的事务级咨询锁
# （payload_object_xact_lock，元数据行尚不存在的存储孤儿也能被覆盖——行锁
# 无法保护不存在的行）。引用方在同一事务、同一把锁内完成
# “锁 -> 确保对象在存储中（PUT）-> 建元数据/引用”，GC 在同一把锁内完成
# “锁 -> 最终复核 -> 物理删对象 -> 删元数据”，两者对同一摘要严格串行：
# 引用方先拿锁则 GC 复核必见引用而复活；GC 先拿锁则引用方等到对象删除完成后
# 再幂等重传同一内容寻址对象并建引用。无论元数据行是否存在，对象一旦被引用
# 都不会被删除。

# 载荷对象咨询锁的固定 classid（两参数形式 (classid, objid)，与一参数形式的
# 键空间独立；objid 取摘要前 8 个 hex 字符的有符号 int32 值，同一摘要恒定
# 映射同一把锁）。
_PAYLOAD_LOCK_CLASSID = 0x5041594C  # 'PAYL'
_INT32_WRAP = 1 << 32
_INT32_HALF = 1 << 31


def _digest_lock_key(digest: str) -> int:
    """摘要前 8 个 hex 字符 -> 有符号 int32（pg_advisory_xact_lock 的 objid）。"""
    value = int(digest[:8], 16)
    return value - _INT32_WRAP if value >= _INT32_HALF else value


async def payload_object_xact_lock(
    conn: asyncpg.Connection, digest: str
) -> None:
    """获取按摘要划分的事务级咨询锁（同事务内可重入，事务结束自动释放）。

    用于把同一内容对象的“引用建立/恢复/迁移”与 GC 的“最终复核+物理删除”
    串行化；覆盖 event_payload_objects 元数据行尚不存在的存储孤儿场景。
    """
    await conn.fetchval(
        "SELECT pg_advisory_xact_lock($1::int4, $2::int4)",
        _PAYLOAD_LOCK_CLASSID,
        _digest_lock_key(digest),
    )


async def payload_object_xact_locks_ordered(
    conn: asyncpg.Connection, digests: list[str]
) -> None:
    """按咨询锁“实际键”的全局统一顺序，一次性取齐一批摘要锁。

    死锁修复：并发迁移批次若各自按“本批事件顺序”逐把取锁，两批含相同摘要
    而事件顺序相反时（A 批 X→Y、B 批 Y→X）会形成 AB-BA 等待环而被 Postgres
    回滚。这里改为先汇总本批所需的全部摘要，按 (classid, objid) 升序统一
    取锁——任意并发批次的取锁顺序都一致，数学上不可能成环。

    - objid 只取摘要前 8 hex：不同摘要可能映射到同一把锁，按 objid 去重，
      同一把锁只获取一次（pg 咨询锁同事务可重入，重复获取无意义）；
    - 调用方须在事务内调用；锁在事务结束（提交/回滚）时统一释放，因此
      “上传对象 → 挂事件引用”全程持锁，与 GC 的“最终复核+物理删除”对同一
      摘要严格互斥，与单把 payload_object_xact_lock 的互斥语义完全相同。
    """
    unique_by_objid: dict[int, str] = {}
    for digest in digests:
        unique_by_objid.setdefault(_digest_lock_key(digest), digest)
    for _objid, digest in sorted(unique_by_objid.items()):
        await payload_object_xact_lock(conn, digest)


async def find_event_by_key(
    conn: asyncpg.Connection, source: str, event_id: str
) -> asyncpg.Record | None:
    """按业务键查重（状态机第 1 步）；返回行含 payload_digest/旧 payload。"""
    return await conn.fetchrow(
        """
        SELECT id, source, event_id, payload, payload_digest, created_at
        FROM events WHERE source = $1 AND event_id = $2
        """,
        source,
        event_id,
    )


async def get_pending_submission_for_event(
    conn: asyncpg.Connection, source: str, event_id: str
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT digest, source, event_id, payload_bytes, owner_id, created_at, updated_at
        FROM payload_upload_pending
        WHERE source = $1 AND event_id = $2
        """,
        source,
        event_id,
    )


async def register_pending_submission(
    conn: asyncpg.Connection,
    *,
    digest: str,
    source: str,
    event_id: str,
    payload_bytes: bytes,
    owner_id: str,
) -> asyncpg.Record:
    """登记提交状态机行（同事务）。

    以 (source,event_id) 为唯一键：调用方已先查事件/进行中冲突，正常路径不会
    撞键；同摘要可被多个不同事件并发引用（内容去重），互不影响各自的恢复。
    """
    return await conn.fetchrow(
        """
        INSERT INTO payload_upload_pending
            (digest, source, event_id, payload_bytes, owner_id)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, digest, source, event_id, payload_bytes, owner_id,
                  created_at, updated_at
        """,
        digest,
        source,
        event_id,
        payload_bytes,
        owner_id,
    )


async def adopt_pending_submission(
    conn: asyncpg.Connection, pending_id: int, owner_id: str
) -> None:
    await conn.execute(
        """
        UPDATE payload_upload_pending
        SET owner_id = $2, updated_at = now()
        WHERE id = $1
        """,
        pending_id,
        owner_id,
    )


async def delete_pending_submission(
    conn: asyncpg.Connection, source: str, event_id: str
) -> None:
    await conn.execute(
        "DELETE FROM payload_upload_pending WHERE source = $1 AND event_id = $2",
        source,
        event_id,
    )


async def finalize_event_submission(
    conn: asyncpg.Connection,
    *,
    source: str,
    event_id: str,
    digest: str,
    size_bytes: int,
) -> tuple[asyncpg.Record, bool]:
    """提交状态机终结（单事务，原子可见）。

    调用方必须已在同一连接上开启事务，并已在持有本摘要咨询锁的状态下完成
    对象存储 PUT（见 payloads._put_and_finalize）。本函数在事务内再次获取
    同一把可重入咨询锁，然后 upsert 元数据行、插入事件并建投递；事件唯一
    冲突说明并发重复提交已抢先完成：不增加引用计数，返回 (原事件行, True)。
    正常插入返回 (新事件行, False)。

    新事件 payload JSONB 列置 NULL——载荷本体只在对象存储；该列仅旧数据使用。
    """
    async with conn.transaction():
        # 与垃圾回收互斥：咨询锁覆盖“元数据行尚不存在”的存储孤儿情形，
        # 行锁再序列化元数据已存在时的引用计数维护；GC 的“行锁复核+物理
        # 删除”同样先取本咨询锁，两边对同一摘要不可能交错。
        await payload_object_xact_lock(conn, digest)
        await conn.execute(
            """
            INSERT INTO event_payload_objects (digest, size_bytes, ref_count)
            VALUES ($1, $2, 0)
            ON CONFLICT (digest) DO NOTHING
            """,
            digest,
            size_bytes,
        )
        # 行锁序列化对象的“引用建立”与 GC 的“行锁复核+删除”（咨询锁之外的
        # 第二重保险，且保证 ref_count 读改写不与其他提交互相丢更新）。
        await conn.execute(
            "SELECT digest FROM event_payload_objects WHERE digest = $1 FOR UPDATE",
            digest,
        )
        event_row = await conn.fetchrow(
            """
            INSERT INTO events (source, event_id, payload, payload_digest)
            VALUES ($1, $2, NULL, $3)
            ON CONFLICT (source, event_id) DO NOTHING
            RETURNING id, source, event_id, payload, payload_digest, created_at
            """,
            source,
            event_id,
            digest,
        )
        if event_row is None:
            # 并发重复提交：原事件已存在（其引用由先提交者持有），本次不计数。
            existing = await find_event_by_key(conn, source, event_id)
            await delete_pending_submission(conn, source, event_id)
            return existing, True

        await conn.execute(
            "UPDATE event_payload_objects SET ref_count = ref_count + 1 WHERE digest = $1",
            digest,
        )

        # 锁住该 source 的活跃订阅：与版本发布串行，读 current_revision 时无竞态。
        await conn.execute(
            """
            SELECT id FROM subscriptions
            WHERE source = $1 AND active = TRUE
            ORDER BY id
            FOR UPDATE
            """,
            source,
        )
        await conn.execute(
            """
            INSERT INTO deliveries
                (event_id_fk, subscription_id, config_version_id,
                 chain_id, chain_seq, status)
            SELECT e.id, s.id, v.id, nextval('delivery_chain_seq'), 1, 'pending'
            FROM events e
            JOIN subscriptions s ON s.source = $2 AND s.active = TRUE
            JOIN subscription_versions v
                 ON v.subscription_id = s.id AND v.revision = s.current_revision
            WHERE e.id = $1
            """,
            event_row["id"],
            source,
        )
        await delete_pending_submission(conn, source, event_id)
        return event_row, False


async def get_event(
    conn: asyncpg.Connection, event_pk: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT id, source, event_id, payload, payload_digest, created_at
        FROM events WHERE id = $1
        """,
        event_pk,
    )


# -- Worker：认领队首任务 --------------------------------------------------------

# 严格顺序的关键：
# 1) 先在事务中锁定该订阅“可投递且 seq 最小”的那一条（FOR UPDATE SKIP LOCKED）；
# 2) 检查它前面是否还有未终结的投递，有则跳过（保证前一事件成功或进死信后才动）；
# 3) 用 lease_token 栅栏把它置为 in_flight，旧租约必须已过期才可接管。
# 认领/重试/接管一律不改变 config_version_id：投递钉死在创建时的版本上。
async def claim_delivery(
    conn: asyncpg.Connection, worker_id: str
) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)
    lease_seconds = settings.lease_seconds
    lease_expires = now + timedelta(seconds=lease_seconds)
    lease_token = f"{worker_id}:{now.timestamp()}"

    async with conn.transaction():
        # 候选：每个订阅 seq 最小的可处理投递（pending 到点 或 租约过期的 in_flight）。
        # NOT EXISTS 保证严格顺序：前面还有未终结投递时不允许发送后续事件。
        candidate = await conn.fetchrow(
            """
            SELECT d.id, d.event_id_fk, d.subscription_id, d.status,
                   d.attempts_made, d.leased_by
            FROM deliveries d
            WHERE (
                    (d.status = 'pending' AND d.not_before <= $1)
                 OR (d.status = 'in_flight' AND d.lease_expires_at < $1)
                )
              AND NOT EXISTS (
                    SELECT 1
                    FROM subscriptions s
                    WHERE s.id = d.subscription_id AND s.active = FALSE
              )
              AND NOT EXISTS (
                    SELECT 1
                    FROM deliveries earlier
                    WHERE earlier.subscription_id = d.subscription_id
                      AND earlier.seq < d.seq
                      AND earlier.status IN ('pending', 'in_flight')
              )
            ORDER BY d.seq
            LIMIT 1
            FOR UPDATE OF d SKIP LOCKED
            """,
            now,
        )
        if candidate is None:
            return None

        updated = await conn.fetchrow(
            """
            UPDATE deliveries
            SET status = 'in_flight',
                leased_at = $2,
                lease_expires_at = $3,
                leased_by = $4,
                updated_at = $2
            WHERE id = $1
            RETURNING id, event_id_fk, subscription_id, config_version_id,
                      chain_id, chain_seq, attempts_made, status, not_before
            """,
            candidate["id"],
            now,
            lease_expires,
            lease_token,
        )
        if updated is None:
            return None

        return {
            "delivery": updated,
            "lease_token": lease_token,
            "leased_at": now,
            "lease_expires_at": lease_expires,
        }


async def load_delivery_context(
    conn: asyncpg.Connection, delivery_id: int
) -> asyncpg.Record | None:
    """加载投递上下文；target_url/密钥材料/重试参数全部取自投递钉住的版本。

    因而切换边界前创建的投递及其后续重试、接管，永远使用旧版本的 URL 与密钥。
    密钥的密文/包裹 DEK 在此一并取出，由 Worker 在签名前才解密（见
    app/envelope.py）；旧格式（迁移未完成）则回退读取 secret 明文列。
    """
    return await conn.fetchrow(
        """
        SELECT d.id AS delivery_id,
               d.attempts_made,
               e.id AS event_pk,
               e.source,
               e.event_id,
               e.payload,
               e.payload_digest,
               s.id AS subscription_pk,
               v.id AS config_version_pk,
               v.revision AS config_revision,
               v.target_url,
               v.secret,
               v.secret_ciphertext,
               v.secret_dek_wrapped,
               v.secret_key_id,
               v.max_attempts,
               v.backoff_base_seconds,
               v.backoff_cap_seconds
        FROM deliveries d
        JOIN events e ON e.id = d.event_id_fk
        JOIN subscriptions s ON s.id = d.subscription_id
        JOIN subscription_versions v ON v.id = d.config_version_id
        WHERE d.id = $1
        """,
        delivery_id,
    )


# -- Worker：记录尝试并结算 ------------------------------------------------------

async def record_attempt(
    conn: asyncpg.Connection,
    *,
    delivery_id: int,
    lease_token: str,
    worker_id: str,
    outcome: str,
    http_status: int | None,
    response_excerpt: str | None,
    error_message: str | None,
    leased_at: datetime,
    lease_expires_at: datetime,
) -> int | None:
    """在租约持有方身份校验通过后追加一条尝试记录并 attempts_made+1。

    返回新的 attempt_number；若租约已被接管则返回 None（本次结果作废）。
    """
    async with conn.transaction():
        locked = await conn.fetchrow(
            """
            SELECT leased_by FROM deliveries
            WHERE id = $1 FOR UPDATE
            """,
            delivery_id,
        )
        if locked is None or locked["leased_by"] != lease_token:
            return None

        attempt_number = await conn.fetchval(
            """
            INSERT INTO delivery_attempts
                (delivery_id, attempt_number, worker_id, outcome, http_status,
                 response_excerpt, error_message, leased_at, lease_expires_at,
                 finished_at)
            SELECT $1, COALESCE(MAX(attempt_number), 0) + 1, $2, $3, $4, $5, $6,
                   $7, $8, now()
            FROM delivery_attempts
            WHERE delivery_id = $1
            RETURNING attempt_number
            """,
            delivery_id,
            worker_id,
            outcome,
            http_status,
            response_excerpt,
            error_message,
            leased_at,
            lease_expires_at,
        )
        await conn.execute(
            "UPDATE deliveries SET attempts_made = attempts_made + 1, updated_at = now() WHERE id = $1",
            delivery_id,
        )
        return attempt_number


async def settle_delivery(
    conn: asyncpg.Connection,
    *,
    delivery_id: int,
    lease_token: str,
    succeeded: bool,
    not_before: datetime | None,
    max_attempts: int,
) -> str | None:
    """根据本次尝试结果结算。

    成功 -> succeeded；失败且已达该投递所钉版本的 max_attempts -> dead_lettered；
    否则回到 pending 并设置指数退避时间。返回结算后的状态；租约失效返回 None。
    """
    async with conn.transaction():
        locked = await conn.fetchrow(
            """
            SELECT attempts_made, leased_by FROM deliveries
            WHERE id = $1 FOR UPDATE
            """,
            delivery_id,
        )
        if locked is None or locked["leased_by"] != lease_token:
            return None

        if succeeded:
            status = "succeeded"
        elif locked["attempts_made"] >= max_attempts:
            status = "dead_lettered"
        else:
            status = "pending"

        await conn.execute(
            """
            UPDATE deliveries
            SET status = $2,
                not_before = COALESCE($3, now()),
                leased_at = NULL,
                lease_expires_at = NULL,
                leased_by = NULL,
                updated_at = now()
            WHERE id = $1
            """,
            delivery_id,
            status,
            not_before,
        )
        return status


# -- 查询：历史 / 死信 -----------------------------------------------------------

_DELIVERY_SELECT = f"""
    SELECT {DELIVERY_COLUMNS},
           e.source AS event_source,
           e.event_id AS source_event_id,
           v.target_url AS target_url,
           v.revision AS config_revision,
           v.id AS config_version_pk,
           v.created_at AS config_effective_at
    FROM deliveries d
    JOIN events e ON e.id = d.event_id_fk
    JOIN subscriptions s ON s.id = d.subscription_id
    JOIN subscription_versions v ON v.id = d.config_version_id
"""


async def list_deliveries(
    conn: asyncpg.Connection,
    *,
    status: str | None = None,
    subscription_id: int | None = None,
    config_revision: int | None = None,
    source: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        _DELIVERY_SELECT
        + """
        WHERE ($1::text IS NULL OR d.status = $1)
          AND ($2::bigint IS NULL OR d.subscription_id = $2)
          AND ($3::text IS NULL OR e.source = $3)
          AND ($4::int IS NULL OR v.revision = $4)
        ORDER BY d.id DESC
        LIMIT $5 OFFSET $6
        """,
        status,
        subscription_id,
        source,
        config_revision,
        limit,
        offset,
    )
    return list(rows)


async def get_delivery(
    conn: asyncpg.Connection, delivery_id: int
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        _DELIVERY_SELECT + " WHERE d.id = $1",
        delivery_id,
    )


async def list_attempts(
    conn: asyncpg.Connection, delivery_id: int
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id, attempt_number, worker_id, started_at, finished_at, outcome,
               http_status, response_excerpt, error_message,
               leased_at, lease_expires_at
        FROM delivery_attempts
        WHERE delivery_id = $1
        ORDER BY attempt_number
        """,
        delivery_id,
    )
    return list(rows)


async def list_deliveries_for_event(
    conn: asyncpg.Connection, event_pk: int
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        _DELIVERY_SELECT + " WHERE d.event_id_fk = $1 ORDER BY d.id",
        event_pk,
    )
    return list(rows)


# -- 死信重放 --------------------------------------------------------------------

async def replay_dead_letter(
    conn: asyncpg.Connection, delivery_id: int, *, use_current_version: bool = False
) -> tuple[asyncpg.Record, int]:
    """为死信投递新建一条投递链记录（同 chain_id，chain_seq+1），保留旧记录。

    配置版本固化在新投递上：
    - 默认沿用原投递钉住的版本（死信重放不改变 URL/密钥/重试参数）；
    - use_current_version=True 时显式选用订阅当前版本。

    原投递为非死信状态时抛 ReplayError(not_dead_lettered)；链上已有活动投递时
    抛 ReplayError(chain_busy)。返回新投递行（含 config_revision）。
    """
    async with conn.transaction():
        original = await conn.fetchrow(
            """
            SELECT d.id, d.event_id_fk, d.subscription_id, d.chain_id, d.chain_seq,
                   d.status, d.config_version_id
            FROM deliveries d
            WHERE d.id = $1
            FOR UPDATE
            """,
            delivery_id,
        )
        if original is None:
            raise LookupError("delivery not found")
        if original["status"] != "dead_lettered":
            raise ReplayError("not_dead_lettered", "只有死信状态的投递可以重放")

        busy = await conn.fetchval(
            """
            SELECT 1 FROM deliveries
            WHERE subscription_id = $1
              AND chain_id = $2
              AND status IN ('pending', 'in_flight')
            LIMIT 1
            """,
            original["subscription_id"],
            original["chain_id"],
        )
        if busy is not None:
            raise ReplayError("chain_busy", "该重放链上已有待投递/投递中的任务")

        if use_current_version:
            # 锁订阅行，与发布竞争时明确取已提交的当前版本。
            current = await conn.fetchrow(
                """
                SELECT v.id AS config_version_id, v.revision AS config_revision
                FROM subscriptions s
                JOIN subscription_versions v
                     ON v.subscription_id = s.id AND v.revision = s.current_revision
                WHERE s.id = $1
                FOR UPDATE OF s
                """,
                original["subscription_id"],
            )
            if current is None:  # 理论上不可能：订阅与版本必然存在
                raise ReplayError("no_current_version", "订阅当前配置版本不存在")
            config_version_id = current["config_version_id"]
            config_revision = current["config_revision"]
        else:
            pinned = await conn.fetchrow(
                """
                SELECT v.id AS config_version_id, v.revision AS config_revision
                FROM subscription_versions v
                WHERE v.id = $1
                """,
                original["config_version_id"],
            )
            config_version_id = pinned["config_version_id"]
            config_revision = pinned["config_revision"]

        # chain_seq 取链上已有最大值 + 1（多次重放时原记录 chain_seq 恒为 1，
        # 不能用 original.chain_seq + 1，否则第二次重放会撞唯一约束）。
        next_seq = await conn.fetchval(
            """
            SELECT COALESCE(MAX(chain_seq), 0) + 1
            FROM deliveries
            WHERE subscription_id = $1 AND chain_id = $2
            """,
            original["subscription_id"],
            original["chain_id"],
        )
        new_row = await conn.fetchrow(
            """
            INSERT INTO deliveries
                (event_id_fk, subscription_id, config_version_id,
                 chain_id, chain_seq, status)
            VALUES ($1, $2, $3, $4, $5, 'pending')
            RETURNING id, event_id_fk, subscription_id, config_version_id,
                      chain_id, chain_seq, status, attempts_made, not_before,
                      leased_at, lease_expires_at, leased_by, created_at, updated_at
            """,
            original["event_id_fk"],
            original["subscription_id"],
            config_version_id,
            original["chain_id"],
            next_seq,
        )
        # 附上 revision 供 API 响应使用
        return new_row, config_revision


# -- 密钥迁移与主密钥轮换（keyadmin） ---------------------------------------------
#
# 两类批处理都按“取一批（FOR UPDATE SKIP LOCKED）→ 处理 → 提交”循环，
# 因此天然幂等、可断点续跑（已处理的行不再满足筛选条件），且多个进程可并发
# 执行互不重复；与在线投递 Worker 并发安全（行级锁，投递读取不受阻塞）。

async def fetch_plaintext_versions_batch(
    conn: asyncpg.Connection, limit: int
) -> list[asyncpg.Record]:
    """取一批仍是明文的配置版本（调用方须在事务内，配合行锁处理）。"""
    rows = await conn.fetch(
        """
        SELECT id, subscription_id, secret
        FROM subscription_versions
        WHERE secret_ciphertext IS NULL
        ORDER BY id
        LIMIT $1
        FOR UPDATE SKIP LOCKED
        """,
        limit,
    )
    return list(rows)


async def mark_version_encrypted(
    conn: asyncpg.Connection,
    version_id: int,
    ciphertext: bytes,
    wrapped_dek: bytes,
    key_id: str,
) -> None:
    """把某版本写为信封格式并清空明文列（同事务保证不丢明文备份）。"""
    await conn.execute(
        """
        UPDATE subscription_versions
        SET secret_ciphertext = $2,
            secret_dek_wrapped = $3,
            secret_key_id = $4,
            secret = ''
        WHERE id = $1
        """,
        version_id,
        ciphertext,
        wrapped_dek,
        key_id,
    )


async def clear_subscription_secret_cache(conn: asyncpg.Connection) -> int:
    """清空 subscriptions.secret 冗余列中的遗留明文，返回清理行数。

    该列仅作兼容冗余，权威配置在版本表；投递链路从不读取它。
    """
    result = await conn.execute(
        "UPDATE subscriptions SET secret = '' WHERE secret <> ''"
    )
    return int(result.split()[-1])


async def fetch_rewrap_batch(
    conn: asyncpg.Connection,
    target_key_id: str,
    limit: int,
    from_key_id: str | None = None,
) -> list[asyncpg.Record]:
    """取一批尚未用目标主密钥包裹的信封版本（调用方须在事务内）。

    from_key_id 指定时只取该来源 key_id 的行。
    """
    rows = await conn.fetch(
        """
        SELECT id, secret_key_id, secret_dek_wrapped
        FROM subscription_versions
        WHERE secret_ciphertext IS NOT NULL
          AND secret_key_id IS DISTINCT FROM $1
          AND ($3::text IS NULL OR secret_key_id = $3)
        ORDER BY id
        LIMIT $2
        FOR UPDATE SKIP LOCKED
        """,
        target_key_id,
        limit,
        from_key_id,
    )
    return list(rows)


async def apply_rewrap(
    conn: asyncpg.Connection, version_id: int, wrapped_dek: bytes, key_id: str
) -> None:
    """更新某版本的 DEK 包裹与 key_id（只重包裹，不动密钥密文本身）。"""
    await conn.execute(
        """
        UPDATE subscription_versions
        SET secret_dek_wrapped = $2,
            secret_key_id = $3
        WHERE id = $1
        """,
        version_id,
        wrapped_dek,
        key_id,
    )


async def start_or_adopt_rotation(
    conn: asyncpg.Connection, new_key_id: str, old_key_id: str
) -> asyncpg.Record:
    """开始或接管一次轮换运行。

    存在同目标的 running（进行中/崩溃残留）或 failed（失败待恢复）记录时
    接管并置回 running，从已持久化的进度断点续跑；否则新建运行。

    返回 (运行记录, 是否为接管)。
    """
    for _attempt in range(2):
        async with conn.transaction():
            existing = await conn.fetchrow(
                """
                SELECT id, old_key_id, new_key_id, status, processed_count,
                       last_version_id, last_error, started_at, updated_at,
                       finished_at
                FROM key_rotations
                WHERE status IN ('running', 'failed') AND new_key_id = $1
                ORDER BY id
                LIMIT 1
                FOR UPDATE
                """,
                new_key_id,
            )
            if existing is not None:
                await conn.execute(
                    """
                    UPDATE key_rotations
                    SET status = 'running', last_error = NULL,
                        old_key_id = $2, updated_at = now(), finished_at = NULL
                    WHERE id = $1
                    """,
                    existing["id"],
                    old_key_id or existing["old_key_id"],
                )
                return existing, True
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO key_rotations (old_key_id, new_key_id, status)
                    VALUES ($2, $1, 'running')
                    RETURNING id, old_key_id, new_key_id, status, processed_count,
                              last_version_id, last_error, started_at, updated_at,
                              finished_at
                    """,
                    new_key_id,
                    old_key_id,
                )
                return row, False
            except asyncpg.UniqueViolationError:
                # 并发创建：另一进程已插入 running 记录；重试即走接管分支。
                continue
    raise RuntimeError("无法创建或接管轮换运行（并发冲突）")


async def update_rotation_progress(
    conn: asyncpg.Connection, rotation_id: int, processed: int, last_version_id: int
) -> None:
    """累加轮换进度（与当批重包裹在同一事务提交，崩溃后进度不超前于数据）。"""
    await conn.execute(
        """
        UPDATE key_rotations
        SET processed_count = processed_count + $2,
            last_version_id = GREATEST(last_version_id, $3),
            updated_at = now()
        WHERE id = $1
        """,
        rotation_id,
        processed,
        last_version_id,
    )


async def finish_rotation(
    conn: asyncpg.Connection, rotation_id: int, status: str, error: str | None = None
) -> None:
    await conn.execute(
        """
        UPDATE key_rotations
        SET status = $2, last_error = $3, updated_at = now(), finished_at = now()
        WHERE id = $1
        """,
        rotation_id,
        status,
        error,
    )


async def list_rotations(
    conn: asyncpg.Connection, limit: int = 10
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id, old_key_id, new_key_id, status, processed_count,
               last_version_id, last_error, started_at, updated_at, finished_at
        FROM key_rotations
        ORDER BY id DESC
        LIMIT $1
        """,
        limit,
    )
    return list(rows)


async def count_versions_by_key_id(conn: asyncpg.Connection) -> list[asyncpg.Record]:
    """按包裹 key_id 统计信封版本数（明文版本不在其中）。"""
    rows = await conn.fetch(
        """
        SELECT secret_key_id AS key_id, COUNT(*) AS n
        FROM subscription_versions
        WHERE secret_ciphertext IS NOT NULL
        GROUP BY secret_key_id
        ORDER BY secret_key_id
        """
    )
    return list(rows)


async def count_plaintext_versions(conn: asyncpg.Connection) -> int:
    return await conn.fetchval(
        "SELECT COUNT(*) FROM subscription_versions WHERE secret_ciphertext IS NULL"
    )


async def count_references_to_key(conn: asyncpg.Connection, key_id: str) -> int:
    """仍引用指定 key_id 的配置版本数（移除旧密钥前的安全检查）。"""
    return await conn.fetchval(
        """
        SELECT COUNT(*) FROM subscription_versions
        WHERE secret_ciphertext IS NOT NULL AND secret_key_id = $1
        """,
        key_id,
    )


# -- 事件载荷：在线迁移 / 恢复 / 垃圾回收 / 状态 ------------------------------------
#
# 与密钥迁移同样的“取一批（FOR UPDATE SKIP LOCKED）→ 处理 → 提交”循环，
# 幂等、断点续跑、可并发；与在线提交/Worker 互不阻塞（行级锁）。

async def fetch_legacy_events_batch(
    conn: asyncpg.Connection, *, limit: int
) -> list[asyncpg.Record]:
    """取一批仍以 JSONB 自存载荷（payload_digest 为空）的旧事件。

    不用单调 id 游标过滤：游标 + SKIP LOCKED 组合在并发下会漏行——若较早的
    事件被另一迁移者锁住（随后其批次回滚），本进程会跳过锁领到较晚事件并把
    游标越过较早行，导致回滚释放的旧行在重跑时永不可再领取。这里每批都从
    仍未迁移的集合（部分索引 idx_events_legacy_payload）重新领取，行一旦
    迁移成功即不再满足筛选条件，断点续跑进度只依赖“剩余集合”本身。
    """
    rows = await conn.fetch(
        """
        SELECT id, payload
        FROM events
        WHERE payload_digest IS NULL
        ORDER BY id
        LIMIT $1
        FOR UPDATE SKIP LOCKED
        """,
        limit,
    )
    return list(rows)


async def attach_payload_object_to_event(
    conn: asyncpg.Connection,
    *,
    event_id_fk: int,
    digest: str,
    size_bytes: int,
) -> bool:
    """把旧事件挂到内容寻址对象（同事务 upsert 元数据并维护引用计数）。

    返回该行是否确由本次调用挂接（True）。行锁领取保证并发迁移者不会处理
    同一行，但仍以防卫性条件更新（仅当 payload_digest 为空时才挂接/计数），
    使重复运行不可能重复计数或新增引用。

    对象字节由调用方（payloadadmin）在已持有本摘要咨询锁的状态下幂等上传到
    对象存储（见 payloads.migrate_legacy_payloads）；此处只做数据库侧链接，
    因此与新提交共用同一份不可变对象、自动去重。咨询锁使引用建立与 GC 的
    “最终复核+物理删除”互斥，杜绝迁移与 GC 并发时（含元数据行尚不存在的
    存储孤儿）的悬空引用。
    """
    await payload_object_xact_lock(conn, digest)
    await conn.execute(
        """
        INSERT INTO event_payload_objects (digest, size_bytes, ref_count)
        VALUES ($1, $2, 0)
        ON CONFLICT (digest) DO NOTHING
        """,
        digest,
        size_bytes,
    )
    await conn.execute(
        "SELECT digest FROM event_payload_objects WHERE digest = $1 FOR UPDATE",
        digest,
    )
    result = await conn.execute(
        """
        UPDATE events SET payload_digest = $2
        WHERE id = $1 AND payload_digest IS NULL
        """,
        event_id_fk,
        digest,
    )
    attached = int(result.split()[-1]) == 1
    if attached:
        await conn.execute(
            "UPDATE event_payload_objects SET ref_count = ref_count + 1 WHERE digest = $1",
            digest,
        )
    return attached


async def get_migration_state(conn: asyncpg.Connection) -> asyncpg.Record:
    return await conn.fetchrow(
        "SELECT id, status, last_event_id, processed, last_error, updated_at FROM payload_migration_state WHERE id = 1"
    )


async def update_migration_progress(
    conn: asyncpg.Connection, *, last_event_id: int, processed_delta: int
) -> None:
    """推进迁移进度：last_event_id 仅作观测高水位，不再用于领取过滤。

    进度权威来自仍待迁移集合（payload_digest IS NULL）本身，因此回滚行
    重新出现时不会被高水位挡住，重复运行也不会重复计数（挂接为防卫性
    条件更新，processed 只随实际挂接的行数增加）。
    """
    if processed_delta <= 0:
        return
    await conn.execute(
        """
        UPDATE payload_migration_state
        SET last_event_id = GREATEST(last_event_id, $1),
            processed = processed + $2,
            status = 'running',
            last_error = NULL,
            updated_at = now()
        WHERE id = 1
        """,
        last_event_id,
        processed_delta,
    )


async def reopen_migration_if_legacy_remaining(conn: asyncpg.Connection) -> None:
    """纠正“status=completed 但仍有旧行”的陈旧状态（旧实现并发误判的修复）。

    旧实现可能在空批/短批（实为别的迁移者持锁、随后该批回滚）时把状态写成
    completed 并以单调游标越过未处理行。completed 只能在“确无旧载荷”时
    成立，因此发现剩余即重开为 running（保留 processed 高水位，仅纠正状态）。
    """
    await conn.execute(
        """
        UPDATE payload_migration_state
        SET status = 'running', last_error = NULL, updated_at = now()
        WHERE id = 1 AND status = 'completed'
          AND EXISTS (SELECT 1 FROM events WHERE payload_digest IS NULL)
        """
    )


async def set_migration_status(
    conn: asyncpg.Connection, status: str, error: str | None = None
) -> None:
    await conn.execute(
        """
        UPDATE payload_migration_state
        SET status = $1, last_error = $2, updated_at = now()
        WHERE id = 1
        """,
        status,
        error,
    )


async def count_legacy_events(conn: asyncpg.Connection) -> int:
    return await conn.fetchval(
        "SELECT COUNT(*) FROM events WHERE payload_digest IS NULL"
    )


async def clear_legacy_payloads(conn: asyncpg.Connection, limit: int) -> int:
    """迁移完成后清空 events.payload 旧 JSONB（分批，返回本批清空行数）。

    仅清空已挂对象引用的行；未迁移行保留，因此任何时刻双读都有数据源。
    """
    result = await conn.execute(
        """
        UPDATE events SET payload = NULL
        WHERE id IN (
            SELECT id FROM events
            WHERE payload_digest IS NOT NULL AND payload IS NOT NULL
            LIMIT $1
        )
        """,
        limit,
    )
    return int(result.split()[-1])


# ---- 提交状态机崩溃恢复 ----

async def list_stale_pending(
    conn: asyncpg.Connection, *, stale_before: datetime, limit: int
) -> list[asyncpg.Record]:
    """列出崩溃/中断残留的提交状态机行（updated_at 早于阈值，可安全接管）。"""
    rows = await conn.fetch(
        """
        SELECT id, digest, source, event_id, payload_bytes, owner_id,
               created_at, updated_at
        FROM payload_upload_pending
        WHERE updated_at < $1
        ORDER BY updated_at
        LIMIT $2
        FOR UPDATE SKIP LOCKED
        """,
        stale_before,
        limit,
    )
    return list(rows)


# ---- 垃圾回收 ----

async def mark_gc_candidates(conn: asyncpg.Connection, grace_seconds: int) -> int:
    """标记阶段：把“零引用且超过宽限期仍零引用”的对象纳入候选（幂等）。

    三重保护，保证并发提交/重放正在引用的对象不被误删：
    1. 只收集 event_payload_objects.ref_count = 0 的对象；
    2. NOT EXISTS payload_upload_pending：进行中的提交（对象尚未在终结事务
       建引用）不进入候选，避免“上传中即被标记”；
    3. 候选首次见时间戳 + 宽限期（sweep 时再判一次），跨越宽限期的引用
       抖动（旧事件对象删除后新事件恰好复用同一载荷）在 sweep 复核被复活。
    """
    result = await conn.execute(
        """
        INSERT INTO payload_gc_candidates (digest)
        SELECT o.digest
        FROM event_payload_objects o
        WHERE o.ref_count = 0
          AND NOT EXISTS (
              SELECT 1 FROM payload_upload_pending p WHERE p.digest = o.digest
          )
        ON CONFLICT (digest) DO NOTHING
        """,
    )
    return int(result.split()[-1])


async def list_gc_candidates(
    conn: asyncpg.Connection, *, grace_before: datetime, limit: int
) -> list[str]:
    rows = await conn.fetch(
        """
        SELECT digest
        FROM payload_gc_candidates
        WHERE first_seen_at < $1
        ORDER BY first_seen_at
        LIMIT $2
        """,
        grace_before,
        limit,
    )
    return [r["digest"] for r in rows]


async def pending_exists_for_digest(conn: asyncpg.Connection, digest: str) -> bool:
    """是否存在引用该摘要的进行中提交状态机行。"""
    return (
        await conn.fetchval(
            "SELECT 1 FROM payload_upload_pending WHERE digest = $1 LIMIT 1",
            digest,
        )
        is not None
    )


async def recheck_gc_candidate(
    conn: asyncpg.Connection, digest: str
) -> str:
    """删除前的最终引用复核（调用方需已开启事务，本函数获取互斥锁）。

    在调用方事务内先获取按摘要的咨询锁（与所有“引用建立”路径互斥，覆盖
    元数据行尚不存在的存储孤儿），再对对象元数据行加行锁后判定。引用真相应
    同时看两处：缓存的 ref_count 计数与“是否存在真正引用该摘要的 events 行”
    （后者是外键的权威来源，防止计数与实际引用短暂不一致时误删）。返回：
    - 'gone'     ：候选行已不存在（被并发 GC 处理），本轮跳过；
    - 'delete'   ：零引用且无进行中提交（或元数据不存在的存储孤儿键）；
    - 'reanimate'：引用已重建（并发提交/恢复/迁移复用了同一内容对象）或仍有
                   进行中提交，候选移除、对象保留。
    """
    await payload_object_xact_lock(conn, digest)
    candidate = await conn.fetchval(
        "SELECT 1 FROM payload_gc_candidates WHERE digest = $1 FOR UPDATE",
        digest,
    )
    if candidate is None:
        return "gone"
    obj = await conn.fetchrow(
        "SELECT ref_count FROM event_payload_objects WHERE digest = $1 FOR UPDATE",
        digest,
    )
    in_flight = await pending_exists_for_digest(conn, digest)
    if in_flight:
        return "reanimate"
    if obj is not None and obj["ref_count"] > 0:
        return "reanimate"
    # 权威复核：是否有事件行真正此外键引用该摘要（咨询锁+行锁已与所有提交
    # 路径串行，此处读到的是一致视图）。即便 ref_count 计数尚未同步，只要
    # 存在引用行就必须复活，否则物理删除会违反外键/造成悬空引用。
    referenced = await conn.fetchval(
        "SELECT 1 FROM events WHERE payload_digest = $1 LIMIT 1",
        digest,
    )
    if referenced is not None:
        return "reanimate"
    return "delete"


async def delete_payload_metadata_locked(
    conn: asyncpg.Connection, digest: str
) -> None:
    """在已持有行锁的事务内删除候选行与（确认零引用的）对象元数据。

    删除条件以“不存在引用该摘要的 events 行”为权威守卫（而非仅看缓存的
    ref_count），与 recheck_gc_candidate 一致，杜绝计数滞后时违反外键。
    """
    await conn.execute(
        "DELETE FROM payload_gc_candidates WHERE digest = $1", digest
    )
    await conn.execute(
        """
        DELETE FROM event_payload_objects o
        WHERE o.digest = $1
          AND o.ref_count = 0
          AND NOT EXISTS (SELECT 1 FROM events e WHERE e.payload_digest = o.digest)
        """,
        digest,
    )


async def remove_gc_candidate(conn: asyncpg.Connection, digest: str) -> None:
    """复活：引用已重建，移除候选（对象保留）。"""
    await conn.execute(
        "DELETE FROM payload_gc_candidates WHERE digest = $1", digest
    )


async def rollback_gc_candidate(conn: asyncpg.Connection, digest: str) -> None:
    """对象删除失败时回滚本候选：宽限重新计时，下次 GC 重试。"""
    await conn.execute(
        "UPDATE payload_gc_candidates SET first_seen_at = now() WHERE digest = $1",
        digest,
    )


async def get_payload_object(
    conn: asyncpg.Connection, digest: str
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT digest, size_bytes, ref_count, created_at
        FROM event_payload_objects WHERE digest = $1
        """,
        digest,
    )


async def list_payload_objects(
    conn: asyncpg.Connection, limit: int = 1000
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT digest, size_bytes, ref_count, created_at
        FROM event_payload_objects
        ORDER BY digest
        LIMIT $1
        """,
        limit,
    )
    return list(rows)


async def count_payload_objects(conn: asyncpg.Connection) -> int:
    return await conn.fetchval("SELECT COUNT(*) FROM event_payload_objects")


async def count_payload_candidates(conn: asyncpg.Connection) -> int:
    return await conn.fetchval("SELECT COUNT(*) FROM payload_gc_candidates")


async def gc_candidate_overview(conn: asyncpg.Connection) -> asyncpg.Record:
    """GC 候选聚合：候选总数、已过宽限期待删数、最老候选年龄（秒）。"""
    grace_before = datetime.now(timezone.utc) - timedelta(
        seconds=settings.payload_gc_grace_seconds
    )
    return await conn.fetchrow(
        """
        SELECT COUNT(*)                                              AS candidates,
               COUNT(*) FILTER (WHERE first_seen_at < $1)            AS due,
               COALESCE(EXTRACT(EPOCH FROM (now() - MIN(first_seen_at))), 0)
                   AS oldest_age_seconds
        FROM payload_gc_candidates
        """,
        grace_before,
    )


async def get_gc_candidate(
    conn: asyncpg.Connection, digest: str
) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT digest, first_seen_at
        FROM payload_gc_candidates WHERE digest = $1
        """,
        digest,
    )


async def count_pending_submissions(conn: asyncpg.Connection) -> int:
    return await conn.fetchval("SELECT COUNT(*) FROM payload_upload_pending")


async def start_gc_run(
    conn: asyncpg.Connection, *, rescanned_store: bool
) -> int:
    return await conn.fetchval(
        """
        INSERT INTO payload_gc_runs (status, rescanned_store)
        VALUES ('running', $1)
        RETURNING id
        """,
        rescanned_store,
    )


async def update_gc_run(
    conn: asyncpg.Connection,
    run_id: int,
    *,
    candidates: int,
    deleted: int,
    status: str,
    error: str | None = None,
) -> None:
    await conn.execute(
        """
        UPDATE payload_gc_runs
        SET status = $2, candidates = $3, deleted_objects = $4,
            last_error = $5,
            finished_at = CASE WHEN $2 = 'running' THEN NULL ELSE now() END
        WHERE id = $1
        """,
        run_id,
        status,
        candidates,
        deleted,
        error,
    )


async def list_gc_runs(conn: asyncpg.Connection, limit: int = 10) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id, status, candidates, deleted_objects, rescanned_store,
               last_error, started_at, finished_at
        FROM payload_gc_runs
        ORDER BY id DESC
        LIMIT $1
        """,
        limit,
    )
    return list(rows)
