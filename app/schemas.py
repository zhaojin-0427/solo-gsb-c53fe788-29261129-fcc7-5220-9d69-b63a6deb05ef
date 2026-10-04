"""API 请求/响应模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    source: str = Field(min_length=1, max_length=200, examples=["orders"])
    event_id: str = Field(min_length=1, max_length=200, examples=["evt-1001"])
    payload: dict[str, Any] = Field(default_factory=dict)


class EventOut(BaseModel):
    id: int
    source: str
    event_id: str
    payload: dict[str, Any]
    # 载荷对象的内容地址（规范化 JSON 的 SHA-256）；旧数据迁移完成前可能为 None
    payload_digest: str | None = None
    created_at: datetime
    duplicate: bool = False


class SubscriptionCreate(BaseModel):
    source: str = Field(min_length=1, max_length=200)
    # 注意：不用 pydantic HttpUrl——出站安全策略（scheme 白名单、禁止 userinfo、
    # 解析地址校验）在 API 层统一执行并返回结构化 422（见 app/egress_policy.py）
    target_url: str = Field(min_length=1, max_length=2000)
    secret: str = Field(min_length=8, max_length=400)
    # 初始版本（revision=1）的重试参数；缺省取服务端全局默认（见配置表）
    max_attempts: int | None = Field(default=None, ge=1, le=100)
    backoff_base_seconds: float | None = Field(default=None, gt=0, le=86400)
    backoff_cap_seconds: float | None = Field(default=None, gt=0, le=86400)


class SubscriptionOut(BaseModel):
    id: int
    source: str
    target_url: str
    active: bool
    current_revision: int
    created_at: datetime


class VersionPublish(BaseModel):
    """发布订阅配置新版本。

    target_url/secret/重试参数构成新的不可变版本；重试参数缺省继承当前版本。
    expected_revision 必填（CAS）：必须等于调用方所见的当前 revision，否则 409。
    """

    target_url: str = Field(min_length=1, max_length=2000)
    secret: str = Field(min_length=8, max_length=400)
    expected_revision: int = Field(ge=1)
    max_attempts: int | None = Field(default=None, ge=1, le=100)
    backoff_base_seconds: float | None = Field(default=None, gt=0, le=86400)
    backoff_cap_seconds: float | None = Field(default=None, gt=0, le=86400)


class VersionOut(BaseModel):
    """配置版本视图：含实际版本与切换边界，但绝不包含 secret。"""

    version_id: int
    subscription_id: int
    revision: int
    target_url: str
    max_attempts: int
    backoff_base_seconds: float
    backoff_cap_seconds: float
    # 包裹该版本 DEK 的主密钥标识（仅标识符，不含任何密钥材料）
    secret_key_id: str | None = None
    # 该版本成为当前版本（切换边界开始）的时刻
    created_at: datetime
    # 被下一版本取代（切换边界结束）的时刻；当前版本为 None
    superseded_at: datetime | None = None
    is_current: bool


class AttemptOut(BaseModel):
    id: int
    attempt_number: int
    worker_id: str
    started_at: datetime
    finished_at: datetime | None
    outcome: Literal[
        "success", "http_error", "network_error", "timeout",
        "security_blocked", "crypto_error", "payload_integrity"
    ]
    http_status: int | None
    response_excerpt: str | None
    error_message: str | None
    leased_at: datetime | None
    lease_expires_at: datetime | None


class DeliveryOut(BaseModel):
    id: int
    event_id_fk: int
    subscription_id: int
    event_source: str | None = None
    source_event_id: str | None = None
    # 实际投递目标（该投递钉住版本的 target_url，非订阅当前 URL）
    target_url: str | None = None
    # 该投递实际固化使用的配置版本，及其切换边界（生效时刻）
    config_version_id: int
    config_revision: int
    config_effective_at: datetime
    chain_id: int | None = None
    chain_seq: int
    status: Literal["pending", "in_flight", "succeeded", "dead_lettered"]
    attempts_made: int
    not_before: datetime
    leased_at: datetime | None
    lease_expires_at: datetime | None
    leased_by: str | None
    created_at: datetime
    updated_at: datetime


class ReplayRequest(BaseModel):
    # 默认沿用原投递版本；显式 true 时选用订阅当前版本
    use_current_version: bool = False


class ReplayOut(BaseModel):
    replayed_from_delivery_id: int
    new_delivery_id: int
    chain_id: int
    chain_seq: int
    status: str
    # 新投递固化的配置版本（默认与原投递相同）
    config_revision: int


# -- 密钥信封加密 / 轮换状态 ---------------------------------------------------------


class RotationRunOut(BaseModel):
    id: int
    old_key_id: str
    new_key_id: str
    status: str
    processed_count: int
    last_version_id: int
    last_error: str | None
    started_at: datetime
    updated_at: datetime
    finished_at: datetime | None


class CryptoStatusOut(BaseModel):
    """密钥环与信封加密状态（只含 key_id 标识符，绝不含密钥材料/明文）。"""

    keyring_configured: bool
    active_key_id: str | None
    key_ids: list[str]
    # 仍是明文、待迁移的配置版本数
    plaintext_versions_pending: int
    # 信封版本按包裹 key_id 的分布
    encrypted_versions_by_key_id: dict[str, int]
    # 数据库引用但本地密钥环中不存在的 key_id（这些版本的投递会被拒绝）
    unknown_key_ids_in_use: list[str]
    rotations: list[RotationRunOut]


class GCRunOut(BaseModel):
    id: int
    status: str
    candidates: int
    deleted_objects: int
    rescanned_store: bool
    last_error: str | None
    started_at: datetime
    finished_at: datetime | None


class PayloadStorageStatusOut(BaseModel):
    """事件载荷对象存储与迁移/回收状态（不含载荷内容）。"""

    store_mode: str
    bucket: str | None = None
    total_events: int
    # 仍只有 JSONB、未挂对象引用的旧事件数（双读迁移剩余量）
    legacy_events_pending: int
    # 去重后的不可变对象数与引用总数（引用数应 == 已迁移事件数）
    payload_objects: int
    total_references: int
    total_object_bytes: int
    # 提交状态机残留（崩溃待恢复）与 GC 候选数
    pending_submissions: int
    gc_candidates: int
    gc_grace_seconds: int
    migration: dict[str, Any]
    gc_runs: list[GCRunOut]


# -- 垃圾回收状态查询 ---------------------------------------------------------------


class GCStatusOut(BaseModel):
    """垃圾回收状态总览（只含计数/时间，绝不含载荷内容）。"""

    gc_grace_seconds: int
    # 当前候选总数；其中已过宽限期、下一轮 gc 可进入最终复核删除的数量
    candidates: int
    due_candidates: int
    # 最老候选已等待的秒数（无候选为 0）
    oldest_candidate_age_seconds: float
    # 进行中的提交状态机行数（这些摘要绝不会被删）
    pending_submissions: int
    recent_runs: list[GCRunOut]


class GCCandidateOut(BaseModel):
    """单个对象摘要的回收状态。"""

    digest: str
    # 是否在 GC 候选表中
    is_candidate: bool
    first_seen_at: datetime | None = None
    # 预计可被物理删除的最早时刻（first_seen_at + 宽限期）；非候选为 None
    eligible_at: datetime | None = None
    # 宽限期是否已过（下一轮 gc 会对其做最终复核删除）
    eligible_now: bool
    # 对象元数据（无元数据行的存储孤儿为 None）
    size_bytes: int | None = None
    ref_count: int | None = None
    object_metadata_exists: bool
    # 是否存在引用该摘要的进行中提交（存在则不会被删）
    pending_submission: bool
    gc_grace_seconds: int
