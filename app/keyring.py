"""本地密钥环（keyring）：主密钥的加载与 DEK 包裹/解包。

密钥环完全来自本地配置（环境变量或文件），**不存数据库**：

- `WEBHOOK_KEYRING_JSON`：JSON 字符串（非空时优先）；
- `WEBHOOK_KEYRING_FILE`：JSON 文件路径（JSON 环境变量为空时使用）。

格式：

```json
{
  "active_key_id": "k1",
  "keys": {"k1": "<base64 编码的 32 字节主密钥>", "k2": "<base64 ...>"}
}
```

- `active_key_id`：包裹**新** DEK 使用的主密钥；轮换时把它指向新密钥即可让
  新写入的配置版本使用新主密钥。
- `keys` 中可同时保留多把主密钥：轮换期间新旧并存，旧 DEK 仍可解包，
  投递不中断；全部记录重包裹到新 key_id 后才允许移除旧密钥
  （`python -m app.keyadmin remove-key` 带引用检查）。

DEK 包裹格式（`secret_dek_wrapped` 列）：

    "WK1" || nonce(12B) || AES-256-GCM(key)[DEK] || tag(16B)

包裹的 AAD 绑定 key_id（`webhook-dek-wrap:v1:<key_id>`），防止把某把主密钥
包裹的 DEK 移到另一把主密钥名下使用。
"""
from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings

log = logging.getLogger("webhook.keyring")

WRAP_MAGIC = b"WK1"
NONCE_SIZE = 12
DEK_SIZE = 32  # AES-256
MASTER_KEY_SIZE = 32  # AES-256

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class KeyringConfigError(Exception):
    """密钥环配置存在但非法（启动即失败，避免静默降级）。"""


class UnknownKeyIdError(Exception):
    """记录引用的 key_id 不在本地密钥环中。"""

    def __init__(self, key_id: str):
        super().__init__(f"密钥环中不存在 key_id={key_id!r}")
        self.key_id = key_id


class KeyUnwrapError(Exception):
    """DEK 解包失败（主密钥不匹配或数据损坏/被篡改）。"""


def _wrap_aad(key_id: str) -> bytes:
    return f"webhook-dek-wrap:v1:{key_id}".encode("ascii")


def _decode_key(key_id: str, raw: str) -> bytes:
    try:
        key = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyringConfigError(f"密钥 {key_id!r} 不是合法的 base64: {exc}") from exc
    if len(key) != MASTER_KEY_SIZE:
        raise KeyringConfigError(
            f"密钥 {key_id!r} 解码后为 {len(key)} 字节，主密钥必须是 "
            f"{MASTER_KEY_SIZE} 字节（AES-256）"
        )
    return key


@dataclass(frozen=True)
class Keyring:
    """内存中的主密钥集合；进程启动时加载一次。"""

    active_key_id: str
    keys: dict[str, bytes]

    @classmethod
    def from_dict(cls, data: object) -> "Keyring":
        if not isinstance(data, dict):
            raise KeyringConfigError("密钥环 JSON 必须是对象")
        active = data.get("active_key_id")
        raw_keys = data.get("keys")
        if not isinstance(active, str) or not active:
            raise KeyringConfigError("密钥环缺少 active_key_id")
        if not isinstance(raw_keys, dict) or not raw_keys:
            raise KeyringConfigError("密钥环 keys 必须是非空对象")
        keys: dict[str, bytes] = {}
        for key_id, raw in raw_keys.items():
            if not isinstance(key_id, str) or not _KEY_ID_RE.match(key_id):
                raise KeyringConfigError(
                    f"非法 key_id {key_id!r}：仅允许字母数字与 . _ -，最长 64"
                )
            if not isinstance(raw, str):
                raise KeyringConfigError(f"密钥 {key_id!r} 的值必须是 base64 字符串")
            keys[key_id] = _decode_key(key_id, raw)
        if active not in keys:
            raise KeyringConfigError(
                f"active_key_id={active!r} 不在 keys 中（现有: {sorted(keys)}）"
            )
        return cls(active_key_id=active, keys=keys)

    @property
    def key_ids(self) -> list[str]:
        return sorted(self.keys)

    def wrap_dek(self, dek: bytes) -> tuple[str, bytes]:
        """用当前活跃主密钥包裹 DEK，返回 (key_id, wrapped_blob)。"""
        return self.active_key_id, self.wrap_dek_with(self.active_key_id, dek)

    def wrap_dek_with(self, key_id: str, dek: bytes) -> bytes:
        """用指定主密钥包裹 DEK（轮换重包裹时使用；不产生明文密钥）。"""
        key = self.keys.get(key_id)
        if key is None:
            raise UnknownKeyIdError(key_id)
        if len(dek) != DEK_SIZE:
            raise ValueError(f"DEK 必须是 {DEK_SIZE} 字节，收到 {len(dek)}")
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(key).encrypt(nonce, dek, _wrap_aad(key_id))
        return WRAP_MAGIC + nonce + ciphertext

    def unwrap_dek(self, key_id: str, blob: bytes) -> bytes:
        """解包 DEK；key_id 未知或认证失败时抛异常（不含任何密钥材料）。"""
        key = self.keys.get(key_id)
        if key is None:
            raise UnknownKeyIdError(key_id)
        if (
            not isinstance(blob, (bytes, bytearray, memoryview))
            or len(blob) < len(WRAP_MAGIC) + NONCE_SIZE + 16
            or bytes(blob[: len(WRAP_MAGIC)]) != WRAP_MAGIC
        ):
            raise KeyUnwrapError(f"key_id={key_id} 的 DEK 包裹格式非法")
        blob = bytes(blob)
        nonce = blob[len(WRAP_MAGIC) : len(WRAP_MAGIC) + NONCE_SIZE]
        ciphertext = blob[len(WRAP_MAGIC) + NONCE_SIZE :]
        try:
            dek = AESGCM(key).decrypt(nonce, ciphertext, _wrap_aad(key_id))
        except Exception as exc:  # InvalidTag 等：密钥不匹配或数据被篡改
            raise KeyUnwrapError(
                f"key_id={key_id} 的 DEK 解包认证失败（主密钥不匹配或数据损坏）"
            ) from exc
        if len(dek) != DEK_SIZE:
            raise KeyUnwrapError(f"key_id={key_id} 解包出的 DEK 长度非法")
        return dek


def load_keyring() -> Keyring | None:
    """按配置加载密钥环；未配置返回 None，配置非法抛 KeyringConfigError。"""
    raw_json = settings.keyring_json.strip()
    source = "WEBHOOK_KEYRING_JSON"
    if not raw_json:
        path = settings.keyring_file.strip()
        if not path:
            return None
        source = path
        try:
            with open(path, "r", encoding="utf-8") as fh:
                raw_json = fh.read()
        except OSError as exc:
            raise KeyringConfigError(f"无法读取密钥环文件 {path}: {exc}") from exc
    try:
        data = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise KeyringConfigError(f"密钥环（{source}）不是合法 JSON: {exc}") from exc
    try:
        return Keyring.from_dict(data)
    except KeyringConfigError as exc:
        raise KeyringConfigError(f"密钥环（{source}）配置非法: {exc}") from exc


_keyring: Keyring | None = None
_loaded = False


def get_keyring() -> Keyring | None:
    """进程级单例；未配置返回 None（调用方决定降级行为）。"""
    global _keyring, _loaded
    if not _loaded:
        _keyring = load_keyring()
        _loaded = True
        if _keyring is None:
            log.warning(
                "未配置本地密钥环（WEBHOOK_KEYRING_JSON / WEBHOOK_KEYRING_FILE）："
                "无法写入新配置版本，已加密的版本密钥也无法解密投递"
            )
        else:
            log.info(
                "本地密钥环已加载：active_key_id=%s，共 %d 把主密钥",
                _keyring.active_key_id,
                len(_keyring.keys),
            )
    return _keyring


def require_keyring() -> Keyring:
    """要求密钥环必须配置（keyadmin 等管理命令使用）。"""
    keyring = get_keyring()
    if keyring is None:
        raise KeyringConfigError(
            "未配置本地密钥环：请设置 WEBHOOK_KEYRING_JSON 或 WEBHOOK_KEYRING_FILE"
        )
    return keyring


def reset_keyring_cache() -> None:
    """清空进程内缓存（测试用）。"""
    global _keyring, _loaded
    _keyring = None
    _loaded = False
