"""订阅 HMAC 密钥的信封加密（envelope encryption）。

每个配置版本保存密钥时：

1. 生成一把随机的 32 字节 DEK（数据加密密钥）；
2. 用 DEK 以 AES-256-GCM 加密 HMAC 密钥明文，AAD 绑定
   `(subscription_id, version_id)`——密文被钉死在这一行上，
   复制到其他行无法通过认证；
3. 用本地密钥环的活跃主密钥包裹 DEK（见 `app/keyring.py`），
   只把 `secret_ciphertext`、`secret_dek_wrapped`、`secret_key_id`
   写入数据库，明文不落盘。

读取路径（仅 Worker 投递前）：

- `secret_ciphertext` 非空 → 解包 DEK 后解密（信封格式）；
- 否则回退读取 `secret` 明文列（迁移前的旧格式），保证批量迁移期间
  新旧格式均可投递、不中断。

任何解密失败都抛 `SecretCryptoError`（带机器可读 code），由 Worker 记录为
可查询的 `crypto_error` 尝试结果并拒绝投递；明文密钥不出现在日志与 API 中。
"""
from __future__ import annotations

import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.keyring import DEK_SIZE, Keyring, KeyUnwrapError, UnknownKeyIdError

SECRET_MAGIC = b"SC1"
NONCE_SIZE = 12


class SecretCryptoError(Exception):
    """密钥解密/解包失败；code 可检索，message 不含明文与密钥材料。"""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _aad(subscription_id: int, version_id: int) -> bytes:
    return f"webhook-secret:v1:{subscription_id}:{version_id}".encode("ascii")


def generate_dek() -> bytes:
    return os.urandom(DEK_SIZE)


def encrypt_secret(
    dek: bytes, subscription_id: int, version_id: int, secret: str
) -> bytes:
    """用 DEK 加密密钥明文，返回 `SC1 || nonce || ciphertext || tag`。"""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(dek).encrypt(
        nonce, secret.encode("utf-8"), _aad(subscription_id, version_id)
    )
    return SECRET_MAGIC + nonce + ciphertext


def decrypt_secret(
    dek: bytes, subscription_id: int, version_id: int, blob: bytes
) -> str:
    """解密并校验 AAD；任何失败抛 SecretCryptoError(decrypt_failed)。"""
    blob = bytes(blob)
    if (
        len(blob) < len(SECRET_MAGIC) + NONCE_SIZE + 16
        or blob[: len(SECRET_MAGIC)] != SECRET_MAGIC
    ):
        raise SecretCryptoError("decrypt_failed", "密钥密文格式非法")
    nonce = blob[len(SECRET_MAGIC) : len(SECRET_MAGIC) + NONCE_SIZE]
    ciphertext = blob[len(SECRET_MAGIC) + NONCE_SIZE :]
    try:
        plaintext = AESGCM(dek).decrypt(
            nonce, ciphertext, _aad(subscription_id, version_id)
        )
    except Exception as exc:
        raise SecretCryptoError(
            "decrypt_failed",
            "密钥密文认证失败（AAD/DEK 不匹配或数据被篡改）",
        ) from exc
    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SecretCryptoError("decrypt_failed", "密钥明文不是合法 UTF-8") from exc


def encrypt_new_secret(
    keyring: Keyring, subscription_id: int, version_id: int, secret: str
) -> tuple[bytes, bytes, str]:
    """为新版本生成 DEK 并加密密钥，返回 (ciphertext, wrapped_dek, key_id)。"""
    dek = generate_dek()
    ciphertext = encrypt_secret(dek, subscription_id, version_id, secret)
    key_id, wrapped = keyring.wrap_dek(dek)
    return ciphertext, wrapped, key_id


def resolve_secret(row: dict[str, Any], keyring: Keyring | None) -> str:
    """从投递上下文行解析出 HMAC 密钥明文（仅此路径会接触明文）。

    - 信封格式：解包 DEK → 解密（AAD 绑定行）；
    - 旧明文格式（迁移未完成）：直接返回 `secret` 列；
    - 未知 key_id / 认证失败 / 未配置密钥环：抛 SecretCryptoError。
    """
    ciphertext = row.get("secret_ciphertext")
    if ciphertext is None:
        # 迁移前的旧格式：明文列。迁移完成后该分支不再命中。
        return row["secret"]
    if keyring is None:
        raise SecretCryptoError(
            "keyring_not_configured",
            "本进程未配置本地密钥环，无法解密订阅密钥",
        )
    key_id = row.get("secret_key_id") or ""
    try:
        dek = keyring.unwrap_dek(key_id, bytes(row["secret_dek_wrapped"]))
    except UnknownKeyIdError:
        raise SecretCryptoError(
            "unknown_key_id", f"密钥环中不存在记录引用的 key_id={key_id!r}"
        ) from None
    except KeyUnwrapError as exc:
        raise SecretCryptoError("unwrap_failed", str(exc)) from None
    return decrypt_secret(
        dek,
        int(row["subscription_pk"]),
        int(row["config_version_pk"]),
        ciphertext,
    )
