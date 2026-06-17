"""Almanac Core — Vault encryption at rest.

Protein-inspired structure-as-key: the encryption key is derived from the
user's identity commitment + a vault-local salt. The structure (who you are +
where you store) IS the key. No separate key file to lose or steal.

    vault_key = HKDF(user_commitment || vault_salt)

Evidence files are encrypted. Receipts are plaintext (they contain no PII
by schema design — raw_pii_stored=false is enforced).
"""

import base64
import hashlib
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


VAULT_SALT_FILE = "vault_salt.key"
HKDF_INFO = b"almanac-core-vault-encryption-v1"


def generate_vault_salt() -> str:
    """Generate a random 32-byte hex salt for a vault."""
    return os.urandom(32).hex()


def derive_vault_key(user_commitment: str, vault_salt: str) -> bytes:
    """Derive a Fernet-compatible encryption key from identity commitment + salt.

    The user_commitment is SHA-256(name|email|user_salt) — it's the secret.
    The vault_salt is random per-vault — stored in the vault directory.
    Together they derive a unique encryption key via HKDF.
    """
    ikm = hashlib.sha256(f"{user_commitment}|{vault_salt}".encode()).digest()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(vault_salt),
        info=HKDF_INFO,
    )
    raw_key = hkdf.derive(ikm)
    return base64.urlsafe_b64encode(raw_key)


def encrypt_evidence(data: bytes, key: bytes) -> bytes:
    """Encrypt evidence data using Fernet (AES-128-CBC + HMAC)."""
    f = Fernet(key)
    return f.encrypt(data)


def decrypt_evidence(token: bytes, key: bytes) -> bytes:
    """Decrypt evidence data."""
    f = Fernet(key)
    return f.decrypt(token)
