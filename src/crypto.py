"""Almanac Core — Vault encryption at rest.

Three inputs to derive the vault encryption key:

    vault_key = HKDF(vault_secret + user_commitment + vault_salt)

Where:
    user_commitment = public/exportable identity hash (appears in receipts)
    vault_salt      = random per-vault salt (stored in vault directory)
    vault_secret    = private passphrase or device key (NEVER stored in vault)

The user_commitment and vault_salt bind the key to a specific identity and
vault instance (the structure/context). The vault_secret unlocks the key.
Neither the commitment nor the salt alone can derive the key.

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


def derive_vault_key(vault_secret: str, user_commitment: str, vault_salt: str) -> bytes:
    """Derive a Fernet-compatible encryption key.

    vault_secret:    private passphrase/device key — the actual secret
    user_commitment: public identity hash — binds key to identity
    vault_salt:      random per-vault — binds key to this vault instance

    The secret provides the entropy. The commitment and salt provide context
    binding so the same passphrase on a different vault or identity produces
    a different key.
    """
    ikm = hashlib.sha256(
        f"{vault_secret}|{user_commitment}|{vault_salt}".encode()
    ).digest()
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
