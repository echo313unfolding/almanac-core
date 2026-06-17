"""Almanac Core — Encryption tests."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from crypto import generate_vault_salt, derive_vault_key, encrypt_evidence, decrypt_evidence
from receipts import user_commitment


# --- Key derivation ---

def test_key_derivation_deterministic():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "salt1")
    k1 = derive_vault_key(commit, salt)
    k2 = derive_vault_key(commit, salt)
    assert k1 == k2

def test_key_changes_with_salt():
    commit = user_commitment("Jane Doe", "jane@example.com", "salt1")
    s1 = generate_vault_salt()
    s2 = generate_vault_salt()
    assert derive_vault_key(commit, s1) != derive_vault_key(commit, s2)

def test_key_changes_with_commitment():
    salt = generate_vault_salt()
    c1 = user_commitment("Jane Doe", "jane@example.com", "salt1")
    c2 = user_commitment("John Doe", "john@example.com", "salt1")
    assert derive_vault_key(c1, salt) != derive_vault_key(c2, salt)


# --- Encrypt / decrypt round-trip ---

def test_encrypt_decrypt_roundtrip():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    key = derive_vault_key(commit, salt)
    plaintext = b"raw HTML evidence with PII"
    ciphertext = encrypt_evidence(plaintext, key)
    assert ciphertext != plaintext
    recovered = decrypt_evidence(ciphertext, key)
    assert recovered == plaintext

def test_wrong_key_fails():
    salt = generate_vault_salt()
    c1 = user_commitment("Jane Doe", "jane@example.com", "s1")
    c2 = user_commitment("Jane Doe", "jane@example.com", "s2")
    k1 = derive_vault_key(c1, salt)
    k2 = derive_vault_key(c2, salt)
    ciphertext = encrypt_evidence(b"secret data", k1)
    try:
        decrypt_evidence(ciphertext, k2)
        assert False, "Should have raised"
    except Exception:
        pass  # InvalidToken or similar

def test_ciphertext_not_plaintext():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    key = derive_vault_key(commit, salt)
    plaintext = b"Social Security Number: 123-45-6789"
    ciphertext = encrypt_evidence(plaintext, key)
    assert b"123-45-6789" not in ciphertext


# --- Encrypted vault round-trip ---

def test_encrypted_vault_evidence():
    from vault import Vault
    commit = user_commitment("Jane Doe", "jane@example.com", "vault-test")
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=commit)
        v.init()
        assert v.encrypted
        path = v.store_evidence("abc123def456", "raw html with PII")
        assert path.suffix == ".enc"
        # Raw file should NOT contain plaintext
        raw = path.read_bytes()
        assert b"raw html with PII" not in raw
        # Decrypt via vault
        recovered = v.load_evidence("abc123def456")
        assert recovered == b"raw html with PII"

def test_unencrypted_vault_evidence():
    from vault import Vault
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        assert not v.encrypted
        path = v.store_evidence("abc123def456", "raw html content")
        assert path.suffix == ".bin"
        assert path.read_bytes() == b"raw html content"

def test_encrypted_vault_wrong_commitment_fails():
    from vault import Vault
    commit1 = user_commitment("Jane Doe", "jane@example.com", "s1")
    commit2 = user_commitment("Jane Doe", "jane@example.com", "s2")
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=commit1)
        v1.init()
        v1.store_evidence("abc123def456", "secret stuff")
        # Open same vault with wrong commitment
        v2 = Vault(td, user_commitment=commit2)
        v2.init()
        try:
            v2.load_evidence("abc123def456")
            assert False, "Should have raised"
        except Exception:
            pass

def test_encrypted_vault_salt_persists():
    from vault import Vault
    from crypto import VAULT_SALT_FILE
    commit = user_commitment("Jane Doe", "jane@example.com", "persist-test")
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=commit)
        v1.init()
        v1.store_evidence("abc123def456", "data1")
        salt_path = Path(td) / VAULT_SALT_FILE
        assert salt_path.exists()
        salt1 = salt_path.read_text().strip()
        # Re-open vault, should use same salt, same key
        v2 = Vault(td, user_commitment=commit)
        v2.init()
        recovered = v2.load_evidence("abc123def456")
        assert recovered == b"data1"
        assert salt_path.read_text().strip() == salt1
