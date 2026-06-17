"""Almanac Core — Encryption tests.

Key security property: user_commitment is PUBLIC (appears in receipts).
vault_salt is stored in the vault directory. Neither alone can derive the
encryption key. The vault_secret (private passphrase) is required.
"""

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
    k1 = derive_vault_key("my-secret", commit, salt)
    k2 = derive_vault_key("my-secret", commit, salt)
    assert k1 == k2

def test_key_changes_with_salt():
    commit = user_commitment("Jane Doe", "jane@example.com", "salt1")
    s1 = generate_vault_salt()
    s2 = generate_vault_salt()
    assert derive_vault_key("secret", commit, s1) != derive_vault_key("secret", commit, s2)

def test_key_changes_with_commitment():
    salt = generate_vault_salt()
    c1 = user_commitment("Jane Doe", "jane@example.com", "salt1")
    c2 = user_commitment("John Doe", "john@example.com", "salt1")
    assert derive_vault_key("secret", c1, salt) != derive_vault_key("secret", c2, salt)

def test_key_changes_with_secret():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "salt1")
    assert derive_vault_key("secret-A", commit, salt) != derive_vault_key("secret-B", commit, salt)


# --- Encrypt / decrypt round-trip ---

def test_encrypt_decrypt_roundtrip():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    key = derive_vault_key("passphrase", commit, salt)
    plaintext = b"raw HTML evidence with PII"
    ciphertext = encrypt_evidence(plaintext, key)
    assert ciphertext != plaintext
    recovered = decrypt_evidence(ciphertext, key)
    assert recovered == plaintext

def test_wrong_secret_fails():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "s1")
    k1 = derive_vault_key("correct-secret", commit, salt)
    k2 = derive_vault_key("wrong-secret", commit, salt)
    ciphertext = encrypt_evidence(b"secret data", k1)
    try:
        decrypt_evidence(ciphertext, k2)
        assert False, "Should have raised"
    except Exception:
        pass  # InvalidToken

def test_ciphertext_not_plaintext():
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    key = derive_vault_key("passphrase", commit, salt)
    plaintext = b"Social Security Number: 123-45-6789"
    ciphertext = encrypt_evidence(plaintext, key)
    assert b"123-45-6789" not in ciphertext


# --- CRITICAL: public components alone cannot decrypt ---

def test_commitment_plus_salt_cannot_decrypt():
    """user_commitment + vault_salt are both public/exported.
    They must NOT be sufficient to derive the vault key."""
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    real_key = derive_vault_key("the-real-secret", commit, salt)
    ciphertext = encrypt_evidence(b"sensitive PII evidence", real_key)

    # Attacker has commitment (from receipts) and salt (from vault dir)
    # but not the vault_secret. Try empty string as secret.
    attacker_key = derive_vault_key("", commit, salt)
    assert attacker_key != real_key
    try:
        decrypt_evidence(ciphertext, attacker_key)
        assert False, "Empty secret must not decrypt"
    except Exception:
        pass

    # Try using the commitment itself as the secret (the old bug)
    attacker_key2 = derive_vault_key(commit, commit, salt)
    assert attacker_key2 != real_key
    try:
        decrypt_evidence(ciphertext, attacker_key2)
        assert False, "Commitment-as-secret must not decrypt"
    except Exception:
        pass

def test_correct_triple_decrypts():
    """Correct vault_secret + user_commitment + vault_salt must decrypt."""
    salt = generate_vault_salt()
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    secret = "correct-passphrase-2026"
    key = derive_vault_key(secret, commit, salt)
    plaintext = b"raw broker scan HTML with name, address, phone"
    ciphertext = encrypt_evidence(plaintext, key)
    # Same triple re-derives same key and decrypts
    key2 = derive_vault_key(secret, commit, salt)
    recovered = decrypt_evidence(ciphertext, key2)
    assert recovered == plaintext


# --- Encrypted vault round-trip ---

def test_encrypted_vault_evidence():
    """v1 test — vault now defaults to v2 (.v2.json), so this verifies the
    new default path still encrypts and round-trips."""
    from vault import Vault
    commit = user_commitment("Jane Doe", "jane@example.com", "vault-test")
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=commit, vault_secret="my-passphrase")
        v.init()
        assert v.encrypted
        path = v.store_evidence("abc123def456", "raw html with PII")
        assert path.name.endswith(".v2.json")
        raw = path.read_text()
        assert "raw html with PII" not in raw
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

def test_vault_commitment_without_secret_not_encrypted():
    """Providing user_commitment alone (no secret) must NOT enable encryption."""
    from vault import Vault
    commit = user_commitment("Jane Doe", "jane@example.com", "test")
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=commit)  # no vault_secret
        v.init()
        assert not v.encrypted
        path = v.store_evidence("abc123def456", "plaintext data")
        assert path.suffix == ".bin"

def test_encrypted_vault_wrong_secret_fails():
    from vault import Vault
    commit = user_commitment("Jane Doe", "jane@example.com", "s1")
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=commit, vault_secret="correct-secret")
        v1.init()
        v1.store_evidence("abc123def456", "secret stuff")
        # Same commitment, wrong secret
        v2 = Vault(td, user_commitment=commit, vault_secret="wrong-secret")
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
        v1 = Vault(td, user_commitment=commit, vault_secret="my-secret")
        v1.init()
        v1.store_evidence("abc123def456", "data1")
        salt_path = Path(td) / VAULT_SALT_FILE
        assert salt_path.exists()
        salt1 = salt_path.read_text().strip()
        # Re-open vault with same secret, same commitment
        v2 = Vault(td, user_commitment=commit, vault_secret="my-secret")
        v2.init()
        recovered = v2.load_evidence("abc123def456")
        assert recovered == b"data1"
        assert salt_path.read_text().strip() == salt1
