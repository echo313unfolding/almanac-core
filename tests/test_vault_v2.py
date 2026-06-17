"""Almanac Core — Vault + crypto_v2 integration tests.

Tests that vault.py correctly uses crypto_v2 for evidence encryption:
  - new evidence writes .v2.json (not .enc or .bin)
  - .v2.json does not contain plaintext
  - correct secret + structure decrypts
  - wrong secret fails
  - wrong structure context fails
  - auto-detection of v2 / v1 / plaintext
  - commitment without secret stays plaintext
  - no raw PII in envelope JSON
  - v2 salts persist across reopens
  - file permissions 0600 on sensitive files
"""

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from receipts import user_commitment
from vault import Vault


COMMIT = user_commitment("Jane Doe", "jane@example.com", "v2-test")
SECRET = "vault-passphrase-2026"


# ── v2 writes .v2.json ──────────────────────────────────────────────────────

def test_v2_evidence_writes_v2_json():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        path = v.store_evidence("a1b2c3d4e5f60000", "raw html with PII")
        assert path.name.endswith(".v2.json"), f"Expected .v2.json, got {path.name}"
        assert path.exists()


def test_v2_json_does_not_contain_plaintext():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        path = v.store_evidence("a1b2c3d4e5f60000", "Social Security: 123-45-6789")
        raw = path.read_text()
        assert "Social Security" not in raw
        assert "123-45-6789" not in raw


def test_v2_envelope_has_expected_schema():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        path = v.store_evidence("a1b2c3d4e5f60000", "evidence data")
        stored = json.loads(path.read_text())
        assert stored["schema"] == "almanac.encrypted_envelope.v2"
        assert stored["algorithm"] == "AES-256-GCM"
        assert "ciphertext_hex" in stored
        assert "wrapped_dek_hex" in stored
        assert "nonce_hex" in stored


# ── Correct decrypt ──────────────────────────────────────────────────────────

def test_v2_correct_secret_decrypts():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "broker scan HTML")
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"broker scan HTML"


def test_v2_bytes_evidence_roundtrip():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        data = b"\x00\x01\x02\xff binary data"
        v.store_evidence("a1b2c3d4e5f60000", data)
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == data


# ── Wrong secret / structure fails ───────────────────────────────────────────

def test_v2_wrong_secret_fails():
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v1.init()
        v1.store_evidence("a1b2c3d4e5f60000", "secret data")
        v2 = Vault(td, user_commitment=COMMIT, vault_secret="wrong-secret")
        v2.init()
        try:
            v2.load_evidence("a1b2c3d4e5f60000")
            assert False, "Wrong secret must fail"
        except Exception:
            pass


def test_v2_wrong_structure_context_fails():
    """Supplying a different structure context at decrypt must fail."""
    from structure_key import build_structure_context
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "data bound to structure")
        # Try loading with a tampered structure context
        bad_ctx = build_structure_context(
            user_commitment=COMMIT,
            capsule_type="vault_evidence",
            vault_id=v.vault_id,
            receipt_id="tampered-id",
        )
        try:
            v.load_evidence("a1b2c3d4e5f60000", structure_context=bad_ctx)
            assert False, "Tampered structure context must fail"
        except Exception:
            pass


def test_v2_wrong_policy_hash_fails():
    from structure_key import build_structure_context
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        # Store with explicit context
        ctx = build_structure_context(
            user_commitment=COMMIT,
            capsule_type="vault_evidence",
            vault_id=v.vault_id,
            receipt_id="a1b2c3d4e5f60000",
            policy_hash="policy-A",
        )
        v.store_evidence("a1b2c3d4e5f60000", "policy-bound data", structure_context=ctx)
        # Load with different policy
        bad_ctx = build_structure_context(
            user_commitment=COMMIT,
            capsule_type="vault_evidence",
            vault_id=v.vault_id,
            receipt_id="a1b2c3d4e5f60000",
            policy_hash="policy-B",
        )
        try:
            v.load_evidence("a1b2c3d4e5f60000", structure_context=bad_ctx)
            assert False, "Wrong policy_hash must fail"
        except Exception:
            pass


# ── Auto-detection ───────────────────────────────────────────────────────────

def test_v2_load_evidence_autodetects_v2():
    """load_evidence must find and decrypt .v2.json files."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "v2 encrypted data")
        # Verify .v2.json exists, not .enc or .bin
        evidence_dir = Path(td) / "evidence"
        assert (evidence_dir / "a1b2c3d4e5f60000.v2.json").exists()
        assert not (evidence_dir / "a1b2c3d4e5f60000.enc").exists()
        assert not (evidence_dir / "a1b2c3d4e5f60000.bin").exists()
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"v2 encrypted data"


def test_plaintext_bin_still_loads():
    """Legacy .bin files must still load via auto-detection."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        path = v.store_evidence("a1b2c3d4e5f60000", "plaintext data")
        assert path.suffix == ".bin"
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"plaintext data"


def test_v2_commitment_without_secret_raises():
    """Commitment without secret must fail-closed — never silently write plaintext."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT)
        try:
            v.init()
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "vault_secret is empty" in str(e)


def test_v2_no_credentials_writes_bin():
    """Without any credentials, evidence is stored as plaintext .bin."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        assert not v.encrypted
        path = v.store_evidence("a1b2c3d4e5f60000", "unencrypted data")
        assert path.suffix == ".bin"
        assert path.read_bytes() == b"unencrypted data"


# ── No PII in envelope ───────────────────────────────────────────────────────

def test_v2_no_pii_in_envelope_json():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "Jane Doe jane@example.com 123-45-6789")
        path = Path(td) / "evidence" / "a1b2c3d4e5f60000.v2.json"
        raw = path.read_text().lower()
        for term in ["jane", "doe", "example.com", "123-45-6789", "secret", "passphrase"]:
            assert term not in raw, f"PII/secret term '{term}' found in envelope"


# ── Salt persistence ─────────────────────────────────────────────────────────

def test_v2_salts_persist_across_reopens():
    from crypto_v2 import VAULT_SALT_FILE, SCRYPT_SALT_FILE
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v1.init()
        v1.store_evidence("a1b2c3d4e5f60000", "persistent data")

        vs_path = Path(td) / VAULT_SALT_FILE
        ss_path = Path(td) / SCRYPT_SALT_FILE
        assert vs_path.exists()
        assert ss_path.exists()
        salt1 = vs_path.read_text().strip()
        scrypt1 = ss_path.read_text().strip()

        # Reopen vault with same credentials
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        assert vs_path.read_text().strip() == salt1
        assert ss_path.read_text().strip() == scrypt1

        # Must still decrypt
        recovered = v2.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"persistent data"


def test_v2_vault_id_derived_from_salt():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        assert len(v.vault_id) == 16
        assert v.vault_id  # non-empty

        # Reopen — same vault_id
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        assert v2.vault_id == v.vault_id


# ── Missing evidence ─────────────────────────────────────────────────────────

def test_load_missing_evidence_raises():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        try:
            v.load_evidence("nonexistent000000")
            assert False, "Should have raised FileNotFoundError"
        except FileNotFoundError:
            pass


# ── Passphrase strength gate ──────────────────────────────────────────────────

def test_weak_passphrase_rejected():
    """Short passphrases must be rejected at vault init."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret="short")
        try:
            v.init()
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "at least 12" in str(e)


def test_low_entropy_passphrase_rejected():
    """All-same-character passphrases must be rejected."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret="aaaaaaaaaaaa")
        try:
            v.init()
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "unique characters" in str(e)


def test_strong_passphrase_accepted():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret="correct-horse-battery")
        v.init()
        assert v.encrypted


# ── Error cases ──────────────────────────────────────────────────────────────

def test_v2_encrypted_but_no_secret_on_load_raises():
    """Opening a vault with v2-encrypted evidence but no secret must fail."""
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v1.init()
        v1.store_evidence("a1b2c3d4e5f60000", "encrypted data")

        # Reopen without secret
        v2 = Vault(td)
        v2.init()
        try:
            v2.load_evidence("a1b2c3d4e5f60000")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "v2-encrypted" in str(e)


# ── File permissions ─────────────────────────────────────────────────────────

def _file_mode(path: Path) -> int:
    """Return the permission bits (last 12 bits) of a file."""
    return stat.S_IMODE(path.stat().st_mode)


def test_salt_files_are_0600():
    from crypto_v2 import VAULT_SALT_FILE, SCRYPT_SALT_FILE
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        assert _file_mode(Path(td) / VAULT_SALT_FILE) == 0o600
        assert _file_mode(Path(td) / SCRYPT_SALT_FILE) == 0o600


def test_v2_evidence_files_are_0600():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        path = v.store_evidence("a1b2c3d4e5f60000", "secret evidence")
        assert _file_mode(path) == 0o600


def test_plaintext_evidence_files_are_0600():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        path = v.store_evidence("a1b2c3d4e5f60000", "plaintext data")
        assert _file_mode(path) == 0o600
