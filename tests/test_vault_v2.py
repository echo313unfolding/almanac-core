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


# ── Receipt HMAC signing (P2) ────────────────────────────────────────────────

def test_receipt_hmac_created_on_store():
    """Storing a receipt in an encrypted vault creates an .hmac sidecar."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        hmac_path = path.with_suffix(".hmac")
        assert hmac_path.exists()
        assert len(hmac_path.read_text().strip()) == 64  # SHA-256 hex


def test_receipt_hmac_not_created_without_secret():
    """Unencrypted vault does not create HMAC sidecars."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        r = discovery_receipt("c", "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        assert not path.with_suffix(".hmac").exists()


def test_receipt_hmac_valid_on_load():
    """Receipt with valid HMAC loads without error."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        loaded = v.load_receipt(path)
        assert loaded["receipt_id"] == r["receipt_id"]


def test_receipt_hmac_tampered_fails():
    """Tampered receipt must fail HMAC verification."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        # Tamper with the receipt file
        tampered = json.loads(path.read_text())
        tampered["confidence"] = 0.1
        path.write_text(json.dumps(tampered, indent=2) + "\n")
        try:
            v.load_receipt(path)
            assert False, "Tampered receipt must fail HMAC"
        except ValueError as e:
            assert "tampered" in str(e).lower()


def test_receipt_hmac_sidecar_is_0600():
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        assert _file_mode(path.with_suffix(".hmac")) == 0o600


# ── v1→v2 migration (P2) ────────────────────────────────────────────────────

def test_v1_enc_migrated_to_v2_on_init():
    """Legacy .enc files are auto-migrated to .v2.json on vault open."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        # Manually create a v1-style .enc file
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        # Set up v1 salt
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
        v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
        ciphertext = fernet_encrypt(b"legacy v1 data", v1_key)
        enc_path = evidence_dir / "a1b2c3d4e5f60000.enc"
        enc_path.write_bytes(ciphertext)

        # Open vault — migration should run
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        # .enc should be gone, .v2.json should exist
        assert not enc_path.exists(), ".enc should be deleted after migration"
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        assert v2_path.exists(), ".v2.json should exist after migration"

        # Data must be recoverable
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"legacy v1 data"


def test_v1_migration_skips_already_migrated():
    """If .v2.json already exists for a hash, migration skips that file."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
        v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
        # Create both .enc and .v2.json for the same hash
        enc_path = evidence_dir / "a1b2c3d4e5f60000.enc"
        enc_path.write_bytes(fernet_encrypt(b"old data", v1_key))
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        v2_path.write_text('{"already":"migrated"}\n')

        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        # .enc should still exist (skipped because .v2.json exists)
        assert enc_path.exists()
        # .v2.json should be untouched
        assert "already" in v2_path.read_text()


# ── Key rotation (P2) ───────────────────────────────────────────────────────

def test_rotate_secret_re_encrypts_evidence():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "data to rotate")
        v.store_evidence("b2c3d4e5f6a10000", "more data")

        new_secret = "rotated-passphrase-2026"
        result = v.rotate_secret(new_secret)
        assert result["evidence_rotated"] == 2

        # Old secret cannot decrypt
        v_old = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v_old.init()
        try:
            v_old.load_evidence("a1b2c3d4e5f60000")
            assert False, "Old secret must fail after rotation"
        except Exception:
            pass

        # New secret decrypts
        v_new = Vault(td, user_commitment=COMMIT, vault_secret=new_secret)
        v_new.init()
        assert v_new.load_evidence("a1b2c3d4e5f60000") == b"data to rotate"
        assert v_new.load_evidence("b2c3d4e5f6a10000") == b"more data"


def test_rotate_secret_re_signs_receipts():
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        old_hmac = path.with_suffix(".hmac").read_text().strip()

        new_secret = "rotated-passphrase-2026"
        result = v.rotate_secret(new_secret)
        assert result["receipts_re_signed"] >= 1

        new_hmac = path.with_suffix(".hmac").read_text().strip()
        assert new_hmac != old_hmac  # different signing key = different HMAC

        # New vault verifies the new HMAC
        v_new = Vault(td, user_commitment=COMMIT, vault_secret=new_secret)
        v_new.init()
        loaded = v_new.load_receipt(path)
        assert loaded["receipt_id"] == r["receipt_id"]


def test_rotate_rejects_weak_new_secret():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        try:
            v.rotate_secret("short")
            assert False, "Weak new secret must be rejected"
        except ValueError as e:
            assert "Weak" in str(e)


def test_rotate_rejects_same_secret():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        try:
            v.rotate_secret(SECRET)
            assert False, "Same secret must be rejected"
        except ValueError as e:
            assert "differ" in str(e)


def test_rotate_unencrypted_vault_fails():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        try:
            v.rotate_secret("new-strong-secret-2026")
            assert False, "Rotate on unencrypted vault must fail"
        except ValueError as e:
            assert "not encrypted" in str(e)


# ── Downgrade protection (P3) ───────────────────────────────────────────────

def test_downgrade_protection_blocks_bin_in_encrypted_vault():
    """Encrypted vault refuses to load .bin evidence (possible downgrade attack)."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        # Manually plant a .bin file (simulates attacker)
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "deadbeef00000000.bin").write_bytes(b"fake data")
        try:
            v.load_evidence("deadbeef00000000")
            assert False, "Should have raised ValueError for downgrade"
        except ValueError as e:
            assert "downgrade" in str(e).lower()


def test_downgrade_protection_allows_bin_in_unencrypted_vault():
    """Unencrypted vault loads .bin normally (no downgrade concern)."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "plaintext data")
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"plaintext data"
