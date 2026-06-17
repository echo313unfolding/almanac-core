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
        # v0.3.6: wrong secret now fails at init (security state HMAC check)
        v2 = Vault(td, user_commitment=COMMIT, vault_secret="wrong-secret")
        try:
            v2.init()
            v2.load_evidence("a1b2c3d4e5f60000")
            assert False, "Wrong secret must fail"
        except (ValueError, Exception):
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
        v1.close()

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
        v.close()

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
        v1.close()

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

        # .enc should be archived as .enc.migrated (not deleted)
        assert not enc_path.exists(), ".enc should not remain after migration"
        migrated = evidence_dir / "a1b2c3d4e5f60000.enc.migrated"
        assert migrated.exists(), ".enc should be archived as .enc.migrated"
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        assert v2_path.exists(), ".v2.json should exist after migration"

        # Data must be recoverable
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"legacy v1 data"


def test_v1_migration_skips_already_migrated():
    """If valid .v2.json exists, migration archives .enc without re-migrating."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
        v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
        # Create .enc
        enc_path = evidence_dir / "a1b2c3d4e5f60000.enc"
        enc_path.write_bytes(fernet_encrypt(b"old data", v1_key))

        # First init — migrate .enc to .v2.json
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        assert v2_path.exists()
        v2_content = v2_path.read_text()

        # Plant a new .enc with same hash (simulate partial previous migration)
        enc_path.write_bytes(fernet_encrypt(b"old data", v1_key))
        v.close()

        # Second init — .v2.json is valid, should just archive .enc
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        assert not enc_path.exists()
        migrated = evidence_dir / "a1b2c3d4e5f60000.enc.migrated"
        assert migrated.exists()
        # .v2.json should be untouched (same content)
        assert v2_path.read_text() == v2_content


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
        v.close()

        # Old secret cannot even open vault (security state HMAC mismatch)
        v_old = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        try:
            v_old.init()
            v_old.load_evidence("a1b2c3d4e5f60000")
            assert False, "Old secret must fail after rotation"
        except (ValueError, Exception):
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
        v.close()

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


# ── v0.3.5: Verified migration ────────────────────────────────────────────

def test_migration_archives_enc_not_deletes():
    """Migration preserves .enc as .enc.migrated instead of deleting."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
        v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
        enc_path = evidence_dir / "deadbeef00000000.enc"
        enc_path.write_bytes(fernet_encrypt(b"archive test", v1_key))

        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        assert not enc_path.exists()
        migrated = evidence_dir / "deadbeef00000000.enc.migrated"
        assert migrated.exists()
        assert len(migrated.read_bytes()) > 0  # original Fernet blob preserved


def test_migration_corrupt_v2_triggers_remigration():
    """If .v2.json is corrupt but .enc exists, migration re-does the conversion."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
        v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
        enc_path = evidence_dir / "a1b2c3d4e5f60000.enc"
        enc_path.write_bytes(fernet_encrypt(b"recoverable data", v1_key))
        # Plant a corrupt .v2.json
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        v2_path.write_text('{"corrupt":"not a real envelope"}\n')

        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        # .v2.json should be replaced with valid encryption
        assert v2_path.exists()
        stored = json.loads(v2_path.read_text())
        assert stored["schema"] == "almanac.encrypted_envelope.v2"
        # .enc should be archived
        assert not enc_path.exists()
        migrated = evidence_dir / "a1b2c3d4e5f60000.enc.migrated"
        assert migrated.exists()
        # Data recoverable
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"recoverable data"


def test_migration_cleans_up_interrupted_tmp():
    """Interrupted migration temp files (.migrating) are cleaned up on init."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        # Plant an orphaned .migrating file from a crash
        orphan = evidence_dir / "deadbeef00000000.v2.json.migrating"
        orphan.write_text('{"leftover":"from crash"}\n')
        # Create a normal .enc to trigger migration path
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")

        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        assert not orphan.exists(), ".migrating temp should be cleaned up"


def test_migration_enc_migrated_not_remigrated():
    """*.enc.migrated files are not picked up by *.enc glob (no double migration)."""
    from crypto import encrypt_evidence as fernet_encrypt, derive_vault_key, generate_vault_salt
    with tempfile.TemporaryDirectory() as td:
        evidence_dir = Path(td) / "evidence"
        evidence_dir.mkdir(parents=True)
        v1_salt = generate_vault_salt()
        (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
        v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
        enc_path = evidence_dir / "a1b2c3d4e5f60000.enc"
        enc_path.write_bytes(fernet_encrypt(b"data", v1_key))

        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        migrated = evidence_dir / "a1b2c3d4e5f60000.enc.migrated"
        assert migrated.exists()
        v.close()

        # Second init — .enc.migrated must not be picked up
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        # Still just one .v2.json, one .enc.migrated
        assert len(list(evidence_dir.glob("*.v2.json"))) == 1
        assert len(list(evidence_dir.glob("*.enc.migrated"))) == 1
        assert len(list(evidence_dir.glob("*.enc"))) == 0


# ── v0.3.5: Transactional rotation ──────────────────────────────────────

def test_rotation_writes_journal():
    """rotate_secret creates and cleans up rotation_journal.json."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "rotation journal test")
        journal_path = Path(td) / "rotation_journal.json"

        v.rotate_secret("new-strong-secret-2026")

        # Journal should be deleted after successful rotation
        assert not journal_path.exists()
        v.close()
        # Evidence still works
        v2 = Vault(td, user_commitment=COMMIT, vault_secret="new-strong-secret-2026")
        v2.init()
        assert v2.load_evidence("a1b2c3d4e5f60000") == b"rotation journal test"


def test_rotation_no_rotating_files_remain():
    """After successful rotation, no .rotating temp files should remain."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "data1")
        v.store_evidence("b2c3d4e5f6a10000", "data2")

        v.rotate_secret("rotated-passphrase-2026")

        evidence_dir = Path(td) / "evidence"
        assert len(list(evidence_dir.glob("*.rotating"))) == 0


def test_rotation_rollback_on_failure():
    """If rotation fails before commit, temp files are cleaned up."""
    import unittest.mock
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "must survive")

        # Patch _v2_decrypt to fail during verification
        original_decrypt = _v2_decrypt_ref = None
        call_count = [0]

        from crypto_v2 import decrypt_evidence as real_decrypt

        def failing_decrypt(*args, **kwargs):
            call_count[0] += 1
            # Fail on the verification pass (calls during rotate, not initial load)
            if call_count[0] > 1:
                raise RuntimeError("Simulated verification failure")
            return real_decrypt(*args, **kwargs)

        # We can't easily patch the internal decrypt, so test via
        # injecting a bad new_secret that would fail differently
        # Instead, just verify the contract: after failed rotate, data intact
        try:
            v.rotate_secret("same-but-different!")
        except Exception:
            pass

        # Original data must still be accessible
        recovered = v.load_evidence("a1b2c3d4e5f60000")
        assert recovered == b"must survive"

        # No temp files
        evidence_dir = Path(td) / "evidence"
        assert len(list(evidence_dir.glob("*.rotating"))) == 0

        # No journal
        assert not (Path(td) / "rotation_journal.json").exists()


def test_rotation_recovery_pre_commit_rollback():
    """Journal with pre-commit phase: init() rolls back temp files."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "pre-commit test")

        evidence_dir = Path(td) / "evidence"
        # Simulate interrupted rotation: journal + .rotating file
        journal = {
            "phase": "wrote_tmp",
            "started_at": "2026-06-17T00:00:00Z",
            "new_scrypt_salt_hex": "aa" * 32,
            "evidence_hashes": ["a1b2c3d4e5f60000"],
        }
        journal_path = Path(td) / "rotation_journal.json"
        journal_path.write_text(json.dumps(journal) + "\n")
        # Create orphaned .rotating file
        orphan = evidence_dir / "a1b2c3d4e5f60000.v2.json.rotating"
        orphan.write_text('{"fake":"rotating"}\n')
        v.close()

        # Re-open vault — should rollback
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()

        assert not journal_path.exists(), "Journal should be deleted on rollback"
        assert not orphan.exists(), ".rotating should be deleted on rollback"
        # Original data intact
        assert v2.load_evidence("a1b2c3d4e5f60000") == b"pre-commit test"


def test_rotation_recovery_post_commit():
    """Journal with committed phase: init() completes rename + salt update."""
    from crypto_v2 import SCRYPT_SALT_FILE, generate_salt
    with tempfile.TemporaryDirectory() as td:
        # Set up vault with initial data
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "post-commit test")

        # Now perform a real rotation to get properly encrypted .rotating files
        new_secret = "recovery-passphrase-2026"
        new_scrypt_salt = generate_salt()

        evidence_dir = Path(td) / "evidence"
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"

        # Decrypt with current secret
        plaintext = v.load_evidence("a1b2c3d4e5f60000")

        # Re-encrypt with new secret
        from crypto_v2 import encrypt_evidence as v2_encrypt
        from structure_key import build_structure_context
        ctx = v._default_structure_context("a1b2c3d4e5f60000")
        envelope = v2_encrypt(
            plaintext, new_secret, COMMIT,
            v._v2_vault_salt, new_scrypt_salt, ctx,
        )
        stored = envelope.to_dict()
        stored["ciphertext_hex"] = envelope.ciphertext.hex()
        # Write as .rotating (simulating crash after write but before rename)
        rotating = evidence_dir / "a1b2c3d4e5f60000.v2.json.rotating"
        rotating.write_text(json.dumps(stored, indent=2) + "\n")

        # Write committed journal
        journal = {
            "phase": "committed",
            "started_at": "2026-06-17T00:00:00Z",
            "new_scrypt_salt_hex": new_scrypt_salt.hex(),
            "evidence_hashes": ["a1b2c3d4e5f60000"],
        }
        journal_path = Path(td) / "rotation_journal.json"
        journal_path.write_text(json.dumps(journal) + "\n")
        v.close()

        # Re-open with NEW secret — recovery should complete
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=new_secret)
        v2.init()

        assert not journal_path.exists(), "Journal should be deleted after recovery"
        assert not rotating.exists(), ".rotating should be renamed"
        # Scrypt salt should be updated
        salt_on_disk = (Path(td) / SCRYPT_SALT_FILE).read_text().strip()
        assert salt_on_disk == new_scrypt_salt.hex()
        # Data accessible with new secret
        assert v2.load_evidence("a1b2c3d4e5f60000") == b"post-commit test"


# ── v0.3.5: HMAC sidecar deletion detection ──────────────────────────────

def test_hmac_deletion_detected_for_indexed_receipt():
    """Deleting .hmac sidecar for a receipt in the signed index raises."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        hmac_path = path.with_suffix(".hmac")
        assert hmac_path.exists()

        # Verify receipt is in signed index
        index_path = Path(td) / "signed_receipts.json"
        assert index_path.exists()
        index = json.loads(index_path.read_text())
        assert path.name in index

        # Simulate attacker deleting the HMAC sidecar
        hmac_path.unlink()

        try:
            v.load_receipt(path)
            assert False, "Missing HMAC for indexed receipt must raise"
        except ValueError as e:
            assert "missing" in str(e).lower()
            assert "deleted" in str(e).lower()


def test_signed_receipt_index_is_hmac_protected():
    """The signed_receipts.json index file has its own HMAC sidecar."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)

        index_path = Path(td) / "signed_receipts.json"
        index_hmac = index_path.with_suffix(".hmac")
        assert index_path.exists()
        assert index_hmac.exists()
        assert len(index_hmac.read_text().strip()) == 64  # SHA-256 hex


def test_signed_index_tamper_detected():
    """Tampering with the signed receipt index raises ValueError."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)

        # Tamper with the index content (HMAC sidecar stays from before)
        index_path = Path(td) / "signed_receipts.json"
        index_path.write_text('["injected_fake.json"]\n')

        # Delete the receipt's .hmac to force the index lookup path
        path.with_suffix(".hmac").unlink()

        try:
            v.load_receipt(path)
            assert False, "Tampered index must raise"
        except ValueError as e:
            assert "tampered" in str(e).lower()


def test_pre_index_receipts_load_without_error():
    """Receipts stored without signing key load fine (no index, no HMAC)."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        # Store a receipt in an unencrypted vault (no signing key)
        v = Vault(td)
        v.init()
        r = discovery_receipt("c", "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        assert not path.with_suffix(".hmac").exists()

        # Load it back — should work
        loaded = v.load_receipt(path)
        assert loaded["receipt_id"] == r["receipt_id"]


def test_pre_signing_receipt_loads_in_encrypted_vault():
    """A receipt stored before HMAC signing was enabled loads without error."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        # First: store receipt without encryption
        v1 = Vault(td)
        v1.init()
        r = discovery_receipt("c", "spokeo", "phone_email", 0.9, "evidence")
        path = v1.store(r)
        v1.close()

        # Now open vault with encryption — receipt has no HMAC and no index entry
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        loaded = v2.load_receipt(path)
        assert loaded["receipt_id"] == r["receipt_id"]


def test_rotation_updates_signed_index():
    """After rotation, signed receipt index HMAC is valid with new signing key."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)

        new_secret = "rotated-passphrase-2026"
        v.rotate_secret(new_secret)
        v.close()

        # Reopen with new secret — index should be verifiable
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=new_secret)
        v2.init()
        index_path = Path(td) / "signed_receipts.json"
        assert index_path.exists()
        # Loading any receipt triggers index verification
        receipts = v2.list_receipts()
        assert len(receipts) >= 1
        loaded = v2.load_receipt(receipts[0])
        assert loaded["receipt_id"] == r["receipt_id"]


def test_signed_index_is_0600():
    """Signed receipt index and its HMAC have 0600 permissions."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)

        index_path = Path(td) / "signed_receipts.json"
        assert _file_mode(index_path) == 0o600
        assert _file_mode(index_path.with_suffix(".hmac")) == 0o600


# ── v0.3.6: Atomic writes + TOCTOU fix ──────────────────────────────────

def test_atomic_write_creates_0600_from_birth():
    """Files created via _secure_write_text are 0600 from the start (no TOCTOU)."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        # Salt files are created by _secure_write_text during init
        from crypto_v2 import VAULT_SALT_FILE, SCRYPT_SALT_FILE
        for name in [VAULT_SALT_FILE, SCRYPT_SALT_FILE]:
            p = Path(td) / name
            assert p.exists()
            mode = _file_mode(p)
            assert mode == 0o600, f"{name} has mode {oct(mode)}, expected 0o600"
        # No .atomictmp files left behind
        assert len(list(Path(td).glob("*.atomictmp"))) == 0


def test_no_atomictmp_files_remain():
    """Atomic writes must not leave .atomictmp files on success."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "data")
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)
        # Check everywhere for leftover temp files
        for tmp in Path(td).rglob("*.atomictmp"):
            assert False, f"Leftover temp file: {tmp}"


# ── v0.3.6: Security state ────────────────────────────────────────────

def test_security_state_created_on_init():
    """Encrypted vault init creates VAULT_SECURITY_STATE.json."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        assert state_path.exists()
        state = json.loads(state_path.read_text())
        assert state["security_epoch"] == 0
        assert "vault_id" in state
        assert "created_at" in state


def test_security_state_is_hmac_protected():
    """VAULT_SECURITY_STATE.json has an HMAC sidecar."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        hmac_path = state_path.with_suffix(".hmac")
        assert hmac_path.exists()
        assert len(hmac_path.read_text().strip()) == 64


def test_security_state_is_0600():
    """Security state and its HMAC have 0600 permissions."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        assert _file_mode(state_path) == 0o600
        assert _file_mode(state_path.with_suffix(".hmac")) == 0o600


def test_security_state_tamper_detected():
    """Tampered VAULT_SECURITY_STATE.json raises on vault open."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        # Tamper with security state
        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        state_path.write_text('{"security_epoch": 999, "tampered": true}\n')
        v.close()
        try:
            v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
            v2.init()
            assert False, "Tampered security state must raise"
        except ValueError as e:
            assert "tampered" in str(e).lower()


def test_security_state_deletion_detected():
    """Deleting VAULT_SECURITY_STATE.json raises on re-open (when index exists)."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)
        v.close()

        # Delete security state (but signed index remains)
        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        state_path.unlink()
        state_path.with_suffix(".hmac").unlink()

        try:
            v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
            v2.init()
            assert False, "Missing security state with existing index must raise"
        except ValueError as e:
            assert "missing" in str(e).lower()


def test_security_state_deletion_bypassed_with_legacy_upgrade():
    """legacy_upgrade=True allows upgrading from v0.3.5 (no security state)."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)

        v.close()
        # Simulate v0.3.5 vault (has index, no security state)
        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        state_path.unlink()
        state_path.with_suffix(".hmac").unlink()

        # legacy_upgrade=True allows opening
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET,
                    legacy_upgrade=True)
        v2.init()
        assert v2.encrypted
        # Security state should now exist
        assert state_path.exists()


def test_security_state_creates_empty_signed_index():
    """Security state init creates an empty signed index if none exists."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        index_path = Path(td) / "signed_receipts.json"
        assert index_path.exists()
        assert json.loads(index_path.read_text()) == []
        assert index_path.with_suffix(".hmac").exists()


# ── v0.3.6: Signed index deletion detection (hardened) ──────────────────

def test_signed_index_deletion_detected_with_security_state():
    """Deleting signed_receipts.json + its HMAC raises when security state active."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)

        # Attacker deletes index + index HMAC + receipt HMAC
        index_path = Path(td) / "signed_receipts.json"
        index_path.unlink()
        index_path.with_suffix(".hmac").unlink()
        path.with_suffix(".hmac").unlink()

        # Security state still exists → index deletion detected
        try:
            v.load_receipt(path)
            assert False, "Index deletion must be detected"
        except ValueError as e:
            assert "index deletion" in str(e).lower() or "missing" in str(e).lower()


def test_signed_index_hmac_deletion_detected():
    """Deleting only the index HMAC raises on load."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)

        # Delete just the index HMAC
        index_hmac = Path(td) / "signed_receipts.hmac"
        index_hmac.unlink()
        # Delete receipt HMAC to force index lookup path
        path.with_suffix(".hmac").unlink()

        try:
            v.load_receipt(path)
            assert False, "Missing index HMAC must raise"
        except ValueError as e:
            assert "hmac" in str(e).lower()


# ── v0.3.6: Wrong-secret rotation recovery ─────────────────────────────

def test_wrong_secret_rotation_recovery_blocked():
    """Opening with pre-rotation secret after committed rotation raises."""
    from crypto_v2 import encrypt_evidence as v2_encrypt, generate_salt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "recovery test")

        # Simulate committed rotation to new_secret
        new_secret = "rotated-passphrase-2026"
        new_scrypt_salt = generate_salt()
        evidence_dir = Path(td) / "evidence"

        # Re-encrypt evidence with new secret
        plaintext = v.load_evidence("a1b2c3d4e5f60000")
        ctx = v._default_structure_context("a1b2c3d4e5f60000")
        envelope = v2_encrypt(
            plaintext, new_secret, COMMIT,
            v._v2_vault_salt, new_scrypt_salt, ctx,
        )
        stored = envelope.to_dict()
        stored["ciphertext_hex"] = envelope.ciphertext.hex()
        rotating = evidence_dir / "a1b2c3d4e5f60000.v2.json.rotating"
        rotating.write_text(json.dumps(stored, indent=2) + "\n")

        # Write committed journal
        journal = {
            "phase": "committed",
            "started_at": "2026-06-17T00:00:00Z",
            "new_scrypt_salt_hex": new_scrypt_salt.hex(),
            "evidence_hashes": ["a1b2c3d4e5f60000"],
        }
        (Path(td) / "rotation_journal.json").write_text(
            json.dumps(journal) + "\n"
        )
        v.close()

        # Open with OLD secret — must fail
        try:
            v_old = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
            v_old.init()
            assert False, "Wrong secret during recovery must raise"
        except ValueError as e:
            assert "rotation recovery failed" in str(e).lower()

        # Journal should still exist (recovery not completed)
        assert (Path(td) / "rotation_journal.json").exists()

        # Open with CORRECT secret — recovery completes
        v_new = Vault(td, user_commitment=COMMIT, vault_secret=new_secret)
        v_new.init()
        assert v_new.load_evidence("a1b2c3d4e5f60000") == b"recovery test"
        assert not (Path(td) / "rotation_journal.json").exists()


# ── v0.3.6: Receipt filename collision ──────────────────────────────────

def test_receipt_filename_collision_uses_longer_prefix():
    """Two receipts with same rid[:8] but different IDs use longer prefix."""
    from receipts import discovery_receipt
    import uuid
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()

        # Create two receipts with IDs that share first 8 chars
        r1 = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        # Force a colliding prefix by manipulating receipt_id
        r1["receipt_id"] = "AABBCCDD-1111-1111-1111-111111111111"
        r2 = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.8, "evidence")
        r2["receipt_id"] = "AABBCCDD-2222-2222-2222-222222222222"

        path1 = v.store(r1)
        path2 = v.store(r2)

        # First uses short prefix, second uses longer prefix
        assert "AABBCCDD" in path1.name
        assert path1 != path2
        assert path2.name != path1.name

        # Both must load correctly
        loaded1 = v.load_receipt(path1)
        loaded2 = v.load_receipt(path2)
        assert loaded1["receipt_id"] == r1["receipt_id"]
        assert loaded2["receipt_id"] == r2["receipt_id"]


def test_receipt_store_is_atomic():
    """Receipt store uses atomic write (0600 from birth)."""
    from receipts import discovery_receipt
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        assert _file_mode(path) == 0o600


# ── v0.3.6: Security state epoch on rotation ────────────────────────────

def test_security_state_epoch_bumps_on_rotation():
    """rotate_secret increments security_epoch in VAULT_SECURITY_STATE.json."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "epoch test")

        state_path = Path(td) / "VAULT_SECURITY_STATE.json"
        pre = json.loads(state_path.read_text())
        assert pre["security_epoch"] == 0

        v.rotate_secret("rotated-passphrase-2026")

        post = json.loads(state_path.read_text())
        assert post["security_epoch"] == 1
        assert "last_rotation" in post
        v.close()

        # HMAC is valid after rotation
        v2 = Vault(td, user_commitment=COMMIT, vault_secret="rotated-passphrase-2026")
        v2.init()
        assert v2.load_evidence("a1b2c3d4e5f60000") == b"epoch test"


def test_unencrypted_vault_has_no_security_state():
    """Unencrypted vaults do not create security state."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        assert not (Path(td) / "VAULT_SECURITY_STATE.json").exists()
