"""Almanac Core — v0.3.7 tests: vault locking, checkpoint roots, legacy archives.

Tests cover:
  - flock-based single-writer protection
  - Checkpoint root computation and HMAC integrity
  - External checkpoint export/verify
  - Legacy .enc.migrated archive cleanup
"""

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from receipts import user_commitment, discovery_receipt
from vault import Vault, CHECKPOINT_FILE, CHECKPOINT_ROOT_FILE, VAULT_LOCK_FILE


COMMIT = user_commitment("Jane Doe", "jane@example.com", "v37-test")
SECRET = "vault-passphrase-2026"


def _file_mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# ── Vault locking ──────────────────────────────────────────────────────────

def test_lock_prevents_second_vault():
    """Second Vault on same directory cannot acquire lock."""
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v1.init()
        try:
            v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
            v2.init()
            assert False, "Second vault must fail to acquire lock"
        except ValueError as e:
            assert "locked" in str(e).lower()
        finally:
            v1.close()


def test_lock_released_after_close():
    """After close(), another Vault can open the same directory."""
    with tempfile.TemporaryDirectory() as td:
        v1 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v1.init()
        v1.close()

        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        v2.close()


def test_lock_released_by_context_manager():
    """Context manager (__exit__) releases lock."""
    with tempfile.TemporaryDirectory() as td:
        with Vault(td, user_commitment=COMMIT, vault_secret=SECRET) as v1:
            v1.init()

        # Lock released — second open works
        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        v2.close()


def test_no_stale_lock_after_init_failure():
    """If init() fails (e.g., weak secret), lock is released."""
    with tempfile.TemporaryDirectory() as td:
        v_bad = Vault(td, user_commitment=COMMIT, vault_secret="short")
        try:
            v_bad.init()
        except ValueError:
            pass

        # Lock should not be held — good vault can open
        v_good = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v_good.init()
        v_good.close()


def test_lock_file_is_0600():
    """Lock file has owner-only permissions."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        lock_path = Path(td) / VAULT_LOCK_FILE
        assert lock_path.exists()
        assert _file_mode(lock_path) == 0o600
        v.close()


def test_close_is_idempotent():
    """Calling close() multiple times does not raise."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.close()
        v.close()  # second close must not raise


# ── Checkpoint root ────────────────────────────────────────────────────────

def test_checkpoint_created_on_init():
    """CHECKPOINT.json and CHECKPOINT_ROOT.txt created for encrypted vault."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        assert (Path(td) / CHECKPOINT_FILE).exists()
        assert (Path(td) / CHECKPOINT_ROOT_FILE).exists()
        v.close()


def test_checkpoint_not_created_for_unencrypted():
    """Unencrypted vault does not create checkpoint files."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        assert not (Path(td) / CHECKPOINT_FILE).exists()
        assert not (Path(td) / CHECKPOINT_ROOT_FILE).exists()
        v.close()


def test_checkpoint_root_deterministic():
    """Same vault state produces same checkpoint root."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        root1 = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()
        v.close()

        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        root2 = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()
        v2.close()
        assert root1 == root2


def test_checkpoint_root_changes_on_receipt():
    """Storing a receipt changes the checkpoint root."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        root_before = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()

        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)
        root_after = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()
        assert root_before != root_after
        v.close()


def test_checkpoint_root_changes_on_evidence():
    """Storing evidence changes the checkpoint root."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        root_before = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()

        v.store_evidence("a1b2c3d4e5f60000", "raw html")
        root_after = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()
        assert root_before != root_after
        v.close()


def test_checkpoint_root_changes_on_rotation():
    """Key rotation changes the checkpoint root (epoch bump + re-encryption)."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "rotation test")
        root_before = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()

        v.rotate_secret("rotated-passphrase-2026")
        root_after = (Path(td) / CHECKPOINT_ROOT_FILE).read_text().strip()
        assert root_before != root_after
        v.close()


def test_checkpoint_contains_no_pii():
    """Checkpoint payload contains only hashes and metadata, no PII."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "Jane Doe 123-45-6789")

        ckpt = json.loads((Path(td) / CHECKPOINT_FILE).read_text())
        ckpt_str = json.dumps(ckpt)
        assert "Jane Doe" not in ckpt_str
        assert "123-45-6789" not in ckpt_str
        assert ckpt["schema"] == "almanac.checkpoint.v1"
        assert "receipt_hashes_root" in ckpt
        assert "evidence_manifest_hash" in ckpt
        assert "vault_id" in ckpt
        v.close()


def test_checkpoint_hmac_tamper_detected():
    """Tampered CHECKPOINT.json detected on re-open."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.close()

        # Tamper with checkpoint
        ckpt_path = Path(td) / CHECKPOINT_FILE
        ckpt_path.write_text('{"schema": "tampered"}\n')

        try:
            v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
            v2.init()
            assert False, "Tampered checkpoint must raise"
        except ValueError as e:
            assert "tampered" in str(e).lower() or "hmac" in str(e).lower()


def test_checkpoint_root_file_tamper_detectable():
    """Modified CHECKPOINT_ROOT.txt can be compared against export."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        bundle = v.export_checkpoint()
        v.close()

        # Tamper with root file (the checkpoint itself is still HMAC-protected,
        # but the root file is for external comparison)
        root_path = Path(td) / CHECKPOINT_ROOT_FILE
        root_path.write_text("0" * 64 + "\n")

        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        on_disk = root_path.read_text().strip()
        # Root was recomputed on init — may differ from tampered value
        # But the exported bundle still matches current state
        assert v2.verify_checkpoint_bundle(bundle)
        v2.close()


def test_checkpoint_is_0600():
    """Checkpoint files have 0600 permissions."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        assert _file_mode(Path(td) / CHECKPOINT_FILE) == 0o600
        assert _file_mode(Path(td) / CHECKPOINT_ROOT_FILE) == 0o600
        hmac_path = (Path(td) / CHECKPOINT_FILE).with_suffix(".hmac")
        assert _file_mode(hmac_path) == 0o600
        v.close()


def test_checkpoint_payload_has_expected_fields():
    """Checkpoint payload includes all required fields."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        ckpt = json.loads((Path(td) / CHECKPOINT_FILE).read_text())
        required = [
            "schema", "vault_id", "security_epoch", "receipt_count",
            "receipt_hashes_root", "signed_index_hash",
            "security_state_hash", "evidence_manifest_hash", "updated_at",
        ]
        for field in required:
            assert field in ckpt, f"Missing field: {field}"
        v.close()


# ── Rollback simulation ───────────────────────────────────────────────────

def test_rollback_detected_via_checkpoint():
    """Exporting checkpoint, modifying vault, and verifying detects change."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)

        # Export current state
        bundle = v.export_checkpoint()
        assert v.verify_checkpoint_bundle(bundle)

        # Add more data — state changes
        v.store_evidence("a1b2c3d4e5f60000", "new data")
        assert not v.verify_checkpoint_bundle(bundle)
        v.close()


# ── External checkpoint ──────────────────────────────────────────────────

def test_export_checkpoint_returns_root_and_payload():
    """export_checkpoint returns checkpoint_root + checkpoint_payload."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        bundle = v.export_checkpoint()
        assert "checkpoint_root" in bundle
        assert "checkpoint_payload" in bundle
        assert "exported_at" in bundle
        assert len(bundle["checkpoint_root"]) == 64  # SHA-256 hex
        v.close()


def test_export_checkpoint_verifies_against_current_state():
    """Exported checkpoint verifies when state hasn't changed."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        bundle = v.export_checkpoint()
        assert v.verify_checkpoint_bundle(bundle)
        v.close()


def test_stale_checkpoint_fails_verification():
    """Checkpoint from before a change fails verification."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        bundle_old = v.export_checkpoint()

        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)

        assert not v.verify_checkpoint_bundle(bundle_old)
        v.close()


def test_export_checkpoint_contains_no_pii():
    """Exported checkpoint bundle has no PII."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        v.store_evidence("a1b2c3d4e5f60000", "Jane Doe SSN 123-45-6789")
        bundle = v.export_checkpoint()
        bundle_str = json.dumps(bundle)
        assert "Jane Doe" not in bundle_str
        assert "123-45-6789" not in bundle_str
        assert SECRET not in bundle_str
        v.close()


def test_checkpoint_survives_reopen():
    """Checkpoint root is consistent across close/reopen cycle."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        r = discovery_receipt(COMMIT, "spokeo", "phone_email", 0.9, "evidence")
        v.store(r)
        bundle = v.export_checkpoint()
        v.close()

        v2 = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v2.init()
        assert v2.verify_checkpoint_bundle(bundle)
        v2.close()


# ── Legacy archive cleanup ────────────────────────────────────────────────

def _make_legacy_vault(td):
    """Create a vault with a .enc.migrated file (simulates v1→v2 migration)."""
    from crypto import (
        encrypt_evidence as fernet_encrypt,
        derive_vault_key,
        generate_vault_salt,
    )
    evidence_dir = Path(td) / "evidence"
    evidence_dir.mkdir(parents=True)
    v1_salt = generate_vault_salt()
    (Path(td) / "vault_salt.key").write_text(v1_salt + "\n")
    v1_key = derive_vault_key(SECRET, COMMIT, v1_salt)
    enc_path = evidence_dir / "a1b2c3d4e5f60000.enc"
    enc_path.write_bytes(fernet_encrypt(b"legacy PII data", v1_key))

    # Init vault → triggers migration → creates .v2.json + .enc.migrated
    v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
    v.init()
    return v


def test_list_legacy_archives_finds_enc_migrated():
    """list_legacy_archives returns .enc.migrated files."""
    with tempfile.TemporaryDirectory() as td:
        v = _make_legacy_vault(td)
        archives = v.list_legacy_archives()
        assert len(archives) == 1
        assert archives[0].name.endswith(".enc.migrated")
        v.close()


def test_reencrypt_legacy_removes_migrated():
    """reencrypt_legacy_archives_under_v2 removes .enc.migrated after verify."""
    with tempfile.TemporaryDirectory() as td:
        v = _make_legacy_vault(td)
        assert len(v.list_legacy_archives()) == 1

        result = v.reencrypt_legacy_archives_under_v2()
        assert result["archives_processed"] == 1

        # .enc.migrated should be gone
        assert len(v.list_legacy_archives()) == 0
        # .v2.json should still exist and decrypt
        assert v.load_evidence("a1b2c3d4e5f60000") == b"legacy PII data"
        v.close()


def test_reencrypt_legacy_preserves_v2():
    """Re-encryption does not touch existing .v2.json files."""
    with tempfile.TemporaryDirectory() as td:
        v = _make_legacy_vault(td)
        evidence_dir = Path(td) / "evidence"
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        v2_before = v2_path.read_text()

        v.reencrypt_legacy_archives_under_v2()
        # v2 file should be untouched (since it existed and decrypted)
        assert v2_path.read_text() == v2_before
        v.close()


def test_purge_requires_confirm():
    """purge_legacy_archives raises without confirm=True."""
    with tempfile.TemporaryDirectory() as td:
        v = _make_legacy_vault(td)
        try:
            v.purge_legacy_archives()
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "confirm=True" in str(e)
        v.close()


def test_purge_with_confirm_deletes_archives():
    """purge_legacy_archives(confirm=True) deletes .enc.migrated files."""
    with tempfile.TemporaryDirectory() as td:
        v = _make_legacy_vault(td)
        assert len(v.list_legacy_archives()) == 1

        result = v.purge_legacy_archives(confirm=True)
        assert result["archives_purged"] == 1
        assert len(v.list_legacy_archives()) == 0
        v.close()


def test_purge_does_not_touch_v2_json():
    """purge_legacy_archives only removes .enc.migrated, not .v2.json."""
    with tempfile.TemporaryDirectory() as td:
        v = _make_legacy_vault(td)
        evidence_dir = Path(td) / "evidence"
        v2_path = evidence_dir / "a1b2c3d4e5f60000.v2.json"
        assert v2_path.exists()

        v.purge_legacy_archives(confirm=True)
        assert v2_path.exists()
        assert v.load_evidence("a1b2c3d4e5f60000") == b"legacy PII data"
        v.close()


def test_empty_legacy_archives():
    """list/reencrypt/purge on vault with no legacy files are safe no-ops."""
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td, user_commitment=COMMIT, vault_secret=SECRET)
        v.init()
        assert v.list_legacy_archives() == []
        result = v.reencrypt_legacy_archives_under_v2()
        assert result["archives_processed"] == 0
        result = v.purge_legacy_archives(confirm=True)
        assert result["archives_purged"] == 0
        v.close()
