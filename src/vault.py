"""Almanac Core — Local user vault.

Stores receipts in a local directory structure. User-owned. Exportable.
No cloud, no blockchain required. Just files.

Evidence encryption:
  v2 (default): AES-256-GCM structure-bound envelope via crypto_v2.
  v1 (legacy):  Fernet via crypto.py — loaded for backwards compatibility.
  plaintext:    .bin fallback when no vault_secret is provided.

Receipts are portable and plaintext (they contain no PII by schema design).
The vault_secret must never be committed, exported, or stored in the vault.
"""

import hashlib
import json
import os
import stat
from pathlib import Path
from datetime import datetime, timezone

# Owner read/write only — no group, no other
_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR  # 0o600


def _secure_write_text(path: Path, content: str) -> None:
    """Write text and set 0600 permissions."""
    path.write_text(content)
    path.chmod(_FILE_MODE)


def _secure_write_bytes(path: Path, content: bytes) -> None:
    """Write bytes and set 0600 permissions."""
    path.write_bytes(content)
    path.chmod(_FILE_MODE)

try:
    from .receipts import receipt_hash, validate_receipt
    from .crypto import (
        generate_vault_salt, derive_vault_key,
        encrypt_evidence as _fernet_encrypt,
        decrypt_evidence as _fernet_decrypt,
        VAULT_SALT_FILE as V1_SALT_FILE,
    )
    from .crypto_v2 import (
        generate_salt,
        encrypt_evidence as _v2_encrypt,
        decrypt_evidence as _v2_decrypt,
        EncryptedEnvelope,
        validate_secret,
        derive_signing_key,
        compute_hmac,
        verify_hmac,
        VAULT_SALT_FILE as V2_SALT_FILE,
        SCRYPT_SALT_FILE,
    )
    from .structure_key import build_structure_context
except ImportError:
    from receipts import receipt_hash, validate_receipt
    from crypto import (
        generate_vault_salt, derive_vault_key,
        encrypt_evidence as _fernet_encrypt,
        decrypt_evidence as _fernet_decrypt,
        VAULT_SALT_FILE as V1_SALT_FILE,
    )
    from crypto_v2 import (
        generate_salt,
        encrypt_evidence as _v2_encrypt,
        decrypt_evidence as _v2_decrypt,
        EncryptedEnvelope,
        validate_secret,
        derive_signing_key,
        compute_hmac,
        verify_hmac,
        VAULT_SALT_FILE as V2_SALT_FILE,
        SCRYPT_SALT_FILE,
    )
    from structure_key import build_structure_context

DEFAULT_VAULT = Path(os.environ.get("ALMANAC_VAULT", "~/.almanac")).expanduser()

SUBDIRS = [
    "discovery",
    "requests",
    "responses",
    "verifications",
    "reappearances",
    "chain",
    "evidence",
]

SCHEMA_TO_SUBDIR = {
    "almanac.record_discovery.v1": "discovery",
    "almanac.deletion_request.v1": "requests",
    "almanac.broker_response.v1": "responses",
    "almanac.verification.v1": "verifications",
    "almanac.reappearance.v1": "reappearances",
}


class Vault:
    """Local receipt vault with structure-bound encryption at rest for evidence.

    Encryption requires both user_commitment (public, appears in receipts)
    and vault_secret (private passphrase/device key, never stored here).

    New evidence uses crypto_v2 (AES-256-GCM + structure binding).
    Legacy v1 Fernet .enc files still load for backwards compatibility.
    """

    def __init__(
        self,
        root: Path | str | None = None,
        user_commitment: str = "",
        vault_secret: str = "",
    ):
        self.root = Path(root) if root else DEFAULT_VAULT
        self._user_commitment = user_commitment
        self._vault_secret = vault_secret
        # v1 legacy key (Fernet)
        self._vault_key: bytes | None = None
        # v2 salts (AES-256-GCM)
        self._v2_vault_salt: bytes | None = None
        self._v2_scrypt_salt: bytes | None = None
        self._vault_id: str = ""
        # HMAC signing key (derived independently from KEK)
        self._signing_key: bytes | None = None

    def init(self) -> Path:
        """Create vault directory structure. Idempotent.

        Raises ValueError if user_commitment is set but vault_secret is
        missing or too weak (fail-closed — never silently store plaintext
        when the caller intended encryption).
        """
        # Fail-closed: commitment without secret is a configuration error
        if self._user_commitment and not self._vault_secret:
            raise ValueError(
                "user_commitment is set but vault_secret is empty. "
                "Evidence would be stored as plaintext. Either provide a "
                "vault_secret or omit user_commitment for an unencrypted vault."
            )
        # Passphrase strength gate
        if self._vault_secret:
            errors = validate_secret(self._vault_secret)
            if errors:
                raise ValueError(
                    f"Weak vault_secret: {'; '.join(errors)}"
                )

        for sub in SUBDIRS:
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        manifest = self.root / "MANIFEST.md"
        if not manifest.exists():
            manifest.write_text(
                "# Almanac Vault\n\n"
                "This directory contains your personal data rights receipts.\n"
                "You own this data. It never leaves your machine unless you export it.\n\n"
                f"Created: {datetime.now(timezone.utc).isoformat()}\n"
            )
        if self._vault_secret and self._user_commitment:
            self._init_v1_encryption()
            self._init_v2_encryption()
            self._init_signing_key()
            self._migrate_v1_to_v2()
        return self.root

    def _init_v1_encryption(self):
        """Initialize legacy v1 Fernet key for reading old .enc files."""
        salt_path = self.root / V1_SALT_FILE
        if salt_path.exists():
            vault_salt = salt_path.read_text().strip()
        else:
            vault_salt = generate_vault_salt()
            _secure_write_text(salt_path, vault_salt + "\n")
        self._vault_key = derive_vault_key(
            self._vault_secret, self._user_commitment, vault_salt
        )

    def _init_v2_encryption(self):
        """Initialize v2 AES-256-GCM salts."""
        vs_path = self.root / V2_SALT_FILE
        if vs_path.exists():
            self._v2_vault_salt = bytes.fromhex(vs_path.read_text().strip())
        else:
            self._v2_vault_salt = generate_salt()
            _secure_write_text(vs_path, self._v2_vault_salt.hex() + "\n")

        ss_path = self.root / SCRYPT_SALT_FILE
        if ss_path.exists():
            self._v2_scrypt_salt = bytes.fromhex(ss_path.read_text().strip())
        else:
            self._v2_scrypt_salt = generate_salt()
            _secure_write_text(ss_path, self._v2_scrypt_salt.hex() + "\n")

        self._vault_id = hashlib.sha256(self._v2_vault_salt).hexdigest()[:16]

    def _init_signing_key(self):
        """Derive HMAC signing key (independent of KEK)."""
        self._signing_key = derive_signing_key(
            self._vault_secret,
            self._user_commitment,
            self._v2_vault_salt,
            self._v2_scrypt_salt,
        )

    def _migrate_v1_to_v2(self):
        """Auto-migrate legacy .enc evidence files to v2 .v2.json.

        Runs on every init when both v1 key and v2 salts are available.
        Decrypts with v1 Fernet, re-encrypts with v2 AES-256-GCM,
        then removes the old .enc file.
        """
        if not self._vault_key or not self._v2_vault_salt:
            return
        evidence_dir = self.root / "evidence"
        if not evidence_dir.exists():
            return
        for enc_path in sorted(evidence_dir.glob("*.enc")):
            evidence_hash = enc_path.stem  # e.g. "abc123def456" from "abc123def456.enc"
            v2_path = evidence_dir / f"{evidence_hash}.v2.json"
            if v2_path.exists():
                continue  # already migrated
            plaintext = _fernet_decrypt(enc_path.read_bytes(), self._vault_key)
            ctx = self._default_structure_context(evidence_hash)
            envelope = _v2_encrypt(
                plaintext,
                self._vault_secret,
                self._user_commitment,
                self._v2_vault_salt,
                self._v2_scrypt_salt,
                ctx,
            )
            stored = envelope.to_dict()
            stored["ciphertext_hex"] = envelope.ciphertext.hex()
            _secure_write_text(v2_path, json.dumps(stored, indent=2) + "\n")
            enc_path.unlink()

    def _sign_receipt(self, path: Path) -> None:
        """Write HMAC-SHA256 sidecar for a receipt file."""
        if not self._signing_key:
            return
        data = path.read_bytes()
        mac = compute_hmac(data, self._signing_key)
        _secure_write_text(path.with_suffix(".hmac"), mac + "\n")

    def _verify_receipt_hmac(self, path: Path) -> None:
        """Verify HMAC sidecar if it exists and vault has signing key.

        Raises ValueError on mismatch. Silent if no sidecar or no key.
        """
        hmac_path = path.with_suffix(".hmac")
        if not hmac_path.exists():
            return
        if not self._signing_key:
            return  # can't verify without key
        expected = hmac_path.read_text().strip()
        data = path.read_bytes()
        if not verify_hmac(data, self._signing_key, expected):
            raise ValueError(
                f"Receipt HMAC verification failed: {path.name} has been tampered with"
            )

    @property
    def encrypted(self) -> bool:
        return self._v2_vault_salt is not None

    @property
    def vault_id(self) -> str:
        return self._vault_id

    def _default_structure_context(self, evidence_hash: str, **overrides) -> dict:
        """Build a minimal deterministic structure context for evidence."""
        ctx = build_structure_context(
            user_commitment=self._user_commitment,
            capsule_type=overrides.get("capsule_type", "vault_evidence"),
            vault_id=self._vault_id,
            receipt_schema=overrides.get("receipt_schema", ""),
            receipt_id=overrides.get("receipt_id", evidence_hash),
            previous_receipt_hash=overrides.get("previous_receipt_hash", ""),
            policy_hash=overrides.get("policy_hash", ""),
            chain_position=overrides.get("chain_position", 0),
        )
        return ctx

    def store(self, receipt: dict) -> Path:
        """Validate and store a receipt. Returns the file path."""
        errors = validate_receipt(receipt)
        if errors:
            raise ValueError(f"Invalid receipt: {errors}")

        schema = receipt["schema"]
        subdir = SCHEMA_TO_SUBDIR.get(schema)
        if not subdir:
            raise ValueError(f"Unknown schema for storage: {schema}")

        target_dir = self.root / subdir
        target_dir.mkdir(parents=True, exist_ok=True)

        rid = receipt["receipt_id"]
        broker = receipt.get("broker_id", "unknown")
        fname = f"{broker}_{rid[:8]}.json"
        path = target_dir / fname

        path.write_text(json.dumps(receipt, indent=2) + "\n")
        self._sign_receipt(path)
        return path

    def store_chain(self, chain: dict) -> Path:
        """Store a chain summary."""
        chain_dir = self.root / "chain"
        chain_dir.mkdir(parents=True, exist_ok=True)
        h = chain["final_chain_hash"][:12]
        path = chain_dir / f"chain_{h}.json"
        path.write_text(json.dumps(chain, indent=2) + "\n")
        return path

    def store_evidence(
        self,
        evidence_hash: str,
        data: str | bytes,
        structure_context: dict | None = None,
    ) -> Path:
        """Store raw evidence locally, encrypted at rest if vault has a secret.

        Uses crypto_v2 (AES-256-GCM + structure binding) by default.
        Falls back to plaintext .bin if no vault_secret is provided.
        """
        evidence_dir = self.root / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()

        if self._v2_vault_salt and self._v2_scrypt_salt:
            # v2: AES-256-GCM with structure binding
            ctx = structure_context or self._default_structure_context(evidence_hash)
            envelope = _v2_encrypt(
                data,
                self._vault_secret,
                self._user_commitment,
                self._v2_vault_salt,
                self._v2_scrypt_salt,
                ctx,
            )
            stored = envelope.to_dict()
            stored["ciphertext_hex"] = envelope.ciphertext.hex()
            path = evidence_dir / f"{evidence_hash[:16]}.v2.json"
            _secure_write_text(path, json.dumps(stored, indent=2) + "\n")
        else:
            # No encryption — plaintext fallback
            path = evidence_dir / f"{evidence_hash[:16]}.bin"
            _secure_write_bytes(path, data)
        return path

    def load_evidence(
        self,
        evidence_hash: str,
        structure_context: dict | None = None,
    ) -> bytes:
        """Load and decrypt evidence by hash prefix.

        Auto-detects format:
          .v2.json → crypto_v2 AES-256-GCM decrypt
          .enc     → legacy v1 Fernet decrypt
          .bin     → plaintext legacy fallback
        """
        evidence_dir = self.root / "evidence"
        v2_path = evidence_dir / f"{evidence_hash[:16]}.v2.json"
        enc_path = evidence_dir / f"{evidence_hash[:16]}.enc"
        bin_path = evidence_dir / f"{evidence_hash[:16]}.bin"

        if v2_path.exists():
            if not self._v2_vault_salt or not self._v2_scrypt_salt:
                raise ValueError(
                    "Evidence is v2-encrypted but no vault_secret provided"
                )
            stored = json.loads(v2_path.read_text())
            ciphertext = bytes.fromhex(stored["ciphertext_hex"])
            envelope = EncryptedEnvelope.from_stored(stored, ciphertext)
            ctx = structure_context or self._default_structure_context(evidence_hash)
            return _v2_decrypt(
                envelope,
                self._vault_secret,
                self._user_commitment,
                self._v2_vault_salt,
                self._v2_scrypt_salt,
                ctx,
            )
        elif enc_path.exists():
            # Legacy v1 Fernet
            if not self._vault_key:
                raise ValueError(
                    "Evidence is v1-encrypted but no vault_secret provided"
                )
            return _fernet_decrypt(enc_path.read_bytes(), self._vault_key)
        elif bin_path.exists():
            # Downgrade protection: if vault is encrypted, refuse plaintext
            # evidence — attacker may have deleted .v2.json and planted .bin
            if self.encrypted:
                raise ValueError(
                    f"Evidence {evidence_hash[:16]} is plaintext (.bin) but vault "
                    "is encrypted. Possible downgrade attack. Re-store the evidence "
                    "or verify the file manually."
                )
            return bin_path.read_bytes()
        else:
            raise FileNotFoundError(f"No evidence for hash {evidence_hash[:16]}")

    def list_receipts(self, subdir: str = "") -> list[Path]:
        """List all receipt files, optionally filtered by subdirectory."""
        if subdir:
            target = self.root / subdir
            if not target.exists():
                return []
            return sorted(target.glob("*.json"))
        results = []
        for sub in SCHEMA_TO_SUBDIR.values():
            target = self.root / sub
            if target.exists():
                results.extend(sorted(target.glob("*.json")))
        return results

    def load_receipt(self, path: Path) -> dict:
        """Load and validate a receipt from file.

        If an HMAC sidecar exists and vault has a signing key,
        verifies integrity before returning. Raises ValueError on tamper.
        """
        self._verify_receipt_hmac(path)
        receipt = json.loads(path.read_text())
        errors = validate_receipt(receipt)
        if errors:
            raise ValueError(f"Invalid receipt at {path}: {errors}")
        return receipt

    def load_all(self, subdir: str = "") -> list[dict]:
        """Load all receipts, optionally filtered."""
        return [self.load_receipt(p) for p in self.list_receipts(subdir)]

    def summary(self) -> dict:
        """Vault summary: counts per category."""
        counts = {}
        for sub in SCHEMA_TO_SUBDIR.values():
            target = self.root / sub
            if target.exists():
                counts[sub] = len(list(target.glob("*.json")))
            else:
                counts[sub] = 0
        counts["chains"] = len(list((self.root / "chain").glob("*.json"))) if (self.root / "chain").exists() else 0
        counts["evidence_files"] = len(list((self.root / "evidence").glob("*"))) if (self.root / "evidence").exists() else 0
        counts["total_receipts"] = sum(v for k, v in counts.items() if k not in ("chains", "evidence_files"))
        return counts

    def rotate_secret(self, new_secret: str) -> dict:
        """Rotate vault_secret: re-encrypt all evidence with new key material.

        Steps:
          1. Validate new secret strength
          2. Decrypt all evidence with current secret
          3. Generate new scrypt salt (vault_salt stays — identifies the vault)
          4. Re-encrypt all evidence with new secret + new scrypt salt
          5. Re-sign all receipts with new signing key
          6. Return summary of what was rotated

        Raises ValueError if vault is not encrypted or new secret is weak.
        """
        if not self.encrypted:
            raise ValueError("Cannot rotate: vault is not encrypted")
        errors = validate_secret(new_secret)
        if errors:
            raise ValueError(f"Weak new secret: {'; '.join(errors)}")
        if new_secret == self._vault_secret:
            raise ValueError("New secret must differ from current secret")

        evidence_dir = self.root / "evidence"
        # Phase 1: Decrypt all evidence with current secret
        evidence_items: list[tuple[str, bytes, Path]] = []
        if evidence_dir.exists():
            for v2_path in sorted(evidence_dir.glob("*.v2.json")):
                evidence_hash = v2_path.name.replace(".v2.json", "")
                plaintext = self.load_evidence(evidence_hash)
                evidence_items.append((evidence_hash, plaintext, v2_path))

        # Phase 2: Generate new scrypt salt, re-derive keys
        new_scrypt_salt = generate_salt()
        old_scrypt_path = self.root / SCRYPT_SALT_FILE

        # Phase 3: Re-encrypt all evidence
        new_paths: list[tuple[Path, Path]] = []  # (new_path, old_path)
        for evidence_hash, plaintext, old_path in evidence_items:
            ctx = self._default_structure_context(evidence_hash)
            envelope = _v2_encrypt(
                plaintext,
                new_secret,
                self._user_commitment,
                self._v2_vault_salt,
                new_scrypt_salt,
                ctx,
            )
            stored = envelope.to_dict()
            stored["ciphertext_hex"] = envelope.ciphertext.hex()
            # Write to .tmp first, rename after all succeed
            tmp_path = old_path.with_suffix(".v2.json.tmp")
            _secure_write_text(tmp_path, json.dumps(stored, indent=2) + "\n")
            new_paths.append((tmp_path, old_path))

        # Phase 4: Atomic-ish commit — rename all .tmp to .v2.json
        for tmp_path, old_path in new_paths:
            tmp_path.rename(old_path)

        # Phase 5: Update scrypt salt on disk
        _secure_write_text(old_scrypt_path, new_scrypt_salt.hex() + "\n")

        # Phase 6: Update internal state
        self._vault_secret = new_secret
        self._v2_scrypt_salt = new_scrypt_salt
        self._signing_key = derive_signing_key(
            new_secret, self._user_commitment,
            self._v2_vault_salt, new_scrypt_salt,
        )

        # Phase 7: Re-sign all receipts
        receipts_signed = 0
        for receipt_path in self.list_receipts():
            self._sign_receipt(receipt_path)
            receipts_signed += 1

        return {
            "evidence_rotated": len(evidence_items),
            "receipts_re_signed": receipts_signed,
            "new_scrypt_salt": new_scrypt_salt.hex()[:16] + "...",
        }

    def broker_report(self) -> dict[str, dict]:
        """Per-broker summary across all receipt types."""
        brokers: dict[str, dict] = {}
        for receipt in self.load_all():
            bid = receipt.get("broker_id", "unknown")
            if bid not in brokers:
                brokers[bid] = {
                    "discovery": 0, "requests": 0, "responses": 0,
                    "verifications": 0, "reappearances": 0,
                    "statuses": [],
                }
            schema = receipt["schema"]
            sub = SCHEMA_TO_SUBDIR.get(schema, "")
            if sub in brokers[bid]:
                brokers[bid][sub] += 1
            if "broker_status" in receipt:
                brokers[bid]["statuses"].append(receipt["broker_status"])
        return brokers
