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
from pathlib import Path
from datetime import datetime, timezone

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

    def init(self) -> Path:
        """Create vault directory structure. Idempotent."""
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
        return self.root

    def _init_v1_encryption(self):
        """Initialize legacy v1 Fernet key for reading old .enc files."""
        salt_path = self.root / V1_SALT_FILE
        if salt_path.exists():
            vault_salt = salt_path.read_text().strip()
        else:
            vault_salt = generate_vault_salt()
            salt_path.write_text(vault_salt + "\n")
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
            vs_path.write_text(self._v2_vault_salt.hex() + "\n")

        ss_path = self.root / SCRYPT_SALT_FILE
        if ss_path.exists():
            self._v2_scrypt_salt = bytes.fromhex(ss_path.read_text().strip())
        else:
            self._v2_scrypt_salt = generate_salt()
            ss_path.write_text(self._v2_scrypt_salt.hex() + "\n")

        self._vault_id = hashlib.sha256(self._v2_vault_salt).hexdigest()[:16]

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
            path.write_text(json.dumps(stored, indent=2) + "\n")
        else:
            # No encryption — plaintext fallback
            path = evidence_dir / f"{evidence_hash[:16]}.bin"
            path.write_bytes(data)
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
        """Load and validate a receipt from file."""
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
