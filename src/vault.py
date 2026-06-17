"""Almanac Core — Local user vault.

Stores receipts in a local directory structure. User-owned. Exportable.
No cloud, no blockchain required. Just files.

Evidence files are encrypted at rest when a user_commitment is provided.
Receipts are plaintext (they contain no PII by schema design).
"""

import json
import os
from pathlib import Path
from datetime import datetime, timezone

try:
    from .receipts import receipt_hash, validate_receipt
    from .crypto import (
        generate_vault_salt, derive_vault_key,
        encrypt_evidence, decrypt_evidence, VAULT_SALT_FILE,
    )
except ImportError:
    from receipts import receipt_hash, validate_receipt
    from crypto import (
        generate_vault_salt, derive_vault_key,
        encrypt_evidence, decrypt_evidence, VAULT_SALT_FILE,
    )

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
    """Local receipt vault with optional encryption at rest for evidence."""

    def __init__(self, root: Path | str | None = None, user_commitment: str = ""):
        self.root = Path(root) if root else DEFAULT_VAULT
        self._user_commitment = user_commitment
        self._vault_key: bytes | None = None

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
        if self._user_commitment:
            self._init_encryption()
        return self.root

    def _init_encryption(self):
        """Initialize or load vault encryption key from salt + user commitment."""
        salt_path = self.root / VAULT_SALT_FILE
        if salt_path.exists():
            vault_salt = salt_path.read_text().strip()
        else:
            vault_salt = generate_vault_salt()
            salt_path.write_text(vault_salt + "\n")
        self._vault_key = derive_vault_key(self._user_commitment, vault_salt)

    @property
    def encrypted(self) -> bool:
        return self._vault_key is not None

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

    def store_evidence(self, evidence_hash: str, data: str | bytes) -> Path:
        """Store raw evidence locally, encrypted at rest if vault has a key."""
        evidence_dir = self.root / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        if self._vault_key:
            data = encrypt_evidence(data, self._vault_key)
            path = evidence_dir / f"{evidence_hash[:16]}.enc"
        else:
            path = evidence_dir / f"{evidence_hash[:16]}.bin"
        path.write_bytes(data)
        return path

    def load_evidence(self, evidence_hash: str) -> bytes:
        """Load and decrypt evidence by hash prefix."""
        evidence_dir = self.root / "evidence"
        enc_path = evidence_dir / f"{evidence_hash[:16]}.enc"
        bin_path = evidence_dir / f"{evidence_hash[:16]}.bin"
        if enc_path.exists():
            if not self._vault_key:
                raise ValueError("Evidence is encrypted but no user_commitment provided")
            return decrypt_evidence(enc_path.read_bytes(), self._vault_key)
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
