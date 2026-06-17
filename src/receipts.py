"""Almanac Core — Receipt creation, validation, and chain hashing."""

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_DIR = Path(__file__).parent.parent / "schemas"

SCHEMAS = {
    "almanac.record_discovery.v1": "record_discovery.v1.json",
    "almanac.deletion_request.v1": "deletion_request.v1.json",
    "almanac.broker_response.v1": "broker_response.v1.json",
    "almanac.verification.v1": "verification.v1.json",
    "almanac.reappearance.v1": "reappearance.v1.json",
}

# ---------- helpers ----------

def _now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _uuid():
    return str(uuid.uuid4())

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def receipt_hash(receipt: dict) -> str:
    """Deterministic hash of a receipt (sorted keys, no whitespace)."""
    canonical = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    return sha256_str(canonical)

def user_commitment(name: str, email: str, salt: str = "") -> str:
    """Hash user identity into a commitment. The identity never leaves local."""
    raw = f"{name.lower().strip()}|{email.lower().strip()}|{salt}"
    return sha256_str(raw)

# ---------- schema validation ----------

def _load_schema(schema_id: str) -> dict:
    fname = SCHEMAS.get(schema_id)
    if not fname:
        raise ValueError(f"Unknown schema: {schema_id}")
    return json.loads((SCHEMA_DIR / fname).read_text())

def validate_receipt(receipt: dict) -> list[str]:
    """Validate receipt against its schema. Returns list of errors (empty = valid)."""
    errors = []
    schema_id = receipt.get("schema")
    if not schema_id:
        return ["Missing 'schema' field"]

    try:
        schema = _load_schema(schema_id)
    except ValueError as e:
        return [str(e)]

    required = schema.get("required", [])
    properties = schema.get("properties", {})

    for field in required:
        if field not in receipt:
            errors.append(f"Missing required field: {field}")

    if schema.get("additionalProperties") is False:
        allowed = set(properties.keys())
        for key in receipt:
            if key not in allowed:
                errors.append(f"Unknown field: {key}")

    for field, spec in properties.items():
        if field not in receipt:
            continue
        val = receipt[field]

        if "const" in spec and val != spec["const"]:
            errors.append(f"{field}: expected {spec['const']!r}, got {val!r}")
        if "enum" in spec and val not in spec["enum"]:
            errors.append(f"{field}: {val!r} not in {spec['enum']}")
        if spec.get("type") == "string" and not isinstance(val, str):
            errors.append(f"{field}: expected string, got {type(val).__name__}")
        if spec.get("type") == "number" and not isinstance(val, (int, float)):
            errors.append(f"{field}: expected number, got {type(val).__name__}")
        if spec.get("type") == "integer" and not isinstance(val, int):
            errors.append(f"{field}: expected integer, got {type(val).__name__}")
        if spec.get("type") == "boolean" and not isinstance(val, bool):
            errors.append(f"{field}: expected boolean, got {type(val).__name__}")
        if "minimum" in spec and isinstance(val, (int, float)) and val < spec["minimum"]:
            errors.append(f"{field}: {val} < minimum {spec['minimum']}")
        if "maximum" in spec and isinstance(val, (int, float)) and val > spec["maximum"]:
            errors.append(f"{field}: {val} > maximum {spec['maximum']}")

    if receipt.get("raw_pii_stored") is not False:
        errors.append("raw_pii_stored must be false")

    return errors

# ---------- receipt builders ----------

def discovery_receipt(
    user_commit: str,
    broker_id: str,
    record_category: str,
    confidence: float,
    evidence: str | bytes,
    service_id: str = "manual",
    previous_hash: str = "",
    broker_url: str = "",
    notes: str = "",
) -> dict:
    evidence_hash = sha256_str(evidence) if isinstance(evidence, str) else sha256_bytes(evidence)
    r = {
        "schema": "almanac.record_discovery.v1",
        "receipt_id": _uuid(),
        "user_commitment": user_commit,
        "service_id": service_id,
        "broker_id": broker_id,
        "record_category": record_category,
        "confidence": confidence,
        "evidence_hash": evidence_hash,
        "discovered_at": _now_iso(),
        "raw_pii_stored": False,
        "previous_receipt_hash": previous_hash,
    }
    if broker_url:
        r["broker_url"] = broker_url
    if notes:
        r["notes"] = notes
    return r


def deletion_request_receipt(
    user_commit: str,
    broker_id: str,
    discovery_receipt_id: str,
    request_type: str,
    request_method: str,
    evidence: str | bytes,
    service_id: str = "manual",
    legal_basis: str = "none",
    confirmation_id: str = "",
    compliance_deadline: str = "",
    previous_hash: str = "",
    notes: str = "",
) -> dict:
    evidence_hash = sha256_str(evidence) if isinstance(evidence, str) else sha256_bytes(evidence)
    r = {
        "schema": "almanac.deletion_request.v1",
        "receipt_id": _uuid(),
        "user_commitment": user_commit,
        "service_id": service_id,
        "broker_id": broker_id,
        "discovery_receipt_id": discovery_receipt_id,
        "request_type": request_type,
        "request_method": request_method,
        "submitted_at": _now_iso(),
        "evidence_hash": evidence_hash,
        "raw_pii_stored": False,
        "previous_receipt_hash": previous_hash,
    }
    if legal_basis != "none":
        r["legal_basis"] = legal_basis
    if confirmation_id:
        r["confirmation_id"] = confirmation_id
    if compliance_deadline:
        r["compliance_deadline"] = compliance_deadline
    if notes:
        r["notes"] = notes
    return r


def broker_response_receipt(
    user_commit: str,
    broker_id: str,
    request_receipt_id: str,
    broker_status: str,
    evidence: str | bytes,
    service_id: str = "manual",
    compliance_days: int = 0,
    deadline_exceeded: bool = False,
    rejection_reason: str = "",
    previous_hash: str = "",
    notes: str = "",
) -> dict:
    evidence_hash = sha256_str(evidence) if isinstance(evidence, str) else sha256_bytes(evidence)
    r = {
        "schema": "almanac.broker_response.v1",
        "receipt_id": _uuid(),
        "user_commitment": user_commit,
        "service_id": service_id,
        "broker_id": broker_id,
        "request_receipt_id": request_receipt_id,
        "broker_status": broker_status,
        "responded_at": _now_iso(),
        "compliance_days": compliance_days,
        "deadline_exceeded": deadline_exceeded,
        "evidence_hash": evidence_hash,
        "raw_pii_stored": False,
        "previous_receipt_hash": previous_hash,
    }
    if rejection_reason:
        r["rejection_reason"] = rejection_reason
    if notes:
        r["notes"] = notes
    return r


def verification_receipt(
    user_commit: str,
    broker_id: str,
    response_receipt_id: str,
    verification_method: str,
    record_still_present: bool,
    evidence: str | bytes,
    service_id: str = "manual",
    days_since_deletion: int = 0,
    previous_hash: str = "",
    notes: str = "",
) -> dict:
    evidence_hash = sha256_str(evidence) if isinstance(evidence, str) else sha256_bytes(evidence)
    r = {
        "schema": "almanac.verification.v1",
        "receipt_id": _uuid(),
        "user_commitment": user_commit,
        "service_id": service_id,
        "broker_id": broker_id,
        "response_receipt_id": response_receipt_id,
        "verification_method": verification_method,
        "record_still_present": record_still_present,
        "verified_at": _now_iso(),
        "days_since_deletion": days_since_deletion,
        "evidence_hash": evidence_hash,
        "raw_pii_stored": False,
        "previous_receipt_hash": previous_hash,
    }
    if notes:
        r["notes"] = notes
    return r


def reappearance_receipt(
    user_commit: str,
    broker_id: str,
    verification_receipt_id: str,
    original_discovery_receipt_id: str,
    record_category: str,
    days_since_removal: int,
    evidence: str | bytes,
    service_id: str = "manual",
    likely_source: str = "unknown",
    previous_hash: str = "",
    notes: str = "",
) -> dict:
    evidence_hash = sha256_str(evidence) if isinstance(evidence, str) else sha256_bytes(evidence)
    r = {
        "schema": "almanac.reappearance.v1",
        "receipt_id": _uuid(),
        "user_commitment": user_commit,
        "service_id": service_id,
        "broker_id": broker_id,
        "verification_receipt_id": verification_receipt_id,
        "original_discovery_receipt_id": original_discovery_receipt_id,
        "record_category": record_category,
        "reappeared_at": _now_iso(),
        "days_since_removal": days_since_removal,
        "likely_source": likely_source,
        "evidence_hash": evidence_hash,
        "raw_pii_stored": False,
        "previous_receipt_hash": previous_hash,
    }
    if notes:
        r["notes"] = notes
    return r


# ---------- chain ----------

def build_chain(receipts: list[dict]) -> dict:
    """Build a receipt chain with running hash. Returns chain summary."""
    chain_hashes = []
    for i, r in enumerate(receipts):
        h = receipt_hash(r)
        chain_hashes.append(h)

    final_hash = sha256_str("|".join(chain_hashes))
    return {
        "chain_length": len(receipts),
        "receipt_ids": [r["receipt_id"] for r in receipts],
        "schemas": [r["schema"] for r in receipts],
        "final_chain_hash": final_hash,
        "built_at": _now_iso(),
    }
