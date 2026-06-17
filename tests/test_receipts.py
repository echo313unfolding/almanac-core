"""Almanac Core — Receipt and Schema Tests"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from receipts import (
    user_commitment,
    sha256_str,
    receipt_hash,
    validate_receipt,
    discovery_receipt,
    deletion_request_receipt,
    broker_response_receipt,
    verification_receipt,
    reappearance_receipt,
    build_chain,
)
from vault import Vault


# ── User commitment ──

def test_commitment_is_deterministic():
    c1 = user_commitment("Jane Doe", "jane@example.com", "salt1")
    c2 = user_commitment("Jane Doe", "jane@example.com", "salt1")
    assert c1 == c2

def test_commitment_is_case_insensitive():
    c1 = user_commitment("Jane Doe", "Jane@Example.com", "s")
    c2 = user_commitment("jane doe", "jane@example.com", "s")
    assert c1 == c2

def test_commitment_changes_with_salt():
    c1 = user_commitment("Jane Doe", "jane@example.com", "salt1")
    c2 = user_commitment("Jane Doe", "jane@example.com", "salt2")
    assert c1 != c2

def test_commitment_hides_identity():
    c = user_commitment("Jane Doe", "jane@example.com")
    assert "jane" not in c.lower()
    assert "doe" not in c.lower()


# ── Discovery receipt ──

def test_discovery_receipt_valid():
    r = discovery_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        record_category="phone_email",
        confidence=0.85,
        evidence="raw html here",
    )
    errors = validate_receipt(r)
    assert errors == [], errors
    assert r["schema"] == "almanac.record_discovery.v1"
    assert r["raw_pii_stored"] is False
    assert r["confidence"] == 0.85

def test_discovery_receipt_rejects_invalid_category():
    r = discovery_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        record_category="invalid_type",
        confidence=0.85,
        evidence="data",
    )
    errors = validate_receipt(r)
    assert any("not in" in e for e in errors)

def test_discovery_receipt_rejects_high_confidence():
    r = discovery_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        record_category="phone_email",
        confidence=1.5,
        evidence="data",
    )
    errors = validate_receipt(r)
    assert any("maximum" in e for e in errors)


# ── Deletion request receipt ──

def test_deletion_request_valid():
    r = deletion_request_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        discovery_receipt_id="disc-001",
        request_type="delete",
        request_method="email",
        evidence="email sent",
    )
    errors = validate_receipt(r)
    assert errors == [], errors
    assert r["request_type"] == "delete"

def test_deletion_request_rejects_bad_method():
    r = deletion_request_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        discovery_receipt_id="disc-001",
        request_type="delete",
        request_method="carrier_pigeon",
        evidence="sent by bird",
    )
    errors = validate_receipt(r)
    assert any("not in" in e for e in errors)


# ── Broker response receipt ──

def test_broker_response_valid():
    r = broker_response_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        request_receipt_id="req-001",
        broker_status="confirmed_deleted",
        evidence="deletion confirmed email",
    )
    errors = validate_receipt(r)
    assert errors == [], errors

def test_broker_response_deadline_exceeded():
    r = broker_response_receipt(
        user_commit="abc123",
        broker_id="intelius",
        request_receipt_id="req-002",
        broker_status="no_response",
        evidence="no reply after 45 days",
        compliance_days=45,
        deadline_exceeded=True,
    )
    errors = validate_receipt(r)
    assert errors == [], errors
    assert r["deadline_exceeded"] is True


# ── Verification receipt ──

def test_verification_still_present():
    r = verification_receipt(
        user_commit="abc123",
        broker_id="mylife",
        response_receipt_id="resp-001",
        verification_method="automated_scan",
        record_still_present=True,
        evidence="profile still visible",
    )
    errors = validate_receipt(r)
    assert errors == [], errors
    assert r["record_still_present"] is True

def test_verification_confirmed_removed():
    r = verification_receipt(
        user_commit="abc123",
        broker_id="fastpeoplesearch",
        response_receipt_id="resp-002",
        verification_method="re_search",
        record_still_present=False,
        evidence="profile returns 404",
    )
    errors = validate_receipt(r)
    assert errors == [], errors
    assert r["record_still_present"] is False


# ── Reappearance receipt ──

def test_reappearance_valid():
    r = reappearance_receipt(
        user_commit="abc123",
        broker_id="spokeo",
        verification_receipt_id="ver-001",
        original_discovery_receipt_id="disc-001",
        record_category="phone_email",
        days_since_removal=60,
        evidence="record reappeared at spokeo",
        likely_source="same_broker",
    )
    errors = validate_receipt(r)
    assert errors == [], errors
    assert r["days_since_removal"] == 60


# ── Raw PII enforcement ──

def test_raw_pii_always_false():
    """Every receipt type must have raw_pii_stored=False."""
    builders = [
        lambda: discovery_receipt("c", "b", "phone_email", 0.5, "e"),
        lambda: deletion_request_receipt("c", "b", "d", "delete", "email", "e"),
        lambda: broker_response_receipt("c", "b", "r", "no_response", "e"),
        lambda: verification_receipt("c", "b", "r", "manual_check", False, "e"),
        lambda: reappearance_receipt("c", "b", "v", "d", "phone_email", 30, "e"),
    ]
    for build in builders:
        r = build()
        assert r["raw_pii_stored"] is False, f"{r['schema']} has raw_pii_stored != False"


# ── Chain ──

def test_chain_hash_deterministic():
    r1 = discovery_receipt("c", "b1", "phone_email", 0.9, "e1")
    r2 = discovery_receipt("c", "b2", "name_address", 0.8, "e2")
    chain1 = build_chain([r1, r2])
    chain2 = build_chain([r1, r2])
    assert chain1["final_chain_hash"] == chain2["final_chain_hash"]

def test_chain_detects_tampering():
    r1 = discovery_receipt("c", "b1", "phone_email", 0.9, "e1")
    r2 = discovery_receipt("c", "b2", "name_address", 0.8, "e2")
    chain_original = build_chain([r1, r2])

    r2_tampered = dict(r2)
    r2_tampered["confidence"] = 0.1
    chain_tampered = build_chain([r1, r2_tampered])

    assert chain_original["final_chain_hash"] != chain_tampered["final_chain_hash"]


# ── Vault ──

def test_vault_init():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        assert (Path(td) / "MANIFEST.md").exists()
        assert (Path(td) / "discovery").is_dir()

def test_vault_store_and_load():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        r = discovery_receipt("c", "spokeo", "phone_email", 0.9, "evidence")
        path = v.store(r)
        assert path.exists()
        loaded = v.load_receipt(path)
        assert loaded["receipt_id"] == r["receipt_id"]

def test_vault_rejects_invalid():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        bad = {"schema": "almanac.record_discovery.v1", "raw_pii_stored": True}
        try:
            v.store(bad)
            assert False, "Should have raised"
        except ValueError:
            pass

def test_vault_summary():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        v.store(discovery_receipt("c", "b1", "phone_email", 0.9, "e"))
        v.store(discovery_receipt("c", "b2", "name_address", 0.8, "e"))
        v.store(deletion_request_receipt("c", "b1", "d1", "delete", "email", "e"))
        s = v.summary()
        assert s["discovery"] == 2
        assert s["requests"] == 1
        assert s["total_receipts"] == 3

def test_vault_broker_report():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        v.store(discovery_receipt("c", "spokeo", "phone_email", 0.9, "e"))
        v.store(broker_response_receipt("c", "spokeo", "r1", "confirmed_deleted", "e"))
        report = v.broker_report()
        assert "spokeo" in report
        assert report["spokeo"]["discovery"] == 1
        assert "confirmed_deleted" in report["spokeo"]["statuses"]

def test_vault_evidence_storage():
    with tempfile.TemporaryDirectory() as td:
        v = Vault(td)
        v.init()
        path = v.store_evidence("abc123def456", "raw html content")
        assert path.exists()
        assert path.read_bytes() == b"raw html content"


# ── Schema validation edge cases ──

def test_unknown_schema_rejected():
    errors = validate_receipt({"schema": "almanac.fake.v99"})
    assert any("Unknown schema" in e for e in errors)

def test_missing_schema_rejected():
    errors = validate_receipt({"broker_id": "test"})
    assert any("schema" in e.lower() for e in errors)

def test_extra_fields_rejected():
    r = discovery_receipt("c", "b", "phone_email", 0.5, "e")
    r["secret_field"] = "should not be here"
    errors = validate_receipt(r)
    assert any("Unknown field" in e for e in errors)


# ── Full demo flow ──

def test_demo_flow():
    """The full demo must complete without errors."""
    sys.path.insert(0, str(Path(__file__).parent.parent / "demo"))
    from privacy_receipt_demo import run_demo
    with tempfile.TemporaryDirectory() as td:
        result = run_demo(td)
        assert result["status"] == "COMPLETE"
        assert result["total_receipts"] > 0
        assert result["chain_hash"] != ""
        assert result["scorecard"]["records_found"] == 8
        assert result["scorecard"]["effective_removal_rate"] > 0
        assert result["scorecard"]["reappeared_60d"] >= 1
