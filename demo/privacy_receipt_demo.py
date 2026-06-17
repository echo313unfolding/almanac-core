#!/usr/bin/env python3
"""Almanac Core — Privacy Receipt Demo

Simulates a full data-rights lifecycle:
  1. Import broker scan report (like DeleteMe/Incogni output)
  2. Generate discovery receipts (filter by confidence)
  3. Submit deletion requests
  4. Process broker responses
  5. Verify removal
  6. Detect reappearance
  7. Store everything in local vault
  8. Print audit summary

No raw PII leaves the vault. Every step has a receipt.
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from receipts import (
    user_commitment,
    discovery_receipt,
    deletion_request_receipt,
    broker_response_receipt,
    verification_receipt,
    reappearance_receipt,
    build_chain,
    receipt_hash,
)
from vault import Vault

FIXTURES = Path(__file__).parent.parent / "fixtures"
CONFIDENCE_THRESHOLD = 0.60  # Below this, flag as likely wrong person


def run_demo(vault_root: str | None = None):
    """Run the full privacy receipt demo."""

    print()
    print("=" * 64)
    print("  ALMANAC CORE — Privacy Receipt Demo")
    print("  Open infrastructure for personal data rights")
    print("=" * 64)
    print()

    # --- Setup vault ---
    vault = Vault(vault_root or tempfile.mkdtemp(prefix="almanac_demo_"))
    vault.init()
    print(f"Vault: {vault.root}")
    print()

    # --- Load fixtures ---
    scan = json.loads((FIXTURES / "broker_scan_report.json").read_text())
    responses = json.loads((FIXTURES / "broker_responses.json").read_text())["responses"]

    # --- Step 0: Create user commitment (identity stays local) ---
    user = scan["user_provided"]
    commit = user_commitment(user["name"], user["email"], salt="demo-salt-2026")
    print(f"[0] User commitment: {commit[:16]}...")
    print(f"    Identity stays LOCAL. Only the hash travels.")
    print()

    # --- Step 1: Discovery receipts ---
    print(f"[1] DISCOVERY — {len(scan['records_found'])} records found across {scan['brokers_scanned']} brokers")
    print()

    all_receipts = []
    discoveries = {}
    high_confidence = 0
    low_confidence = 0

    prev_hash = ""
    for record in scan["records_found"]:
        conf = record["match_confidence"]
        if conf >= CONFIDENCE_THRESHOLD:
            high_confidence += 1
            flag = "MATCH"
        else:
            low_confidence += 1
            flag = "LIKELY WRONG PERSON"

        dr = discovery_receipt(
            user_commit=commit,
            broker_id=record["broker"],
            record_category=record["record_type"],
            confidence=conf,
            evidence=record["raw_evidence"],
            service_id=scan["service"],
            previous_hash=prev_hash,
            broker_url=record.get("broker_url", ""),
            notes=f"{flag}: {record['details_summary']}"
        )

        vault.store(dr)
        vault.store_evidence(dr["evidence_hash"], record["raw_evidence"])
        all_receipts.append(dr)
        discoveries[record["broker"]] = dr
        prev_hash = receipt_hash(dr)

        conf_bar = "█" * int(conf * 20) + "░" * (20 - int(conf * 20))
        print(f"    {record['broker']:25s} [{conf_bar}] {conf:.0%}  {flag}")

    print()
    print(f"    High confidence (>={CONFIDENCE_THRESHOLD:.0%}): {high_confidence}")
    print(f"    Likely wrong person:  {low_confidence}")
    accuracy = high_confidence / len(scan["records_found"]) * 100
    print(f"    Effective accuracy:   {accuracy:.0f}% (industry avg: 41%)")
    print()

    # --- Step 2: Deletion requests (only for high-confidence matches) ---
    print(f"[2] DELETION REQUESTS — submitting for {high_confidence} high-confidence records")
    print()

    requests = {}
    for broker_id, dr in discoveries.items():
        if dr["confidence"] < CONFIDENCE_THRESHOLD:
            print(f"    {broker_id:25s} SKIPPED (confidence {dr['confidence']:.0%} < {CONFIDENCE_THRESHOLD:.0%})")
            continue

        resp_data = responses.get(broker_id, {})
        method = resp_data.get("method", "email")

        req = deletion_request_receipt(
            user_commit=commit,
            broker_id=broker_id,
            discovery_receipt_id=dr["receipt_id"],
            request_type="delete",
            request_method=method,
            evidence=f"Deletion request submitted via {method} to {broker_id}",
            service_id=scan["service"],
            legal_basis="ccpa",
            previous_hash=prev_hash,
        )

        vault.store(req)
        all_receipts.append(req)
        requests[broker_id] = req
        prev_hash = receipt_hash(req)

        print(f"    {broker_id:25s} {method:10s} CCPA delete request submitted")

    print()

    # --- Step 3: Broker responses ---
    print(f"[3] BROKER RESPONSES")
    print()

    broker_resps = {}
    for broker_id, req in requests.items():
        resp_data = responses.get(broker_id, {"status": "no_response", "days_to_respond": 45})
        status = resp_data["status"]
        days = resp_data.get("days_to_respond", 0)
        exceeded = resp_data.get("deadline_exceeded", days > 45)

        br = broker_response_receipt(
            user_commit=commit,
            broker_id=broker_id,
            request_receipt_id=req["receipt_id"],
            broker_status=status,
            evidence=resp_data.get("evidence", "no evidence"),
            service_id=scan["service"],
            compliance_days=days,
            deadline_exceeded=exceeded,
            rejection_reason=resp_data.get("rejection_reason", ""),
            previous_hash=prev_hash,
            notes=resp_data.get("note", ""),
        )

        vault.store(br)
        all_receipts.append(br)
        broker_resps[broker_id] = br
        prev_hash = receipt_hash(br)

        status_icon = {
            "confirmed_deleted": "✓ DELETED",
            "partial": "◐ PARTIAL",
            "no_response": "✗ NO RESPONSE",
            "rejected": "✗ REJECTED",
            "pending": "… PENDING",
            "unverifiable": "? UNVERIFIABLE",
        }.get(status, status)

        deadline_flag = " ⚠ DEADLINE EXCEEDED" if exceeded else ""
        print(f"    {broker_id:25s} {status_icon:20s} {days:2d} days{deadline_flag}")

    print()

    # --- Step 4: Verification ---
    print(f"[4] VERIFICATION — checking 14 days after response")
    print()

    verifications = {}
    for broker_id, br in broker_resps.items():
        resp_data = responses.get(broker_id, {})
        v14 = resp_data.get("verification_14d", {"still_present": True})
        still_present = v14.get("still_present", True)

        vr = verification_receipt(
            user_commit=commit,
            broker_id=broker_id,
            response_receipt_id=br["receipt_id"],
            verification_method="automated_scan",
            record_still_present=still_present,
            evidence=f"14-day automated re-scan of {broker_id}: {'STILL PRESENT' if still_present else 'CONFIRMED REMOVED'}",
            service_id=scan["service"],
            days_since_deletion=14,
            previous_hash=prev_hash,
            notes=v14.get("note", ""),
        )

        vault.store(vr)
        all_receipts.append(vr)
        verifications[broker_id] = vr
        prev_hash = receipt_hash(vr)

        status = "⚠ STILL PRESENT" if still_present else "✓ CONFIRMED REMOVED"
        note = f"  ({v14['note']})" if v14.get("note") else ""
        print(f"    {broker_id:25s} {status}{note}")

    print()

    # --- Step 5: Reappearance detection (60-day check) ---
    print(f"[5] REAPPEARANCE CHECK — 60 days after deletion")
    print()

    reappearances = []
    for broker_id, vr in verifications.items():
        if vr["record_still_present"]:
            continue  # Already flagged as not removed

        resp_data = responses.get(broker_id, {})
        v60 = resp_data.get("verification_60d")
        if not v60:
            print(f"    {broker_id:25s} — no 60-day check available")
            continue

        if v60.get("still_present", False):
            rr = reappearance_receipt(
                user_commit=commit,
                broker_id=broker_id,
                verification_receipt_id=vr["receipt_id"],
                original_discovery_receipt_id=discoveries[broker_id]["receipt_id"],
                record_category=discoveries[broker_id]["record_category"],
                days_since_removal=60,
                evidence=f"60-day re-scan: record reappeared at {broker_id}",
                service_id=scan["service"],
                likely_source="same_broker",
                previous_hash=prev_hash,
                notes=v60.get("note", ""),
            )

            vault.store(rr)
            all_receipts.append(rr)
            reappearances.append(rr)
            prev_hash = receipt_hash(rr)

            print(f"    {broker_id:25s} ⚠ REAPPEARED after {60} days — {v60.get('note', '')}")
        else:
            print(f"    {broker_id:25s} ✓ still removed at 60 days")

    if not any(responses.get(b, {}).get("verification_60d") for b in verifications if not verifications[b]["record_still_present"]):
        print(f"    (no 60-day data available)")

    print()

    # --- Step 6: Build receipt chain ---
    chain = build_chain(all_receipts)
    vault.store_chain(chain)

    # --- Step 7: Audit summary ---
    summary = vault.summary()
    broker_report = vault.broker_report()

    print("=" * 64)
    print("  AUDIT SUMMARY")
    print("=" * 64)
    print()
    print(f"  Vault location:       {vault.root}")
    print(f"  Total receipts:       {summary['total_receipts']}")
    print(f"  Discovery:            {summary['discovery']}")
    print(f"  Deletion requests:    {summary['requests']}")
    print(f"  Broker responses:     {summary['responses']}")
    print(f"  Verifications:        {summary['verifications']}")
    print(f"  Reappearances:        {summary['reappearances']}")
    print(f"  Evidence files:       {summary['evidence_files']}")
    print(f"  Chain hash:           {chain['final_chain_hash'][:16]}...")
    print()

    # Scorecard — count verified removals only among those that claimed deletion
    deleted_confirmed = sum(1 for b in broker_resps.values() if b["broker_status"] == "confirmed_deleted")
    # Count how many "confirmed_deleted" are actually gone at 14d verification
    claimed_deleted_brokers = [bid for bid, b in broker_resps.items() if b["broker_status"] == "confirmed_deleted"]
    verified_removed_14d = sum(
        1 for bid in claimed_deleted_brokers
        if bid in verifications and not verifications[bid]["record_still_present"]
    )
    still_present_despite_claim = deleted_confirmed - verified_removed_14d
    reappeared = len(reappearances)
    rejected = sum(1 for b in broker_resps.values() if b["broker_status"] == "rejected")
    no_response = sum(1 for b in broker_resps.values() if b["broker_status"] == "no_response")
    partial = sum(1 for b in broker_resps.values() if b["broker_status"] == "partial")
    deadline_exceeded_count = sum(1 for b in broker_resps.values() if b.get("deadline_exceeded"))

    print("  SCORECARD")
    print(f"  ─────────────────────────────────")
    print(f"  Brokers claimed deleted:   {deleted_confirmed}")
    print(f"  Verified removed (14d):    {verified_removed_14d}")
    print(f"  Still present despite claim: {still_present_despite_claim}")
    print(f"  Reappeared after removal:  {reappeared}")
    print(f"  Partial compliance:        {partial}")
    print(f"  Rejected:                  {rejected}")
    print(f"  No response:               {no_response}")
    print(f"  Deadline exceeded:         {deadline_exceeded_count}")
    print()

    effective_removal = verified_removed_14d - reappeared
    total_requested = len(requests)
    if total_requested > 0:
        rate = effective_removal / total_requested * 100
        print(f"  Effective removal rate: {effective_removal}/{total_requested} = {rate:.0f}%")
        print(f"  (Industry average per PETS 2025 study: ~20% end-to-end)")
    print()

    print("  BROKER DETAIL")
    print(f"  ─────────────────────────────────")
    for bid, info in sorted(broker_report.items()):
        statuses = ", ".join(info["statuses"]) if info["statuses"] else "no response data"
        print(f"  {bid:25s} {statuses}")
    print()

    print(f"  Receipt chain: {chain['chain_length']} receipts")
    print(f"  Chain hash:    {chain['final_chain_hash']}")
    print()
    print("  Every receipt is user-owned. No raw PII left the vault.")
    print("  raw_pii_stored = false on every receipt (enforced by schema).")
    print()

    return {
        "status": "COMPLETE",
        "vault": str(vault.root),
        "total_receipts": summary["total_receipts"],
        "chain_hash": chain["final_chain_hash"],
        "scorecard": {
            "brokers_scanned": scan["brokers_scanned"],
            "records_found": len(scan["records_found"]),
            "high_confidence": high_confidence,
            "low_confidence": low_confidence,
            "deletion_requests": total_requested,
            "confirmed_deleted": deleted_confirmed,
            "verified_removed_14d": verified_removed_14d,
            "reappeared_60d": reappeared,
            "rejected": rejected,
            "no_response": no_response,
            "partial": partial,
            "deadline_exceeded": deadline_exceeded_count,
            "effective_removal_rate": effective_removal / total_requested if total_requested else 0,
        },
    }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Almanac Privacy Receipt Demo")
    parser.add_argument("--vault", default=None, help="Vault directory (default: temp dir)")
    args = parser.parse_args()
    result = run_demo(args.vault)
    print(f"Demo result: {result['status']}")
