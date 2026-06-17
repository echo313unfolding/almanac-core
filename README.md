# Almanac Core

Open infrastructure for personal data rights receipts.

Privacy companies use it to prove discovery, deletion, broker response,
reappearance, and user-owned vaulting. No raw PII leaves the local vault.

## Quick Start

```bash
make demo    # full privacy receipt lifecycle
make test    # 28 tests
```

## What It Does

```
Import broker scan report (DeleteMe/Incogni-style)
    ↓
Generate discovery receipts (confidence-filtered)
    ↓
Submit deletion requests (CCPA/GDPR/DELETE Act)
    ↓
Process broker responses (deleted/rejected/silent/partial)
    ↓
Verify removal (automated re-scan)
    ↓
Detect reappearance (60-day check)
    ↓
Store in local user vault
    ↓
Chain hash proves integrity
```

## Receipt Types

| Schema | Purpose |
|--------|---------|
| `record_discovery.v1` | A record was found at a broker |
| `deletion_request.v1` | A deletion/opt-out request was submitted |
| `broker_response.v1` | The broker responded (or didn't) |
| `verification.v1` | Independent check: was the record actually removed? |
| `reappearance.v1` | A deleted record came back |

## Design Principles

- **Local-first.** Vault is `~/.almanac/`. User-owned. Exportable.
- **No raw PII in receipts.** `raw_pii_stored = false` enforced by schema.
- **Identity = commitment.** SHA-256 hash of user identity. The identity stays local.
- **Evidence stays local.** Receipts contain `evidence_hash`, not evidence.
- **Chain integrity.** Every receipt links to the previous. Final hash proves the chain.

## Vault Structure

```
~/.almanac/
  discovery/          # broker scan findings
  requests/           # deletion/opt-out requests
  responses/          # broker responses
  verifications/      # removal verification checks
  reappearances/      # records that came back
  chain/              # chain summaries
  evidence/           # raw evidence (local only, never exported)
  MANIFEST.md
```

## Why This Exists

PII removal services have a proof problem. A 2025 PETS study found:
- Only 41.1% of records flagged by removal services were actually about the user
- Services removed only 48.2% of identified records
- End-to-end effectiveness: ~20%

There is no open standard for "proof that a broker deleted your data."
GDPR has DSAR but no receipt format. CCPA has deletion rights but no
portable proof. California's DELETE Act/DROP requires broker compliance
by August 1, 2026, but has no user-owned audit chain.

Almanac Core is the missing receipt layer.

## Relationship to Almanac Market

Almanac Core = receipt protocol (this repo)
Almanac Market = optional licensing/auction/settlement for derived signals

Core first. Market second. The market layer exists at `almanac-field-signal-demo/`
and `hxq-solana/programs/almanac/` but requires Core as its foundation.
