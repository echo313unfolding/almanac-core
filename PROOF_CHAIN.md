# Almanac Core Proof Chain

Open receipt protocol for personal data-rights infrastructure.

## Audit Gate

```text
Almanac Core receipt protocol: 56/56 PASS
  test_receipts:  27 (schemas, chain, vault, demo)
  test_crypto:    10 (key derivation, encrypt/decrypt, vault encryption)
  test_safety:    19 (risk scoring, cohort gates, contextual adjustments)
```

## What is proven

* Record discovery receipts validate against schema.
* Deletion request receipts validate against schema.
* Broker response receipts validate against schema.
* Verification receipts validate against schema.
* Reappearance receipts validate against schema.
* Receipt chain hashing works.
* Local vault stores and summarizes receipts.
* End-to-end privacy receipt demo runs.
* No raw PII is required in receipts.
* Vault evidence encrypted at rest (HKDF + Fernet/AES).
* Wrong user commitment cannot decrypt evidence.
* Vault salt persists across reopens.
* PII risk scoring across 15 record categories (6 dimensions).
* High-risk categories (SSN, health, mugshot) correctly blocked.
* Cohort safety gate enforces minimums (50 default, 100 sensitive).
* Contextual risk adjustments (location, financial, health, cohort size).

## What is not proven yet

* Real broker connector integrations.
* Production DSAR/DROP workflows.
* Legal compliance certification.
* Hosted receipt indexing.
* Adoption by privacy companies.
* Differential privacy noise injection.
* Rotating identity commitments.

## Doctrine

Almanac Core is not a data marketplace.

It is open infrastructure for proving discovery, deletion, broker response,
verification, reappearance, and user-owned vaulting.

Almanac Market is optional and downstream.
