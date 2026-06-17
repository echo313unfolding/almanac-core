# Almanac Core Proof Chain

Open receipt protocol for personal data-rights infrastructure.

## Audit Gate

```text
Almanac Core receipt protocol: 104/104 PASS
  test_receipts:   27 (schemas, chain, vault, demo)
  test_crypto:     14 (v1 key derivation, Fernet encrypt/decrypt, vault encryption)
  test_crypto_v2:  28 (structure binding, AES-256-GCM, KEK/DEK, AAD, tamper detection)
  test_vault_v2:   16 (vault↔crypto_v2 integration, auto-detect, salt persistence)
  test_safety:     19 (risk scoring, cohort gates, contextual adjustments)
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
* Vault evidence encrypted at rest (v1: HKDF + Fernet, v2: AES-256-GCM).
* Encryption requires vault_secret (private) + user_commitment (public) + vault_salt.
* Public components alone (commitment + salt) cannot derive the vault key.
* Commitment without secret does not enable encryption (fail-safe).
* Wrong secret cannot decrypt evidence.
* Vault salt persists across reopens.
* crypto_v2 is the default vault evidence encryption path (.v2.json).
* Vault auto-detects evidence format: .v2.json → .enc (legacy) → .bin (plaintext).
* v2 salts (vault_salt_v2.key, scrypt_salt_v2.key) persist across vault reopens.
* vault_id derived from SHA-256 of v2 vault_salt.
* Default structure context binds evidence to user_commitment + evidence_hash + vault_id.
* Wrong structure context (receipt_id, policy_hash) fails v2 vault decrypt.
* Encrypted v2 vault without secret on load raises descriptive error.
* v2: scrypt passphrase hardening + HKDF context binding.
* v2: Per-blob DEK wrapped by KEK (key hierarchy).
* v2: Structure context (receipt_id, chain_position, policy_hash) binds the key.
* v2: Different receipt context produces different KEK and different ciphertext.
* v2: Wrong receipt_id, wrong previous_hash, wrong policy_hash all fail decrypt.
* v2: Tampered AAD (structure context) fails GCM authentication.
* v2: Tampered ciphertext fails GCM authentication.
* v2: Canonical structure hash is deterministic.
* v2: No raw PII appears in encrypted envelope fields.
* v2: Envelope serialization round-trips correctly.
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
* Post-quantum key encapsulation (ML-KEM / FIPS 203).
* Post-quantum receipt signatures (ML-DSA / FIPS 204).
* Hash-based backup signatures (SLH-DSA / FIPS 205).

## Encryption Doctrine

The structure binds the key.
The secret unlocks it.
The receipt gates access.
Revocation destroys it.

Almanac does not invent new cryptography. It uses standardized primitives
(AES-256-GCM, scrypt, HKDF-SHA256) wrapped in a bio-inspired structure-bound
vault model: receipt chains, contextual binding, rotating commitments,
capsule boundaries, and policy-gated access.

## PQ Roadmap

```text
v0.2: Encrypted local vault with structure-bound keys (Fernet MVP)
v0.3: AES-256-GCM + AAD + scrypt/HKDF + structure-bound envelope  ← current
v0.4: PQ-ready interfaces (ML-KEM/ML-DSA/SLH-DSA type stubs)
v1.0: ML-KEM/ML-DSA/SLH-DSA wired and tested
```

## Protocol Doctrine

Almanac Core is not a data marketplace.

It is open infrastructure for proving discovery, deletion, broker response,
verification, reappearance, and user-owned vaulting.

Almanac Market is optional and downstream.
