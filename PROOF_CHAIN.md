# Almanac Core Proof Chain

Open receipt protocol for personal data-rights infrastructure.

## Audit Gate

```text
Almanac Core receipt protocol: 144/144 PASS
  test_receipts:   27 (schemas, chain, vault, demo)
  test_crypto:     14 (v1 key derivation, Fernet encrypt/decrypt, vault encryption)
  test_crypto_v2:  31 (structure binding, AES-256-GCM, KEK/DEK, AAD, DEK wrap AAD)
  test_vault_v2:   53 (vault integration, signing, verified migration, transactional rotation, HMAC index, downgrade)
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
* Passphrase strength gate: minimum 12 characters, minimum 4 unique characters.
* Weak passphrase rejected at vault init (fail-closed).
* user_commitment without vault_secret raises ValueError (fail-closed, not fail-open).
* scrypt cost parameter n=2^17 (OWASP recommended for file encryption).
* DEK wrapping uses AAD (structure context hash) — prevents cross-envelope DEK swap.
* Wrong wrap AAD fails GCM authentication.
* Salt files written with 0600 permissions (owner-only read/write).
* Evidence files (encrypted and plaintext) written with 0600 permissions.
* Receipt HMAC-SHA256 signing: sidecar .hmac file created on store, verified on load.
* Signing key derived independently from KEK (different HKDF info field).
* Tampered receipt detected by HMAC verification on load.
* HMAC sidecars written with 0600 permissions.
* v1→v2 auto-migration: legacy .enc files re-encrypted to .v2.json on vault open.
* Migration skips already-migrated files (idempotent).
* Key rotation: rotate_secret() re-encrypts all evidence with new scrypt salt.
* Rotation re-signs all receipts with new signing key.
* Rotation rejects weak secrets, same secret, and unencrypted vaults.
* Downgrade protection: encrypted vault refuses to load .bin evidence.
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
* v1→v2 migration writes .v2.json.migrating temp before commit (crash-safe).
* Migration verifies temp decrypts to same plaintext before rename.
* Migration archives .enc as .enc.migrated (non-destructive, reversible).
* Corrupt .v2.json with .enc present triggers re-migration (crash recovery).
* Interrupted migration temp files cleaned up on init.
* .enc.migrated files not picked up by *.enc glob (no double migration).
* Key rotation writes rotation_journal.json with phase tracking.
* Rotation verifies all .rotating temp files decrypt before commit.
* Rotation rollback on pre-commit failure: no .rotating files remain.
* Rotation recovery pre-commit: init() deletes temp files + journal.
* Rotation recovery post-commit: init() completes rename + salt update + re-sign.
* No .rotating temp files remain after successful rotation.
* Signed receipt index (signed_receipts.json) tracks HMAC-required receipts.
* Signed receipt index is HMAC-protected (tamper detected).
* Deleting .hmac sidecar for indexed receipt raises integrity error.
* Pre-signing receipts (no index entry) load without error.
* Rotation re-signs index HMAC with new signing key.
* Signed receipt index and HMAC written with 0600 permissions.
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
v0.3: AES-256-GCM + AAD + scrypt-n17/HKDF + structure-bound envelope + passphrase gate
v0.3.5: Verified migration, transactional rotation, HMAC sidecar deletion detection  ← current
v0.4: PQ-ready interfaces (ML-KEM/ML-DSA/SLH-DSA type stubs)
v1.0: ML-KEM/ML-DSA/SLH-DSA wired and tested
```

## Protocol Doctrine

Almanac Core is not a data marketplace.

It is open infrastructure for proving discovery, deletion, broker response,
verification, reappearance, and user-owned vaulting.

Almanac Market is optional and downstream.
