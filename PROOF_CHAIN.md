# Almanac Core Proof Chain

Open receipt protocol for personal data-rights infrastructure.

## Audit Gate

```text
Almanac Core receipt protocol: 190/190 PASS
  test_receipts:   27 (schemas, chain, vault, demo)
  test_crypto:     14 (v1 key derivation, Fernet encrypt/decrypt, vault encryption)
  test_crypto_v2:  31 (structure binding, AES-256-GCM, KEK/DEK, AAD, DEK wrap AAD)
  test_vault_v2:   69 (vault integration, signing, migration, rotation, HMAC index, downgrade, security state, atomic writes)
  test_vault_v37:  30 (vault locking, checkpoint roots, external checkpoint, legacy archive cleanup)
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
* Atomic file writes: 0600 permissions from birth (no TOCTOU window).
* Atomic write uses os.open(O_CREAT|O_TRUNC, 0600) + fsync + os.replace.
* No .atomictmp files remain after successful write.
* VAULT_SECURITY_STATE.json created on encrypted vault init (integrity marker).
* Security state is HMAC-protected (tamper detected).
* Security state deletion detected on re-open (when signed index exists).
* legacy_upgrade=True bypasses security state deletion check (v0.3.5 upgrade path).
* Security state init creates empty signed index (deletion detectable from first open).
* Signed index deletion detected when security state is active.
* Signed index HMAC deletion detected (raises when signing key exists).
* Wrong vault_secret detected at init via security state HMAC (early fail-closed).
* Wrong-secret rotation recovery blocked (decrypt verification before re-signing).
* Rotation recovery re-signs security state + index + receipts with post-rotation key.
* Receipt filename collision detected (rid[:8] clash → falls back to rid[:16]).
* Receipt store uses atomic write (0600 from birth).
* Security epoch increments on key rotation.
* Security state + HMAC written with 0600 permissions.
* Unencrypted vaults do not create security state.
* Vault locking: flock-based single-writer protection (LOCK_EX | LOCK_NB).
* Second Vault on same directory blocked while first holds lock.
* Lock released on close(), context manager exit, and init() failure.
* No stale lock after failed init (weak passphrase, wrong secret).
* Lock file written with 0600 permissions.
* close() is idempotent (multiple calls safe).
* CHECKPOINT.json computed on init and updated on store/evidence/rotation.
* Checkpoint root: SHA-256 of canonical JSON (sorted keys, compact separators).
* Checkpoint root is deterministic (same state → same hash).
* Checkpoint root changes on receipt store, evidence store, and key rotation.
* Checkpoint payload contains no raw PII (only hashes and metadata).
* Checkpoint HMAC tamper detected on re-open.
* Checkpoint files written with 0600 permissions.
* Checkpoint payload includes vault_id, security_epoch, receipt_hashes_root, evidence_manifest_hash.
* Unencrypted vaults do not create checkpoint files.
* Rollback detection: export_checkpoint() + verify_checkpoint_bundle() detect vault state changes.
* Exported checkpoint contains checkpoint_root (64-char SHA-256 hex) + full payload.
* Stale checkpoint (pre-change) fails verification against post-change state.
* Exported checkpoint contains no PII or secrets.
* Checkpoint survives close/reopen cycle (consistent root across sessions).
* Rotation recovery re-signs checkpoint HMAC with post-rotation key.
* Legacy archive listing: list_legacy_archives() finds .enc.migrated files.
* Legacy re-encryption: reencrypt_legacy_archives_under_v2() verifies + removes .enc.migrated.
* Re-encryption preserves existing .v2.json (does not overwrite valid copies).
* purge_legacy_archives() requires explicit confirm=True (fail-closed).
* Purge deletes only .enc.migrated, not .v2.json evidence.
* Empty legacy archive operations are safe no-ops.
* PII risk scoring across 15 record categories (6 dimensions).
* High-risk categories (SSN, health, mugshot) correctly blocked.
* Cohort safety gate enforces minimums (50 default, 100 sensitive).
* Contextual risk adjustments (location, financial, health, cohort size).

## What is not proven yet

* Approved device registry (v0.3.8).
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

## Control Doctrine

Three controls protect the vault:

1. **Secret** — who can decrypt (vault_secret).
2. **Checkpoint** — whether history was rolled back (checkpoint root).
3. **Device** — where state may advance (approved device registry, v0.3.8).

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
v0.3.5: Verified migration, transactional rotation, HMAC sidecar deletion detection
v0.3.6: Atomic writes, security state marker, wrong-secret recovery guard, collision detection
v0.3.7: Vault locking, checkpoint roots, external checkpoint, legacy archive hardening  ← current
v0.3.8: Approved device registry
v0.4: PQ-ready interfaces (ML-KEM/ML-DSA/SLH-DSA type stubs)
v1.0: ML-KEM/ML-DSA/SLH-DSA wired and tested
```

## Protocol Doctrine

Almanac Core is not a data marketplace.

It is open infrastructure for proving discovery, deletion, broker response,
verification, reappearance, and user-owned vaulting.

Almanac Market is optional and downstream.
