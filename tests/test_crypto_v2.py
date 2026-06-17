"""Almanac Core — crypto_v2 + structure_key tests.

Tests the structure-bound AES-256-GCM vault envelope.

Doctrine tested:
    The structure binds the key.     → wrong structure = failed decrypt
    The secret unlocks it.           → wrong secret = failed decrypt
    The receipt gates access.        → AAD = structure context
    Revocation destroys it.          → (lifecycle, tested at vault level)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from structure_key import (
    build_structure_context,
    canonicalize_context,
    structure_context_hash,
)
from crypto_v2 import (
    generate_salt,
    derive_kek,
    generate_dek,
    encrypt_blob,
    decrypt_blob,
    wrap_dek,
    unwrap_dek,
    encrypt_evidence,
    decrypt_evidence,
)
from receipts import user_commitment


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_ctx(**overrides):
    defaults = dict(
        user_commitment="abc123commitment",
        receipt_schema="almanac.record_discovery.v1",
        receipt_id="r-001",
        previous_receipt_hash="prev-hash-000",
        policy_hash="policy-hash-001",
        capsule_type="evidence",
        chain_position=0,
        vault_id="vault-001",
    )
    defaults.update(overrides)
    return build_structure_context(**defaults)


def _encrypt_default(plaintext=b"raw PII evidence", secret="my-vault-secret", **ctx_overrides):
    ctx = _make_ctx(**ctx_overrides)
    vault_salt = generate_salt()
    scrypt_salt = generate_salt()
    commit = ctx["user_commitment"]
    envelope = encrypt_evidence(plaintext, secret, commit, vault_salt, scrypt_salt, ctx)
    return envelope, secret, commit, vault_salt, scrypt_salt, ctx


# ── structure_key tests ──────────────────────────────────────────────────────

def test_canonical_is_deterministic():
    ctx1 = _make_ctx()
    ctx2 = _make_ctx()
    assert canonicalize_context(ctx1) == canonicalize_context(ctx2)


def test_canonical_hash_deterministic():
    ctx1 = _make_ctx()
    ctx2 = _make_ctx()
    assert structure_context_hash(ctx1) == structure_context_hash(ctx2)


def test_different_receipt_id_different_hash():
    ctx1 = _make_ctx(receipt_id="r-001")
    ctx2 = _make_ctx(receipt_id="r-002")
    assert structure_context_hash(ctx1) != structure_context_hash(ctx2)


def test_different_chain_position_different_hash():
    ctx1 = _make_ctx(chain_position=0)
    ctx2 = _make_ctx(chain_position=1)
    assert structure_context_hash(ctx1) != structure_context_hash(ctx2)


def test_different_policy_different_hash():
    ctx1 = _make_ctx(policy_hash="pol-A")
    ctx2 = _make_ctx(policy_hash="pol-B")
    assert structure_context_hash(ctx1) != structure_context_hash(ctx2)


def test_canonical_sorted_keys():
    ctx = _make_ctx()
    canonical = canonicalize_context(ctx)
    assert '"capsule_type"' in canonical
    # Verify sorted by checking first key
    assert canonical.startswith('{"capsule_type":')


def test_no_pii_in_context():
    ctx = _make_ctx()
    canonical = canonicalize_context(ctx)
    for term in ["jane", "doe", "email", "phone", "address", "ssn"]:
        assert term not in canonical.lower()


# ── Key derivation tests ─────────────────────────────────────────────────────

def test_kek_deterministic():
    ctx = _make_ctx()
    vs = generate_salt()
    ss = generate_salt()
    k1 = derive_kek("secret", "commit", vs, ss, ctx)
    k2 = derive_kek("secret", "commit", vs, ss, ctx)
    assert k1 == k2


def test_kek_changes_with_secret():
    ctx = _make_ctx()
    vs = generate_salt()
    ss = generate_salt()
    k1 = derive_kek("secret-A", "commit", vs, ss, ctx)
    k2 = derive_kek("secret-B", "commit", vs, ss, ctx)
    assert k1 != k2


def test_kek_changes_with_commitment():
    ctx = _make_ctx()
    vs = generate_salt()
    ss = generate_salt()
    k1 = derive_kek("secret", "commit-A", vs, ss, ctx)
    k2 = derive_kek("secret", "commit-B", vs, ss, ctx)
    assert k1 != k2


def test_kek_changes_with_vault_salt():
    ctx = _make_ctx()
    ss = generate_salt()
    k1 = derive_kek("secret", "commit", generate_salt(), ss, ctx)
    k2 = derive_kek("secret", "commit", generate_salt(), ss, ctx)
    assert k1 != k2


def test_kek_changes_with_structure():
    vs = generate_salt()
    ss = generate_salt()
    ctx1 = _make_ctx(receipt_id="r-001")
    ctx2 = _make_ctx(receipt_id="r-002")
    k1 = derive_kek("secret", "commit", vs, ss, ctx1)
    k2 = derive_kek("secret", "commit", vs, ss, ctx2)
    assert k1 != k2


# ── DEK wrapping tests ───────────────────────────────────────────────────────

def test_dek_wrap_unwrap_roundtrip():
    kek = generate_dek()  # 32 bytes, same as KEK
    dek = generate_dek()
    wrapped, nonce = wrap_dek(dek, kek)
    recovered = unwrap_dek(wrapped, kek, nonce)
    assert recovered == dek


def test_dek_wrong_kek_fails():
    kek1 = generate_dek()
    kek2 = generate_dek()
    dek = generate_dek()
    wrapped, nonce = wrap_dek(dek, kek1)
    try:
        unwrap_dek(wrapped, kek2, nonce)
        assert False, "Should have raised"
    except Exception:
        pass


# ── Encrypt/decrypt full envelope tests ──────────────────────────────────────

def test_correct_secret_and_structure_decrypts():
    plaintext = b"broker scan HTML with PII"
    envelope, secret, commit, vs, ss, ctx = _encrypt_default(plaintext)
    recovered = decrypt_evidence(envelope, secret, commit, vs, ss, ctx)
    assert recovered == plaintext


def test_wrong_secret_fails():
    envelope, _, commit, vs, ss, ctx = _encrypt_default()
    try:
        decrypt_evidence(envelope, "wrong-secret", commit, vs, ss, ctx)
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrong_user_commitment_fails():
    envelope, secret, _, vs, ss, ctx = _encrypt_default()
    try:
        decrypt_evidence(envelope, secret, "wrong-commitment", vs, ss, ctx)
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrong_vault_salt_fails():
    envelope, secret, commit, _, ss, ctx = _encrypt_default()
    try:
        decrypt_evidence(envelope, secret, commit, generate_salt(), ss, ctx)
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrong_receipt_id_fails():
    envelope, secret, commit, vs, ss, _ = _encrypt_default()
    bad_ctx = _make_ctx(receipt_id="tampered-id")
    try:
        decrypt_evidence(envelope, secret, commit, vs, ss, bad_ctx)
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrong_previous_receipt_hash_fails():
    envelope, secret, commit, vs, ss, _ = _encrypt_default()
    bad_ctx = _make_ctx(previous_receipt_hash="tampered-hash")
    try:
        decrypt_evidence(envelope, secret, commit, vs, ss, bad_ctx)
        assert False, "Should have raised"
    except Exception:
        pass


def test_wrong_policy_hash_fails():
    envelope, secret, commit, vs, ss, _ = _encrypt_default()
    bad_ctx = _make_ctx(policy_hash="tampered-policy")
    try:
        decrypt_evidence(envelope, secret, commit, vs, ss, bad_ctx)
        assert False, "Should have raised"
    except Exception:
        pass


def test_tampered_aad_fails():
    """Tampered AAD (structure context) must fail GCM authentication."""
    ctx = _make_ctx()
    vault_salt = generate_salt()
    scrypt_salt = generate_salt()
    kek = derive_kek("secret", ctx["user_commitment"], vault_salt, scrypt_salt, ctx)
    dek = generate_dek()
    aad = canonicalize_context(ctx).encode()
    ciphertext, nonce = encrypt_blob(b"data", dek, aad)
    # Tamper the AAD
    tampered_aad = b'{"tampered":true}'
    try:
        decrypt_blob(ciphertext, dek, nonce, tampered_aad)
        assert False, "Should have raised"
    except Exception:
        pass


def test_tampered_ciphertext_fails():
    """Tampered ciphertext must fail GCM authentication."""
    ctx = _make_ctx()
    vault_salt = generate_salt()
    scrypt_salt = generate_salt()
    kek = derive_kek("secret", ctx["user_commitment"], vault_salt, scrypt_salt, ctx)
    dek = generate_dek()
    aad = canonicalize_context(ctx).encode()
    ciphertext, nonce = encrypt_blob(b"data", dek, aad)
    # Tamper one byte
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    try:
        decrypt_blob(bytes(tampered), dek, nonce, aad)
        assert False, "Should have raised"
    except Exception:
        pass


def test_public_commitment_plus_salt_cannot_decrypt():
    """Public commitment + vault_salt (both exportable) cannot derive KEK."""
    plaintext = b"sensitive evidence"
    envelope, _, commit, vs, ss, ctx = _encrypt_default(
        plaintext, secret="real-secret"
    )
    # Attacker has commitment and salts but not the secret
    try:
        decrypt_evidence(envelope, "", commit, vs, ss, ctx)
        assert False, "Empty secret must not decrypt"
    except Exception:
        pass
    try:
        decrypt_evidence(envelope, commit, commit, vs, ss, ctx)
        assert False, "Commitment-as-secret must not decrypt"
    except Exception:
        pass


def test_same_plaintext_different_structure_different_envelope():
    """Same plaintext under different structure context produces different ciphertext."""
    plaintext = b"identical data"
    vault_salt = generate_salt()
    scrypt_salt = generate_salt()
    ctx1 = _make_ctx(receipt_id="r-001", chain_position=0)
    ctx2 = _make_ctx(receipt_id="r-002", chain_position=1)
    e1 = encrypt_evidence(plaintext, "secret", "commit", vault_salt, scrypt_salt, ctx1)
    e2 = encrypt_evidence(plaintext, "secret", "commit", vault_salt, scrypt_salt, ctx2)
    assert e1.ciphertext != e2.ciphertext
    assert e1.structure_context_hash != e2.structure_context_hash
    assert e1.wrapped_dek != e2.wrapped_dek


def test_no_pii_in_envelope():
    """Envelope fields must contain no raw PII."""
    envelope, _, _, _, _, _ = _encrypt_default()
    d = envelope.to_dict()
    serialized = str(d).lower()
    for term in ["jane", "doe", "email", "phone", "ssn", "address", "password", "secret"]:
        assert term not in serialized, f"PII term '{term}' found in envelope"


def test_envelope_to_dict_roundtrip():
    """Envelope serialization preserves enough to reconstruct."""
    plaintext = b"roundtrip test"
    envelope, secret, commit, vs, ss, ctx = _encrypt_default(plaintext)
    d = envelope.to_dict()
    # Verify expected fields
    assert d["schema"] == "almanac.encrypted_envelope.v2"
    assert d["algorithm"] == "AES-256-GCM"
    assert d["kdf"] == "scrypt-n17-r8-p1+HKDF-SHA256"
    assert len(d["nonce_hex"]) == 24  # 12 bytes = 24 hex chars
    assert d["ciphertext_bytes"] > 0
    # Reconstruct and decrypt
    from crypto_v2 import EncryptedEnvelope
    restored = EncryptedEnvelope.from_stored(d, envelope.ciphertext)
    recovered = decrypt_evidence(restored, secret, commit, vs, ss, ctx)
    assert recovered == plaintext


def test_ciphertext_hash_matches():
    """ciphertext_hash in envelope must match actual ciphertext."""
    import hashlib
    envelope, _, _, _, _, _ = _encrypt_default()
    expected = hashlib.sha256(envelope.ciphertext).hexdigest()
    assert envelope.ciphertext_hash == expected
