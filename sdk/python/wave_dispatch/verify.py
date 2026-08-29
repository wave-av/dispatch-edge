"""verify.py — offline, trustless verifiers for the TWO RECEIPTS in the Python SDK (E4 verify-everywhere).

Mirrors sdk/js (verifyPaymentReceipt + verifyAttestation): a Payment-Receipt is the MONEY proof ("I paid,
dispatch verified the settlement"), a context-attestation the PROVENANCE proof ("what the model saw"). An
Ed25519 record embeds its own pubkey, so anyone verifies it with NO secret and NO network; HMAC needs the
shared key. The canonical signing string is byte-for-byte identical to the edge signers
(edge-router/payment-receipt.ts, context_integrity) — pinned by the shared vectors in
tests/test_sdk_python_verify.py (the same EXPECTED constants as the JS SDK). Canonical + HMAC + tri-state are
stdlib-only; Ed25519 lazily imports `cryptography` (the optional `cdp` extra) and raises a clear error if it
is absent (mirrors the JS verifier's "WebCrypto unavailable")."""
import hmac as _hmac
import hashlib as _hashlib
import json as _json
from typing import Any, Dict, Optional

# Field order is irrelevant (we sort) but the SET is the contract — identical to the edge signers + JS SDK.
RECEIPT_FIELDS = ["v", "ts", "protocol", "mode", "resource", "network", "asset",
                  "amount_atomic", "pay_to", "tx_hash", "verified"]
ATTEST_FIELDS = ["v", "ts", "model", "source", "chunk", "chunk_sha", "chunk_chars",
                 "num_ctx", "prompt_sha", "kept", "dropped_hallucinated"]


def _canonical(obj: Optional[Dict[str, Any]], fields) -> str:
    """asciiEscape(JSON.stringify(sorted-fields-with-nulls)). Python's json.dumps with
    separators=(",", ":") + ensure_ascii=True is byte-identical to the JS scheme: compact (no spaces),
    sorted keys, every non-ASCII char as \\uXXXX. A missing field -> None -> null, exactly like JS `?? null`."""
    sorted_obj = {k: ((obj or {}).get(k)) for k in sorted(fields)}
    return _json.dumps(sorted_obj, separators=(",", ":"), ensure_ascii=True)


def canonical_payment_receipt(r: Dict[str, Any]) -> str:
    """Canonical signing string for a Payment-Receipt — byte-identical to the edge signer."""
    return _canonical(r, RECEIPT_FIELDS)


def canonical_attestation(att: Dict[str, Any]) -> str:
    """Canonical signing string for a context-attestation — byte-identical to the Python/edge signer."""
    return _canonical(att, ATTEST_FIELDS)


def _verify_ed25519(pubkey_hex: str, sig_hex: str, msg: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as e:   # be explicit (like JS's WebCrypto error) — never silently treat as valid/invalid
        raise RuntimeError(
            "Ed25519 verify needs the `cryptography` package — pip install 'wave-dispatch[cdp]'"
        ) from e
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False   # malformed pubkey/sig hex -> not a valid signature


def _verify(obj: Optional[Dict[str, Any]], canonical_fn, hmac_key: Optional[str]) -> Optional[bool]:
    if not obj or not obj.get("alg") or obj.get("alg") == "none" or not obj.get("sig"):
        return None   # unsigned / no-alg -> None (NOT False), mirroring the JS tri-state
    msg = canonical_fn(obj).encode("utf-8")
    alg = obj["alg"]
    if alg == "ed25519":
        pubkey = obj.get("pubkey")
        if not pubkey:
            return None   # self-describing record missing its pubkey -> uncheckable
        return _verify_ed25519(pubkey, obj["sig"], msg)
    if alg == "hmac-sha256":
        if not hmac_key:
            return None   # HMAC without the shared key -> uncheckable
        want = _hmac.new(hmac_key.encode("utf-8"), msg, _hashlib.sha256).hexdigest()
        return _hmac.compare_digest(want, str(obj["sig"]))   # constant-time
    return None


def _is_hex(s: Any) -> bool:
    return isinstance(s, str) and len(s) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in s)


def make_registry(entries: Any) -> frozenset:
    """Build a trusted-key registry — a frozenset of lowercase-hex pubkeys — from a list of {pubkey, key_id?}
    dicts (or bare pubkey-hex strings), or a /.well-known/wave-keys.json payload {"keys": [...]}. Malformed
    (non-hex / odd-length) entries are dropped. Membership test: `pubkey_hex.lower() in registry`."""
    if isinstance(entries, dict):
        entries = entries.get("keys") or []
    out = set()
    for e in (entries or []):
        pub = e if isinstance(e, str) else (e.get("pubkey") if isinstance(e, dict) else None)
        if pub and _is_hex(pub):
            out.add(pub.lower())
    return frozenset(out)


def trusted_signer(obj: Optional[Dict[str, Any]], registry: Any) -> Optional[bool]:
    """Is the signer's key one WAVE published? Tri-state. True = ed25519 key in `registry` with an honest
    key_id; False = a valid-shaped key NOT in the registry, or a key_id that LIES about its pubkey; None =
    cannot decide (no/empty registry, unsigned, "none", or HMAC — a pubkey registry can't vouch for a shared
    secret). Does NOT verify the signature. key_id mirrors the edge: sha256(pubkey)[:16]."""
    if not registry or not obj or obj.get("alg") != "ed25519" or not obj.get("pubkey"):
        return None
    pub = str(obj["pubkey"]).lower()
    if not _is_hex(pub):
        return False
    kid = obj.get("key_id")
    if kid and str(kid).lower() != _hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:16]:
        return False
    return pub in registry


def verify_payment_receipt(r: Dict[str, Any], hmac_key: Optional[str] = None,
                           registry: Any = None) -> Optional[bool]:
    """Tri-state: True/False when signed & checkable, None when unsigned or an HMAC receipt without its key.
    Ed25519 is self-describing -> fully offline & trustless (no secret, no network). Pass `registry` (see
    make_registry) to FOLD in the trusted-key check: a valid signature from an untrusted key returns False (a
    registry never upgrades a bad sig). Omit it -> behaviour is identical to before."""
    v = _verify(r, canonical_payment_receipt, hmac_key)
    if registry and v is True and trusted_signer(r, registry) is False:
        return False
    return v


def verify_attestation(att: Dict[str, Any], hmac_key: Optional[str] = None,
                       registry: Any = None) -> Optional[bool]:
    """Tri-state verifier for a context-attestation. `registry` folds in the trusted-key check (see
    verify_payment_receipt)."""
    v = _verify(att, canonical_attestation, hmac_key)
    if registry and v is True and trusted_signer(att, registry) is False:
        return False
    return v


def attestation_truncated(att: Dict[str, Any]) -> Optional[bool]:
    """True/False/None: chunk_sha != prompt_sha proves the model saw less than the full input; None when the
    second hash is absent (truncation indeterminable)."""
    a = att or {}
    chunk_sha, prompt_sha = a.get("chunk_sha"), a.get("prompt_sha")
    if not chunk_sha or not prompt_sha:
        return None
    return chunk_sha != prompt_sha
