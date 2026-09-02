// SPLIT-PLAN: the runtime code (canonical/verify/trusted/fold) is ~160 lines; the rest is `#[cfg(test)]` —
// the Rust convention of inline tests. Splitting these into a separate file is the OPPOSITE of idiomatic and
// would only obscure the cross-impl vector pin (the whole point of this module). Architecture is correct.
//! verify.rs — offline, trustless verifiers for "the two receipts" in the Rust SDK (E4 verify-everywhere).
//!
//! A Payment-Receipt is the MONEY proof ("I paid, dispatch verified the settlement"); a context-Attestation
//! is the PROVENANCE proof ("what the model saw"). An Ed25519 record embeds its own public key, so anyone
//! verifies it with NO secret and NO network; HMAC records need the shared key. The canonical signing string
//! is byte-for-byte identical to every other implementation (JS/Python/Go/Ruby + the edge signers), pinned by
//! the shared vectors in the `tests` module below.
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use hmac::digest::KeyInit;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

// The exact field sets shared by every signer. canonical() uses ONLY these, sorted (BTreeMap), missing => null.
const RECEIPT_FIELDS: [&str; 11] = [
    "v",
    "ts",
    "protocol",
    "mode",
    "resource",
    "network",
    "asset",
    "amount_atomic",
    "pay_to",
    "tx_hash",
    "verified",
];
const ATTEST_FIELDS: [&str; 11] = [
    "v",
    "ts",
    "model",
    "source",
    "chunk",
    "chunk_sha",
    "chunk_chars",
    "num_ctx",
    "prompt_sha",
    "kept",
    "dropped_hallucinated",
];

// Compact, key-sorted, ASCII-escaped JSON over exactly `fields`. A BTreeMap serializes its keys in sorted
// order; serde_json::to_string is compact and does NOT HTML-escape <>& (which we also must not); ascii_escape
// then matches the JS asciiEscape(JSON.stringify) / Python ensure_ascii shape.
fn canonical(record: &Value, fields: &[&str]) -> String {
    let mut sorted: BTreeMap<&str, Value> = BTreeMap::new();
    for &k in fields {
        sorted.insert(k, record.get(k).cloned().unwrap_or(Value::Null));
    }
    ascii_escape(&serde_json::to_string(&sorted).unwrap_or_default())
}

// Rewrite every char >= U+0080 as \uXXXX (lowercase, 4 hex digits); chars above U+FFFF become a UTF-16
// surrogate pair, matching JS JSON's UTF-16 code-unit escaping and Python's ensure_ascii.
fn ascii_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp < 0x80 {
            out.push(c);
        } else if cp <= 0xFFFF {
            out.push_str(&format!("\\u{:04x}", cp));
        } else {
            let mut buf = [0u16; 2];
            for &unit in c.encode_utf16(&mut buf).iter() {
                out.push_str(&format!("\\u{:04x}", unit));
            }
        }
    }
    out
}

/// Canonical signing string for a Payment-Receipt — byte-identical to the edge signer.
pub fn canonical_payment_receipt(receipt: &Value) -> String {
    canonical(receipt, &RECEIPT_FIELDS)
}

/// Canonical signing string for a context-Attestation.
pub fn canonical_attestation(att: &Value) -> String {
    canonical(att, &ATTEST_FIELDS)
}

// Tri-state core: None when unsigned / no alg / alg "none" / no sig / ed25519 without pubkey / hmac without
// the key / unknown alg; otherwise a real true/false crypto verdict.
fn verify_record(record: &Value, canonical_str: &str, hmac_key: Option<&str>) -> Option<bool> {
    let alg = record.get("alg").and_then(Value::as_str)?;
    let sig = record.get("sig").and_then(Value::as_str)?;
    if alg.is_empty() || alg == "none" {
        return None;
    }
    match alg {
        "ed25519" => {
            let pubkey = record.get("pubkey").and_then(Value::as_str)?; // None if no pubkey
            Some(verify_ed25519(pubkey, sig, canonical_str.as_bytes()))
        }
        "hmac-sha256" => {
            let key = hmac_key?; // None if the key was not supplied
            Some(verify_hmac(key, sig, canonical_str.as_bytes()))
        }
        _ => None,
    }
}

// Raw 32-byte public key (hex) + raw 64-byte signature (hex) over the canonical bytes. Any malformed hex /
// wrong length is a hard false (never a panic) — None is reserved for "no pubkey supplied".
fn verify_ed25519(pubkey_hex: &str, sig_hex: &str, msg: &[u8]) -> bool {
    let pub_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pub_arr: [u8; 32] = match pub_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    match VerifyingKey::from_bytes(&pub_arr) {
        Ok(vk) => vk
            .verify_strict(msg, &Signature::from_bytes(&sig_arr))
            .is_ok(),
        Err(_) => false,
    }
}

fn verify_hmac(key: &str, sig_hex: &str, msg: &[u8]) -> bool {
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(msg);
    mac.verify_slice(&sig_bytes).is_ok() // constant-time
}

/// Verify a Payment-Receipt. `Some(true)`/`Some(false)` when signed & checkable, `None` when unsigned or an
/// HMAC receipt without its key. Ed25519 is self-describing — offline & trustless (no secret, no network).
pub fn verify_payment_receipt(receipt: &Value, hmac_key: Option<&str>) -> Option<bool> {
    verify_record(receipt, &canonical_payment_receipt(receipt), hmac_key)
}

/// Verify a context-Attestation (same tri-state scheme as `verify_payment_receipt`).
pub fn verify_attestation(att: &Value, hmac_key: Option<&str>) -> Option<bool> {
    verify_record(att, &canonical_attestation(att), hmac_key)
}

/// Did the model see less than the full prompt? `chunk_sha` != `prompt_sha` => `Some(true)`, equal =>
/// `Some(false)`, either missing => `None` (undeterminable). Pure data, no crypto.
pub fn attestation_truncated(att: &Value) -> Option<bool> {
    let c = att.get("chunk_sha").and_then(Value::as_str);
    let p = att.get("prompt_sha").and_then(Value::as_str);
    match (c, p) {
        (Some(c), Some(p)) if !c.is_empty() && !p.is_empty() => Some(c != p),
        _ => None,
    }
}

// ── trusted-key registry (E4.followup): trust's SECOND axis — "is the signer one WAVE published?" ──
// trusted_signer answers registry membership + key_id honesty (NOT the signature; compose with verify_*, or
// use verify_*_trusted for the conjunction). Rust has no optional args, so the fold is a sibling fn rather
// than an extra param. Mirrors sdk/js/verify.js byte-for-byte (pinned by the shared FIXED vector).

/// A set of trusted signer pubkeys (lowercase hex), built by [`make_registry`].
pub struct Registry(HashSet<String>);

impl Registry {
    /// Number of distinct trusted keys.
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// True when the registry holds no keys (it then decides nothing).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Is `pubkey_hex` (case-insensitive) a trusted key?
    pub fn has(&self, pubkey_hex: &str) -> bool {
        self.0.contains(&pubkey_hex.to_lowercase())
    }
}

fn is_hex(s: &str) -> bool {
    s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build a trusted-key registry from a serde_json value: an array of pubkey-hex strings or `{pubkey, key_id?}`
/// objects, or a `/.well-known/wave-keys.json` payload `{"keys": [...]}`. Malformed entries are dropped.
pub fn make_registry(entries: &Value) -> Registry {
    let list = entries.get("keys").unwrap_or(entries);
    let mut set = HashSet::new();
    if let Some(arr) = list.as_array() {
        for e in arr {
            let pubkey = e.as_str().or_else(|| e.get("pubkey").and_then(Value::as_str));
            if let Some(p) = pubkey {
                if !p.is_empty() && is_hex(p) {
                    set.insert(p.to_lowercase());
                }
            }
        }
    }
    Registry(set)
}

fn key_id_of(pubkey_hex: &str) -> String {
    match hex::decode(pubkey_hex) {
        Ok(bytes) => hex::encode(Sha256::digest(&bytes))[..16].to_string(), // the edge derivation
        Err(_) => String::new(),
    }
}

/// Is the signer's key one WAVE published? Tri-state: `Some(true)` = ed25519 key in `registry` with an honest
/// key_id; `Some(false)` = a valid-shaped key NOT in the registry, or a key_id that lies about its pubkey;
/// `None` = cannot decide (empty registry, unsigned, "none", or HMAC). Does NOT verify the signature.
pub fn trusted_signer(record: &Value, registry: &Registry) -> Option<bool> {
    if registry.is_empty() || record.get("alg").and_then(Value::as_str) != Some("ed25519") {
        return None;
    }
    let pubkey = record
        .get("pubkey")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())?;
    let pub_lc = pubkey.to_lowercase();
    if !is_hex(&pub_lc) {
        return Some(false);
    }
    if let Some(kid) = record.get("key_id").and_then(Value::as_str) {
        if kid.to_lowercase() != key_id_of(&pub_lc) {
            return Some(false); // key_id lies about its pubkey
        }
    }
    Some(registry.has(&pub_lc))
}

fn fold(v: Option<bool>, record: &Value, registry: &Registry) -> Option<bool> {
    if v == Some(true) && trusted_signer(record, registry) == Some(false) {
        return Some(false); // valid signature, but the key is not WAVE's
    }
    v // a registry never upgrades an invalid signature
}

/// Verify a Payment-Receipt AND require the signer be in `registry` (the trusted-key fold): a valid signature
/// from an untrusted key returns `Some(false)`. For the signature-only check use [`verify_payment_receipt`].
pub fn verify_payment_receipt_trusted(
    receipt: &Value,
    registry: &Registry,
    hmac_key: Option<&str>,
) -> Option<bool> {
    fold(verify_payment_receipt(receipt, hmac_key), receipt, registry)
}

/// Verify a context-Attestation with the trusted-key fold (see [`verify_payment_receipt_trusted`]).
pub fn verify_attestation_trusted(
    att: &Value,
    registry: &Registry,
    hmac_key: Option<&str>,
) -> Option<bool> {
    fold(verify_attestation(att, hmac_key), att, registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixed_receipt() -> Value {
        json!({"v":"wave.payment-receipt/v0","ts":1700000000,"protocol":"x402","mode":"wave-x402","resource":"/extract","network":"base","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","amount_atomic":"1000","pay_to":"0x0000000000000000000000000000000000000001","tx_hash":"0xdeadbeef","verified":true})
    }
    const EXPECTED_RECEIPT_CANONICAL: &str = r#"{"amount_atomic":"1000","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913","mode":"wave-x402","network":"base","pay_to":"0x0000000000000000000000000000000000000001","protocol":"x402","resource":"/extract","ts":1700000000,"tx_hash":"0xdeadbeef","v":"wave.payment-receipt/v0","verified":true}"#;
    const RECEIPT_PUBKEY: &str = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
    const RECEIPT_SIG: &str = "e333772435ba2b16c9b52188a489de18f0dbba870a84b6dcc6fe63ef3dffae5ab9e65daa85b3306d4d3df879bc47c6282f87c661e634390a9a5d93e7c502220a";

    fn base_att() -> Value {
        json!({"v":"wave.context-attestation/v0","ts":1700000000,"model":"qwen3:30b","source":"café.md","chunk":2,"chunk_sha":"deadbeef","chunk_chars":2980,"num_ctx":8192,"prompt_sha":"cafe1234","kept":3,"dropped_hallucinated":1})
    }
    // café (real é in the source field) -> café in the canonical OUTPUT (raw string keeps it as 6 literal chars).
    const PY_ATT_CANONICAL: &str = r#"{"chunk":2,"chunk_chars":2980,"chunk_sha":"deadbeef","dropped_hallucinated":1,"kept":3,"model":"qwen3:30b","num_ctx":8192,"prompt_sha":"cafe1234","source":"caf\u00e9.md","ts":1700000000,"v":"wave.context-attestation/v0"}"#;
    const ATT_PUBKEY: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    const ATT_SIG: &str = "68017540b4c3b060e51faab64c28f4e1ea6994d3781fec14878e73052046d78d05757a8287af644b245b10274ba3b60329ed216472839d7573debf4256e9730b";

    fn with(base: &Value, over: Value) -> Value {
        let mut m = base.as_object().unwrap().clone();
        for (k, v) in over.as_object().unwrap() {
            m.insert(k.clone(), v.clone());
        }
        Value::Object(m)
    }
    fn hmac_hex(key: &str, msg: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key.as_bytes()).unwrap();
        mac.update(msg.as_bytes());
        hex::encode(mac.finalize().into_bytes().to_vec())
    }

    #[test]
    fn receipt_canonical() {
        assert_eq!(
            canonical_payment_receipt(&fixed_receipt()),
            EXPECTED_RECEIPT_CANONICAL
        );
    }
    #[test]
    fn attestation_canonical_cafe() {
        assert_eq!(canonical_attestation(&base_att()), PY_ATT_CANONICAL);
    }
    #[test]
    fn receipt_ed25519() {
        let signed = with(
            &fixed_receipt(),
            json!({"alg":"ed25519","sig":RECEIPT_SIG,"pubkey":RECEIPT_PUBKEY}),
        );
        assert_eq!(verify_payment_receipt(&signed, None), Some(true));
        assert_eq!(
            verify_payment_receipt(&with(&signed, json!({"amount_atomic":"999999"})), None),
            Some(false)
        );
        assert_eq!(
            verify_payment_receipt(&with(&signed, json!({"verified":false})), None),
            Some(false)
        );
    }
    #[test]
    fn attestation_ed25519() {
        let signed = with(
            &base_att(),
            json!({"alg":"ed25519","sig":ATT_SIG,"pubkey":ATT_PUBKEY}),
        );
        assert_eq!(verify_attestation(&signed, None), Some(true));
        assert_eq!(
            verify_attestation(&with(&signed, json!({"kept":999})), None),
            Some(false)
        );
    }
    #[test]
    fn hmac_tristate() {
        let r = with(
            &fixed_receipt(),
            json!({"alg":"hmac-sha256","sig":hmac_hex("k", EXPECTED_RECEIPT_CANONICAL)}),
        );
        assert_eq!(verify_payment_receipt(&r, Some("k")), Some(true));
        assert_eq!(verify_payment_receipt(&r, Some("wrong")), Some(false));
        assert_eq!(verify_payment_receipt(&r, None), None);
        let a = with(
            &base_att(),
            json!({"alg":"hmac-sha256","sig":hmac_hex("k", PY_ATT_CANONICAL)}),
        );
        assert_eq!(verify_attestation(&a, Some("k")), Some(true));
        assert_eq!(verify_attestation(&a, None), None);
    }
    #[test]
    fn unsigned() {
        assert_eq!(verify_payment_receipt(&fixed_receipt(), None), None);
        assert_eq!(
            verify_payment_receipt(
                &with(&fixed_receipt(), json!({"alg":"none","sig":null})),
                None
            ),
            None
        );
        assert_eq!(verify_attestation(&base_att(), None), None);
    }
    #[test]
    fn truncated() {
        assert_eq!(
            attestation_truncated(&json!({"chunk_sha":"a","prompt_sha":"b"})),
            Some(true)
        );
        assert_eq!(
            attestation_truncated(&json!({"chunk_sha":"a","prompt_sha":"a"})),
            Some(false)
        );
        assert_eq!(attestation_truncated(&json!({"chunk_sha":"a"})), None);
    }

    // ── trusted-key registry (E4.followup) — same FIXED vector as sdk/js/trusted.test.js + the other ports ──
    const KEY_ID: &str = "34750f98bd59fcfc"; // sha256(RECEIPT_PUBKEY bytes)[:16] — the edge derivation
    const OTHER: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn make_registry_membership() {
        let reg = make_registry(&json!([{"pubkey": RECEIPT_PUBKEY, "key_id": KEY_ID}]));
        assert_eq!(reg.len(), 1);
        assert!(reg.has(RECEIPT_PUBKEY));
        assert!(reg.has(&RECEIPT_PUBKEY.to_uppercase())); // case-insensitive
        assert!(!reg.has(OTHER));
        assert_eq!(
            make_registry(&json!({"keys":[RECEIPT_PUBKEY,"nothex!!","abc"]})).len(),
            1
        );
        assert!(make_registry(&json!([])).is_empty());
    }

    #[test]
    fn trusted_signer_tristate() {
        let signed = json!({"alg":"ed25519","pubkey":RECEIPT_PUBKEY,"key_id":KEY_ID,"sig":"ab"});
        let reg = make_registry(&json!([RECEIPT_PUBKEY]));
        assert_eq!(trusted_signer(&signed, &reg), Some(true)); // ours
        assert_eq!(
            trusted_signer(&signed, &make_registry(&json!([OTHER]))),
            Some(false)
        ); // valid shape, not trusted
        assert_eq!(trusted_signer(&signed, &make_registry(&json!([]))), None); // empty
        assert_eq!(
            trusted_signer(&with(&signed, json!({"alg":"hmac-sha256"})), &reg),
            None
        ); // HMAC -> can't vouch
        assert_eq!(
            trusted_signer(&with(&signed, json!({"key_id":"deadbeefdeadbeef"})), &reg),
            Some(false)
        ); // key_id lie
    }

    #[test]
    fn registry_folds_into_verify() {
        let signed = with(
            &fixed_receipt(),
            json!({"alg":"ed25519","sig":RECEIPT_SIG,"pubkey":RECEIPT_PUBKEY}),
        );
        let reg = make_registry(&json!([RECEIPT_PUBKEY]));
        assert_eq!(verify_payment_receipt(&signed, None), Some(true)); // no registry -> unchanged
        assert_eq!(verify_payment_receipt_trusted(&signed, &reg, None), Some(true)); // valid + ours
        assert_eq!(
            verify_payment_receipt_trusted(&signed, &make_registry(&json!([OTHER])), None),
            Some(false)
        ); // valid sig, untrusted key
        assert_eq!(
            verify_payment_receipt_trusted(
                &with(&signed, json!({"amount_atomic":"999999"})),
                &reg,
                None
            ),
            Some(false)
        ); // registry never upgrades a bad sig
    }
}
