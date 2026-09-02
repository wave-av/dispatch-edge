// verify.js — WAVE Payment-Receipt verifier: the MONEY half of "the two receipts", offline + trustless +
// zero-dep + instance-free. Extracted to its own module (the context-attestation verifier stays in index.js)
// so the published entrypoint stays under the 300-line gate. Re-exported from index.js so the public API is
// unchanged: `import { verifyPaymentReceipt } from "@wave-av/dispatch"`.
//
// A Payment-Receipt is dispatch's signed, self-describing statement that it verified a settlement for a
// resource — the cryptographic twin of the context-attestation. Ed25519 receipts embed their own pubkey, so
// an agent confirms "I really paid for this, and dispatch verified the settlement" with NO secret and NO
// network. HMAC receipts need the shared key. The canonical is byte-identical to the edge signer
// (edge-router/payment-receipt.ts), pinned by the shared EXPECTED vector in receipt.test.js. The helper
// copies below intentionally mirror the canonical WIRE PROTOCOL (the same scheme context-attest + the edge
// re-implement and pin) — replicating it here keeps this verifier self-contained.

function _asciiEscape(s) {
  // Python's json.dumps(ensure_ascii=True) escapes every non-ASCII char as \uXXXX; JSON.stringify does not.
  return s.replace(/[-￿]/g, (c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"));
}
function _fromHex(h) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return a; }
function _toHex(buf) { let o = ""; for (const x of new Uint8Array(buf)) o += x.toString(16).padStart(2, "0"); return o; }
// constant-time string compare — no length/early-exit leak (mirrors edge crypto-util.timingSafeEqual).
function _timingSafeEqual(a, b) { const n = Math.max(a.length, b.length); let m = a.length ^ b.length; for (let i = 0; i < n; i++) m |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return m === 0; }

const RECEIPT_FIELDS = ["v", "ts", "protocol", "mode", "resource", "network", "asset", "amount_atomic", "pay_to", "tx_hash", "verified"];

/** Canonical signing string for a Payment-Receipt — byte-for-byte identical to the edge signer. */
export function canonicalPaymentReceipt(r) {
  const sorted = {};
  for (const k of [...RECEIPT_FIELDS].sort()) sorted[k] = r?.[k] ?? null;    // missing -> null, like Python None
  return _asciiEscape(JSON.stringify(sorted));
}

/**
 * Verify a Payment-Receipt. Tri-state, mirroring verifyAttestation: `true`/`false` when signed & checkable,
 * `null` when unsigned or an HMAC receipt given without its key. Ed25519 is self-describing (fully trustless,
 * offline). Throws only if WebCrypto is unavailable (Node >=18 or a modern browser).
 */
async function _receiptSigValid(r, hmacKey) {                                // crypto half: is the SIGNATURE valid? (true/false/null)
  if (!r || !r.alg || r.alg === "none" || !r.sig) return null;
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error("WebCrypto unavailable — verifyPaymentReceipt needs Node >=18 or a modern browser");
  const msg = new TextEncoder().encode(canonicalPaymentReceipt(r));
  if (r.alg === "ed25519") {
    if (!r.pubkey) return null;
    try {
      const pub = await subtle.importKey("raw", _fromHex(r.pubkey), "Ed25519", false, ["verify"]);
      return await subtle.verify("Ed25519", pub, _fromHex(r.sig), msg);      // self-describing: anyone verifies
    } catch { return false; }
  }
  if (r.alg === "hmac-sha256") {
    if (!hmacKey) return null;
    const key = await subtle.importKey("raw", new TextEncoder().encode(hmacKey), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return _timingSafeEqual(_toHex(await subtle.sign("HMAC", key, msg)), r.sig);
  }
  return null;
}

// ── trusted-key registry: trust's SECOND axis ("is the signer WAVE's key?", not just "is the sig valid?") ──
// A receipt/attestation embeds its own Ed25519 pubkey, so verify*() proves the SIGNATURE — but ANY keypair
// makes a valid signature. trustedSigner answers the orthogonal question: is this pubkey one WAVE PUBLISHED?
// Pure sha256 + set lookup (NO signature check — compose with verify*(), or pass {registry} to verify*() for
// the conjunction). Tri-state like verify*(): null when it cannot decide (no/empty registry, unsigned, alg
// "none", or HMAC — a PUBLIC-key registry can never vouch for a shared secret).
async function _sha256Hex(bytes) {
  // Only reached from trustedSigner's key_id self-consistency check (so a registry lookup with NO key_id stays
  // crypto-free). Mirror _receiptSigValid: fail LOUD on a missing WebCrypto runtime rather than throwing an
  // opaque `TypeError` — and never degrade to null, which would let the {registry} fold silently pass an
  // untrusted key (the fold only rejects on === false).
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error("WebCrypto unavailable — trustedSigner key_id check needs Node >=18 or a modern browser");
  return _toHex(await subtle.digest("SHA-256", bytes));
}
function _isHex(s) { return typeof s === "string" && s.length % 2 === 0 && /^[0-9a-fA-F]*$/.test(s); }

/**
 * Build a trusted-key registry from entries — `{pubkey, key_id?}` objects (or bare pubkey-hex strings), or a
 * `/.well-known/wave-keys.json` payload `{keys:[...]}`. Returns `{ has(pubkeyHex), size }`: a normalized set
 * of lowercase-hex pubkeys. Malformed (non-hex / odd-length) entries are silently dropped.
 */
export function makeRegistry(entries) {
  const list = Array.isArray(entries) ? entries : (entries && Array.isArray(entries.keys) ? entries.keys : []);
  const set = new Set();
  for (const e of list) {
    const pub = typeof e === "string" ? e : (e && e.pubkey);
    if (_isHex(pub) && pub.length) set.add(pub.toLowerCase());
  }
  return { has: (p) => typeof p === "string" && set.has(p.toLowerCase()), size: set.size };
}

/**
 * Is the signer's key one WAVE published? `true` = ed25519 key present in `registry` AND its stated key_id
 * (if any) hashes from its pubkey. `false` = a valid-shaped ed25519 key NOT in the registry, or a key_id
 * that LIES about its pubkey. `null` = cannot decide (no/empty registry, unsigned, alg "none", HMAC). Does
 * NOT verify the signature — that's verify*(). key_id mirrors the edge: sha256Hex(fromHex(pubkey)).slice(0,16).
 */
export async function trustedSigner(r, registry) {
  if (!registry || !registry.size || !r || r.alg !== "ed25519" || !r.pubkey) return null;
  const pub = String(r.pubkey).toLowerCase();
  if (!_isHex(pub)) return false;
  if (r.key_id && String(r.key_id).toLowerCase() !== (await _sha256Hex(_fromHex(pub))).slice(0, 16)) return false;
  return registry.has(pub);
}

/**
 * Verify a Payment-Receipt. Tri-state (true/false/null), offline + trustless. Pass `{registry}` to FOLD in
 * the trusted-key check: a cryptographically-valid receipt whose key is NOT in `registry` returns `false`
 * (a registry NEVER upgrades an invalid signature). Without `{registry}`, behaviour is byte-identical to before.
 */
export async function verifyPaymentReceipt(r, { hmacKey, registry } = {}) {
  const v = await _receiptSigValid(r, hmacKey);
  if (registry && v === true && (await trustedSigner(r, registry)) === false) return false;
  return v;
}
