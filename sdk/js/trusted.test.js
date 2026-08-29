// trusted.test.js — the cross-implementation pin for the TRUSTED-KEY REGISTRY: trust's SECOND axis.
// verify*() proves the SIGNATURE; trustedSigner() proves the KEY is one WAVE published (registry membership
// + key_id honesty); passing {registry} to verify*() FOLDS the two into one verdict ("valid AND ours").
// The FIXED vectors below are byte-identical to tests/test_sdk_python_verify.py and the Go/Ruby/Rust ports +
// the edge — a green here proves the trust logic is the SAME in every runtime. NOTE key_id is the edge's
// real derivation: sha256Hex(fromHex(pubkey)).slice(0,16) — the FIRST 16 hex chars, not the full digest.
import { test } from "node:test";
import assert from "node:assert/strict";
import { makeRegistry, trustedSigner, verifyPaymentReceipt, verifyAttestation } from "./index.js";

// --- FIXED Payment-Receipt vector (identical to receipt.test.js / test_sdk_python_verify.py) ---
const PUBKEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c";
const KEY_ID = "34750f98bd59fcfc";          // = sha256Hex(fromHex(PUBKEY)).slice(0,16) — the edge's exact id
const OTHER  = "00".repeat(32);             // a structurally-valid 32-byte pubkey that is NOT WAVE's
const FIXED_RECEIPT = {
  v: "wave.payment-receipt/v0", ts: 1700000000, protocol: "x402", mode: "wave-x402",
  resource: "/extract", network: "base", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  amount_atomic: "1000", pay_to: "0x0000000000000000000000000000000000000001",
  tx_hash: "0xdeadbeef", verified: true,
};
const RECEIPT_SIG = "e333772435ba2b16c9b52188a489de18f0dbba870a84b6dcc6fe63ef3dffae5a" +
                    "b9e65daa85b3306d4d3df879bc47c6282f87c661e634390a9a5d93e7c502220a";
const SIGNED = { ...FIXED_RECEIPT, alg: "ed25519", sig: RECEIPT_SIG, pubkey: PUBKEY, key_id: KEY_ID };

// --- FIXED context-attestation vector (different signer key — the Python-signer key) ---
const ATT_PUBKEY = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const ATT_KEY_ID = "56475aa75463474c";
const BASE_ATT = {
  v: "wave.context-attestation/v0", ts: 1700000000, model: "qwen3:30b", source: "café.md",
  chunk: 2, chunk_sha: "deadbeef", chunk_chars: 2980, num_ctx: 8192, prompt_sha: "cafe1234",
  kept: 3, dropped_hallucinated: 1,
};
const ATT_SIG = "68017540b4c3b060e51faab64c28f4e1ea6994d3781fec14878e73052046d78d" +
                "05757a8287af644b245b10274ba3b60329ed216472839d7573debf4256e9730b";
const SIGNED_ATT = { ...BASE_ATT, alg: "ed25519", sig: ATT_SIG, pubkey: ATT_PUBKEY, key_id: ATT_KEY_ID };

test("makeRegistry: pubkey membership, case-insensitive, drops malformed, reads /.well-known payload", () => {
  const reg = makeRegistry([{ pubkey: PUBKEY, key_id: KEY_ID }]);
  assert.equal(reg.size, 1);
  assert.equal(reg.has(PUBKEY), true);
  assert.equal(reg.has(PUBKEY.toUpperCase()), true);     // membership is case-insensitive
  assert.equal(reg.has(OTHER), false);
  // accepts a {keys:[...]} well-known payload AND bare-string entries; silently drops non-hex / odd-length
  const reg2 = makeRegistry({ keys: [PUBKEY, "nothex!!", "abc"] });
  assert.equal(reg2.size, 1);
  assert.equal(makeRegistry(null).size, 0);              // no entries -> empty (an empty registry decides nothing)
});

test("trustedSigner: tri-state — true=ours, false=valid-but-untrusted, null=cannot-decide", async () => {
  const reg = makeRegistry([PUBKEY]);
  assert.equal(await trustedSigner(SIGNED, reg), true);                              // WAVE's published key
  assert.equal(await trustedSigner(SIGNED, makeRegistry([OTHER])), false);           // valid shape, NOT trusted
  assert.equal(await trustedSigner(SIGNED, null), null);                             // no registry -> cannot decide
  assert.equal(await trustedSigner(SIGNED, makeRegistry([])), null);                 // empty registry -> cannot decide
  assert.equal(await trustedSigner({ ...SIGNED, alg: "hmac-sha256" }, reg), null);   // a pubkey-registry can't vouch for a shared secret
  assert.equal(await trustedSigner({ ...FIXED_RECEIPT, alg: "none" }, reg), null);   // unsigned
});

test("trustedSigner: a key_id that LIES about its pubkey -> false (even when the pubkey IS trusted)", async () => {
  const reg = makeRegistry([PUBKEY]);
  assert.equal(await trustedSigner({ ...SIGNED, key_id: "deadbeefdeadbeef" }, reg), false);  // recompute catches the lie
  assert.equal(await trustedSigner({ ...SIGNED, key_id: undefined }, reg), true);            // absent key_id is fine (membership is by pubkey)
});

test("FOLD: verifyPaymentReceipt({registry}) = signature-valid AND key-trusted; backward-compatible without it", async () => {
  assert.equal(await verifyPaymentReceipt(SIGNED), true);                                              // no registry -> identical to today
  assert.equal(await verifyPaymentReceipt(SIGNED, { registry: makeRegistry([PUBKEY]) }), true);        // valid + ours
  assert.equal(await verifyPaymentReceipt(SIGNED, { registry: makeRegistry([OTHER]) }), false);        // valid sig, UNtrusted key -> reject
  assert.equal(                                                                                        // a registry NEVER upgrades a bad sig
    await verifyPaymentReceipt({ ...SIGNED, amount_atomic: "999999" }, { registry: makeRegistry([PUBKEY]) }), false);
});

test("FOLD: verifyAttestation({registry}) works on the provenance half too", async () => {
  assert.equal(await verifyAttestation(SIGNED_ATT), true);                                             // backward-compat
  assert.equal(await verifyAttestation(SIGNED_ATT, { registry: makeRegistry([ATT_PUBKEY]) }), true);   // valid + ours
  assert.equal(await verifyAttestation(SIGNED_ATT, { registry: makeRegistry([OTHER]) }), false);       // valid sig, untrusted key
});

test("trustedSigner: no-WebCrypto + key_id throws a DESCRIPTIVE error; a pure no-key_id lookup stays crypto-free", async () => {
  // Sentry #381 review: a direct trustedSigner() in a runtime without WebCrypto (Node <18) must surface a clear
  // error from the key_id self-consistency check — never an opaque `TypeError: …'subtle' of undefined`. And it
  // must FAIL LOUD, not degrade to null (a null would let the {registry} fold silently pass an untrusted key).
  const reg = makeRegistry([PUBKEY]);
  const saved = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  try {
    Object.defineProperty(globalThis, "crypto", { value: undefined, configurable: true });    // simulate Node <18
    await assert.rejects(trustedSigner(SIGNED, reg), /WebCrypto unavailable/);                 // key_id forces sha256 -> clear throw
    // a registry-membership lookup with NO key_id needs no crypto and must still decide (the guard is surgical)
    assert.equal(await trustedSigner({ ...SIGNED, key_id: undefined }, reg), true);
    assert.equal(await trustedSigner({ ...SIGNED, key_id: undefined }, makeRegistry([OTHER])), false);
  } finally {
    Object.defineProperty(globalThis, "crypto", saved);                                        // restore for the rest of the suite
  }
});
