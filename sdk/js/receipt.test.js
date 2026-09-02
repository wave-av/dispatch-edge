// Zero-dep tests (node:test) for the SDK's offline Payment-Receipt verifier — the MONEY half of "the two
// receipts". The decisive test is CROSS-IMPLEMENTATION: EXPECTED_CANONICAL is the SAME constant pinned in
// edge-router/payment-receipt.test.ts, so a green here proves the SDK and the edge signer produce byte-for-
// byte identical canonical strings — "sign on the edge, verify in any SDK, trust no one" for payments.
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalPaymentReceipt, verifyPaymentReceipt } from "./index.js";

// Pinned identically in edge-router/payment-receipt.test.ts (the byte-parity vector).
const FIXED = {
  v: "wave.payment-receipt/v0", ts: 1700000000, protocol: "x402", mode: "wave-x402",
  resource: "/extract", network: "base", asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  amount_atomic: "1000", pay_to: "0x0000000000000000000000000000000000000001",
  tx_hash: "0xdeadbeef", verified: true,
};
const EXPECTED_CANONICAL =
  '{"amount_atomic":"1000","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",' +
  '"mode":"wave-x402","network":"base","pay_to":"0x0000000000000000000000000000000000000001",' +
  '"protocol":"x402","resource":"/extract","ts":1700000000,"tx_hash":"0xdeadbeef",' +
  '"v":"wave.payment-receipt/v0","verified":true}';

const _toHex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");

test("canonical receipt string is byte-identical to the edge signer (cross-impl parity)", () => {
  assert.equal(canonicalPaymentReceipt(FIXED), EXPECTED_CANONICAL);
});

test("Ed25519: signs, self-verifies with NO secret (trustless, offline); tamper fails", async () => {
  const subtle = globalThis.crypto.subtle, enc = new TextEncoder();
  const kp = await subtle.generateKey("Ed25519", true, ["sign", "verify"]);
  const pubkey = _toHex(await subtle.exportKey("raw", kp.publicKey));
  const sig = _toHex(await subtle.sign("Ed25519", kp.privateKey, enc.encode(canonicalPaymentReceipt(FIXED))));
  const signed = { ...FIXED, alg: "ed25519", sig, pubkey };
  assert.equal(await verifyPaymentReceipt(signed), true);
  assert.equal(await verifyPaymentReceipt({ ...signed, amount_atomic: "999999" }), false);   // tampered money amount
  assert.equal(await verifyPaymentReceipt({ ...signed, verified: false }), false);            // tampered settlement flag
});

test("HMAC: verifies with the key, fails with the wrong one, null without it", async () => {
  const subtle = globalThis.crypto.subtle, enc = new TextEncoder();
  const key = await subtle.importKey("raw", enc.encode("k"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = _toHex(await subtle.sign("HMAC", key, enc.encode(canonicalPaymentReceipt(FIXED))));
  const r = { ...FIXED, alg: "hmac-sha256", sig };
  assert.equal(await verifyPaymentReceipt(r, { hmacKey: "k" }), true);
  assert.equal(await verifyPaymentReceipt(r, { hmacKey: "wrong" }), false);
  assert.equal(await verifyPaymentReceipt(r), null);                  // HMAC without our key -> uncheckable
});

test("unsigned / no-alg -> null (not false)", async () => {
  assert.equal(await verifyPaymentReceipt({ ...FIXED }), null);
  assert.equal(await verifyPaymentReceipt({ ...FIXED, alg: "none", sig: null }), null);
});
