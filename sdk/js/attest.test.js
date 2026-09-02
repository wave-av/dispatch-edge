// Zero-dep tests (node:test) for the SDK's offline attestation verifier. The decisive test is
// CROSS-LANGUAGE: an attestation signed by the Python signer (attest.py) must verify here byte-for-byte —
// that's what makes "sign in the runtime, verify in any SDK, trust no one" real.
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAttestation, attestationTruncated, canonicalAttestation } from "./index.js";

// The exact vector emitted by attest.py (also pinned in edge-router/context-attest.test.ts).
const BASE = {
  v: "wave.context-attestation/v0", ts: 1700000000, model: "qwen3:30b", source: "café.md",
  chunk: 2, chunk_sha: "deadbeef", chunk_chars: 2980, num_ctx: 8192, prompt_sha: "cafe1234",
  kept: 3, dropped_hallucinated: 1,
};
const PY_CANONICAL =
  '{"chunk":2,"chunk_chars":2980,"chunk_sha":"deadbeef","dropped_hallucinated":1,"kept":3,' +
  '"model":"qwen3:30b","num_ctx":8192,"prompt_sha":"cafe1234","source":"caf\\u00e9.md",' +
  '"ts":1700000000,"v":"wave.context-attestation/v0"}';
const PY_PUBKEY = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
const PY_SIG =
  "68017540b4c3b060e51faab64c28f4e1ea6994d3781fec14878e73052046d78d" +
  "05757a8287af644b245b10274ba3b60329ed216472839d7573debf4256e9730b";

test("canonical string matches the Python signer byte-for-byte (café -> caf\\u00e9)", () => {
  assert.equal(canonicalAttestation(BASE), PY_CANONICAL);
});

test("verifies a Python Ed25519 signature with NO secret (trustless, offline)", async () => {
  assert.equal(await verifyAttestation({ ...BASE, alg: "ed25519", sig: PY_SIG, pubkey: PY_PUBKEY }), true);
});

test("rejects a tampered field against the Python signature", async () => {
  assert.equal(await verifyAttestation({ ...BASE, kept: 999, alg: "ed25519", sig: PY_SIG, pubkey: PY_PUBKEY }), false);
});

test("HMAC: verifies with the key, fails with the wrong one, null without it", async () => {
  const subtle = globalThis.crypto.subtle;
  const enc = new TextEncoder();
  const key = await subtle.importKey("raw", enc.encode("k"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = [...new Uint8Array(await subtle.sign("HMAC", key, enc.encode(canonicalAttestation(BASE))))]
    .map((x) => x.toString(16).padStart(2, "0")).join("");
  const att = { ...BASE, alg: "hmac-sha256", sig };
  assert.equal(await verifyAttestation(att, { hmacKey: "k" }), true);
  assert.equal(await verifyAttestation(att, { hmacKey: "wrong" }), false);
  assert.equal(await verifyAttestation(att), null);            // HMAC without our key -> uncheckable
});

test("unsigned / no-alg -> null (not false)", async () => {
  assert.equal(await verifyAttestation({ ...BASE }), null);
  assert.equal(await verifyAttestation({ ...BASE, alg: "none", sig: null }), null);
});

test("truncation is derivable from two hashes", () => {
  assert.equal(attestationTruncated({ chunk_sha: "a", prompt_sha: "b" }), true);
  assert.equal(attestationTruncated({ chunk_sha: "a", prompt_sha: "a" }), false);
  assert.equal(attestationTruncated({ chunk_sha: "a" }), null);
});
