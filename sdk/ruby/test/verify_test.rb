# Zero-dep tests (minitest, stdlib-bundled) for the SDK's offline verifiers — "the two receipts". The
# decisive assertions are CROSS-IMPLEMENTATION: every EXPECTED_* constant below is the SAME byte-exact vector
# pinned in the JS (receipt.test.js / attest.test.js), the edge signer, and the other SDKs. Green here proves
# this Ruby SDK produces a byte-for-byte identical canonical string and verifies the very signatures the
# Python signer emitted — "sign on the edge / in the runtime, verify in any SDK, trust no one".
#
# Ed25519 verify needs OpenSSL >= 1.1.1 (OpenSSL::PKey.new_raw_public_key). On a host whose Ruby is linked
# against LibreSSL or an older OpenSSL, that method is absent and the Ed25519-specific cases SKIP (the canonical
# pin, HMAC, and tri-state cases — all pure json/openssl-HMAC — always run). See ED25519_AVAILABLE below.
require "minitest/autorun"
require_relative "../lib/wave_dispatch/verify"

ED25519_AVAILABLE = OpenSSL::PKey.respond_to?(:new_raw_public_key)

class VerifyTest < Minitest::Test
  # ── Payment-Receipt (the MONEY half) ──────────────────────────────────────────────────────────────
  RECEIPT = {
    "v" => "wave.payment-receipt/v0", "ts" => 1700000000, "protocol" => "x402", "mode" => "wave-x402",
    "resource" => "/extract", "network" => "base", "asset" => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "amount_atomic" => "1000", "pay_to" => "0x0000000000000000000000000000000000000001",
    "tx_hash" => "0xdeadbeef", "verified" => true
  }.freeze
  EXPECTED_RECEIPT_CANONICAL =
    '{"amount_atomic":"1000","asset":"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",' \
    '"mode":"wave-x402","network":"base","pay_to":"0x0000000000000000000000000000000000000001",' \
    '"protocol":"x402","resource":"/extract","ts":1700000000,"tx_hash":"0xdeadbeef",' \
    '"v":"wave.payment-receipt/v0","verified":true}'
  RECEIPT_PUBKEY = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
  RECEIPT_SIG =
    "e333772435ba2b16c9b52188a489de18f0dbba870a84b6dcc6fe63ef3dffae5a" \
    "b9e65daa85b3306d4d3df879bc47c6282f87c661e634390a9a5d93e7c502220a"

  # ── context-Attestation (the CONTEXT half) ────────────────────────────────────────────────────────
  ATTEST = {
    "v" => "wave.context-attestation/v0", "ts" => 1700000000, "model" => "qwen3:30b", "source" => "café.md",
    "chunk" => 2, "chunk_sha" => "deadbeef", "chunk_chars" => 2980, "num_ctx" => 8192,
    "prompt_sha" => "cafe1234", "kept" => 3, "dropped_hallucinated" => 1
  }.freeze
  # The café -> café ascii-escape pin: byte-exact with the Python signer (ensure_ascii=True).
  EXPECTED_ATTEST_CANONICAL =
    '{"chunk":2,"chunk_chars":2980,"chunk_sha":"deadbeef","dropped_hallucinated":1,"kept":3,' \
    '"model":"qwen3:30b","num_ctx":8192,"prompt_sha":"cafe1234","source":"caf\\u00e9.md",' \
    '"ts":1700000000,"v":"wave.context-attestation/v0"}'
  ATTEST_PUBKEY = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
  ATTEST_SIG =
    "68017540b4c3b060e51faab64c28f4e1ea6994d3781fec14878e73052046d78d" \
    "05757a8287af644b245b10274ba3b60329ed216472839d7573debf4256e9730b"

  # ── canonical byte-parity (always runs — pure json) ───────────────────────────────────────────────
  def test_receipt_canonical_is_byte_identical_to_edge_signer
    assert_equal EXPECTED_RECEIPT_CANONICAL, WaveDispatch.canonical_payment_receipt(RECEIPT)
  end

  def test_attestation_canonical_matches_python_signer_cafe_escape
    assert_equal EXPECTED_ATTEST_CANONICAL, WaveDispatch.canonical_attestation(ATTEST)
  end

  # ── Ed25519: trustless + offline, self-describing (gated on OpenSSL capability) ────────────────────
  def test_receipt_ed25519_verifies_with_no_secret_and_tamper_fails
    skip "Ed25519 unavailable (need OpenSSL >= 1.1.1; this Ruby links #{OpenSSL::OPENSSL_VERSION})" unless ED25519_AVAILABLE
    signed = RECEIPT.merge("alg" => "ed25519", "sig" => RECEIPT_SIG, "pubkey" => RECEIPT_PUBKEY)
    assert_equal true, WaveDispatch.verify_payment_receipt(signed)
    assert_equal false, WaveDispatch.verify_payment_receipt(signed.merge("amount_atomic" => "999999")) # tampered money
    assert_equal false, WaveDispatch.verify_payment_receipt(signed.merge("verified" => false))          # tampered flag
  end

  def test_attestation_ed25519_verifies_python_signature_and_tamper_fails
    skip "Ed25519 unavailable (need OpenSSL >= 1.1.1; this Ruby links #{OpenSSL::OPENSSL_VERSION})" unless ED25519_AVAILABLE
    signed = ATTEST.merge("alg" => "ed25519", "sig" => ATTEST_SIG, "pubkey" => ATTEST_PUBKEY)
    assert_equal true, WaveDispatch.verify_attestation(signed)
    assert_equal false, WaveDispatch.verify_attestation(signed.merge("kept" => 999))                    # tampered field
  end

  def test_ed25519_without_pubkey_is_nil
    skip "Ed25519 unavailable" unless ED25519_AVAILABLE
    assert_nil WaveDispatch.verify_payment_receipt(RECEIPT.merge("alg" => "ed25519", "sig" => RECEIPT_SIG))
    assert_nil WaveDispatch.verify_attestation(ATTEST.merge("alg" => "ed25519", "sig" => ATTEST_SIG))
  end

  # ── HMAC tri-state (always runs — openssl HMAC is in every Ruby/OpenSSL build) ─────────────────────
  def test_receipt_hmac_verifies_with_key_fails_wrong_nil_without
    sig = OpenSSL::HMAC.hexdigest("SHA256", "k", WaveDispatch.canonical_payment_receipt(RECEIPT))
    r = RECEIPT.merge("alg" => "hmac-sha256", "sig" => sig)
    assert_equal true,  WaveDispatch.verify_payment_receipt(r, hmac_key: "k")
    assert_equal false, WaveDispatch.verify_payment_receipt(r, hmac_key: "wrong")
    assert_nil          WaveDispatch.verify_payment_receipt(r)                 # HMAC without our key -> uncheckable
  end

  def test_attestation_hmac_verifies_with_key_fails_wrong_nil_without
    sig = OpenSSL::HMAC.hexdigest("SHA256", "k", WaveDispatch.canonical_attestation(ATTEST))
    att = ATTEST.merge("alg" => "hmac-sha256", "sig" => sig)
    assert_equal true,  WaveDispatch.verify_attestation(att, hmac_key: "k")
    assert_equal false, WaveDispatch.verify_attestation(att, hmac_key: "wrong")
    assert_nil          WaveDispatch.verify_attestation(att)
  end

  # ── unsigned / no-alg -> nil (not false) (always runs) ─────────────────────────────────────────────
  def test_unsigned_records_are_nil
    assert_nil WaveDispatch.verify_payment_receipt(RECEIPT)
    assert_nil WaveDispatch.verify_payment_receipt(RECEIPT.merge("alg" => "none", "sig" => nil))
    assert_nil WaveDispatch.verify_attestation(ATTEST)
    assert_nil WaveDispatch.verify_attestation(ATTEST.merge("alg" => "none", "sig" => nil))
  end

  def test_non_hash_and_unknown_alg_are_nil
    assert_nil WaveDispatch.verify_payment_receipt("not a hash")
    assert_nil WaveDispatch.verify_attestation(nil)
    assert_nil WaveDispatch.verify_payment_receipt(RECEIPT.merge("alg" => "rsa-pss", "sig" => "ab"))
  end

  # ── truncation tri-state (always runs — pure data) ─────────────────────────────────────────────────
  def test_truncation_is_derivable_from_two_hashes
    assert_equal true,  WaveDispatch.attestation_truncated("chunk_sha" => "a", "prompt_sha" => "b")
    assert_equal false, WaveDispatch.attestation_truncated("chunk_sha" => "a", "prompt_sha" => "a")
    assert_nil          WaveDispatch.attestation_truncated("chunk_sha" => "a")
    assert_nil          WaveDispatch.attestation_truncated("prompt_sha" => "b")
  end

  # ── E4.followup: trusted-key registry (the SECOND axis). Cross-impl with sdk/js/trusted.test.js ──────
  TRUSTED_KEY_ID = "34750f98bd59fcfc" # = sha256(RECEIPT_PUBKEY bytes)[0, 16] — the edge derivation
  OTHER_KEY = "00" * 32

  def test_make_registry_membership_and_wellknown_payload
    reg = WaveDispatch.make_registry([{ "pubkey" => RECEIPT_PUBKEY, "key_id" => TRUSTED_KEY_ID }])
    assert_equal 1, reg.size
    assert reg.key?(RECEIPT_PUBKEY) # stored lowercase
    refute reg.key?(OTHER_KEY)
    assert_equal 1, WaveDispatch.make_registry("keys" => [RECEIPT_PUBKEY, "nothex!!", "abc"]).size
    assert_equal 0, WaveDispatch.make_registry(nil).size
  end

  def test_trusted_signer_tristate_and_keyid_lie
    signed = { "alg" => "ed25519", "pubkey" => RECEIPT_PUBKEY, "key_id" => TRUSTED_KEY_ID, "sig" => "ab" }
    reg = WaveDispatch.make_registry([RECEIPT_PUBKEY])
    assert_equal true,  WaveDispatch.trusted_signer(signed, reg)
    assert_equal true,  WaveDispatch.trusted_signer(signed.merge("pubkey" => RECEIPT_PUBKEY.upcase), reg) # case-insensitive
    assert_equal false, WaveDispatch.trusted_signer(signed, WaveDispatch.make_registry([OTHER_KEY]))
    assert_nil          WaveDispatch.trusted_signer(signed, nil)
    assert_nil          WaveDispatch.trusted_signer(signed, {})
    assert_nil          WaveDispatch.trusted_signer(signed.merge("alg" => "hmac-sha256"), reg)
    assert_equal false, WaveDispatch.trusted_signer(signed.merge("key_id" => "deadbeefdeadbeef"), reg) # key_id lie
    assert_equal true,  WaveDispatch.trusted_signer(signed.merge("key_id" => nil), reg)                # absent key_id ok
  end

  def test_registry_folds_into_verify
    skip "Ed25519 unavailable" unless ED25519_AVAILABLE

    signed = RECEIPT.merge("alg" => "ed25519", "sig" => RECEIPT_SIG, "pubkey" => RECEIPT_PUBKEY)
    assert_equal true,  WaveDispatch.verify_payment_receipt(signed) # no registry -> unchanged
    assert_equal true,  WaveDispatch.verify_payment_receipt(signed, registry: WaveDispatch.make_registry([RECEIPT_PUBKEY]))
    assert_equal false, WaveDispatch.verify_payment_receipt(signed, registry: WaveDispatch.make_registry([OTHER_KEY])) # valid sig, untrusted
    assert_equal false, WaveDispatch.verify_payment_receipt(signed.merge("amount_atomic" => "999999"),
                                                            registry: WaveDispatch.make_registry([RECEIPT_PUBKEY])) # bad sig not upgraded
  end
end
