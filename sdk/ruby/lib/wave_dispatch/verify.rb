# WAVE Dispatch — offline verifiers for "the two receipts": the Payment-Receipt (the MONEY half) and the
# context-Attestation (the CONTEXT half). Both are dispatch's signed, self-describing statements — a
# Payment-Receipt says "I paid for this and dispatch verified the settlement"; an Attestation says "this is
# exactly what the model saw, and whether the prompt was truncated". Verifying them is offline, trustless,
# instance-free, and stdlib-only (json + openssl): an Ed25519 record embeds its own public key, so anyone
# confirms it with NO secret and NO network. HMAC records need the shared key.
#
# The canonical signing string is BYTE-IDENTICAL across every implementation (JS, Python, Go, Rust, the edge
# signer, and this one), pinned by the shared cross-language vectors in test/verify_test.rb. That byte-parity
# is the whole point: "sign on the edge / in the runtime, verify in any SDK, trust no one".
#
# This file is intentionally self-contained (only json + openssl) and re-opens the WaveDispatch module, so it
# loads on its own — the published entrypoint (wave_dispatch.rb) just `require_relative`s it to expose the flat
# API. Ed25519 verify needs OpenSSL >= 1.1.1 (OpenSSL::PKey.new_raw_public_key); HMAC + canonical are universal.
# Plain `def...end` only (no endless defs) so it parses on the gemspec's declared floor (Ruby >= 2.7).
require "json"
require "openssl"

module WaveDispatch
  module Verify
    # The exact field set + order semantics shared by every signer. canonical() takes ONLY these fields,
    # sorts the NAMES alphabetically, inserts nil for any that are missing, then serializes compactly with
    # every non-ASCII char escaped to \uXXXX (Python's json.dumps(ensure_ascii=True) shape).
    RECEIPT_FIELDS = %w[v ts protocol mode resource network asset amount_atomic pay_to tx_hash verified].freeze
    ATTEST_FIELDS  = %w[v ts model source chunk chunk_sha chunk_chars num_ctx prompt_sha kept dropped_hallucinated].freeze

    module_function

    # Compact, ASCII-escaped JSON over exactly `fields` (sorted; missing => nil). Ruby Hash preserves insertion
    # order, so inserting keys in sorted order yields sorted output. JSON.generate(ascii_only: true) is compact
    # AND escapes every char >= U+0080 as \uXXXX (astral chars as a UTF-16 surrogate pair) — exactly the wire
    # shape — and, unlike a browser JSON.stringify, it does NOT HTML-escape <>& (which we also must not).
    def canonical(record, fields)
      record = record.is_a?(Hash) ? record : {}
      sorted = {}
      fields.sort.each { |k| sorted[k] = record.key?(k) ? record[k] : nil }
      JSON.generate(sorted, ascii_only: true)
    end

    def canonical_payment_receipt(receipt)
      canonical(receipt, RECEIPT_FIELDS)
    end

    def canonical_attestation(att)
      canonical(att, ATTEST_FIELDS)
    end

    # Tri-state verify shared by both records. Returns true/false when signed & checkable, nil when the record
    # is unsigned or is an HMAC record handed over without its key (uncheckable, NOT a cryptographic failure):
    #   nil  — not a Hash; no "alg"; alg == "none"; no "sig"; ed25519 w/o "pubkey"; hmac w/o the key; unknown alg
    #   true/false — a real cryptographic verdict
    def verify(record, canonical_str, hmac_key)
      return nil unless record.is_a?(Hash)
      alg = record["alg"]
      sig = record["sig"]
      return nil if alg.nil? || alg == "none" || sig.nil?

      case alg
      when "ed25519"
        pubkey = record["pubkey"]
        return nil if pubkey.nil?
        verify_ed25519(pubkey, sig, canonical_str)
      when "hmac-sha256"
        return nil if hmac_key.nil?
        expected = OpenSSL::HMAC.hexdigest("SHA256", hmac_key, canonical_str)
        secure_compare(expected, sig.to_s)
      end # any other alg falls through to nil
    end

    # Ed25519 verify from the 32 raw public-key bytes (hex) over the canonical bytes; the signature is the raw
    # 64 bytes (hex). Ruby's OpenSSL exposes raw-key Ed25519 on OpenSSL >= 1.1.1; verify() takes a nil digest
    # for Ed25519. Any malformed key/sig (bad hex length, wrong size, unsupported OpenSSL) is a hard false —
    # never an exception, never nil (nil is reserved for "no pubkey supplied").
    def verify_ed25519(pubkey_hex, sig_hex, canonical_str)
      raw_pub = [pubkey_hex.to_s].pack("H*")
      sig_bytes = [sig_hex.to_s].pack("H*")
      return false unless raw_pub.bytesize == 32 && sig_bytes.bytesize == 64
      key = OpenSSL::PKey.new_raw_public_key("ED25519", raw_pub)
      key.verify(nil, sig_bytes, canonical_str)
    rescue StandardError
      false
    end

    # Constant-time string compare — no length/early-exit leak (mirrors the edge crypto-util.timingSafeEqual).
    # Implemented in pure Ruby so it works on every Ruby/OpenSSL build (OpenSSL.secure_compare and
    # Rack::Utils.secure_compare are not universally present — e.g. a LibreSSL-linked stdlib lacks the former).
    def secure_compare(a, b)
      a = a.to_s.b
      b = b.to_s.b
      n = [a.bytesize, b.bytesize].max
      mismatch = a.bytesize ^ b.bytesize
      n.times { |i| mismatch |= (a.getbyte(i) || 0) ^ (b.getbyte(i) || 0) }
      mismatch.zero?
    end

    # E4.followup — trusted-key registry: trust's SECOND axis ("is the signer one WAVE published?"). hex?,
    # make_registry, trusted_signer mirror sdk/js/verify.js byte-for-byte (pinned by the shared FIXED vector).
    def hex?(s)
      s.is_a?(String) && s.length.even? && s.match?(/\A[0-9a-fA-F]*\z/)
    end

    # Build a trusted-key registry (a Hash used as a SET of lowercase-hex pubkeys) from a list of
    # {pubkey, key_id?} hashes (or bare pubkey-hex strings), or a /.well-known/wave-keys.json payload
    # {"keys" => [...]}. Malformed (non-hex / odd-length) entries are dropped. Membership: registry.key?(pub).
    def make_registry(entries)
      entries = entries["keys"] if entries.is_a?(Hash)
      set = {}
      Array(entries).each do |e|
        pub = e.is_a?(String) ? e : (e.is_a?(Hash) ? e["pubkey"] : nil)
        set[pub.downcase] = true if pub.is_a?(String) && !pub.empty? && hex?(pub)
      end
      set
    end

    # key_id mirrors the edge derivation: sha256(pubkey-bytes)[0, 16] hex.
    def key_id_of(pubkey_hex)
      OpenSSL::Digest.hexdigest("SHA256", [pubkey_hex].pack("H*"))[0, 16]
    end

    # Is the signer's key one WAVE published? Tri-state. true = ed25519 key in `registry` with an honest
    # key_id; false = a valid-shaped key NOT in the registry, or a key_id that LIES about its pubkey; nil =
    # cannot decide (no/empty registry, unsigned, "none", HMAC). Does NOT verify the signature.
    def trusted_signer(record, registry)
      return nil unless registry.is_a?(Hash) && !registry.empty? && record.is_a?(Hash)
      return nil unless record["alg"] == "ed25519"

      pub = record["pubkey"]
      return nil if pub.nil? || pub.to_s.empty?

      pub = pub.to_s.downcase
      return false unless hex?(pub)

      kid = record["key_id"]
      return false if kid && !kid.to_s.empty? && kid.to_s.downcase != key_id_of(pub)

      registry.key?(pub)
    end

    # Public: verify a Payment-Receipt. `hmac_key:` only for HMAC receipts (Ed25519 is self-describing). Pass
    # `registry:` (see make_registry) to FOLD in the trusted-key check: a valid signature from an untrusted key
    # returns false (a registry never upgrades a bad sig). Omit it -> behaviour is identical to before.
    def verify_payment_receipt(receipt, hmac_key: nil, registry: nil)
      v = verify(receipt, canonical_payment_receipt(receipt), hmac_key)
      return false if registry && v == true && trusted_signer(receipt, registry) == false

      v
    end

    # Public: verify a context-Attestation. `registry:` folds in the trusted-key check (see verify_payment_receipt).
    def verify_attestation(att, hmac_key: nil, registry: nil)
      v = verify(att, canonical_attestation(att), hmac_key)
      return false if registry && v == true && trusted_signer(att, registry) == false

      v
    end

    # Public: did the model see less than the full prompt? chunk_sha vs prompt_sha — both present & differ =>
    # true; equal => false; either missing => nil (undeterminable). Pure data, no crypto.
    def attestation_truncated(att)
      return nil unless att.is_a?(Hash)
      c = att["chunk_sha"]
      p = att["prompt_sha"]
      return nil if c.nil? || p.nil?
      c != p
    end
  end

  # Re-export at the module top level so the public API is flat:
  #   WaveDispatch.canonical_payment_receipt(r) / .verify_payment_receipt(r, hmac_key:) /
  #   WaveDispatch.canonical_attestation(a) / .verify_attestation(a, hmac_key:) / .attestation_truncated(a)
  # Explicit delegators (not metaprogrammed) so keyword forwarding is correct on every Ruby — a `**kwargs`
  # splat-forward mis-separates a trailing positional Hash on Ruby 2.6/2.7, and `def self.x = ...` endless
  # defs would break the gemspec's declared floor (>= 2.7).
  class << self
    def canonical_payment_receipt(receipt)
      Verify.canonical_payment_receipt(receipt)
    end

    def canonical_attestation(att)
      Verify.canonical_attestation(att)
    end

    def verify_payment_receipt(receipt, hmac_key: nil, registry: nil)
      Verify.verify_payment_receipt(receipt, hmac_key: hmac_key, registry: registry)
    end

    def verify_attestation(att, hmac_key: nil, registry: nil)
      Verify.verify_attestation(att, hmac_key: hmac_key, registry: registry)
    end

    def make_registry(entries)
      Verify.make_registry(entries)
    end

    def trusted_signer(record, registry)
      Verify.trusted_signer(record, registry)
    end

    def attestation_truncated(att)
      Verify.attestation_truncated(att)
    end
  end
end
