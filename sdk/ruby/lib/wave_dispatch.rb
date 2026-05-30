# wave Dispatch — thin Ruby client. Route each request to the cheapest capable model (local-first;
# escalate to your frontier only when needed). BYO keys + infra. Stdlib only (net/http).
require "base64"
require "net/http"
require "json"
require "uri"
require "openssl"

module WaveDispatch
  VERSION = "0.6.3"

  # 0.5.1 — payment hook: a Proc called once with the 402 challenge body (Hash) that returns the
  # headers (Hash[String => String]) to retry the request with. Pair with `Client.wallet_hook(provider:,
  # credentials:)` for the built-in CDP / Privy / Bridge factories, or build a Proc yourself.
  class Client
    def initialize(license = ENV["WAVE_LICENSE"], endpoint: "https://dispatch.wave.online",
                   agents_endpoint: ENV["WAVE_AGENTS_ENDPOINT"] || "https://dispatch-agents.wave.online",
                   payment_hook: nil)
      @license = license
      @endpoint = endpoint
      @agents = agents_endpoint
      @payment_hook = payment_hook       # 0.5.1 — handles 402 inside the client
    end

    # Classify a prompt (no execution) -> {"route", "probability", "margin", "forward"}
    # Sovereign tier: pass profile (Fast|Expert|Heavy|Code) to request a named routing profile.
    def route(prompt, profile = nil) = send_req(:post, @endpoint + "/", with_profile({ prompt: prompt }, profile))

    # Classify and run on the edge if your plan allows it. Optional profile as in route.
    def execute(prompt, profile = nil) = send_req(:post, @endpoint + "/", with_profile({ prompt: prompt, execute: true }, profile))

    # Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest).
    def route_vector(vector, profile = nil) = send_req(:post, @endpoint + "/", with_profile({ vector: vector }, profile))

    # This license's savings ledger (decisions, saved_usd, saved_pct, ...). Requires a license.
    def savings = send_req(:get, "#{@agents}/ledger/summary?license=#{lic}")

    # This license's agent-subscription status.
    def subscription = send_req(:get, "#{@agents}/subscription/status?license=#{lic}")

    # Start/replace a programmatic subscription (plan: agent_starter | agent_pro | agent_scale).
    def subscribe(plan) = send_req(:post, "#{@agents}/subscription/create", { license: @license, plan: plan })

    # 0.5.1 — build a payment_hook for a built-in provider. provider: :cdp | :privy | :bridge.
    # credentials per provider: cdp: {api_key:, api_secret:, address:}; privy: {app_id:, app_secret:,
    # wallet_id:}; bridge: {api_key:, source_wallet:, destination:}. For custom wallets, build a Proc
    # of your own that returns the header Hash you want set on the retry.
    def self.wallet_hook(provider:, credentials: {})
      provider = provider.to_sym
      header = { cdp: "cdp-payment", privy: "privy-payment", bridge: "bridge-payment" }[provider]
      raise "dispatch.wallet_hook: unknown provider #{provider.inspect}" unless header
      ->(challenge) { { header => WaveDispatch.wallet_sign(provider, credentials, challenge) } }
    end

    private

    # Sovereign tier (D3): attach a named routing profile to the request body. snake_case `profile` is
    # the cross-SDK contract; the edge resolveProfile() honors body.profile over per-license KV + defaults.
    def with_profile(body, profile)
      profile ? body.merge(profile: profile) : body
    end

    def lic
      raise "dispatch: a license is required for savings/subscription" unless @license
      URI.encode_www_form_component(@license)
    end

    def build_req(method, url, body)
      uri = URI(url)
      req = (method == :post ? Net::HTTP::Post : Net::HTTP::Get).new(uri, "content-type" => "application/json")
      req["authorization"] = "Bearer #{@license}" if @license
      req.body = body.to_json if body
      [uri, req]
    end

    def http_call(uri, req)
      Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                      verify_mode: OpenSSL::SSL::VERIFY_PEER) { |h| h.request(req) }
    end

    def send_req(method, url, body = nil)
      uri, req = build_req(method, url, body)
      res = http_call(uri, req)
      if res.code == "402" && @payment_hook
        challenge = (JSON.parse(res.body) rescue {})
        extra = @payment_hook.call(challenge) || {}
        uri2, req2 = build_req(method, url, body)
        extra.each { |k, v| req2[k.to_s] = v }
        res = http_call(uri2, req2)
      end
      raise "dispatch: 402 payment required (x402) — pay and retry, or set a license / payment_hook" if res.code == "402"
      raise "dispatch: 401 unauthorized — set a valid license" if res.code == "401"
      raise "dispatch: #{res.code} #{res.body.to_s[0, 160]}" unless res.code.start_with?("2")
      JSON.parse(res.body)
    end
  end

  # Built-in provider sign — HTTP orchestration only; actual signing happens at the provider.
  def self.wallet_sign(provider, creds, challenge)
    accepts = challenge.is_a?(Hash) ? (challenge["accepts"] || []) : []
    accept = accepts.find { |a| a.is_a?(Hash) && a["protocol"] == provider.to_s } || accepts.first || {}
    case provider
    when :cdp
      # 0.6.2 — real CDP-JWT (ES256/P-256) signing via OpenSSL stdlib. creds: {api_key, api_secret (PEM EC),
      # address?, network?}. The signed JWT is the cdp-payment header value; WAVE's CDP verifier validates
      # the signature on its side. No optional dep needed — Ruby's stdlib OpenSSL handles everything.
      raise "dispatch.wallet_hook(cdp): api_key required" unless creds[:api_key]
      raise "dispatch.wallet_hook(cdp): api_secret required (PEM EC private key)" unless creds[:api_secret]
      jwt = WaveDispatch.sign_cdp_jwt(creds, accept)
      { provider: "cdp", jwt: jwt, address: creds[:address],
        network: creds[:network] || "base", accept: accept }.to_json
    when :privy
      %i[app_id app_secret wallet_id].each { |k| raise "dispatch.wallet_hook(privy): #{k} required" unless creds[k] }
      basic = Base64.strict_encode64("#{creds[:app_id]}:#{creds[:app_secret]}")
      uri = URI("https://auth.privy.io/api/v1/wallets/#{URI.encode_www_form_component(creds[:wallet_id])}/rpc")
      req = Net::HTTP::Post.new(uri, "content-type" => "application/json",
                                "authorization" => "Basic #{basic}", "privy-app-id" => creds[:app_id])
      req.body = { method: "personal_sign", params: { message: accept.to_json }, chain_type: "ethereum" }.to_json
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true,
                            verify_mode: OpenSSL::SSL::VERIFY_PEER) { |h| h.request(req) }
      raise "dispatch.wallet_hook(privy): provider #{res.code}" unless res.code.start_with?("2")
      j = (JSON.parse(res.body) rescue {})
      sig = (j.dig("data", "signature") || j["signature"])
      { provider: "privy", signature: sig, accept: accept }.to_json
    when :bridge
      raise "dispatch.wallet_hook(bridge): :api_key required" unless creds[:api_key]
      uri = URI("https://api.bridge.xyz/v0/transfers")
      req = Net::HTTP::Post.new(uri, "content-type" => "application/json", "api-key" => creds[:api_key])
      req.body = { source: creds[:source_wallet], destination: creds[:destination] || accept["payTo"],
                   amount: accept["maxAmountRequired"] }.to_json
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: true,
                            verify_mode: OpenSSL::SSL::VERIFY_PEER) { |h| h.request(req) }
      raise "dispatch.wallet_hook(bridge): provider #{res.code}" unless res.code.start_with?("2")
      j = (JSON.parse(res.body) rescue {})
      { provider: "bridge", id: j["id"], accept: accept }.to_json
    else
      raise "dispatch.wallet_sign: unsupported provider #{provider.inspect}"
    end
  end

  # 0.6.2 — CDP-JWT (ES256/P-256) signing via OpenSSL stdlib. Header:
  # {alg:'ES256', kid:<api_key>, typ:'JWT', nonce:<rand-hex16>}. Payload: {sub:<api_key>, iss:'cdp',
  # nbf:<now>, exp:<now+120>, uri:'POST dispatch.wave.online<resource>', claim:<accept>}.
  # ECDSA signs the base64url(header).base64url(payload) input; the DER signature is unpacked to raw
  # 32+32 r||s (IEEE P-1363), which is exactly what JWS ES256 expects.
  def self.sign_cdp_jwt(creds, accept)
    require "openssl"
    require "securerandom"
    nonce = SecureRandom.hex(16)
    now = Time.now.to_i
    uri = "POST dispatch.wave.online#{(accept || {})["resource"] || "/"}"
    header = { alg: "ES256", kid: creds[:api_key], typ: "JWT", nonce: nonce }
    payload = { sub: creds[:api_key], iss: "cdp", nbf: now, exp: now + 120, uri: uri, claim: accept }
    b64url = ->(s) { Base64.urlsafe_encode64(s).gsub("=", "") }
    to_sign = b64url.call(header.to_json) + "." + b64url.call(payload.to_json)
    key = OpenSSL::PKey.read(creds[:api_secret])
    raise "dispatch.wallet_hook(cdp): api_secret must be an EC P-256 private key" unless key.is_a?(OpenSSL::PKey::EC)
    der_sig = key.sign(OpenSSL::Digest.new("SHA256"), to_sign)
    # DER → raw r||s. OpenSSL ASN1 parses the SEQUENCE into [r, s] big-integers.
    asn1 = OpenSSL::ASN1.decode(der_sig)
    r = asn1.value[0].value.to_s(2).rjust(32, "\x00".b)
    s = asn1.value[1].value.to_s(2).rjust(32, "\x00".b)
    to_sign + "." + b64url.call(r + s)
  end
end
