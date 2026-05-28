# wave Dispatch — thin Ruby client. Route each request to the cheapest capable model (local-first;
# escalate to your frontier only when needed). BYO keys + infra. Stdlib only (net/http).
require "net/http"
require "json"
require "uri"
require "openssl"

module WaveDispatch
  VERSION = "0.4.4"

  class Client
    def initialize(license = ENV["WAVE_LICENSE"], endpoint: "https://dispatch.wave.online",
                   agents_endpoint: ENV["WAVE_AGENTS_ENDPOINT"] || "https://dispatch-agents.wave.online")
      @license = license
      @endpoint = endpoint
      @agents = agents_endpoint
    end

    # Classify a prompt (no execution) -> {"route", "probability", "margin", "forward"}
    def route(prompt) = send_req(:post, @endpoint + "/", { prompt: prompt })

    # Classify and run on the edge if your plan allows it.
    def execute(prompt) = send_req(:post, @endpoint + "/", { prompt: prompt, execute: true })

    # This license's savings ledger (decisions, saved_usd, saved_pct, ...). Requires a license.
    def savings = send_req(:get, "#{@agents}/ledger/summary?license=#{lic}")

    # This license's agent-subscription status.
    def subscription = send_req(:get, "#{@agents}/subscription/status?license=#{lic}")

    # Start/replace a programmatic subscription (plan: agent_starter | agent_pro | agent_scale).
    def subscribe(plan) = send_req(:post, "#{@agents}/subscription/create", { license: @license, plan: plan })

    private

    def lic
      raise "dispatch: a license is required for savings/subscription" unless @license
      URI.encode_www_form_component(@license)
    end

    def send_req(method, url, body = nil)
      uri = URI(url)
      req = (method == :post ? Net::HTTP::Post : Net::HTTP::Get).new(uri, "content-type" => "application/json")
      req["authorization"] = "Bearer #{@license}" if @license
      req.body = body.to_json if body
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https",
                            verify_mode: OpenSSL::SSL::VERIFY_PEER) { |h| h.request(req) }
      raise "dispatch: 402 payment required (x402)" if res.code == "402"
      raise "dispatch: 401 unauthorized — set a valid license" if res.code == "401"
      # any other non-2xx must raise — never JSON.parse an error body and return it as a success result
      raise "dispatch: #{res.code} #{res.body.to_s[0, 160]}" unless res.code.start_with?("2")
      JSON.parse(res.body)
    end
  end
end
