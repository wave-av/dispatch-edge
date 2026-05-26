# wave Dispatch — thin Ruby client. Route each request to the cheapest capable model (local-first;
# escalate to your frontier only when needed). BYO keys + infra. Stdlib only (net/http).
require "net/http"
require "json"
require "uri"

module WaveDispatch
  VERSION = "0.1.0"

  class Client
    def initialize(license = ENV["WAVE_LICENSE"], endpoint: "https://dispatch.wave.online")
      @license = license
      @endpoint = endpoint
    end

    # Classify a prompt (no execution) -> {"route", "probability", "margin", "forward"}
    def route(prompt) = post({ prompt: prompt })

    # Classify and run on the edge if your plan allows it.
    def execute(prompt) = post({ prompt: prompt, execute: true })

    private

    def post(body)
      uri = URI(@endpoint + "/")
      req = Net::HTTP::Post.new(uri, "content-type" => "application/json")
      req["authorization"] = "Bearer #{@license}" if @license
      req.body = body.to_json
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |h| h.request(req) }
      raise "dispatch: 402 payment required (x402)" if res.code == "402"
      JSON.parse(res.body)
    end
  end
end
