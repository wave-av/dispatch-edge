# wave Dispatch — Ruby client. Route each request to the cheapest capable model (local-first;
# escalate to your frontier model only when needed). Your keys + infra stay yours.
require "net/http"
require "json"
require "uri"

module Dispatch
  DEFAULT_ENDPOINT = "https://dispatch.wave.online".freeze

  class Client
    def initialize(license = nil, endpoint: DEFAULT_ENDPOINT)
      @license = license
      @endpoint = endpoint
    end

    # Classify a prompt (no execution). Returns a Hash: route, probability, margin, forward, ...
    def route(prompt)
      post("prompt" => prompt)
    end

    # Classify and run on the edge (if your plan enables it).
    def execute(prompt)
      post("prompt" => prompt, "execute" => true)
    end

    # Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest).
    def route_vector(vec)
      post("vector" => vec)
    end

    private

    def post(body)
      uri = URI(@endpoint.to_s.chomp("/") + "/")
      req = Net::HTTP::Post.new(uri)
      req["content-type"] = "application/json"
      req["authorization"] = "Bearer #{@license}" if @license && !@license.empty?
      req.body = JSON.generate(body)
      res = Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == "https") { |h| h.request(req) }
      code = res.code.to_i
      return JSON.parse(res.body) if code == 200
      raise "dispatch: 402 payment required (x402) — pay and retry, or set a license" if code == 402

      err = (JSON.parse(res.body)["error"] rescue res.body)
      raise "dispatch: status #{code}: #{err}"
    end
  end
end

if __FILE__ == $PROGRAM_NAME
  c = Dispatch::Client.new(ENV["WAVE_LICENSE"])
  d = c.route("find the auth handler")
  puts "route=#{d['route']} prob=#{d['probability']} forward=#{d['forward']}"
end
