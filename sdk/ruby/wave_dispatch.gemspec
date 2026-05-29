Gem::Specification.new do |s|
  s.name        = "wave-dispatch"
  s.version     = "0.6.3"
  s.summary     = "wave Dispatch — local-first AI router client"
  s.description = "Route each request to the cheapest capable model (local-first; escalate to your frontier only when needed). BYO keys + infra."
  s.authors     = ["WAVE Online, LLC"]
  s.homepage    = "https://dispatch.wave.online"
  s.license     = "MIT"
  s.files       = ["lib/wave_dispatch.rb"]
  s.require_paths = ["lib"]
  s.required_ruby_version = ">= 2.7"
  s.metadata    = { "source_code_uri" => "https://github.com/wave-av/dispatch-edge" }
end
