//! wave Dispatch — thin Rust client. Route each request to the cheapest capable model (local-first;
//! escalate to your frontier only when needed). BYO keys + infra; the service returns a routing decision.
use serde_json::{json, Value};
use std::error::Error;

pub struct Dispatch {
    license: Option<String>,
    endpoint: String,
    agents: String,
}

impl Dispatch {
    /// `license`: your `wv_...` key, or `None` to read `WAVE_LICENSE` (omit for x402 pay-per-use).
    pub fn new(license: Option<String>) -> Self {
        Dispatch {
            license: license.or_else(|| std::env::var("WAVE_LICENSE").ok()),
            endpoint: std::env::var("DISPATCH_ENDPOINT").unwrap_or_else(|_| "https://dispatch.wave.online".into()),
            agents: std::env::var("WAVE_AGENTS_ENDPOINT").unwrap_or_else(|_| "https://dispatch-agents.wave.online".into()),
        }
    }

    /// Classify a prompt (no execution): `{route, probability, margin, forward}`.
    pub fn route(&self, prompt: &str) -> Result<Value, Box<dyn Error>> {
        self.post(&self.endpoint, json!({ "prompt": prompt }))
    }

    /// Classify and run on the edge if your plan allows it.
    pub fn execute(&self, prompt: &str) -> Result<Value, Box<dyn Error>> {
        self.post(&self.endpoint, json!({ "prompt": prompt, "execute": true }))
    }

    /// This license's savings ledger (decisions, saved_usd, saved_pct, ...). Requires a license.
    pub fn savings(&self) -> Result<Value, Box<dyn Error>> {
        self.get(&format!("{}/ledger/summary?license={}", self.agents, self.lic()?))
    }

    /// This license's agent-subscription status.
    pub fn subscription(&self) -> Result<Value, Box<dyn Error>> {
        self.get(&format!("{}/subscription/status?license={}", self.agents, self.lic()?))
    }

    /// Start/replace a programmatic subscription (plan: agent_starter|agent_pro|agent_scale).
    pub fn subscribe(&self, plan: &str) -> Result<Value, Box<dyn Error>> {
        self.post(&format!("{}/subscription/create", self.agents),
                  json!({ "license": self.license, "plan": plan }))
    }

    fn lic(&self) -> Result<String, Box<dyn Error>> {
        self.license.clone().ok_or_else(|| "dispatch: a license is required for savings()/subscription()".into())
    }

    fn auth(&self, mut req: ureq::Request) -> ureq::Request {
        if let Some(l) = &self.license {
            req = req.set("authorization", &format!("Bearer {}", l));
        }
        req
    }

    fn post(&self, url: &str, body: Value) -> Result<Value, Box<dyn Error>> {
        let req = self.auth(ureq::post(url).set("content-type", "application/json"));
        Ok(serde_json::from_str(&req.send_string(&body.to_string())?.into_string()?)?)
    }

    fn get(&self, url: &str) -> Result<Value, Box<dyn Error>> {
        let req = self.auth(ureq::get(url).set("content-type", "application/json"));
        Ok(serde_json::from_str(&req.call()?.into_string()?)?)
    }
}
