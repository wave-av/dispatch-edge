//! wave Dispatch — thin Rust client. Route each request to the cheapest capable model (local-first;
//! escalate to your frontier only when needed). BYO keys + infra; the service returns a routing decision.
use serde_json::{json, Value};
use std::error::Error;

pub struct Dispatch {
    license: Option<String>,
    endpoint: String,
}

impl Dispatch {
    /// `license`: your `wv_...` key, or `None` to read `WAVE_LICENSE` (omit for x402 pay-per-use).
    pub fn new(license: Option<String>) -> Self {
        Dispatch {
            license: license.or_else(|| std::env::var("WAVE_LICENSE").ok()),
            endpoint: std::env::var("DISPATCH_ENDPOINT").unwrap_or_else(|_| "https://dispatch.wave.online".into()),
        }
    }

    /// Classify a prompt (no execution): `{route, probability, margin, forward}`.
    pub fn route(&self, prompt: &str) -> Result<Value, Box<dyn Error>> {
        self.post(json!({ "prompt": prompt }))
    }

    /// Classify and run on the edge if your plan allows it.
    pub fn execute(&self, prompt: &str) -> Result<Value, Box<dyn Error>> {
        self.post(json!({ "prompt": prompt, "execute": true }))
    }

    fn post(&self, body: Value) -> Result<Value, Box<dyn Error>> {
        let mut req = ureq::post(&self.endpoint).set("content-type", "application/json");
        if let Some(l) = &self.license {
            req = req.set("authorization", &format!("Bearer {}", l));
        }
        let resp = req.send_string(&body.to_string())?.into_string()?;
        Ok(serde_json::from_str(&resp)?)
    }
}
