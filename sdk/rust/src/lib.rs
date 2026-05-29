//! wave Dispatch — thin Rust client. Route each request to the cheapest capable model (local-first;
//! escalate to your frontier only when needed). BYO keys + infra; the service returns a routing decision.
use serde_json::{json, Value};
use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};

/// 0.6.2 — CDP-JWT (ES256/P-256) signer. Uses the `p256` crate (added to dependencies). Pure Rust;
/// no openssl FFI. Header: {alg:'ES256', kid:<api_key>, typ:'JWT', nonce:<rand-hex16>}. Payload:
/// {sub:<api_key>, iss:'cdp', nbf:<now>, exp:<now+120>, uri:'POST dispatch.wave.online<resource>', claim:<accept>}.
/// p256's ECDSA signer returns r||s as a Signature; we serialize to raw 32+32 (IEEE P-1363) — the JWS
/// ES256 spec representation — then base64url-encode the three parts.
pub fn sign_cdp_jwt(api_key: &str, pem_secret: &str, accept: &Value) -> Result<String, Box<dyn Error>> {
    use base64::Engine;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as i64;
    // 16 random bytes → 32 hex chars (uses rand from p256/sec1 transitive)
    let mut nonce_bytes = [0u8; 16];
    {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut nonce_bytes);
    }
    let nonce = nonce_bytes.iter().fold(String::with_capacity(32), |mut s, b| { use std::fmt::Write; let _ = write!(s, "{:02x}", b); s });
    let resource = accept.get("resource").and_then(|v| v.as_str()).unwrap_or("/");
    let uri = format!("POST dispatch.wave.online{}", resource);
    let header = json!({ "alg": "ES256", "kid": api_key, "typ": "JWT", "nonce": nonce });
    let payload = json!({ "sub": api_key, "iss": "cdp", "nbf": now, "exp": now + 120, "uri": uri, "claim": accept });
    let b64 = |s: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
    let to_sign = format!("{}.{}", b64(header.to_string().as_bytes()), b64(payload.to_string().as_bytes()));

    let key = SigningKey::from_pkcs8_pem(pem_secret)
        .map_err(|e| format!("dispatch::sign_cdp_jwt: PEM parse failed ({}); api_secret must be a PKCS8 EC P-256 private key", e))?;
    let sig: Signature = key.sign(to_sign.as_bytes());
    Ok(format!("{}.{}", to_sign, b64(sig.to_bytes().as_slice())))
}

/// 0.5.1 — payment hook: called once with the 402 challenge body, returns headers to retry the
/// request with (e.g. `{"x-payment": "..."}` for x402, `{"tempo-payment": "..."}` for tempo). Pair with
/// `Dispatch::wallet_hook(provider, credentials)` for the built-in CDP / Privy / Bridge factories, or
/// build a closure yourself for any custom wallet stack.
pub type PaymentHook =
    Box<dyn Fn(&Value) -> Result<HashMap<String, String>, Box<dyn Error>> + Send + Sync>;

pub struct Dispatch {
    license: Option<String>,
    endpoint: String,
    agents: String,
    payment_hook: Option<PaymentHook>,
}

impl Dispatch {
    /// `license`: your `wv_...` key, or `None` to read `WAVE_LICENSE` (omit for x402 pay-per-use).
    pub fn new(license: Option<String>) -> Self {
        Dispatch {
            license: license.or_else(|| std::env::var("WAVE_LICENSE").ok()),
            endpoint: std::env::var("DISPATCH_ENDPOINT").unwrap_or_else(|_| "https://dispatch.wave.online".into()),
            agents: std::env::var("WAVE_AGENTS_ENDPOINT").unwrap_or_else(|_| "https://dispatch-agents.wave.online".into()),
            payment_hook: None,
        }
    }

    /// 0.5.1 — attach a payment hook so 402 challenges are handled inside the client (signs + retries
    /// in one .route() call). See `Dispatch::wallet_hook` for the built-in factory.
    pub fn with_payment_hook(mut self, hook: PaymentHook) -> Self {
        self.payment_hook = Some(hook);
        self
    }

    /// Classify a prompt (no execution): `{route, probability, margin, forward}`.
    pub fn route(&self, prompt: &str) -> Result<Value, Box<dyn Error>> {
        self.post(&self.endpoint, json!({ "prompt": prompt }))
    }

    /// Classify and run on the edge if your plan allows it.
    pub fn execute(&self, prompt: &str) -> Result<Value, Box<dyn Error>> {
        self.post(&self.endpoint, json!({ "prompt": prompt, "execute": true }))
    }

    /// Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest).
    pub fn route_vector(&self, vector: &[f32]) -> Result<Value, Box<dyn Error>> {
        self.post(&self.endpoint, json!({ "vector": vector }))
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

    /// 0.5.1 — Build a `PaymentHook` that signs each 402 challenge via a wallet provider.
    ///
    /// `provider`: `"cdp"` | `"privy"` | `"bridge"`. For custom wallets, build your own
    /// closure and pass it to `with_payment_hook` directly.
    /// `credentials`: provider-specific. CDP: `{api_key, api_secret, address}`. Privy: `{app_id,
    /// app_secret, wallet_id}`. Bridge: `{api_key, source_wallet, destination?}`.
    pub fn wallet_hook(provider: &str, credentials: HashMap<String, String>) -> Result<PaymentHook, Box<dyn Error>> {
        let p = provider.to_string();
        match p.as_str() {
            "cdp" | "privy" | "bridge" => {
                let header_name: &'static str = match p.as_str() {
                    "cdp"    => "cdp-payment",
                    "privy"  => "privy-payment",
                    "bridge" => "bridge-payment",
                    _ => unreachable!(),
                };
                let creds = credentials;
                let proto = p.clone();
                let hook: PaymentHook = Box::new(move |challenge: &Value| -> Result<HashMap<String, String>, Box<dyn Error>> {
                    let payload = wallet_sign(&proto, &creds, challenge)?;
                    let mut h = HashMap::new();
                    h.insert(header_name.to_string(), payload);
                    Ok(h)
                });
                Ok(hook)
            }
            other => Err(format!("dispatch::wallet_hook: unknown provider \"{}\"", other).into()),
        }
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
        let body_str = body.to_string();
        let req = self.auth(ureq::post(url).set("content-type", "application/json"));
        match req.send_string(&body_str) {
            Ok(r) => Ok(serde_json::from_str(&r.into_string()?)?),
            Err(ureq::Error::Status(402, r)) => self.retry_with_hook("POST", url, Some(&body_str), r),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn get(&self, url: &str) -> Result<Value, Box<dyn Error>> {
        let req = self.auth(ureq::get(url).set("content-type", "application/json"));
        match req.call() {
            Ok(r) => Ok(serde_json::from_str(&r.into_string()?)?),
            Err(ureq::Error::Status(402, r)) => self.retry_with_hook("GET", url, None, r),
            Err(e) => Err(Box::new(e)),
        }
    }

    fn retry_with_hook(&self, method: &str, url: &str, body: Option<&str>, r: ureq::Response) -> Result<Value, Box<dyn Error>> {
        let hook = self.payment_hook.as_ref()
            .ok_or("dispatch: 402 payment required (x402) — pay and retry, or set a license / payment_hook")?;
        let challenge: Value = serde_json::from_str(&r.into_string()?)?;
        let headers = hook(&challenge)?;
        let mut retry = if method == "POST" {
            self.auth(ureq::post(url).set("content-type", "application/json"))
        } else {
            self.auth(ureq::get(url).set("content-type", "application/json"))
        };
        for (k, v) in &headers {
            retry = retry.set(k, v);
        }
        let resp = if let Some(b) = body { retry.send_string(b)? } else { retry.call()? };
        Ok(serde_json::from_str(&resp.into_string()?)?)
    }
}

// Built-in provider sign — HTTP orchestration only; actual signing happens at the provider.
// CDP-JWT signing is non-trivial in pure Rust (needs P-256 ECDSA + JWT lib); the built-in returns a
// marker payload that the worker accepts via the wave-payments adapter (when WAVE_VERIFY_URL is set).
// For full on-chain CDP signing, build your own closure with the official Coinbase Rust SDK.
fn wallet_sign(provider: &str, creds: &HashMap<String, String>, challenge: &Value) -> Result<String, Box<dyn Error>> {
    let accepts = challenge.get("accepts").and_then(|a| a.as_array()).cloned().unwrap_or_default();
    let accept = accepts.iter().find(|a| a.get("protocol").and_then(|p| p.as_str()) == Some(provider))
        .or_else(|| accepts.first())
        .cloned()
        .unwrap_or(Value::Null);

    match provider {
        "cdp" => {
            // 0.6.2 — real CDP-JWT (ES256/P-256) signing via the `p256` crate (added to deps).
            let api_key = creds.get("api_key").ok_or("dispatch::wallet_hook(cdp): api_key required")?;
            let api_secret = creds.get("api_secret").ok_or("dispatch::wallet_hook(cdp): api_secret required (PEM EC private key)")?;
            let jwt = sign_cdp_jwt(api_key, api_secret, &accept)?;
            Ok(json!({
                "provider": "cdp",
                "jwt": jwt,
                "address": creds.get("address"),
                "network": creds.get("network").map(|s| s.as_str()).unwrap_or("base"),
                "accept": accept
            }).to_string())
        },
        "privy" => {
            let app_id = creds.get("app_id").ok_or("dispatch::wallet_hook(privy): app_id required")?;
            let app_secret = creds.get("app_secret").ok_or("dispatch::wallet_hook(privy): app_secret required")?;
            let wallet_id = creds.get("wallet_id").ok_or("dispatch::wallet_hook(privy): wallet_id required")?;
            use base64::Engine;
            let basic = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", app_id, app_secret).as_bytes());
            let body = json!({ "method": "personal_sign", "params": { "message": accept.to_string() }, "chain_type": "ethereum" }).to_string();
            let url = format!("https://auth.privy.io/api/v1/wallets/{}/rpc", urlencoding::encode(wallet_id));
            let resp = ureq::post(&url)
                .set("content-type", "application/json")
                .set("authorization", &format!("Basic {}", basic))
                .set("privy-app-id", app_id)
                .send_string(&body)?;
            let j: Value = serde_json::from_str(&resp.into_string()?)?;
            let sig = j.get("data").and_then(|d| d.get("signature")).or_else(|| j.get("signature")).cloned().unwrap_or(Value::Null);
            Ok(json!({ "provider": "privy", "signature": sig, "accept": accept }).to_string())
        }
        "bridge" => {
            let api_key = creds.get("api_key").ok_or("dispatch::wallet_hook(bridge): api_key required")?;
            let body = json!({
                "source": creds.get("source_wallet"),
                "destination": creds.get("destination").cloned().unwrap_or_else(|| accept.get("payTo").cloned().unwrap_or(Value::Null).as_str().map(String::from).unwrap_or_default()),
                "amount": accept.get("maxAmountRequired")
            }).to_string();
            let resp = ureq::post("https://api.bridge.xyz/v0/transfers")
                .set("content-type", "application/json")
                .set("api-key", api_key)
                .send_string(&body)?;
            let j: Value = serde_json::from_str(&resp.into_string()?)?;
            Ok(json!({ "provider": "bridge", "id": j.get("id"), "accept": accept }).to_string())
        }
        other => Err(format!("dispatch::wallet_sign: unsupported provider \"{}\"", other).into()),
    }
}
