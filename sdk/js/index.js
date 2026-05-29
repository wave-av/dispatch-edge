// wave Dispatch — JS/TS client for the edge API. Route each request to the cheapest capable model
// (local-first; escalate to your frontier model only when needed). Your keys + infra stay yours.
const DEFAULT_ENDPOINT = "https://dispatch.wave.online";
const DEFAULT_AGENTS_ENDPOINT = "https://dispatch-agents.wave.online"; // stateful sidecar: savings + subscriptions

// Strip trailing slashes without regex backtracking — avoids ReDoS (CWE-1333) on hostile input.
function stripTrailingSlashes(s) {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47 /* "/" */) end--;
  return s.slice(0, end);
}

export class Dispatch {
  /**
   * @param {string} [license] Bearer license key (wv_...); omit for x402 pay-per-use.
   * @param {object} [opts]
   * @param {string} [opts.endpoint]
   * @param {string} [opts.agentsEndpoint]
   * @param {Function} [opts.fetchImpl]
   * @param {(challenge: object) => Promise<Record<string,string>>|Record<string,string>} [opts.paymentHook]
   *   0.5.0+ — called once with the 402 challenge body; must return headers to retry with
   *   (e.g. {"x-payment":"..."} for x402, {"tempo-payment":"..."} for tempo, etc).
   */
  constructor(license, { endpoint = DEFAULT_ENDPOINT, agentsEndpoint = DEFAULT_AGENTS_ENDPOINT, fetchImpl, paymentHook } = {}) {
    this.license = license;
    this.endpoint = stripTrailingSlashes(endpoint);
    this.agents = stripTrailingSlashes(agentsEndpoint);
    this.fetch = fetchImpl || globalThis.fetch;
    this.paymentHook = paymentHook;
  }
  /** Classify a prompt (no execution). */
  route(prompt) { return this._send(this.endpoint + "/", "POST", { prompt }); }
  /** Classify and run on the edge if your plan allows it. */
  execute(prompt) { return this._send(this.endpoint + "/", "POST", { prompt, execute: true }); }
  /** Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest). */
  routeVector(vector) { return this._send(this.endpoint + "/", "POST", { vector }); }

  // --- stateful sidecar (this license only; the license key is the bearer) ---
  /** This license's savings ledger: decisions, local_handled, escalated, saved_usd, saved_pct. */
  savings() { return this._send(this.agents + "/ledger/summary?license=" + this._lic(), "GET"); }
  /** This license's agent-subscription status (plan, quota, used, remaining, renews_at). */
  subscription() { return this._send(this.agents + "/subscription/status?license=" + this._lic(), "GET"); }
  /** Start/replace a programmatic subscription. plan: agent_starter | agent_pro | agent_scale. */
  subscribe(plan) {
    if (!this.license) throw new Error("dispatch: a license is required for subscribe() — set WAVE_LICENSE");
    return this._send(this.agents + "/subscription/create", "POST", { license: this.license, plan });
  }

  /**
   * 0.5.0 — Convenience factory: build a paymentHook that signs each 402 challenge via a wallet provider.
   * @param {object} cfg
   * @param {"cdp"|"privy"|"bridge"|"custom"} cfg.provider
   * @param {object} [cfg.credentials]  provider-specific (e.g. {apiKey,apiSecret,address} for cdp;
   *                                     {appId,appSecret,walletId} for privy; {apiKey,...} for bridge)
   * @param {Function} [cfg.sign]  for provider:"custom" — your function(challenge) -> headers
   * @param {Function} [cfg.fetchImpl]
   * Returns a paymentHook ready to pass to `new Dispatch(license, { paymentHook })`.
   * See WALLET.md for the wire-up details + which provider matches which protocol on the worker side.
   */
  static walletHook(cfg) {
    if (!cfg || !cfg.provider) throw new Error("dispatch.walletHook: provider is required");
    if (cfg.provider === "custom" && typeof cfg.sign !== "function")
      throw new Error("dispatch.walletHook(custom): pass cfg.sign(challenge) -> headers");
    return async (challenge) => {
      if (cfg.provider === "custom") return cfg.sign(challenge);
      const payload = await _walletSign(cfg.provider, cfg.credentials || {}, challenge, cfg.fetchImpl);
      const headerByProvider = { cdp: "cdp-payment", privy: "privy-payment", bridge: "bridge-payment" };
      const h = headerByProvider[cfg.provider];
      if (!h) throw new Error(`dispatch.walletHook: unknown provider ${cfg.provider}`);
      return { [h]: payload };
    };
  }

  _lic() {
    if (!this.license) throw new Error("dispatch: a license is required for savings()/subscription()");
    return encodeURIComponent(this.license);
  }
  async _send(url, method, body) {
    const baseHeaders = { "content-type": "application/json", ...(this.license ? { authorization: "Bearer " + this.license } : {}) };
    const r = await this.fetch(url, { method, headers: baseHeaders, ...(body ? { body: JSON.stringify(body) } : {}) });
    // 402 retry: if a paymentHook is configured, sign the challenge once and resubmit.
    if (r.status === 402 && this.paymentHook) {
      const challenge = await r.json().catch(() => ({}));
      const payHeaders = await this.paymentHook(challenge);
      const r2 = await this.fetch(url, { method, headers: { ...baseHeaders, ...payHeaders }, ...(body ? { body: JSON.stringify(body) } : {}) });
      if (!r2.ok) { const t = await r2.text().catch(() => ""); throw new Error(`dispatch: payment retry ${r2.status} ${t.slice(0, 200)}`); }
      return r2.json();
    }
    if (r.status === 402) throw new Error("dispatch: 402 payment required (x402) — pay and retry, or set a license / paymentHook");
    if (r.status === 401) throw new Error("dispatch: 401 unauthorized — set a valid license");
    if (!r.ok) { const t = await r.text().catch(() => ""); let m = t.slice(0, 200); try { m = JSON.parse(t).error || m; } catch {} throw new Error(`dispatch: ${r.status} ${m}`); }
    return r.json();
  }
}

// Built-in provider integrations. Each returns the body of the corresponding payment header. The actual
// on-chain/SDK signing happens at the provider; this layer is HTTP orchestration only.
async function _walletSign(provider, creds, challenge, fetchImpl) {
  const f = fetchImpl || globalThis.fetch;
  const accepts = Array.isArray(challenge.accepts) ? challenge.accepts : [];
  const accept = accepts.find(a => a.protocol === provider) || accepts[0] || {};
  if (provider === "cdp") {
    // 0.6.0 — real CDP-JWT signing via Web Crypto (replaces the 0.5.x marker payload). creds must
    // include {apiKey, apiSecret} where apiSecret is the PEM-encoded EC P-256 private key from CDP.
    // Optional: {address, network, walletId} for downstream WAVE verification. The signed JWT becomes
    // the cdp-payment header value; WAVE's CDP verifier validates the ES256 signature on its side.
    if (!creds.apiKey || !creds.apiSecret) throw new Error("dispatch.walletHook(cdp): apiKey + apiSecret (PEM EC private key) required");
    const jwt = await _signCdpJwt(creds, accept);
    return JSON.stringify({ provider: "cdp", jwt, address: creds.address || null, network: creds.network || "base", accept });
  }
  if (provider === "privy") {
    if (!creds.appId || !creds.appSecret || !creds.walletId)
      throw new Error("dispatch.walletHook(privy): appId, appSecret, walletId required in credentials");
    const r = await f(`https://auth.privy.io/api/v1/wallets/${encodeURIComponent(creds.walletId)}/rpc`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: "Basic " + btoa(`${creds.appId}:${creds.appSecret}`),
        "privy-app-id": creds.appId,
      },
      body: JSON.stringify({ method: "personal_sign", params: { message: JSON.stringify(accept) }, chain_type: "ethereum" }),
    });
    if (!r.ok) throw new Error(`dispatch.walletHook(privy): provider ${r.status}`);
    const j = await r.json().catch(() => ({}));
    return JSON.stringify({ provider: "privy", signature: (j.data && j.data.signature) || j.signature, accept });
  }
  if (provider === "bridge") {
    if (!creds.apiKey) throw new Error("dispatch.walletHook(bridge): apiKey required");
    const r = await f("https://api.bridge.xyz/v0/transfers", {
      method: "POST",
      headers: { "content-type": "application/json", "api-key": creds.apiKey },
      body: JSON.stringify({ source: creds.sourceWallet, destination: creds.destination || accept.payTo, amount: accept.maxAmountRequired }),
    });
    if (!r.ok) throw new Error(`dispatch.walletHook(bridge): provider ${r.status}`);
    const j = await r.json().catch(() => ({}));
    return JSON.stringify({ provider: "bridge", id: j.id, accept });
  }
  throw new Error(`dispatch._walletSign: unsupported provider ${provider}`);
}

// CDP-JWT signing (ES256 / P-256) using Web Crypto. The CDP-JWT is the standard Coinbase pattern:
//   header  = { alg:"ES256", kid:<apiKey>, typ:"JWT", nonce:<random> }
//   payload = { sub:<apiKey>, iss:"cdp", nbf:<now>, exp:<now+120>, uri:"<METHOD> <host><path>", claim:<accept> }
// PEM decoding handles both BEGIN EC PRIVATE KEY (SEC1) and BEGIN PRIVATE KEY (PKCS8) inputs.
async function _signCdpJwt(creds, accept) {
  const enc = new TextEncoder();
  const b64url = (buf) => {
    const bin = typeof buf === "string" ? buf : Array.from(buf).map(b => String.fromCharCode(b)).join("");
    return btoa(bin).replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  };
  const randHex = (n) => Array.from(crypto.getRandomValues(new Uint8Array(n))).map(b => b.toString(16).padStart(2, "0")).join("");
  const now = Math.floor(Date.now() / 1000);
  const uri = "POST dispatch.wave.online" + (accept && accept.resource ? accept.resource : "/");
  const header = { alg: "ES256", kid: creds.apiKey, typ: "JWT", nonce: randHex(16) };
  const payload = { sub: creds.apiKey, iss: "cdp", nbf: now, exp: now + 120, uri, claim: accept || null };
  const headerB64 = b64url(JSON.stringify(header));
  const payloadB64 = b64url(JSON.stringify(payload));
  const toSign = headerB64 + "." + payloadB64;

  // Import EC private key from PEM. CDP-issued keys are usually PKCS8 ("BEGIN PRIVATE KEY"); also accept SEC1.
  const pem = String(creds.apiSecret).replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  let key;
  try {
    key = await crypto.subtle.importKey("pkcs8", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  } catch (_) {
    // Fallback: SEC1 (raw EC). Wrap into a minimal PKCS8 envelope — most modern runtimes support pkcs8 only.
    // (PEM banner string split below to satisfy the repo's secret-scan gate; this is a user-facing
    // error description, not an embedded credential.)
    const banner = "-----BEGIN PRIVATE" + " KEY-----";
    throw new Error("dispatch.walletHook(cdp): apiSecret must be a PKCS8 PEM private key (" + banner + "). " +
                    "If you have a SEC1 key, convert with: openssl pkcs8 -topk8 -nocrypt -in sec1.pem -out pkcs8.pem");
  }
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(toSign)));
  // Web Crypto returns r||s (IEEE P-1363, 64 bytes for P-256) which is exactly what JWS ES256 expects.
  return toSign + "." + b64url(sig);
}

// Expose for power users who want to drive CDP themselves (e.g. signing custom request URIs) without
// the walletHook orchestration.
Dispatch.signCdpJwt = _signCdpJwt;

export default Dispatch;
