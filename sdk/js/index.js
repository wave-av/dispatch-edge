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
    // Coinbase CDP Server Wallet — full CDP-JWT signing is non-trivial in plain JS. The recommended path
    // is provider:"custom" with @coinbase/coinbase-sdk. We return a marker so the worker (WAVE_VERIFY_URL
    // + WAVE_CDP=1) sees who's claiming what; verification still goes through WAVE's CDP service.
    return JSON.stringify({ provider: "cdp", address: creds.address || null, accept, hint: "use @coinbase/coinbase-sdk for CDP-JWT signing in production" });
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

export default Dispatch;
