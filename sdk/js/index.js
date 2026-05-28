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
  /** @param {string} [license] Bearer license key (wv_...); omit for x402 pay-per-use. */
  constructor(license, { endpoint = DEFAULT_ENDPOINT, agentsEndpoint = DEFAULT_AGENTS_ENDPOINT, fetchImpl } = {}) {
    this.license = license;
    this.endpoint = stripTrailingSlashes(endpoint);
    this.agents = stripTrailingSlashes(agentsEndpoint);
    this.fetch = fetchImpl || globalThis.fetch;
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
    if (!this.license) throw new Error("dispatch: a license is required for subscribe() — set WAVE_LICENSE");   // CR/#3: fail-fast (was posting null)
    return this._send(this.agents + "/subscription/create", "POST", { license: this.license, plan });
  }

  _lic() {
    if (!this.license) throw new Error("dispatch: a license is required for savings()/subscription()");
    return encodeURIComponent(this.license);
  }
  async _send(url, method, body) {
    const r = await this.fetch(url, {
      method,
      headers: { "content-type": "application/json", ...(this.license ? { authorization: "Bearer " + this.license } : {}) },
      ...(body ? { body: JSON.stringify(body) } : {}),
    });
    if (r.status === 402) throw new Error("dispatch: 402 payment required (x402) — pay and retry, or set a license");
    if (r.status === 401) throw new Error("dispatch: 401 unauthorized — set a valid license");
    if (!r.ok) { const t = await r.text().catch(() => ""); let m = t.slice(0, 200); try { m = JSON.parse(t).error || m; } catch {} throw new Error(`dispatch: ${r.status} ${m}`); }
    return r.json();
  }
}
export default Dispatch;
