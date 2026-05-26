// wave Dispatch — JS/TS client for the edge API. Route each request to the cheapest capable model
// (local-first; escalate to your frontier model only when needed). Your keys + infra stay yours.
const DEFAULT_ENDPOINT = "https://dispatch.wave.online";

export class Dispatch {
  /** @param {string} [license] Bearer license key (wv_...); omit for x402 pay-per-use. */
  constructor(license, { endpoint = DEFAULT_ENDPOINT, fetchImpl } = {}) {
    this.license = license;
    this.endpoint = endpoint.replace(/\/+$/, "");
    this.fetch = fetchImpl || globalThis.fetch;
  }
  /** Classify a prompt (no execution). */
  route(prompt) { return this._post({ prompt }); }
  /** Classify and run on the edge if your plan allows it. */
  execute(prompt) { return this._post({ prompt, execute: true }); }
  /** Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest). */
  routeVector(vector) { return this._post({ vector }); }

  async _post(body) {
    const r = await this.fetch(this.endpoint + "/", {
      method: "POST",
      headers: { "content-type": "application/json", ...(this.license ? { authorization: "Bearer " + this.license } : {}) },
      body: JSON.stringify(body),
    });
    if (r.status === 402) throw new Error("dispatch: 402 payment required (x402) — pay and retry, or set a license");
    if (!r.ok) { const e = await r.json().catch(() => ({})); throw new Error(`dispatch: ${r.status} ${e.error || ""}`); }
    return r.json();
  }
}
export default Dispatch;
