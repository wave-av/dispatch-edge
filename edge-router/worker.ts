// wave edge-router — the classifier router as a Cloudflare Worker, running INSIDE WAVE's own infra
// (Workers + KV). Routing happens at the global edge with zero server hop: embed via Cloudflare
// Workers AI, matmul against the bundled classifier weights (embed_router.json), return the route +
// calibrated probability. The cascade pattern still applies: low-margin -> forward to the origin
// (granite4) for the accurate decision; high-margin is answered at the edge in ~ms.
//
// IMPORTANT (honest): embed_router.json must be RETRAINED on the SAME embedder this Worker uses
// (@cf/baai/bge-base-en-v1.5, 768-dim) — a classifier's weights live in its embedder's vector space.
// The matmul/softmax below is embedder-agnostic and parity-tested against the Python impl.
import MODEL from "./embed_router.json";

interface Model { classes: string[]; coef: number[][]; intercept: number[]; }
const M = MODEL as Model;
const MARGIN = 0.20;                 // edge handles margin>=this; else forward to origin (cascade)

function normalize(v: number[]): number[] {
  const n = Math.sqrt(v.reduce((s, x) => s + x * x, 0)) || 1;
  return v.map((x) => x / n);
}

export function classify(vec: number[]): { route: string; probability: number; margin: number } {
  const x = normalize(vec);
  const logits = M.coef.map((row, i) => M.intercept[i] + row.reduce((s, c, j) => s + c * x[j], 0));
  const mx = Math.max(...logits);
  const exps = logits.map((l) => Math.exp(l - mx));
  const z = exps.reduce((s, e) => s + e, 0);
  const ranked = exps.map((e, i) => ({ p: e / z, c: M.classes[i] })).sort((a, b) => b.p - a.p);
  return { route: ranked[0].c, probability: ranked[0].p, margin: ranked[0].p - ranked[1].p };
}

// timing-safe compare (same pattern as the alert worker) — no early-exit on mismatch
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return mismatch === 0;
}
// FAIL-CLOSED: if ROUTER_TOKEN isn't configured, deny — a misconfig can NEVER leave AI spend open.
function authed(req: Request, env: any): boolean {
  const tok = env.ROUTER_TOKEN;
  if (!tok) return false;
  const h = req.headers.get("authorization") || "";
  return h.startsWith("Bearer ") && timingSafeEqual(h.slice(7), tok);
}

// x402 PAY-PER-USE (#62) — flag-gated (WAVE_X402=1), the HTTP-402 micropayment protocol Cloudflare
// co-founded. A request with no X-PAYMENT gets a 402 challenge (price/asset/recipient); the agent
// pays a stablecoin micro-amount and retries with X-PAYMENT. STUB: we don't yet verify settlement
// on-chain (that's #63 via a facilitator) — presence of X-PAYMENT is accepted. No real money moves.
// Multi-tenant licensing (#64): a bearer token is valid if it's the admin ROUTER_TOKEN (unlimited)
// OR a license key in the LICENSES KV (lic:<token> -> {plan, limit}). Returns the principal or null.
// Admin keeps working so existing tooling + the .env token are unaffected.
async function authorize(req: Request, env: any): Promise<any> {
  const h = req.headers.get("authorization") || "";
  if (!h.startsWith("Bearer ")) return null;
  const token = h.slice(7);
  if (env.ROUTER_TOKEN && timingSafeEqual(token, env.ROUTER_TOKEN)) return { token: "admin", plan: "admin", limit: Infinity };
  if (env.LICENSES) {
    const lic = await env.LICENSES.get("lic:" + token, { type: "json" });
    if (lic) return { token, plan: lic.plan || "pro", limit: lic.limit ?? 1000000 };
  }
  return null;
}
// Daily quota meter (#64): increments use:<token>:<YYYYMMDD>; enforced BEFORE any AI spend, so an
// over-quota request costs $0. KV daily counter — fine at this scale (DO/Analytics Engine for high-rate later).
async function meter(env: any, who: any): Promise<{ count: number; over: boolean }> {
  if (!env.LICENSES || who.limit === Infinity) return { count: 0, over: false };
  const day = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const key = `use:${who.token}:${day}`;
  const n = (parseInt((await env.LICENSES.get(key)) || "0") || 0) + 1;
  await env.LICENSES.put(key, String(n), { expirationTtl: 172800 });   // 2-day TTL, auto-clean
  return { count: n, over: n > who.limit };
}
// Per-minute burst guard (#107): rl:<token>:<minute> counter. FAIL-OPEN on KV error — a transient blip
// must not lock out a paying caller; the daily quota above stays fail-closed for cost protection.
const RPM_LIMITS: Record<string, number> = { starter: 120, pro: 600, scale: 1800, test: 5 };  // no free tier (anti-fraud)
async function rateLimit(env: any, who: any): Promise<{ over: boolean; limit: number; retry: number }> {
  if (!env.LICENSES || who.limit === Infinity) return { over: false, limit: 0, retry: 0 };   // admin unlimited
  const rpm = RPM_LIMITS[who.plan] ?? RPM_LIMITS.starter;
  const key = `rl:${who.token}:${Math.floor(Date.now() / 60000)}`;
  try {
    const n = (parseInt((await env.LICENSES.get(key)) || "0") || 0) + 1;
    await env.LICENSES.put(key, String(n), { expirationTtl: 120 });
    return { over: n > rpm, limit: rpm, retry: 60 - (Math.floor(Date.now() / 1000) % 60) };
  } catch { return { over: false, limit: rpm, retry: 0 }; }   // fail-open: never block legit traffic on a KV blip
}

// ---- Stripe checkout -> license issuance (#63) ----
async function hmacHex(secret: string, msg: string): Promise<string> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function verifyStripe(sigHeader: string, body: string, secret: string): Promise<boolean> {
  const parts = Object.fromEntries(sigHeader.split(",").map((s) => s.split("=")));
  if (!parts.t || !parts.v1) return false;
  if (Math.abs(Date.now() / 1000 - Number(parts.t)) > 300) return false;     // 5-min replay window
  return timingSafeEqual(parts.v1, await hmacHex(secret, `${parts.t}.${body}`));
}
const PLAN_LIMITS: Record<string, number> = { starter: 15000, pro: 50000, scale: 200000, test: 2 };  // no free tier (anti-fraud); card required
async function handleStripeWebhook(req: Request, env: any): Promise<Response> {
  const raw = await req.text();
  if (!env.STRIPE_WEBHOOK_SECRET || !(await verifyStripe(req.headers.get("stripe-signature") || "", raw, env.STRIPE_WEBHOOK_SECRET)))
    return new Response("bad signature", { status: 400 });            // FAIL-CLOSED: no/invalid secret -> reject
  const evt = JSON.parse(raw);
  if (evt.type !== "checkout.session.completed") return Response.json({ ok: true, ignored: evt.type });
  const s = evt.data.object;
  const plan = (s.metadata?.plan || "pro").toLowerCase();
  const key = "wv_" + crypto.randomUUID().replace(/-/g, "");          // the customer's license key
  const lic = { plan, limit: PLAN_LIMITS[plan] ?? PLAN_LIMITS.starter, email: s.customer_details?.email || null,
                stripe_customer: s.customer || null, created: new Date().toISOString() };
  await env.LICENSES.put("lic:" + key, JSON.stringify(lic));
  await env.LICENSES.put("sess:" + s.id, key, { expirationTtl: 86400 });  // success page can fetch the key by session
  return Response.json({ ok: true, issued: true, plan });             // (key itself shown via success page / email)
}

// Pay-per-use challenge (HTTP 402). Advertises every accepted rail in one `accepts[]` array so the
// agent picks: x402 (stablecoin, always on) + MPP (Stripe Machine Payments Protocol, when WAVE_MPP=1).
// `extra.settlement` is HONEST: "verified-via-facilitator" only when a facilitator URL is configured,
// otherwise "stub-not-verified" — we never imply money moved when it didn't.
function paymentChallenge(env: any, resource: string): Response {
  const accepts: any[] = [{
    scheme: "exact", protocol: "x402",
    network: env.X402_NETWORK || "base-sepolia",          // testnet default
    maxAmountRequired: env.X402_PRICE || "1000",          // atomic units; USDC 6dp 1000 = $0.001
    resource, description: "dispatch routing decision",
    mimeType: "application/json",
    payTo: env.X402_PAYTO || "0x0000000000000000000000000000000000000000",
    maxTimeoutSeconds: 60,
    asset: env.X402_ASSET || "0x036CbD53842c5426634e7929541eC2318f3dCF7e",  // USDC base-sepolia
    extra: { settlement: env.X402_FACILITATOR ? "verified-via-facilitator" : "stub-not-verified" },
  }];
  if (env.WAVE_MPP === "1" || env.WAVE_MPP === "true")  // Stripe MPP rail (flag-gated, header: Payment)
    accepts.push({
      scheme: "mpp", protocol: "mpp",
      maxAmountRequired: env.MPP_PRICE || env.X402_PRICE || "1000",
      resource, description: "dispatch routing decision",
      payTo: env.MPP_PAYTO || null, maxTimeoutSeconds: 60,
      extra: { settlement: env.MPP_FACILITATOR ? "verified-via-facilitator" : "rolling-out-not-verified" },
    });
  return Response.json({ x402Version: 1, error: "payment required", accepts }, { status: 402 });
}

// Settlement verification for pay-per-use. Returns {ok} — true only if the request carries a payment
// we accept. When a facilitator URL is set we REALLY verify settlement over HTTP; with no facilitator
// we fall back to the documented STUB (header present = accept) so the rail is demoable without moving
// real money. This is the honest #63 path: production-capable the moment creds exist, never faking.
async function verifyPayment(env: any, req: Request): Promise<{ ok: boolean; mode: string }> {
  const x402 = req.headers.get("x-payment");
  if (x402) {
    // WAVE settlement (the real rails): delegate to WAVE's on-chain x402 verify — USDC on Base,
    // amount + treasury-wallet checked there. X-PAYMENT carries JSON {tx_hash, session_id, product};
    // we forward it with a service token. Flag-gated by WAVE_VERIFY_URL; needs the WAVE service-auth
    // path (task #68 WAVE side). Shapes the request to WAVE's contract exactly (see x402/verify route).
    if (env.WAVE_VERIFY_URL) {
      try {
        const p = JSON.parse(x402);
        const r = await fetch(env.WAVE_VERIFY_URL.replace(/\/+$/, ""), {
          method: "POST",
          headers: { "content-type": "application/json", ...(env.WAVE_SERVICE_TOKEN ? { authorization: "Bearer " + env.WAVE_SERVICE_TOKEN } : {}) },
          body: JSON.stringify({ tx_hash: p.tx_hash, session_id: p.session_id, product: p.product || "llm_routing" }),
        });
        const j: any = await r.json().catch(() => ({}));
        return { ok: r.ok && j.verified === true, mode: "wave-verify" };        // WAVE confirms on-chain settlement
      } catch { return { ok: false, mode: "wave-error" }; }
    }
    if (!env.X402_FACILITATOR) return { ok: true, mode: "x402-stub" };          // no facilitator -> stub accept
    try {
      const r = await fetch(env.X402_FACILITATOR.replace(/\/+$/, "") + "/verify", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ x402Version: 1, paymentPayload: x402, resource: new URL(req.url).pathname }),
      });
      const j: any = await r.json().catch(() => ({}));
      return { ok: r.ok && (j.isValid === true || j.valid === true), mode: "x402-facilitator" };
    } catch { return { ok: false, mode: "x402-error" }; }
  }
  const mpp = req.headers.get("payment") || req.headers.get("x-mpp-payment");   // Stripe MPP
  if (mpp && (env.WAVE_MPP === "1" || env.WAVE_MPP === "true")) {
    if (!env.MPP_FACILITATOR) return { ok: true, mode: "mpp-stub" };
    try {
      const r = await fetch(env.MPP_FACILITATOR.replace(/\/+$/, "") + "/verify", {
        method: "POST",
        headers: { "content-type": "application/json", ...(env.MPP_API_KEY ? { authorization: "Bearer " + env.MPP_API_KEY } : {}) },
        body: JSON.stringify({ payment: mpp, resource: new URL(req.url).pathname }),
      });
      const j: any = await r.json().catch(() => ({}));
      return { ok: r.ok && j.verified === true, mode: "mpp-facilitator" };
    } catch { return { ok: false, mode: "mpp-error" }; }
  }
  return { ok: false, mode: "none" };
}

// Defensive headers for all HTML responses. These pages run ZERO JavaScript, so a strict CSP
// (default-src 'none', only inline styles allowed) is safe and blocks XSS/clickjacking/embedding.
const SEC_HEADERS: Record<string, string> = {
  "x-frame-options": "DENY",
  "referrer-policy": "no-referrer",
  "permissions-policy": "geolocation=(), camera=(), microphone=()",
  "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'",
};

// #111 edge-local execution: optionally RUN the classified route on a cheap Workers AI text-gen model
// at the edge (not just classify) — for customers with no local infra. Flag-gated (WAVE_EDGE_EXEC=1),
// output-token-capped to bound cost. COGS ~$0.0002/call (qwen3-30b $0.051/M in, $0.34/M out) so it's a
// higher-priced tier than matmul routing ($0.0001). Maps route -> best CF model for the job.
const EDGE_EXEC_MODELS: Record<string, string> = {
  local_code: "@cf/qwen/qwen2.5-coder-32b-instruct",
  claude_reason: "@cf/qwen/qwq-32b", reason: "@cf/qwen/qwq-32b",
  local_summarize: "@cf/qwen/qwen3-30b-a3b-fp8", direct: "@cf/qwen/qwen3-30b-a3b-fp8",
  local_search: "@cf/qwen/qwen3-30b-a3b-fp8",
};
async function executeAtEdge(env: any, route: string, prompt: string): Promise<{ model: string; answer: string }> {
  const model = EDGE_EXEC_MODELS[route] || "@cf/qwen/qwen3-30b-a3b-fp8";
  try {
    const out: any = await env.AI.run(model, { messages: [{ role: "user", content: String(prompt).slice(0, 8000) }], max_tokens: 512 });
    return { model, answer: (out?.response || "").trim() };
  } catch { return { model, answer: "" }; }   // exec failed; routing decision is still returned
}

// Public, static, $0 landing page — no env.AI call, no data, safe to be on the open internet.
const LANDING = `<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>wave Dispatch — local-first AI routing</title>
<style>
:root{--bg:#0b0f14;--fg:#cfe3f7;--dim:#5b7287;--acc:#43d9ad;--warn:#e6b450}
::selection{background:var(--acc);color:var(--bg)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;display:flex;min-height:100vh;
align-items:center;justify-content:center;padding:2rem}
.card{max-width:660px;width:100%}
h1{font-size:1.5rem;margin:0 0 .25rem;color:#fff;letter-spacing:.5px}
.sub{color:var(--dim);margin:0 0 1.5rem}
.acc{color:var(--acc)}.warn{color:var(--warn)}.dim{color:var(--dim)}
pre{background:#0e141b;border:1px solid #1c2733;border-radius:10px;padding:1rem 1.1rem;overflow:auto;
white-space:pre-wrap}
.row{display:flex;gap:.5rem;align-items:baseline;margin:.15rem 0}
.k{color:var(--acc);min-width:9.5rem}
.btn{display:inline-block;background:var(--acc);color:var(--bg);padding:.45rem 1rem;border-radius:8px;text-decoration:none;font-weight:600;margin:.3rem 0}
.btn:hover{filter:brightness(1.1)}
a{color:var(--acc)}@media(max-width:480px){pre{font-size:.68rem;line-height:1.45}body{padding:1.1rem}.row,.top{flex-wrap:wrap;gap:.3rem}}
.tag{display:inline-block;border:1px solid #1c2733;border-radius:999px;padding:.1rem .6rem;
color:var(--dim);font-size:.8rem;margin-right:.4rem}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem}
.top a{text-decoration:none;color:var(--dim)}
.foot{margin-top:1.8rem;border-top:1px solid #1c2733;padding-top:1rem;color:var(--dim);font-size:.85rem}
.foot a{margin-right:.4rem}
</style></head><body><div class="card">
<div class="top"><a href="/" style="text-decoration:none;color:#fff"><strong>wave <span class="acc">Dispatch</span></strong></a><a href="https://wave.online">wave.online ↗</a></div>
<h1>wave <span class="acc">Dispatch</span></h1>
<p class="sub">local-first AI dispatch — a serverless router that sends each request to the cheapest capable model, your infra + your keys.</p>
<div><span class="tag">tier 1 · local pool</span><span class="tag">tier 2 · local agent</span><span class="tag">tier 3 · your frontier model (rare)</span></div>
<pre>  prompt
    │
    ▼   embed @ edge · Workers AI (bge-base-en)
  classify ─▶ {route · confidence · margin}
    │
    ├─ local_code       ┐
    ├─ local_search     │  <span class="dim">$0 · runs on</span>
    ├─ local_summarize  ┤  <span class="dim">YOUR infra + keys</span>
    ├─ direct           │
    └─ reason           ┘
         │
         └─ low confidence ─▶ <span class="dim">escalate to your</span>
            <span class="dim">frontier model (Claude · GPT · Gemini)</span>
</pre>
<div class="row"><span class="k">classify</span><span><span class="dim">POST</span> <span class="acc">/</span> <span class="dim">{"prompt":"…"}</span> → {route, probability, margin}</span></div>
<div class="row"><span class="k">auth</span><span class="warn">Authorization: Bearer &lt;license-key&gt;</span></div>
<div class="row"><span class="k">health</span><span class="dim">GET /health</span></div>
<h2 style="font-size:1rem;margin:1.6rem 0 .5rem;color:#fff">pricing — you bring infra + keys, we run the edge</h2>
<div class="row"><span class="k acc">Starter</span><span><a href="https://pay.wave.online/b/aFacN5e1raG7csqfqf5EY09"><span class="warn">$9/mo</span></a> · 15k decisions / day · <span class="dim">free trial, card required — no anonymous tier (keeps fraud out)</span></span></div>
<div class="row"><span class="k acc">Pro</span><span><a href="https://pay.wave.online/b/4gMdR9g9zg0r6420vl5EY0a"><span class="warn">$29/mo</span></a> · 50k decisions / day · full orchestration (cost-gate · pool · eval-gate · dashboard)</span></div>
<div class="row"><span class="k acc">Scale</span><span><a href="https://pay.wave.online/b/bJebJ14qR01tbom2Dt5EY0b"><span class="warn">$99/mo</span></a> · 200k decisions / day · priority routing</span></div>
<div class="row"><span class="k acc">Enterprise</span><span>custom · self-managed · volume · SLA · support · <a href="https://wave.online">talk to us →</a></span></div>
<div class="row"><span class="k acc">Pay-per-use</span><span><span class="warn">$0.0001</span>/decision via x402 · <span class="dim">raw routing, agent micropayments, no account</span></span></div>
<div class="row"><span class="k acc">Dispatch+</span><span><span class="warn">$0.0005</span>/decision · <span class="dim">full orchestration — pool · verify-gate · edge execution · savings ledger</span></span></div>
<div class="row" style="margin-top:.8rem"><a class="btn" href="https://pay.wave.online/b/aFacN5e1raG7csqfqf5EY09">Start free trial — Starter $9/mo →</a></div>
<div class="row"><span class="dim">WAVE customers: enter code <span class="acc">WAVE</span> at checkout for 30% off.</span></div>
<div class="row"><span class="k">payments</span><span class="dim">cards · Apple&nbsp;Pay · Google&nbsp;Pay (Stripe) <span class="acc">·</span> x402 stablecoin for agents <span class="acc">·</span> <span class="warn">MPP &amp; ACP rolling out</span></span></div>
<p class="sub" style="margin-top:1.4rem"><span class="acc">BYOK</span> — your API keys + data + inference stay on your infra. We only ever return a routing decision.</p>
<footer class="foot">
<a href="/about">about</a> · <a href="/status">status</a> · <a href="/docs">docs</a> · <a href="/transparency">data &amp; privacy</a> · <a href="/llms.txt">llms.txt</a> · <a href="https://wave.online">← wave.online</a>
<div style="margin-top:.5rem">a <a href="https://wave.online">WAVE</a> product · local-first by design</div>
</footer>
</div></body></html>`;

function transparencyHtml(m: any): string {
  const li = (xs: string[]) => xs.map((x) => `<li>${x}</li>`).join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>wave Dispatch — data &amp; privacy</title>
<style>
:root{--bg:#0b0f14;--fg:#cfe3f7;--dim:#5b7287;--acc:#43d9ad;--warn:#e6b450}
::selection{background:var(--acc);color:var(--bg)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;display:flex;min-height:100vh;
align-items:center;justify-content:center;padding:2rem}
.card{max-width:680px;width:100%}h1{font-size:1.4rem;margin:0 0 .25rem;color:#fff}
.sub{color:var(--dim);margin:0 0 1.4rem}.acc{color:var(--acc)}.warn{color:var(--warn)}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem}
a{color:var(--acc)}@media(max-width:480px){pre{font-size:.68rem;line-height:1.45}body{padding:1.1rem}.row,.top{flex-wrap:wrap;gap:.3rem}}.top a{text-decoration:none;color:var(--dim)}
.box{background:#0e141b;border:1px solid #1c2733;border-radius:10px;padding:1rem 1.1rem;margin:.7rem 0}
.box h3{margin:0 0 .4rem;font-size:.95rem;color:#fff}ul{margin:.3rem 0 0;padding-left:1.2rem}
.good{color:var(--acc)}.foot{margin-top:1.6rem;border-top:1px solid #1c2733;padding-top:1rem;color:var(--dim);font-size:.85rem}
.foot a{margin-right:.4rem}
</style></head><body><div class="card">
<div class="top"><a href="/" style="text-decoration:none;color:#fff"><strong>wave <span class="acc">Dispatch</span></strong></a><a href="https://wave.online">wave.online ↗</a></div>
<h1>data &amp; privacy</h1>
<p class="sub">${m.role}. The trust contract — verify it programmatically at <a href="/transparency?format=json">/transparency?format=json</a>.</p>
<div class="box"><h3>What the edge sees</h3>${m.data_policy.sees}</div>
<div class="box"><h3>What we log</h3><ul>${li(m.data_policy.logs)}</ul></div>
<div class="box"><h3 class="good">What we NEVER log</h3><ul>${li(m.data_policy.never_logs)}</ul></div>
<div class="box"><h3>Where your data lives</h3>${m.data_policy.data_plane}</div>
<div class="box"><h3>Using your data to improve</h3>
<p><span class="acc">Default:</span> ${m.data_use.default}</p>
<p><span class="acc">Self-improvement:</span> ${m.data_use.self_improvement}</p>
<p><span class="acc">Opt-in:</span> ${m.data_use.opt_in}</p></div>
<p class="sub">edge model: ${m.edge_model} · ${m.source}</p>
<footer class="foot"><a href="/">dispatch</a> · <a href="/about">about</a> · <a href="/status">status</a> · <a href="/docs">docs</a> · <a href="/transparency">data &amp; privacy</a> · <a href="/llms.txt">llms.txt</a> · <a href="https://wave.online">← wave.online</a>
<div style="margin-top:.5rem">a <a href="https://wave.online">WAVE</a> product · local-first by design</div></footer>
</div></body></html>`;
}

// Favicon: the real WAVE curled-wave mark, recolored to the solid dispatch teal (#43d9ad), no gradient.
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 102"><title>wave Dispatch</title><g transform="translate(-55.797,177.088) scale(0.024,-0.024)" fill="#43d9ad" stroke="none"><path d="M5055 7373 c-222 -26 -372 -59 -559 -123 -542 -184 -1021 -519 -1397 -980 -438 -535 -683 -1114 -761 -1795 -24 -207 -13 -775 14 -775 16 0 217 123 368 224 359 241 729 567 1156 1017 466 491 757 732 1081 897 247 126 458 178 683 169 277 -11 487 -99 680 -284 194 -184 305 -402 333 -650 38 -343 -148 -743 -438 -943 -262 -180 -592 -170 -791 25 -141 140 -188 357 -125 582 25 86 99 256 135 309 14 21 24 39 22 41 -6 7 -129 -83 -203 -149 -177 -156 -306 -352 -369 -563 -24 -79 -28 -107 -28 -230 0 -160 13 -220 74 -352 124 -265 364 -476 660 -581 155 -55 236 -67 435 -66 150 0 196 4 274 22 291 69 536 208 762 432 301 297 482 651 560 1095 19 105 23 167 23 325 1 259 -25 431 -100 680 -83 272 -251 577 -453 820 -434 523 -1196 868 -1896 858 -60 0 -123 -3 -140 -5z"/></g></svg>`;

const LLMS_TXT = `# wave Dispatch
> Local-first AI dispatch — routes each LLM request to the cheapest capable model. Bring your own
> infra and API keys (BYOK); the service only ever returns a routing decision, never your data.

## What it does
Classifies a prompt at the edge and returns which model tier should handle it (local_code,
local_search, local_summarize, direct, or escalate to your frontier model). Cuts your LLM bill by
keeping work on the cheapest capable tier.

## API
- POST /  body {"prompt":"..."}  header  Authorization: Bearer <license-key>
  -> {route, probability, margin, decided_at, forward}
- GET /transparency   data & privacy policy (append ?format=json for machine-readable)
- GET /health   -> ok
- Pay-per-use agents: a request without payment returns HTTP 402 (x402) with payment requirements.

## Pricing
- Free: 10000 routing decisions/day ($0)
- Pro: $29/mo, 100,000 decisions/day, full orchestration
- Pay-per-use: $0.0001/decision via x402 (stablecoin micropayments, no account)

## Data policy
Private by default for everyone. Your API keys, data, and inference stay on YOUR infrastructure.
We never log prompt content, your data, your keys, or model outputs.

## Links
- Home: https://wave.online
- Transparency (JSON): /transparency?format=json
`;

// Shared page shell — consistent header + footer + style for /status, /docs (and future pages).
function shell(title: string, inner: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="icon" href="/favicon.svg" type="image/svg+xml">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>wave Dispatch — ${title}</title><style>
body{margin:0;background:#0b0f14;color:#cfe3f7;font:15px/1.6 ui-monospace,Menlo,monospace;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:2rem}
::selection{background:#43d9ad;color:#0b0f14}
.card{max-width:640px;width:100%}h1{font-size:1.3rem;margin:0 0 .25rem;color:#fff}
.sub{color:#5b7287;margin:.2rem 0 1.2rem}.good{color:#43d9ad}.warn{color:#e6b450}.dim{color:#5b7287}a{color:#43d9ad}@media(max-width:480px){pre{font-size:.68rem;line-height:1.45}body{padding:1.1rem}.row,.top,.r{flex-wrap:wrap;gap:.3rem}}
.top{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem}.top a{text-decoration:none;color:#5b7287}
.box{background:#0e141b;border:1px solid #1c2733;border-radius:10px;padding:.8rem 1rem;margin:.6rem 0}
.r{display:flex;gap:.6rem;margin:.2rem 0}.kk{color:#43d9ad;min-width:8rem}
.foot{margin-top:1.6rem;border-top:1px solid #1c2733;padding-top:1rem;color:#5b7287;font-size:.85rem}.foot a{margin-right:.5rem}
</style></head><body><div class="card">
<div class="top"><a href="/" style="text-decoration:none;color:#fff"><strong>wave <span class="good">Dispatch</span></strong></a><a href="https://wave.online">wave.online ↗</a></div>
${inner}
<footer class="foot"><a href="/">dispatch</a> · <a href="/about">about</a> · <a href="/quickstart">quickstart</a> · <a href="/status">status</a> · <a href="/docs">docs</a> · <a href="/transparency">data &amp; privacy</a> · <a href="https://wave.online">← wave.online</a></footer>
</div></body></html>`;
}

function successHtml(key: string | null): string {
  const body = key
    ? `<h1 class="good">✓ you're in</h1><p class="sub">Your wave Dispatch license key — store it securely, it authorizes your edge calls.</p>
       <div class="box"><code>${key}</code></div>
       <p class="sub">Use it: <code>Authorization: Bearer ${key}</code> on POST <a href="/">dispatch.wave.online</a>, or as <code>WAVE_LICENSE</code> for the proxies. See <a href="https://wave.online">wave.online</a>.</p>`
    : `<h1>payment received</h1><p class="sub">Your license key is being issued — refresh this page in a few seconds. If it doesn't appear, contact support via <a href="https://wave.online">wave.online</a>.</p>`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><link rel="icon" href="/favicon.svg" type="image/svg+xml"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>wave Dispatch — welcome</title><style>
body{margin:0;background:#0b0f14;color:#cfe3f7;font:15px/1.6 ui-monospace,Menlo,monospace;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:2rem}
::selection{background:#43d9ad;color:#0b0f14}
.card{max-width:600px}.sub{color:#5b7287}.good{color:#43d9ad}a{color:#43d9ad}
.box{background:#0e141b;border:1px solid #1c2733;border-radius:10px;padding:1rem;margin:.8rem 0;word-break:break-all}
code{color:#e6b450}</style></head><body><div class="card">${body}
<p class="sub" style="margin-top:1.5rem">a <a href="https://wave.online">WAVE</a> product</p></div></body></html>`;
}

export default {
  async fetch(req: Request, env: any): Promise<Response> {
    const url = new URL(req.url); const path = url.pathname;
    if (path === "/health") return new Response("ok");
    if (req.method === "GET") {
      if (path === "/key" && env.LICENSES) {       // machine: fetch the issued key by session id (JSON)
        const key = await env.LICENSES.get("sess:" + (url.searchParams.get("session") || ""));
        return key ? Response.json({ license_key: key }) : Response.json({ error: "not found" }, { status: 404 });
      }
      if (path === "/success") {                   // human: post-checkout page showing the license key
        const key = env.LICENSES ? await env.LICENSES.get("sess:" + (url.searchParams.get("session") || "")) : null;
        return new Response(successHtml(key), { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      }
      if (path === "/status") {                    // REAL status: probe deps live on each load (/health stays plain for monitors)
        const colo = (req as any).cf?.colo || "edge";
        const ver = env.CF_VERSION_METADATA?.id || "live";
        let aiOk = false, kvOk = false;
        try { const e = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text: ["ping"] }); aiOk = Array.isArray(e?.data?.[0]); } catch {}
        try { await env.LICENSES.get("__status_probe__"); kvOk = true; } catch {}   // a successful read (even null) means KV is up
        const all = aiOk && kvOk;
        if (url.searchParams.get("format") === "json" || (req.headers.get("accept") || "").includes("application/json"))
          return Response.json({ operational: all, checks: { edge_embed: aiOk, classifier: aiOk, licensing_kv: kvOk },
            colo, version: ver, checked: new Date().toISOString() }, { headers: { "cache-control": "no-store" } });
        const dot = (ok: boolean) => ok ? '<span class="good">● operational</span>' : '<span class="warn">● degraded</span>';
        return new Response(shell("status", `<h1 class="${all ? "good" : "warn"}">● ${all ? "all systems operational" : "degraded — a check is failing"}</h1>
<p class="sub">Live checks, run on every load. Your inference runs on your infra; this covers the edge decision layer.</p>
<div class="box"><div class="r"><span class="kk">edge embed (Workers AI)</span> ${dot(aiOk)}</div>
<div class="r"><span class="kk">classifier</span> ${dot(aiOk)}</div>
<div class="r"><span class="kk">licensing / metering (KV)</span> ${dot(kvOk)}</div>
<div class="r"><span class="kk">served from</span> ${colo}</div>
<div class="r"><span class="kk">version</span> ${ver}</div>
<div class="r"><span class="kk">checked</span> ${new Date().toISOString()}</div>
<div class="r"><span class="kk">machine-readable</span> <a href="/health">/health</a> · <a href="/status?format=json">/status?format=json</a></div></div>`),
          { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...SEC_HEADERS } });
      }
      if (path === "/docs") {                      // human docs / integration surfaces
        return new Response(shell("docs", `<h1>docs</h1>
<p class="sub">Route any agent or script through wave Dispatch. Your keys + data stay on your infra.</p>
<div class="box"><div class="r"><span class="kk">classify</span> <span class="dim">POST</span> / <span class="dim">{"prompt":"…"}</span> + <span class="warn">Authorization: Bearer &lt;key&gt;</span></div>
<div class="r"><span class="kk">returns</span> {route, probability, margin, decided_at, forward}</div>
<div class="r"><span class="kk">Claude Code</span> ANTHROPIC_BASE_URL → local dispatch proxy</div>
<div class="r"><span class="kk">Codex/Cursor/Gemini</span> OPENAI_BASE_URL → local dispatch openai-proxy</div>
<div class="r"><span class="kk">MCP</span> wave_route · wave_dispatch · wave_pool · wave_agent</div>
<div class="r"><span class="kk">pay-per-use</span> x402 (HTTP 402 → pay → retry)</div></div>
<p class="sub">machine-readable: <a href="/llms.txt">/llms.txt</a> · <a href="/transparency?format=json">/transparency.json</a></p>`),
          { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      }
      if (path === "/about") {                     // positioning / what wave Dispatch is (#74)
        return new Response(shell("about", `<h1>about wave <span class="good">Dispatch</span></h1>
<p class="sub">The cheapest capable model wins. We make sure it does.</p>
<div class="box">
<p>Most AI bills are paid sending <em>every</em> request to a frontier model — even the trivial ones. wave Dispatch is a serverless edge router that classifies each request and sends it to the cheapest model that can actually do the job: your local models first, your frontier model (Claude · GPT · Gemini) only when the work genuinely needs it.</p>
<p><span class="acc">Your infra · your keys · your data.</span> We never see your inference — we return a routing decision. You bring the models (local + any frontier, BYOK); we orchestrate at the edge and bill only the decision.</p>
<p><span class="acc">Safe by default, smarter over time.</span> A verify-gate catches weak local answers and escalates instead of shipping them — so local-first is reliable, not risky. We learn the best model for each kind of work, so your routing keeps getting cheaper and faster.</p></div>
<div class="box"><div class="r"><span class="kk">for</span> agents + humans who want frontier quality without the frontier bill</div>
<div class="r"><span class="kk">pay</span> per routing decision (x402) or a plan — your inference stays yours</div>
<div class="r"><span class="kk">part of</span> <a href="https://wave.online">WAVE</a></div></div>`),
          { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      }
      if (path === "/quickstart") {                // #100: how humans + agents start
        return new Response(shell("quickstart", `<h1>quickstart</h1>
<p class="sub">Route any request to the cheapest capable model. Your keys + infra stay yours.</p>
<div class="box"><div class="r"><span class="kk">human · CLI</span> <span class="dim">pipx install wave-dispatch · dispatch "find the auth handler"</span></div>
<div class="r"><span class="kk">Claude Code</span> ANTHROPIC_BASE_URL → local dispatch proxy</div>
<div class="r"><span class="kk">Codex/Cursor/Gemini</span> OPENAI_BASE_URL → local dispatch openai-proxy</div>
<div class="r"><span class="kk">MCP agent</span> wave_route · wave_dispatch · wave_pool</div>
<div class="r"><span class="kk">edge API</span> <span class="dim">POST / + Bearer &lt;key&gt; → {route, probability, margin}</span></div>
<div class="r"><span class="kk">agent pay-per-use</span> x402 (HTTP 402 → pay → retry, no account)</div></div>
<p class="sub">Starter $9 (free trial) · Pro $29 · pay-per-use $0.0001/decision · <a href="/about">how it works →</a> · <a href="/docs">docs →</a></p>`),
          { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      }
      if (path === "/transparency") {              // trust contract — JSON for agents, HTML page for humans
        const m = {
          service: "wave Dispatch", role: "routing decision only — control plane",
          data_policy: {
            sees: "your prompt, truncated to 2000 chars, used ONLY to pick a model",
            logs: ["per-license daily request COUNT (use:<key>:<YYYYMMDD>)", "license metadata (plan/limit/email)"],
            never_logs: ["prompt content", "your data", "your API keys", "model outputs"],
            data_plane: "your API keys, inference, and data stay on YOUR infra. We return only {route, probability, margin}.",
          },
          data_use: {
            default: "PRIVATE for everyone (all plans). Your prompt routes a request in-the-moment; it is NOT stored or used to train any central/shared model.",
            self_improvement: "happens LOCALLY on your own instance (your traffic improves your router); your data never leaves your infra.",
            opt_in: "you may OPT IN to contribute anonymized routing labels (the route decision, not raw prompts) to improve the shared router — for account credit. Never opt-out, never default.",
          },
          edge_model: "@cf/baai/bge-base-en-v1.5 (embedding only, at the edge)",
          source: "open edge worker (audit the only code that touches your prompt)",
          version: env.CF_VERSION_METADATA?.id || "see deploy",
        };
        const wantsJson = (req.headers.get("accept") || "").includes("application/json") || url.searchParams.get("format") === "json";
        if (wantsJson) return Response.json(m);    // agents verify programmatically
        return new Response(transparencyHtml(m), { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });
      }
      if (path === "/favicon.svg" || path === "/favicon.ico") {   // the WAVE wave mark in dispatch teal
        return new Response(FAVICON_SVG, { headers: { "content-type": "image/svg+xml", "cache-control": "public,max-age=86400" } });
      }
      if (path === "/llms.txt") {                  // agent-discovery: LLM-readable description of the service
        return new Response(LLMS_TXT, { headers: { "content-type": "text/plain; charset=utf-8" } });
      }
      if (path === "/robots.txt") {
        return new Response("User-agent: *\nAllow: /\nAllow: /llms.txt\n", { headers: { "content-type": "text/plain" } });
      }
      return new Response(LANDING, { headers: { "content-type": "text/html; charset=utf-8", ...SEC_HEADERS } });  // public landing, $0
    }
    if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
    if (path === "/stripe-webhook") return handleStripeWebhook(req, env);   // #63: signature-verified, mints license
    if (path === "/report") {                    // #90: bug/issue report (humans + agents) — public, size-capped, stored
      let rb: any; try { rb = await req.json(); } catch { rb = {}; }
      const msg = String(rb?.message || "").slice(0, 4000);
      if (!msg) return Response.json({ error: 'need {"message":"..."}' }, { status: 400 });
      const incident_id = "inc_" + crypto.randomUUID().replace(/-/g, "").slice(0, 16);
      const rec = { id: incident_id, message: msg, severity: String(rb?.severity || "normal").slice(0, 16),
        context: String(rb?.context || "").slice(0, 1000), ua: (req.headers.get("user-agent") || "").slice(0, 200), at: new Date().toISOString() };
      try { if (env.LICENSES) await env.LICENSES.put("report:" + incident_id, JSON.stringify(rec), { expirationTtl: 2592000 }); } catch {}
      return Response.json({ ok: true, incident_id });   // TODO #90: also forward to WAVE Linear/Sentry/Intercom
    }

    // GATE — checked BEFORE any env.AI call, so an unpaid/over-quota/unauthorized request costs $0.
    const payPerUse = env.WAVE_X402 === "1" || env.WAVE_X402 === "true" || env.WAVE_MPP === "1" || env.WAVE_MPP === "true";
    let who: any = null;
    if (payPerUse) {                                             // pay-per-use mode (#62/#63): x402 + MPP rails
      const paid = await verifyPayment(env, req);               // REAL settlement when a facilitator is set, else stub
      if (!paid.ok) return paymentChallenge(env, path);         // 402 — no/failed payment, no AI spend ($0)
    } else {                                                     // license mode (#64): admin or KV key
      who = await authorize(req, env);
      if (!who) return Response.json({ error: "unauthorized — Authorization: Bearer <license-key> required" }, { status: 401 });
    }
    let body: any;
    try { body = await req.json(); }
    catch { return Response.json({ error: "invalid JSON body" }, { status: 400 }); }
    if (path === "/embed") {                       // admin-only batch embed — reweight in bge-space (#61)
      if (!payPerUse && who.plan !== "admin") return Response.json({ error: "/embed is admin-only" }, { status: 403 });
      const texts = (body?.texts || []).slice(0, 200).map((t: any) => String(t).slice(0, 2000));
      if (!texts.length) return Response.json({ error: "need {texts:[...]}" }, { status: 400 });
      const e = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text: texts });
      return Response.json({ embeddings: e.data });
    }
    if (who) {                                     // per-minute burst guard (#107) THEN daily quota — both before AI spend
      const rl = await rateLimit(env, who);
      if (rl.over) return Response.json({ error: `rate limit exceeded — ${rl.limit}/min for ${who.plan} plan`, plan: who.plan },
        { status: 429, headers: { "Retry-After": String(rl.retry) } });
      const m = await meter(env, who);
      if (m.over) return Response.json({ error: `quota exceeded — ${who.plan} plan limit ${who.limit}/day`,
        plan: who.plan, used: m.count }, { status: 429 });
    }
    const prompt = body?.prompt;
    // #80 matmul-only: client may send a pre-computed 768-d embedding to SKIP the edge embed — cheapest +
    // fastest path (zero Neurons, sub-ms classify). Otherwise we embed the prompt at the edge.
    const providedVec = Array.isArray(body?.vector) ? body.vector : null;
    if (!prompt && !providedVec) return Response.json({ error: 'need {"prompt":"..."} or {"vector":[768 floats]}' }, { status: 400 });
    let vec: number[];
    if (providedVec) {
      if (providedVec.length !== 768) return Response.json({ error: "vector must be 768-dim (bge-base-en)", got: providedVec.length }, { status: 400 });
      vec = providedVec;                          // matmul-only: trust the client's embedding, skip Workers AI
    } else {
      // COST GUARD: routing only needs the gist; cap input so a huge prompt can't run up Neurons.
      const text = String(prompt).slice(0, 2000);
      try { const e = await env.AI.run("@cf/baai/bge-base-en-v1.5", { text: [text] }); vec = e.data[0]; }
      catch (err: any) { return Response.json({ error: "edge embed failed", detail: String(err).slice(0, 120) }, { status: 502 }); }
    }
    const r = classify(vec);
    // cascade: uncertain (low margin) -> let the origin's granite4 decide (the accurate path)
    const resp: any = { ...r, decided_at: r.margin < MARGIN ? "origin-fallback" : "edge", forward: r.margin < MARGIN };
    const execAllowed = (env.WAVE_EDGE_EXEC === "1" || env.WAVE_EDGE_EXEC === "true")   // #111: edge-exec costs us Neurons —
      && (payPerUse || (who && who.plan !== "free"));                                   // gate to x402-paid or PAID plans (free can't abuse)
    if (prompt && body?.execute === true && execAllowed) {
      const model = EDGE_EXEC_MODELS[r.route] || "@cf/qwen/qwen3-30b-a3b-fp8";
      if (body?.stream === true) {                            // #105: stream tokens (SSE) for low TTFB; decision in headers
        const s: any = await env.AI.run(model, { messages: [{ role: "user", content: String(prompt).slice(0, 8000) }], max_tokens: 512, stream: true });
        return new Response(s, { headers: { "content-type": "text/event-stream", "cache-control": "no-store",
          "x-dispatch-route": r.route, "x-dispatch-margin": String(r.margin), "x-dispatch-tier": "edge-local", "x-dispatch-model": model } });
      }
      const ex = await executeAtEdge(env, r.route, prompt);   // #111 edge-local tier: run it on Workers AI here
      resp.answer = ex.answer; resp.executed_by = ex.model; resp.tier = "edge-local";
    }
    return Response.json(resp);
  },
};
