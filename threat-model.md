# wave Dispatch — threat model (#102)

Adversarial review of the public surface (`dispatch.wave.online` + the local stack). ✅ = mitigated &
verified, ⚠️ = partial, ☐ = open. The control-plane/data-plane split means the customer's keys, data,
and inference never transit us — that bounds the blast radius up front.

## Edge worker (the public attack surface)
- ✅ **Unauthorized access** — no/invalid bearer → 401, before any AI spend ($0). Verified (probe).
- ✅ **Malformed / oversized input** — bad JSON → 401/400; prompt capped at 2000 chars (Neuron cost bound). Verified.
- ✅ **Webhook spoofing** — Stripe sig verified, fail-closed (no/invalid secret → 400). Verified.
- ✅ **Clickjacking / injection on pages** — strict CSP (`default-src 'none'`, zero JS), `X-Frame-Options: DENY`, `frame-ancestors none`, HSTS, nosniff, Referrer-Policy. Verified.
- ✅ **Method abuse** — non-POST to the API → 405.
- ✅ **Per-minute burst** — rate limit (rl:<key>:<min>, per-plan RPM, 429+Retry-After) before AI spend; fail-open on KV blip, daily quota fail-closed.
- ⚠️ **Free-tier abuse / scammers** — daily quota enforced; needs card-required free trial + Stripe Radar + per-card dedupe + Turnstile on signup (#101).
- ⚠️ **License key sharing / leakage** — keys are revocable; needs per-key anomaly detection + rotation UX.
- ☐ **Edge-exec cost abuse** — `execute:true` is flag-gated OFF in prod; before enabling, plan-gate it + cap tokens (#111).
- ☐ **Tenant isolation** — KV keys are namespaced per token; add a test proving one key can't read another's usage.

## Payments
- ✅ Webhook → license mint is signature-verified + e2e-tested (live).
- ✅ **x402 replay** — when settling via WAVE's verifier, `tx_hash` is single-use (TX_HASH_ALREADY_USED) + amount + treasury-recipient checked (WAVE side).
- ☐ Real settlement still stubbed until a facilitator is wired (#81/#68); MPP/ACP labeled "rolling out" (honest).

## Local stack
- ✅ **Dangerous misroute** — eval gate asserts 0 dangerous under-escalations every run + pre-commit; ROUTER_MODE fails SAFE (generative) if config missing.
- ✅ **Wrong/empty/truncated local answer** — verify-gate escalates instead of shipping; full-answer fix (#76) batch-validated.
- ✅ **Self-learning degradation** — online-update acceptance guard: never promote a classifier that regresses the held-out eval.
- ⚠️ **Prompt injection via /report or inputs** — capped + stored; scrub/sanitize before any human/Linear surface (#90).

## Open (tracked)
key-sharing anomaly detection · tenant-isolation test · rate-limit load test under concurrency · card-required free (#101) · edge-exec plan-gating (#111) · real x402 settlement (#81).
