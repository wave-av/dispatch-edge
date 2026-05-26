<div align="center">

# wave Dispatch — edge worker

**Local-first AI routing.** Send every request to the cheapest *capable* model — your local models first
($0, your infra), escalating to a frontier (Claude / GPT / Gemini / …) only when confidence is low.

This repo is **the only code that touches your prompt**, published so you can verify exactly what it does.

[Product](https://dispatch.wave.online) · [Pricing](https://dispatch.wave.online/pricing) · [Playground](https://dispatch.wave.online/playground) · [SDKs](https://dispatch.wave.online/sdks) · [Status](https://dispatch.wave.online/status) · [a WAVE product](https://wave.online)

[![npm](https://img.shields.io/npm/v/%40wave-av%2Fdispatch?label=npm)](https://www.npmjs.com/package/@wave-av/dispatch)
[![PyPI](https://img.shields.io/pypi/v/wave-dispatch?label=PyPI)](https://pypi.org/project/wave-dispatch/)
[![crates.io](https://img.shields.io/crates/v/wave-dispatch?label=crates.io)](https://crates.io/crates/wave-dispatch)
[![Gem](https://img.shields.io/gem/v/wave-dispatch?label=gem)](https://rubygems.org/gems/wave-dispatch)
[![License: MIT](https://img.shields.io/badge/license-MIT-43d9ad)](./LICENSE)

</div>

---

## Why it exists

Most agent and LLM workloads send *everything* to a frontier model — including the cheap turns a small
local model handles perfectly. You pay frontier prices for work that didn't need it, and your prompts leave
your infra on every call.

wave Dispatch puts a tiny classifier at the edge. It embeds each request (Workers AI, `bge-base-en`),
runs a matmul over bundled weights, and returns a **routing decision**: which tier should handle this, with
a confidence and margin. Your runtime does the rest — local models on your hardware, frontier only when the
classifier isn't confident enough.

- **63–79% cost reduction** vs all-frontier on measured hybrid workloads.
- **Tool-calling proven** — a free local model (`qwen2.5:3b-instruct`) passes tool-calling, so agent loop-turns run at $0 and escalate only the hard turn.
- **BYOK / BYO-infra** — your API keys, prompts, and inference stay yours. We return a decision, nothing more.

## The trust boundary

```
                          THIS REPO (public, MIT)              YOUR INFRA (private)
prompt ──▶ embed @ edge ──▶ classify {route · conf · margin} ──▶ local pool · frontier fallback
           Workers AI         matmul over bundled weights          (your keys, your hardware)
```

- `edge-router/worker.ts` — the deployed Cloudflare Worker: classify, meter, rate-limit, x402, edge-exec.
- `edge-router/wrangler.example.toml` — bindings (Workers AI, KV) to run your own copy.
- `threat-model.md` — security posture and what is / isn't logged.

**It logs zero prompt content.** The trained weights, local orchestration, and business logic are the
proprietary part and stay private — but the code that sees your prompt is right here, auditable.

### Verify deployed == source

Every deploy embeds its commit. Confirm the running edge is built from this repo:

```bash
curl -s https://dispatch.wave.online/status?format=json | jq .version
```

## Use it

No infra to stand up — point a client at the hosted edge with your license key (or pay-per-use via x402).

### Install (5 languages)

| Language | Install | Registry |
|---|---|---|
| **JavaScript / TS** | `npm i @wave-av/dispatch` | [npm](https://www.npmjs.com/package/@wave-av/dispatch) |
| **Python** | `pip install wave-dispatch` | [PyPI](https://pypi.org/project/wave-dispatch/) |
| **Rust** | `cargo add wave-dispatch` | [crates.io](https://crates.io/crates/wave-dispatch) |
| **Ruby** | `gem install wave-dispatch` | [RubyGems](https://rubygems.org/gems/wave-dispatch) |
| **Go** | `go get github.com/wave-av/dispatch-edge/sdk/go` | [pkg.go.dev](https://pkg.go.dev/github.com/wave-av/dispatch-edge/sdk/go) |

The source for every client lives in [`sdk/`](./sdk) — thin, dependency-light, generated against one contract.

### Quickstart

```js
import { Dispatch } from "@wave-av/dispatch";
const d = new Dispatch(process.env.WAVE_LICENSE);          // or omit for x402 pay-per-use
const { route, probability, forward } = await d.route("find the auth handler");
// route="local_search" forward=false → handle locally, skip the frontier
```

```python
from wave_dispatch import Dispatch
d = Dispatch()                                              # reads $WAVE_LICENSE
print(d.route("summarize this PR")["route"])
```

```
POST https://dispatch.wave.online/
  Authorization: Bearer <license>            # or none → HTTP 402 x402 payment requirements
  {"prompt": "…"}                            # → {route, probability, margin, forward}
  {"prompt": "…", "execute": true}           # run on the edge (if your plan enables it)
  {"vector": [768 floats]}                   # matmul-only — cheapest + fastest
```

### Framework adapters

Drop-in cost routing beneath the stacks you already use: **LangChain · LlamaIndex · Vercel AI SDK ·
OpenAI Agents SDK**. See [`dispatch.wave.online/integrate`](https://dispatch.wave.online/integrate) for the
agent integration context pack, and `/llms.txt` for machine discovery.

## Run your own edge

```bash
cd edge-router
cp wrangler.example.toml wrangler.toml      # fill in your account + KV namespace
npx wrangler deploy
```

You supply the Workers AI binding and a KV namespace for licenses/metering. Bring your own local models
(Ollama / vLLM / LM Studio / TGI — any OpenAI-compatible server) and frontier keys.

## Pricing

Starter **$9/mo** (15k/day) · Pro **$29/mo** (50k/day) · Scale **$99/mo** (200k/day) · Enterprise custom ·
pay-per-use **$0.0001**/decision (x402, no account). Card required, 7-day trial. WAVE customers: code `WAVE` for 30% off.
Full breakdown → [pricing](https://dispatch.wave.online/pricing).

## License

MIT © 2026 WAVE Online, LLC. A [WAVE](https://wave.online) product — local-first by design.
