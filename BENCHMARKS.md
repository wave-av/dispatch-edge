# Benchmarks & savings methodology

How the numbers on [dispatch.wave.online/benchmarks](https://dispatch.wave.online/benchmarks) are produced.
The thesis: **most decisions are easy — pay frontier prices only for the hard ones.**

## What's measured

A per-route eval suite with **objective graders** (no LLM-as-judge for scoring):

| Dimension | Grader | Source |
|---|---|---|
| math | exact numeric match | GSM8K-style |
| multiple-choice | exact label | MMLU-style |
| reading comprehension | span/exact match | — |
| instruction-following | rule checks | — |
| structured JSON | schema validation | — |
| code | unit tests pass | HumanEval-style |
| tool-calls | correct tool + args | — |

Models: a local model (`qwen2.5`) vs **6 frontier models + 356 more via OpenRouter**, scored on the same
prompts with the same graders, then ranked on a **cost-aware leaderboard** (quality first, then $/decision).

## Routing

Each prompt is embedded at the edge (`@cf/baai/bge-base-en-v1.5`, 768-dim) and classified
(matmul over the trained router) → `{route, probability, margin}`. If `margin < 0.20` the decision is
low-confidence and **escalates to your frontier** (your key); otherwise the local route handles it.

## Headline results

- Local handles **~80%** of decisions on mixed agent/dev workloads.
- `qwen2.5` (local, $0) wins **code · reason · summarize · tool-calling** routes outright (tool-calling 2/2).
- Customer savings **63–79%** vs frontier-only; dispatch gross margin **~90%**.

## Savings model (identical to the on-site calculator)

For `N` decisions/month, a `baseline` $/decision for your frontier, a `localShare` in [0,1], and the
dispatch `fee` $/decision:

```
frontier_only  = N · baseline
with_dispatch  = N · fee            (the routing decision, every call)
               + N · (1 − localShare) · baseline   (the escalated remainder still pays your frontier)
savings        = frontier_only − with_dispatch
```

Worked example (`N = 1,000,000`, `localShare = 0.80`, fee `$0.0001`):

| Frontier baseline | frontier-only | with dispatch | saves |
|---|---|---|---|
| GPT-4o ($0.01) | $10,000 | $2,100 | **79.0%** |
| Claude Haiku ($0.004) | $4,000 | $900 | **77.5%** |
| Mistral Small ($0.0006) | $600 | $220 | **63.3%** |

These are estimates — your real baseline depends on your token mix. Local inference cost is **$0 to
dispatch** because it runs on your infra (your electricity/hardware).

## Reproducibility

The eval harness (`benchmark.py`, `thesis.py`) runs the suite and emits this table; the trained router and
its weights are proprietary (the value we add), so the harness lives in the private repo. The contract,
graders, and savings formula above are the public, auditable part — and the live `/playground` runs the
**same** classifier you'd call via the API. Machine-readable pricing: `/pricing.json`.
