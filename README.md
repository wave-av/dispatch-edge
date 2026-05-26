# wave Dispatch — edge worker (public)

The **only code that touches your prompt**: it embeds at the edge, classifies the request (matmul over
bundled weights), and returns a routing decision. **It logs zero prompt content.** Open here so you can
verify exactly that — the trained weights, local orchestration, and business logic stay private.

- `edge-router/worker.ts` — the Cloudflare Worker (classify, meter, gate, x402, edge-exec).
- `sdk/go`, `sdk/ruby` — thin clients for the edge API.
- `threat-model.md` — security posture.
- Verify deployed == source: `GET https://dispatch.wave.online/status?format=json` returns the version.

Product: https://dispatch.wave.online · a [WAVE](https://wave.online) product.
