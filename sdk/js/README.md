# @wave-av/dispatch

JS/TS client for [wave Dispatch](https://dispatch.wave.online) — route each request to the cheapest
capable model (local-first; escalate to your frontier model only when needed). BYO keys + infra.

```js
import { Dispatch } from "@wave-av/dispatch";
const d = new Dispatch(process.env.WAVE_LICENSE);          // or omit for x402 pay-per-use
const r = await d.route("find the auth handler");          // { route, probability, margin, forward }
// await d.execute("name 3 colors");                       // run on the edge (if plan allows)
// await d.routeVector(vec768);                            // matmul-only: cheapest/fastest
```
Node 18+. The edge worker is open-source: github.com/wave-av/dispatch-edge. A WAVE product.
