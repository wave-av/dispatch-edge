# wave Dispatch SDKs

Thin clients for the edge API (`POST /` → `{route, probability, margin, forward}`; `execute:true` for
edge-local answers; `vector:[768]` for matmul-only; bearer license or x402). Your keys + infra stay yours.
All five are generated against one contract — see `/docs` and `/llms.txt` on the edge.

| Language | Install | Registry | Source |
|---|---|---|---|
| JavaScript / TS | `npm i @wave-av/dispatch` | [npm](https://www.npmjs.com/package/@wave-av/dispatch) | [`sdk/js`](./js) |
| Python | `pip install wave-dispatch` | [PyPI](https://pypi.org/project/wave-dispatch/) | [`sdk/python`](./python) |
| Rust | `cargo add wave-dispatch` | [crates.io](https://crates.io/crates/wave-dispatch) | [`sdk/rust`](./rust) |
| Ruby | `gem install wave-dispatch` | [RubyGems](https://rubygems.org/gems/wave-dispatch) | [`sdk/ruby`](./ruby) |
| Go | `go get github.com/wave-av/dispatch-edge/sdk/go` | [pkg.go.dev](https://pkg.go.dev/github.com/wave-av/dispatch-edge/sdk/go) | [`sdk/go`](./go) |

## Usage is the same shape in every language

```js   // JavaScript / TypeScript
import { Dispatch } from "@wave-av/dispatch";
const d = new Dispatch(process.env.WAVE_LICENSE);
const { route, forward } = await d.route("find the auth handler");   // local_search false
```

```python   # Python
from wave_dispatch import Dispatch
print(Dispatch().route("summarize this PR")["route"])
```

```rust   // Rust
let d = wave_dispatch::Dispatch::new(None);          // reads WAVE_LICENSE
let r = d.route("find the auth handler")?;
```

```ruby   # Ruby
require "wave_dispatch"
WaveDispatch::Client.new.route("find the auth handler")
```

```go   // Go
c := dispatch.New(os.Getenv("WAVE_LICENSE"))
r, _ := c.Route(context.Background(), "find the auth handler")
// c.Execute(ctx, prompt)      // run on the edge (if plan enables)
// c.RouteVector(ctx, vec768)  // matmul-only: cheapest/fastest
```

Each client is dependency-light (stdlib HTTP where possible) and reads `WAVE_LICENSE` /
`DISPATCH_ENDPOINT` from the environment. Omit the license to get an HTTP 402 x402 challenge for
pay-per-use agents.
