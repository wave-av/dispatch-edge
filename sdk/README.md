# wave Dispatch SDKs (#108)

Thin clients for the edge API (`POST /` → `{route, probability, margin}`; `execute:true` for edge-local
answers; bearer license or x402). Your keys + infra stay yours.

| Language | Status | Path |
|---|---|---|
| Python | ✅ (CLI + `wave_core`) | repo root — `pipx install wave-dispatch` |
| Go | ✅ | `sdk/go` — `import dispatch "github.com/wave-av/dispatch-go"` |
| Rust | ⚙️ native router exists (`rust-router/`) — SDK wrapper TODO | `rust-router/` |
| Ruby | ☐ TODO | `sdk/ruby` |

## Go
```go
c := dispatch.New(os.Getenv("WAVE_LICENSE"))
d, _ := c.Route(context.Background(), "find the auth handler")
fmt.Println(d.Route, d.Forward)   // local_search false
// d, _ := c.Execute(ctx, prompt)        // run on the edge (if plan enables)
// d, _ := c.RouteVector(ctx, vec768)    // matmul-only: cheapest/fastest
```
Builds clean on Go 1.21+ (`go build ./...`, `go vet ./...`).

All SDKs are generated/kept consistent against the same contract — see `/docs` and `/llms.txt` on the edge.
