# wave-dispatch (Python)

Thin client for [wave Dispatch](https://dispatch.wave.online) — route each request to the cheapest
capable model (local-first; escalate to your frontier only when needed). BYO keys + infra. Zero deps.

```python
from wave_dispatch import Dispatch

d = Dispatch()                      # reads WAVE_LICENSE env; omit license for x402 pay-per-use
print(d.route("find the auth handler"))   # {route, probability, margin, forward}
# d.execute("name 3 colors")        # run on the edge (if your plan allows)
# d.route_vector(vec768)            # matmul-only: cheapest/fastest
```

Python 3.8+. The edge worker is open-source: github.com/wave-av/dispatch-edge. A WAVE product.
