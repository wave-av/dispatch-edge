"""wave Dispatch — thin Python client. Route each request to the cheapest capable model (local-first;
escalate to your frontier only when needed). BYO keys + infra; the service returns a routing decision.
Stdlib-only (urllib) — zero dependencies."""
import json
import os
import urllib.request
import urllib.error

__version__ = "0.1.0"
DEFAULT_ENDPOINT = "https://dispatch.wave.online"


class Dispatch:
    """Client for the wave Dispatch edge API."""

    def __init__(self, license: str | None = None, endpoint: str = DEFAULT_ENDPOINT):
        self.license = license or os.environ.get("WAVE_LICENSE")
        self.endpoint = endpoint.rstrip("/")

    def route(self, prompt: str) -> dict:
        """Classify a prompt (no execution). Returns {route, probability, margin, forward}."""
        return self._post({"prompt": prompt})

    def execute(self, prompt: str) -> dict:
        """Classify and run on the edge if your plan allows it."""
        return self._post({"prompt": prompt, "execute": True})

    def route_vector(self, vector: list) -> dict:
        """Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest)."""
        return self._post({"vector": vector})

    def _post(self, body: dict) -> dict:
        headers = {"content-type": "application/json"}
        if self.license:
            headers["authorization"] = "Bearer " + self.license
        req = urllib.request.Request(self.endpoint + "/", json.dumps(body).encode(), headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 402:
                raise RuntimeError("dispatch: 402 payment required (x402) — pay and retry, or set a license")
            raise RuntimeError(f"dispatch: {e.code} {e.read().decode()[:120]}")
