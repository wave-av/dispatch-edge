"""wave Dispatch — thin Python client. Route each request to the cheapest capable model (local-first;
escalate to your frontier only when needed). BYO keys + infra; the service returns a routing decision.
Stdlib-only (urllib) — zero dependencies."""
import json
import os
import urllib.parse
import urllib.request
import urllib.error
from typing import Optional   # CR/#3: keep type hints compatible with requires-python >=3.8 (str | None is py3.10+)

__version__ = "0.4.4"
DEFAULT_ENDPOINT = "https://dispatch.wave.online"
DEFAULT_AGENTS_ENDPOINT = "https://dispatch-agents.wave.online"   # stateful sidecar: savings ledger + subscriptions


class Dispatch:
    """Client for the wave Dispatch edge API."""

    def __init__(self, license: Optional[str] = None, endpoint: str = DEFAULT_ENDPOINT,
                 agents_endpoint: Optional[str] = None):
        self.license = license or os.environ.get("WAVE_LICENSE")
        self.endpoint = endpoint.rstrip("/")
        self.agents = (agents_endpoint or os.environ.get("WAVE_AGENTS_ENDPOINT") or DEFAULT_AGENTS_ENDPOINT).rstrip("/")

    def route(self, prompt: str) -> dict:
        """Classify a prompt (no execution). Returns {route, probability, margin, forward}."""
        return self._post(self.endpoint + "/", {"prompt": prompt})

    def execute(self, prompt: str) -> dict:
        """Classify and run on the edge if your plan allows it."""
        return self._post(self.endpoint + "/", {"prompt": prompt, "execute": True})

    def route_vector(self, vector: list) -> dict:
        """Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest)."""
        return self._post(self.endpoint + "/", {"vector": vector})

    # --- stateful sidecar (scoped to THIS license; the license key is the bearer) ---
    def savings(self) -> dict:
        """This license's savings ledger: decisions, local_handled, escalated, saved_usd, saved_pct."""
        return self._get(self.agents + "/ledger/summary?license=" + self._lic())

    def subscription(self) -> dict:
        """This license's agent-subscription status (plan, quota, used, remaining, renews_at)."""
        return self._get(self.agents + "/subscription/status?license=" + self._lic())

    def subscribe(self, plan: str) -> dict:
        """Start/replace a programmatic subscription. plan: agent_starter | agent_pro | agent_scale."""
        if not self.license:
            raise RuntimeError("dispatch: a license is required for subscribe() — set WAVE_LICENSE")
        return self._post(self.agents + "/subscription/create", {"license": self.license, "plan": plan})

    def _lic(self) -> str:
        if not self.license:
            raise RuntimeError("dispatch: a license is required for savings()/subscription() — set WAVE_LICENSE")
        return urllib.parse.quote(self.license)

    def _headers(self) -> dict:
        h = {"content-type": "application/json"}
        if self.license:
            h["authorization"] = "Bearer " + self.license
        return h

    def _send(self, req: urllib.request.Request) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 402:
                raise RuntimeError("dispatch: 402 payment required (x402) — pay and retry, or set a license") from e
            if e.code == 401:
                raise RuntimeError("dispatch: 401 unauthorized — set a valid license (WAVE_LICENSE)") from e
            raise RuntimeError(f"dispatch: {e.code} {e.read().decode()[:120]}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"dispatch: network error — {e.reason}") from e

    def _post(self, url: str, body: dict) -> dict:
        return self._send(urllib.request.Request(url, json.dumps(body).encode(), self._headers()))

    def _get(self, url: str) -> dict:
        return self._send(urllib.request.Request(url, headers=self._headers()))
