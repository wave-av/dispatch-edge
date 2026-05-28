"""wave Dispatch — thin Python client. Route each request to the cheapest capable model (local-first;
escalate to your frontier only when needed). BYO keys + infra; the service returns a routing decision.
Stdlib-only (urllib) — zero dependencies."""
import base64
import json
import os
import urllib.parse
import urllib.request
import urllib.error
from typing import Callable, Optional, Dict, Any   # CR/#3: py3.8 compat (str | None is py3.10+)

__version__ = "0.5.0"
DEFAULT_ENDPOINT = "https://dispatch.wave.online"
DEFAULT_AGENTS_ENDPOINT = "https://dispatch-agents.wave.online"   # stateful sidecar: savings ledger + subscriptions

# 0.5.0 — payment_hook: callable taking the 402 challenge body (dict) and returning headers to retry
# with (dict[str,str]). Pair with `Dispatch.wallet_hook(provider=..., credentials=...)` for built-in
# CDP / Privy / Bridge providers, or pass a custom callable for any provider you want.
PaymentHook = Callable[[Dict[str, Any]], Dict[str, str]]


class Dispatch:
    """Client for the wave Dispatch edge API."""

    def __init__(self, license: Optional[str] = None, endpoint: str = DEFAULT_ENDPOINT,
                 agents_endpoint: Optional[str] = None,
                 payment_hook: Optional[PaymentHook] = None):
        self.license = license or os.environ.get("WAVE_LICENSE")
        self.endpoint = endpoint.rstrip("/")
        self.agents = (agents_endpoint or os.environ.get("WAVE_AGENTS_ENDPOINT") or DEFAULT_AGENTS_ENDPOINT).rstrip("/")
        self.payment_hook = payment_hook    # 0.5.0 — auto-pay on 402 via this hook

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

    @staticmethod
    def wallet_hook(provider: str, credentials: Optional[dict] = None,
                    sign: Optional[Callable[[dict], dict]] = None) -> PaymentHook:
        """0.5.0 — Build a payment_hook that signs each 402 challenge via a wallet provider.

        provider:    "cdp" | "privy" | "bridge" | "custom"
        credentials: provider-specific. CDP: {api_key, api_secret, address}. Privy: {app_id, app_secret,
                     wallet_id}. Bridge: {api_key, source_wallet, destination?}.
        sign:        only for provider="custom" — sign(challenge_dict) -> headers_dict.

        See WALLET.md for the full wire-up + which header each provider sets.
        """
        if not provider:
            raise ValueError("dispatch.wallet_hook: provider is required")
        if provider == "custom" and not callable(sign):
            raise ValueError('dispatch.wallet_hook(custom): pass sign=fn(challenge) -> headers')
        creds = credentials or {}
        header_by_provider = {"cdp": "cdp-payment", "privy": "privy-payment", "bridge": "bridge-payment"}

        def hook(challenge: dict) -> dict:
            if provider == "custom":
                return sign(challenge)
            payload = _wallet_sign(provider, creds, challenge)
            h = header_by_provider.get(provider)
            if not h:
                raise ValueError("dispatch.wallet_hook: unknown provider " + str(provider))
            return {h: payload}
        return hook

    def _lic(self) -> str:
        if not self.license:
            raise RuntimeError("dispatch: a license is required for savings()/subscription() — set WAVE_LICENSE")
        return urllib.parse.quote(self.license)

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> dict:
        h = {"content-type": "application/json"}
        if self.license:
            h["authorization"] = "Bearer " + self.license
        if extra:
            h.update(extra)
        return h

    def _send(self, req: urllib.request.Request, on_402_retry=None) -> dict:
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 402:
                if on_402_retry is not None:                          # 0.5.0 — let payment_hook resubmit
                    challenge = {}
                    try:
                        challenge = json.loads(e.read().decode() or "{}")
                    except Exception:
                        pass
                    return on_402_retry(challenge)
                raise RuntimeError("dispatch: 402 payment required (x402) — pay and retry, or set a license / payment_hook") from e
            if e.code == 401:
                raise RuntimeError("dispatch: 401 unauthorized — set a valid license (WAVE_LICENSE)") from e
            raise RuntimeError("dispatch: " + str(e.code) + " " + e.read().decode()[:120]) from e
        except urllib.error.URLError as e:
            raise RuntimeError("dispatch: network error — " + str(e.reason)) from e

    def _post(self, url: str, body: dict) -> dict:
        def retry(challenge):
            pay_headers = self.payment_hook(challenge) if self.payment_hook else {}
            req = urllib.request.Request(url, json.dumps(body).encode(), self._headers(pay_headers))
            return self._send(req)
        req = urllib.request.Request(url, json.dumps(body).encode(), self._headers())
        return self._send(req, on_402_retry=(retry if self.payment_hook else None))

    def _get(self, url: str) -> dict:
        def retry(challenge):
            pay_headers = self.payment_hook(challenge) if self.payment_hook else {}
            req = urllib.request.Request(url, headers=self._headers(pay_headers))
            return self._send(req)
        req = urllib.request.Request(url, headers=self._headers())
        return self._send(req, on_402_retry=(retry if self.payment_hook else None))


def _wallet_sign(provider: str, creds: dict, challenge: dict) -> str:
    """Built-in provider sign — HTTP orchestration only; actual signing lives at the provider."""
    accepts = challenge.get("accepts") or []
    accept = next((a for a in accepts if a.get("protocol") == provider), accepts[0] if accepts else {})
    if provider == "cdp":
        # CDP-JWT signing is non-trivial in stdlib-only Python. Recommended: provider="custom" with the
        # `coinbase-cdp-sdk` package. We return a marker; the worker (WAVE_VERIFY_URL + WAVE_CDP=1)
        # delegates verification to WAVE's CDP service.
        return json.dumps({"provider": "cdp", "address": creds.get("address"), "accept": accept,
                           "hint": "use coinbase-cdp-sdk for CDP-JWT signing in production"})
    if provider == "privy":
        for k in ("app_id", "app_secret", "wallet_id"):
            if not creds.get(k):
                raise ValueError("dispatch.wallet_hook(privy): app_id, app_secret, wallet_id required")
        basic = base64.b64encode(("%s:%s" % (creds["app_id"], creds["app_secret"])).encode()).decode()
        body = json.dumps({"method": "personal_sign", "params": {"message": json.dumps(accept)}, "chain_type": "ethereum"}).encode()
        req = urllib.request.Request(
            "https://auth.privy.io/api/v1/wallets/" + urllib.parse.quote(creds["wallet_id"]) + "/rpc",
            data=body,
            headers={"content-type": "application/json", "authorization": "Basic " + basic, "privy-app-id": creds["app_id"]},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                j = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError("dispatch.wallet_hook(privy): provider " + str(e.code)) from e
        sig = (j.get("data") or {}).get("signature") or j.get("signature")
        return json.dumps({"provider": "privy", "signature": sig, "accept": accept})
    if provider == "bridge":
        if not creds.get("api_key"):
            raise ValueError("dispatch.wallet_hook(bridge): api_key required")
        body = json.dumps({"source": creds.get("source_wallet"),
                           "destination": creds.get("destination") or accept.get("payTo"),
                           "amount": accept.get("maxAmountRequired")}).encode()
        req = urllib.request.Request("https://api.bridge.xyz/v0/transfers", data=body,
                                     headers={"content-type": "application/json", "api-key": creds["api_key"]})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                j = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raise RuntimeError("dispatch.wallet_hook(bridge): provider " + str(e.code)) from e
        return json.dumps({"provider": "bridge", "id": j.get("id"), "accept": accept})
    raise ValueError("dispatch._wallet_sign: unsupported provider " + str(provider))
