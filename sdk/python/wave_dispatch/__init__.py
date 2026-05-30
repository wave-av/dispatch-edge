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

__version__ = "0.6.2"
DEFAULT_ENDPOINT = "https://dispatch.wave.online"
DEFAULT_AGENTS_ENDPOINT = "https://dispatch-agents.wave.online"   # stateful sidecar: savings ledger + subscriptions

# 0.5.0 — payment_hook: callable taking the 402 challenge body (dict) and returning headers to retry
# with (dict[str,str]). Pair with `Dispatch.wallet_hook(provider=..., credentials=...)` for built-in
# CDP / Privy / Bridge providers, or pass a custom callable for any provider you want.
PaymentHook = Callable[[Dict[str, Any]], Dict[str, str]]


def _with_profile(body: dict, profile: Optional[str]) -> dict:
    """Sovereign tier (D3): attach an optional named routing profile to the request body. snake_case
    `profile` is the cross-SDK contract; the edge resolveProfile() honors body.profile over KV/defaults.
    Omitted/empty => unchanged body (zero behavior change for non-Sovereign callers)."""
    if profile:
        return {**body, "profile": profile}
    return body


class Dispatch:
    """Client for the wave Dispatch edge API."""

    def __init__(self, license: Optional[str] = None, endpoint: str = DEFAULT_ENDPOINT,
                 agents_endpoint: Optional[str] = None,
                 payment_hook: Optional[PaymentHook] = None):
        self.license = license or os.environ.get("WAVE_LICENSE")
        self.endpoint = endpoint.rstrip("/")
        self.agents = (agents_endpoint or os.environ.get("WAVE_AGENTS_ENDPOINT") or DEFAULT_AGENTS_ENDPOINT).rstrip("/")
        self.payment_hook = payment_hook    # 0.5.0 — auto-pay on 402 via this hook

    def route(self, prompt: str, profile: Optional[str] = None) -> dict:
        """Classify a prompt (no execution). Returns {route, probability, margin, forward}.
        Sovereign tier: pass profile= (Fast|Expert|Heavy|Code) to request a named routing profile."""
        return self._post(self.endpoint + "/", _with_profile({"prompt": prompt}, profile))

    def execute(self, prompt: str, profile: Optional[str] = None) -> dict:
        """Classify and run on the edge if your plan allows it. Optional profile= as in route()."""
        return self._post(self.endpoint + "/", _with_profile({"prompt": prompt, "execute": True}, profile))

    def route_vector(self, vector: list, profile: Optional[str] = None) -> dict:
        """Classify a pre-computed 768-d embedding (matmul-only: cheapest + fastest)."""
        return self._post(self.endpoint + "/", _with_profile({"vector": vector}, profile))

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
        # 0.6.1 — real CDP-JWT (ES256/P-256) signing when `cryptography` is available; falls back to a
        # marker payload otherwise. Install with: pip install wave-dispatch[cdp].
        # creds: { api_key, api_secret (PEM PKCS8 EC private key), address?, network? }
        for k in ("api_key", "api_secret"):
            if not creds.get(k):
                raise ValueError("dispatch.wallet_hook(cdp): " + k + " required")
        jwt = _sign_cdp_jwt(creds, accept)
        return json.dumps({"provider": "cdp", "jwt": jwt, "address": creds.get("address"),
                           "network": creds.get("network") or "base", "accept": accept})
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


def _sign_cdp_jwt(creds: dict, accept: Optional[dict]) -> str:
    """0.6.1 — CDP-JWT (ES256/P-256) signing. Requires the `cryptography` package
    (install with `pip install wave-dispatch[cdp]`). Without it, raises RuntimeError pointing the user
    at the optional dependency or the `provider='custom'` escape hatch.

    Header: {alg:'ES256', kid:<api_key>, typ:'JWT', nonce:<rand-hex16>}
    Payload: {sub:<api_key>, iss:'cdp', nbf:<now>, exp:<now+120>, uri:'POST dispatch.wave.online<resource>', claim:<accept>}
    Signature: ECDSA over base64url(header).base64url(payload), output as 64-byte r||s (IEEE P-1363),
               base64url-encoded — matches JWS ES256 spec exactly.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError as e:
        raise RuntimeError("dispatch.wallet_hook(cdp): real CDP-JWT signing needs `cryptography` "
                           "(install with: pip install wave-dispatch[cdp]). Or pass provider='custom' "
                           "and supply your own sign(challenge) -> headers using the official "
                           "coinbase-cdp-sdk package.") from e
    import os as _os, secrets as _secrets, time as _time

    def b64url(data) -> str:
        if isinstance(data, str):
            data = data.encode()
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    now = int(_time.time())
    uri = "POST dispatch.wave.online" + ((accept or {}).get("resource") or "/")
    header = {"alg": "ES256", "kid": creds["api_key"], "typ": "JWT", "nonce": _secrets.token_hex(16)}
    payload = {"sub": creds["api_key"], "iss": "cdp", "nbf": now, "exp": now + 120, "uri": uri, "claim": accept}
    to_sign = b64url(json.dumps(header, separators=(",", ":"))) + "." + b64url(json.dumps(payload, separators=(",", ":")))

    # Parse PEM PKCS8. cryptography handles both PKCS8 and SEC1 PEMs transparently.
    try:
        key = serialization.load_pem_private_key(creds["api_secret"].encode(), password=None)
    except Exception as e:
        raise RuntimeError("dispatch.wallet_hook(cdp): could not parse api_secret as a PEM EC private key (" + str(e) + ")") from e
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise RuntimeError("dispatch.wallet_hook(cdp): api_secret must be an EC P-256 private key")
    der_sig = key.sign(to_sign.encode(), ec.ECDSA(hashes.SHA256()))
    # cryptography returns DER-encoded (r,s); JWS ES256 expects raw 64-byte r||s (32+32 for P-256).
    r, s = decode_dss_signature(der_sig)
    raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return to_sign + "." + b64url(raw_sig)


# Expose for power users who want to drive CDP themselves (e.g. signing custom request URIs) without
# the wallet_hook orchestration.
Dispatch.sign_cdp_jwt = staticmethod(_sign_cdp_jwt)
