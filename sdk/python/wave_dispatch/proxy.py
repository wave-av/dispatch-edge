#!/usr/bin/env python3
"""wave Dispatch — local-first proxy (`dispatch serve`). Speaks the OpenAI /v1/chat/completions wire
format, so ANY agent/SDK with a custom base URL routes through it (Codex, Cursor, Continue, aider, …).
Stdlib only — no extra deps.

Decision source:
  - WAVE_LICENSE set -> asks the hosted classifier (dispatch.wave.online) for the route, then serves
    LOCAL from your Ollama ($0) when it's confident-local, or escalates to your UPSTREAM frontier when
    the classifier says forward.
  - no license -> a local heuristic offloads only TRIVIAL requests (free; the trained classifier is the
    paid edge).
Always falls through to UPSTREAM on any local/edge error — so enabling it can only save money, never
break an agent loop. Binds localhost only.

Auth: WAVE_LICENSE (your `wv_...` key) authenticates to the edge; your frontier key is passed through
the Authorization header to UPSTREAM. The same license works from as many proxies/machines as you want
(metered per-key by daily quota + per-minute rate, not per-device).
"""
import os, sys, json, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("WAVE_OAI_PORT", "8090"))
UPSTREAM = os.environ.get("WAVE_OAI_UPSTREAM", "https://api.openai.com").rstrip("/")
EDGE = os.environ.get("DISPATCH_ENDPOINT", "https://dispatch.wave.online").rstrip("/")
LICENSE = os.environ.get("WAVE_LICENSE", "")
OLLAMA = os.environ.get("WAVE_ENDPOINT", "http://127.0.0.1:11434").rstrip("/")
LOCAL_MODEL = os.environ.get("WAVE_PROXY_LOCAL_MODEL", "qwen2.5:3b-instruct")
LOG = os.environ.get("WAVE_PROXY_LOG", os.path.expanduser("~/.wave-dispatch-proxy.jsonl"))


def _log(rec):
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps({"ts": round(time.time(), 1), **rec}) + "\n")
    except Exception:
        pass


def _prompt_of(body):
    for m in reversed(body.get("messages", [])):
        if m.get("role") == "user":
            c = m.get("content")
            return c if isinstance(c, str) else json.dumps(c)
    return ""


def _trivial(body):
    if body.get("tools") or body.get("functions"):
        return False
    msgs = body.get("messages", [])
    if len([m for m in msgs if m.get("role") == "user"]) != 1:
        return False
    return len(json.dumps(msgs)) < 2000


def _is_local_route(route):
    return route.startswith("local_") or route == "direct"


def _route_local(body):
    """True -> serve from local Ollama. Hosted classifier when licensed, else a safe heuristic.

    Serve local ONLY when BOTH (a) the predicted route is a LOCAL route (never reason/frontier routes)
    AND (b) the classifier is confident (forward is false). A confident frontier route must still
    escalate — failing to check the route would serve frontier-needed prompts locally (dangerous)."""
    if body.get("tools") or body.get("functions"):
        return False  # keep tool turns on upstream unless you extend this
    if LICENSE:
        try:
            req = urllib.request.Request(
                EDGE + "/", data=json.dumps({"prompt": _prompt_of(body)}).encode(),
                headers={"content-type": "application/json", "authorization": "Bearer " + LICENSE},
                method="POST")
            d = json.loads(urllib.request.urlopen(req, timeout=15).read())
            return _is_local_route(d.get("route", "")) and not bool(d.get("forward"))
        except Exception:
            return _trivial(body)  # edge unreachable -> safe heuristic
    return _trivial(body)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        raw = self.rfile.read(n)
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):   # only route on JSON objects; arrays/scalars -> passthrough
                body = {}
        except Exception:
            body = {}
        auth = self.headers.get("Authorization")
        local = self.path.startswith("/v1/chat/completions") and _route_local(body)
        if local:
            out = dict(body); out["model"] = LOCAL_MODEL
            send_data = json.dumps(out).encode()    # local payload (model swapped); `raw` stays the ORIGINAL for upstream fallback
            target = OLLAMA + "/v1/chat/completions"
            hdrs = {"Content-Type": "application/json", "Authorization": "Bearer ollama"}
        else:
            send_data = raw
            target = UPSTREAM + self.path
            hdrs = {"Content-Type": "application/json"}
            if auth:
                hdrs["Authorization"] = auth
        _log({"path": self.path, "served": "local" if local else "upstream", "model": body.get("model")})
        try:
            resp = urllib.request.urlopen(urllib.request.Request(target, data=send_data, headers=hdrs, method="POST"), timeout=600)
        except Exception as e:
            if local:  # local failed -> fall through to upstream, never break the caller
                try:
                    up_hdrs = {"Content-Type": "application/json"}
                    if auth:
                        up_hdrs["Authorization"] = auth
                    resp = urllib.request.urlopen(urllib.request.Request(UPSTREAM + self.path, data=raw, headers=up_hdrs, method="POST"), timeout=600)
                except Exception as e2:
                    self.send_error(502, str(e2)); return
            else:
                self.send_error(502, str(e)); return
        self.send_response(resp.status)
        self.send_header("content-type", resp.headers.get("content-type", "application/json"))
        self.end_headers()
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            try:
                self.wfile.write(chunk)
            except Exception:
                break


def serve():
    mode = "hosted classifier (licensed)" if LICENSE else "local heuristic (no license — trivial only)"
    print(f"wave Dispatch proxy :{PORT}  decision={mode}")
    print(f"  upstream={UPSTREAM}  local={OLLAMA} ({LOCAL_MODEL})")
    print(f"  point your agent:  OPENAI_BASE_URL=http://localhost:{PORT}/v1")
    ThreadingHTTPServer(("127.0.0.1", PORT), _Handler).serve_forever()


if __name__ == "__main__":
    serve()
