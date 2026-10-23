"""HTTP service exposing the fixed schema.

POST /analyze        {"code": "..."}            -> verdict JSON
POST /analyze/batch  {"items": [{"code": ...}]} -> {"results": [...]}
GET  /health

Uses FastAPI if installed (`uvicorn codeguard.api:app`), otherwise a
zero-dependency stdlib server (`python -m codeguard.api --port 8000`).
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .engine import analyze, warmup

PUBLIC_KEYS = ("verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines")


def public(result, debug=False):
    return result if debug else {k: result[k] for k in PUBLIC_KEYS} | {"latency_ms": result["latency_ms"]}


try:  # ---------- FastAPI flavour ----------
    from fastapi import FastAPI, Body

    app = FastAPI(title="CodeGuard", version="0.1.0")
    warmup()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/analyze")
    def analyze_ep(payload: dict = Body(...), debug: bool = False):
        return public(analyze(payload.get("code", "")), debug)

    @app.post("/analyze/batch")
    def batch_ep(payload: dict = Body(...), debug: bool = False):
        items = payload.get("items") or payload.get("snippets") or []
        return {"results": [public(analyze(i.get("code", "") if isinstance(i, dict) else i), debug) | ({"id": i.get("id")} if isinstance(i, dict) and "id" in i else {}) for i in items]}
except ImportError:
    app = None


class Handler(BaseHTTPRequestHandler):  # ---------- stdlib flavour ----------
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        self._send(200, {"status": "ok"}) if self.path.startswith("/health") else self._send(404, {"error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            payload = {}
        if not isinstance(payload, dict):  # e.g. a bare JSON string or list: answer, don't crash
            payload = {}
        debug = "debug=1" in self.path or "debug=true" in self.path
        if self.path.startswith("/analyze/batch"):
            items = payload.get("items") or payload.get("snippets") or []
            res = []
            for i in items:
                r = public(analyze(i.get("code", "") if isinstance(i, dict) else i), debug)
                if isinstance(i, dict) and "id" in i:
                    r["id"] = i["id"]
                res.append(r)
            self._send(200, {"results": res})
        elif self.path.startswith("/analyze") or self.path == "/":
            self._send(200, public(analyze(payload.get("code", "") if isinstance(payload, dict) else ""), debug))
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()
    warmup()
    print(f"CodeGuard listening on http://{a.host}:{a.port}  (POST /analyze)", flush=True)
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
