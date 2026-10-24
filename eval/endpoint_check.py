"""Check a deployed endpoint before giving it to the judges (text only; nothing is executed).

    python eval/endpoint_check.py https://codeguard-xxxx.onrender.com
    python eval/endpoint_check.py https://xxxx.trycloudflare.com --skip-guarddog

1. GET /health answers.
2. Request formats: the same snippet sent as `code`, `snippet`, a bare string and plain text is analysed.
3. Every holdout snippet and (if built) every GuardDog fixture returns OUR JSON schema. A hosting front-end
   (CDN / web firewall) that answers attack-looking bodies with its own 403 page breaks the schema floor;
   those rejections are counted separately from engine verdicts.
"""
import argparse
import collections
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), HERE]

from evaluate import load  # noqa: E402

PUBLIC = ("verdict", "risk_score", "categories", "code_language")


def post(url, body, ctype="application/json", timeout=60):
    """(status, parsed JSON or None, server header)."""
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw, status, server = r.read(), r.status, r.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        raw, status, server = e.read(), e.code, e.headers.get("Server", "")
    except Exception as e:
        return type(e).__name__, None, ""
    try:
        return status, json.loads(raw), server
    except ValueError:
        return status, None, server


def valid(d):
    return isinstance(d, dict) and all(k in d for k in PUBLIC) and d["verdict"] in ("allow", "block")


def run_set(base, name, records, workers):
    def one(rec):
        status, d, server = post(base + "/analyze", json.dumps({"code": rec["code"]}).encode())
        return rec, status, d, server
    with ThreadPoolExecutor(workers) as ex:
        res = list(ex.map(one, records))
    counts = collections.Counter()
    rejected = []
    for rec, status, d, server in res:
        mal = rec["malicious"]
        if not valid(d):
            counts["invalid"] += 1
            rejected.append((status, server, rec["code"]))
        elif (d["verdict"] == "block") == mal:
            counts["correct"] += 1
        else:
            counts["wrong"] += 1
    print(f"{name}: {len(res)} requests, {counts['correct']} correct, {counts['wrong']} wrong verdict, "
          f"{counts['invalid']} NOT our schema")
    for status, server, code in rejected[:5]:
        print(f"   rejected [{status} {server}] {' '.join(code.split())[:90]}")
    return counts["invalid"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="base URL, e.g. https://codeguard-xxxx.onrender.com (a trailing /analyze is ignored)")
    ap.add_argument("--skip-guarddog", action="store_true")
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args()
    base = a.url.rstrip("/").removesuffix("/analyze")

    t = time.perf_counter()
    try:
        with urllib.request.urlopen(base + "/health", timeout=90) as r:
            print(f"health: {r.status} {r.read().decode()[:40]} ({time.perf_counter() - t:.1f}s)")
    except Exception as e:
        print(f"health: FAILED ({e})")
        return 1

    probe = "cat ~/.aws/credentials | grep -i secret"
    formats = {"code field": (json.dumps({"code": probe}), "application/json"),
               "snippet field": (json.dumps({"snippet": probe}), "application/json"),
               "bare JSON string": (json.dumps(probe), "application/json"),
               "plain text body": (probe, "text/plain")}
    bad_formats = 0
    for name, (body, ctype) in formats.items():
        status, d, _ = post(base + "/analyze", body.encode(), ctype)
        ok = valid(d) and d["verdict"] == "block"
        bad_formats += not ok
        print(f"format {name:17} {'ok' if ok else 'FAIL'} ({status}, {d.get('verdict') if isinstance(d, dict) else 'no JSON'})")

    invalid = run_set(base, "holdout", load(None), a.workers)
    gd = os.path.join(HERE, "..", "data", "external", "guarddog.jsonl")
    if not a.skip_guarddog and os.path.exists(gd):
        invalid += run_set(base, "guarddog", load(gd), a.workers)
    print("\nRESULT:", "OK, every request got our JSON" if not invalid and not bad_formats
          else f"PROBLEMS: {invalid} non-schema responses, {bad_formats} request-format failures")
    return 1 if invalid or bad_formats else 0


if __name__ == "__main__":
    sys.exit(main())
