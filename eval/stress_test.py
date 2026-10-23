"""Robustness test: pathological but harmless inputs. Does the engine stay fast, keep the schema, and not
block benign code just because it is odd? Nothing is executed; every input is benign (or empty/garbage).

    python eval/stress_test.py                      # in-process
    python eval/stress_test.py --url http://127.0.0.1:8000   # through the HTTP endpoint (+ a concurrency burst)
"""
import base64
import json
import os
import random
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

SLOW_MS = 1000          # a judge client may time out; anything above this is flagged
rnd = random.Random(7)


def nest_b64(text, n):
    for _ in range(n):
        text = base64.b64encode(text.encode()).decode()
    return text


CASES = {
    # --- size
    "empty": "",
    "whitespace only": " \n\t\r\n" * 1000,
    "1 MB single line of letters": "a" * 1_000_000,
    "20k-line python file": "\n".join(f"x{i} = {i} + 1" for i in range(20_000)),
    "5k small functions": "\n".join(f"def f{i}(a):\n    return a * {i}\n" for i in range(5_000)),
    "minified JS 500 KB": "var a=1;" + "function g(b){return b+1};" * 20_000,
    "SQL 10k statements": "\n".join(f"SELECT id, name FROM users WHERE id = {i};" for i in range(10_000)),
    "markdown 1 MB": ("# Title\n\nSome *text* with `code`.\n\n" * 25_000),
    # --- nesting (AST / JSON recursion)
    "10k nested parens": "x = " + "(" * 10_000 + "1" + ")" * 10_000,
    "5k nested lists": "x = " + "[" * 5_000 + "]" * 5_000,
    "deep JSON 10k": "[" * 10_000 + "]" * 10_000,
    "deep YAML indentation": "\n".join("  " * i + f"k{i}:" for i in range(2_000)) + " 1",
    "notebook with 1000 cells": json.dumps({"cells": [{"cell_type": "code", "source": [f"print({i})\n"]} for i in range(1_000)],
                                            "metadata": {}, "nbformat": 4, "nbformat_minor": 5}),
    "Dockerfile 5k RUN lines": "FROM python:3.12-slim\n" + "\n".join(f"RUN echo step{i}" for i in range(5_000)),
    # --- encodings / garbage
    "binary noise (latin-1)": bytes(rnd.randrange(256) for _ in range(200_000)).decode("latin-1"),
    "null bytes": "print('a')\x00\x00\x00" * 1000,
    "unicode soup": "".join(chr(rnd.randrange(0x20, 0x2FFF)) for _ in range(100_000)),
    "emoji + CJK identifiers": "名前 = '😀'\nprint(名前 * 3)\n" * 500,
    "CRLF + tabs mix": "def f():\r\n\treturn 1\r\n" * 5000,
    "benign base64, 10 layers": f"msg = '{nest_b64('hello world, this is a harmless note', 10)}'\nprint(len(msg))",
    "1 MB benign base64 blob": f"DATA = '{base64.b64encode(os.urandom(750_000)).decode()}'\n",
    "huge int literal": "x = " + "9" * 100_000,
    # --- regex stress (long runs that bounded quantifiers must not choke on)
    "word 'ignore' x100k": "# " + "ignore " * 100_000,
    "'mark as' x50k": "# " + "mark this as " * 50_000,
    "long comment no newline": "# " + "abc, " * 200_000,
    "200k spaces then token": " " * 200_000 + "rm",
    "repeated quotes": "'" * 100_001,
    "unterminated triple quote": 'x = """' + "text\n" * 50_000,
    "path-like spam": "/".join(["home"] * 100_000),
}


def local_analyze():
    from codeguard.engine import analyze, warmup
    warmup()
    return analyze


def http_analyze(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(code):
        req = urllib.request.Request(url.rstrip("/") + "/analyze", data=json.dumps({"code": code}).encode(),
                                     headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=30) as r:
            return json.loads(r.read())
    return call


def valid(r):
    return (r.get("verdict") in ("allow", "block") and isinstance(r.get("risk_score"), (int, float))
            and 0 <= r["risk_score"] <= 1 and isinstance(r.get("categories"), list)
            and isinstance(r.get("code_language"), str) and r["code_language"] != "")


def main():
    url = sys.argv[sys.argv.index("--url") + 1] if "--url" in sys.argv else None
    analyze = http_analyze(url) if url else local_analyze()
    problems = 0
    print(f"{'case':34} {'ms':>8}  verdict  risk  language     note")
    for name, code in CASES.items():
        t0 = time.perf_counter()
        try:
            r = analyze(code)
            err = ""
        except Exception as e:
            r, err = {}, f"{type(e).__name__}: {str(e)[:80]}"
        ms = (time.perf_counter() - t0) * 1000
        notes = []
        if err:
            notes.append("EXCEPTION " + err)
        elif not valid(r):
            notes.append("INVALID SCHEMA")
        if ms > SLOW_MS:
            notes.append("SLOW")
        if r.get("verdict") == "block":
            notes.append("BLOCKED (benign input): " + (r.get("reason") or "")[:70])
        problems += bool(notes)
        print(f"{name:34} {ms:8.1f}  {r.get('verdict', '-'):7}  {r.get('risk_score', '-'):<4}  "
              f"{r.get('code_language', '-'):11}  {'; '.join(notes)}")

    if url:  # concurrency burst: 200 requests, 16 at a time
        codes = [CASES["5k small functions"][:2000], "print(1)", "SELECT 1;", "ls -la"] * 50
        t0 = time.perf_counter()
        with ThreadPoolExecutor(16) as ex:
            res = list(ex.map(analyze, codes))
        wall = time.perf_counter() - t0
        bad = sum(not valid(r) for r in res)
        problems += bad > 0
        print(f"\nconcurrency: {len(res)} requests x16 in {wall:.2f}s ({len(res) / wall:.0f}/s), invalid={bad}")

    print(f"\n{problems} case(s) with problems" if problems else "\nNO PROBLEMS")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
