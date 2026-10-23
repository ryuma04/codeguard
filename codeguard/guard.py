"""Interception: a decorator that gates a function on CodeGuard's verdict.

If the verdict is block (or the engine errors / times out) the wrapped function
is NEVER called. Uses the in-process engine by default, or a running HTTP
service when CODEGUARD_URL is set.
"""
import functools
import json
import os
import urllib.request


class CodeGuardBlocked(Exception):
    def __init__(self, result):
        self.result = result
        super().__init__(f"CodeGuard blocked execution: {result.get('reason')}")


def check(code: str, timeout: float = 2.0) -> dict:
    url = os.environ.get("CODEGUARD_URL")
    try:
        if url:
            req = urllib.request.Request(url.rstrip("/") + "/analyze", data=json.dumps({"code": code}).encode(),
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        from .engine import analyze
        return analyze(code)
    except Exception as e:  # fail closed
        return {"verdict": "block", "risk_score": 1.0, "categories": [], "code_language": "unknown",
                "reason": f"guard unavailable, failing closed: {type(e).__name__}"}


def codeguard(func=None, *, code_arg: int = 0, on_verdict=None):
    """Decorate any function whose `code_arg`-th argument is code about to run."""
    def deco(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            code = kwargs.get("code", args[code_arg] if len(args) > code_arg else "")
            result = check(code)
            if on_verdict:
                on_verdict(result)
            if result.get("verdict") != "allow":
                raise CodeGuardBlocked(result)
            return fn(*args, **kwargs)
        return wrapper
    return deco(func) if func else deco
