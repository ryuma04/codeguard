"""Interception proof: a blocked snippet NEVER executes.

Only the one controlled safe/unsafe pair below is ever passed to exec().
(Swap in the organizer-provided pair when it is shared.)
Each snippet's only side effect is creating a marker file in a temp folder.
The unsafe one *looks* malicious to static analysis (base64 -> exec, a
'rm -rf ~' string) but its decoded body only writes a marker and echoes text.
"""
import base64
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from codeguard import codeguard, CodeGuardBlocked  # noqa: E402

WORKDIR = tempfile.mkdtemp(prefix="codeguard_demo_")
SAFE_MARKER = os.path.join(WORKDIR, "marker_safe.txt")
UNSAFE_MARKER = os.path.join(WORKDIR, "marker_unsafe.txt")

SAFE_SNIPPET = f"""
total = sum(range(10))
with open({SAFE_MARKER!r}, "w") as f:
    f.write(f"safe snippet ran, total={{total}}")
"""

_hidden = f"open({UNSAFE_MARKER!r}, 'w').write('UNSAFE SNIPPET RAN'); print('would run: rm -rf ~')"
UNSAFE_SNIPPET = f"""
import base64
payload = base64.b64decode({base64.b64encode(_hidden.encode()).decode()!r})
exec(payload)
"""

verdicts = {}


@codeguard(on_verdict=lambda r: verdicts.__setitem__("last", r))
def execute_code(code: str):
    """The risky function an agent would call. Guarded: only runs on 'allow'."""
    exec(compile(code, "<agent-code>", "exec"), {})


def run(name, code):
    t0 = time.perf_counter()
    try:
        execute_code(code)
        status = "EXECUTED"
    except CodeGuardBlocked:
        status = "BLOCKED (never executed)"
    r = verdicts["last"]
    print(f"[{name}] verdict={r['verdict']} risk={r['risk_score']} categories={r['categories']} "
          f"lines={r.get('vulnerable_lines')} -> {status}  ({(time.perf_counter() - t0) * 1000:.1f} ms)")
    if r["verdict"] == "block":
        print(f"    reason: {r['reason']}")


if __name__ == "__main__":
    print(f"Working folder: {WORKDIR}\n")
    run("safe  ", SAFE_SNIPPET)
    run("unsafe", UNSAFE_SNIPPET)
    safe_ok, unsafe_absent = os.path.exists(SAFE_MARKER), not os.path.exists(UNSAFE_MARKER)
    print(f"\nmarker_safe.txt exists:   {safe_ok}")
    print(f"marker_unsafe.txt exists: {not unsafe_absent}")
    ok = safe_ok and unsafe_absent
    print("\nPASS: safe code ran, blocked code never executed." if ok else "\nFAIL")
    sys.exit(0 if ok else 1)
