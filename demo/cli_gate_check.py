"""Interception proof through the Go CLI gate: `codeguard exec -- python <snippet>`.

Same controlled safe/unsafe pair as demo/intercept_check.py, but the gate is a
separate binary in front of the interpreter: on block it exits 2 and the
python process is never started, so the unsafe marker file cannot appear.

    python -m codeguard.api --port 8000      # terminal 1: warm engine
    python demo/cli_gate_check.py            # terminal 2
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
GATE = os.path.join(HERE, "gate")
BIN = os.path.join(ROOT, "cli", "codeguard.exe" if os.name == "nt" else "codeguard")


def main():
    if not os.path.exists(BIN):
        sys.exit(f"build the CLI first: cd cli && go build -o {os.path.basename(BIN)} .")
    out = tempfile.mkdtemp(prefix="codeguard_gate_")
    env = dict(os.environ, CODEGUARD_DEMO_OUT=out)
    print(f"Working folder: {out}\n")
    codes = {}
    for name in ("safe", "unsafe"):
        snippet = os.path.join(GATE, f"{name}_snippet.py")
        cmd = [BIN, "exec", "--", sys.executable, snippet]
        print(f"$ codeguard exec -- python demo/gate/{name}_snippet.py")
        r = subprocess.run(cmd, env=env, capture_output=True, text=True)
        for line in (r.stderr + r.stdout).strip().splitlines():
            print("   ", line)
        print(f"    exit code: {r.returncode}\n")
        codes[name] = r.returncode
    safe_ok = os.path.exists(os.path.join(out, "marker_safe.txt"))
    unsafe_absent = not os.path.exists(os.path.join(out, "marker_unsafe.txt"))
    print(f"marker_safe.txt exists:   {safe_ok}")
    print(f"marker_unsafe.txt exists: {not unsafe_absent}")
    ok = safe_ok and unsafe_absent and codes["safe"] == 0 and codes["unsafe"] == 2
    print("\nPASS: gate ran the safe snippet and never started the blocked one." if ok else "\nFAIL")
    shutil.rmtree(out, ignore_errors=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
