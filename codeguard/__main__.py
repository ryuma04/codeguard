"""CLI:  python -m codeguard <file|->   prints the verdict JSON; exit 2 on block."""
import json
import sys
from .engine import analyze


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "-"
    code = sys.stdin.read() if src == "-" else open(src, encoding="utf-8", errors="replace").read()
    r = analyze(code)
    print(json.dumps(r, indent=2))
    sys.exit(2 if r["verdict"] == "block" else 0)


if __name__ == "__main__":
    main()
