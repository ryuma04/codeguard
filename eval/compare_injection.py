"""Compare injection-classifier candidates through the FULL engine, on held-out data only.

    python eval/compare_injection.py models/injection.json path/to/candidate.json ...

For each candidate model it reports:
  recall   deepset TEST split, LLMail TEST slice, yanismiraoui TEST slice
           (each text placed in a code comment/docstring/string, as an agent's code would carry it)
  false+   LLMail TEST non-attacks, real library code, vulnerable-not-malicious code,
           team benign cases (if data/team_cases.jsonl exists), hand-written holdout benign
A candidate should only replace the live model if it raises recall without raising false positives.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), HERE]

from codeguard import analyze, textclf  # noqa: E402
from evaluate import load  # noqa: E402
from external import _WRAPPERS  # noqa: E402
import injection_data  # noqa: E402

EXT = os.path.join(HERE, "..", "data", "external")


def use_model(path):
    textclf.MODEL_PATH = path
    textclf._loaded = False
    textclf._model = None
    return textclf.available()


def wrap(text, i):
    return _WRAPPERS[i % len(_WRAPPERS)](" ".join(text.replace('"', "'").replace("*/", "").split()))


def blocked(codes):
    return sum(analyze(c)["verdict"] == "block" for c in codes)


def build_sets():
    sets = {}
    pi = load(os.path.join(EXT, "prompt_injections.jsonl"))
    test = [r for r in pi if "/test/" in str(r["id"])]
    sets["deepset test (inj)"] = ("recall", [r["code"] for r in test if r["malicious"]])
    sets["deepset test (normal)"] = ("false+", [r["code"] for r in test if not r["malicious"]])
    lm = injection_data.llmail("test")
    sets["LLMail test (attacks)"] = ("recall", [wrap(t, i) for i, (t, l) in enumerate(lm) if l == 1])
    sets["LLMail test (non-attacks)"] = ("false+", [wrap(t, i) for i, (t, l) in enumerate(lm) if l == 0])
    sets["yanis test (multilingual)"] = ("recall", [wrap(t, i) for i, (t, _) in enumerate(injection_data.yanis("test"))])
    for name, fn in (("library code", "benign_oss.jsonl"), ("vulnerable code", "vulnerable_code.jsonl")):
        p = os.path.join(EXT, fn)
        if os.path.exists(p):
            sets[name] = ("false+", [r["code"] for r in load(p)])
    team = os.path.join(HERE, "..", "data", "team_cases.jsonl")
    if os.path.exists(team):
        sets["team benign"] = ("false+", [r["code"] for r in load(team) if not r["malicious"]])
    hold = load(None)
    sets["holdout benign"] = ("false+", [r["code"] for r in hold if not r["malicious"]])
    sets["holdout malicious"] = ("recall", [r["code"] for r in hold if r["malicious"]])
    return sets


def main():
    models = sys.argv[1:] or [textclf.MODEL_PATH]
    sets = build_sets()
    results = {}
    for m in models:
        if not use_model(m):
            sys.exit(f"cannot load model {m}")
        results[m] = {name: blocked(codes) for name, (_, codes) in sets.items()}
    width = max(len(os.path.basename(m)) for m in models) + 2
    print(f"{'set':28}{'n':>6}  " + "".join(f"{os.path.basename(m):>{width}}" for m in models))
    for name, (kind, codes) in sets.items():
        n = len(codes)
        cells = "".join(f"{results[m][name] / max(1, n):>{width}.1%}" for m in models)
        print(f"{name:28}{n:>6}  {cells}   {'(higher is better)' if kind == 'recall' else '(lower is better)'}")
    use_model(os.path.join(HERE, "..", "models", "injection.json"))


if __name__ == "__main__":
    main()
