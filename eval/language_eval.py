"""Language-detection accuracy on labelled snippets (text only, nothing is executed).

    python eval/language_eval.py               # report on the held-out half (odd rows)
    python eval/language_eval.py --tune        # the tuning half (even rows), with a confusion list
    python eval/language_eval.py --errors 20   # print misdetected samples

Data: CyberNative/Code_Vulnerability_Security_DPO (data/external/raw/cybernative.jsonl, 11 languages,
both the vulnerable and the fixed variant of each row). Signals in codeguard/languages.py were tuned on
the even rows only, so the odd-row number is the honest one.
"""
import argparse
import collections
import json
import os
import re
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from codeguard.router import detect_language  # noqa: E402

LABEL = {"c++": "cpp", "c#": "csharp"}


def _strip_fence(code):
    m = re.search(r"```[\w+#-]*\n(.*?)(```|$)", code, re.S)
    return (m.group(1) if m else code).strip("\n")


def load(tune):
    path = os.path.join(ROOT, "data", "external", "raw", "cybernative.jsonl")
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(l) for l in f]
    out = []
    for i, r in enumerate(rows):
        if (i % 2 == 0) != tune:
            continue
        for v in ("chosen", "rejected"):
            out.append((LABEL.get(r["lang"], r["lang"]), _strip_fence(r[v])))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tune", action="store_true")
    ap.add_argument("--errors", type=int, default=0)
    args = ap.parse_args()
    data = load(args.tune)
    per, conf, errs = collections.Counter(), collections.Counter(), []
    tot = collections.Counter()
    for lang, code in data:
        got = detect_language(code)
        tot[lang] += 1
        if got == lang:
            per[lang] += 1
        else:
            conf[(lang, got)] += 1
            errs.append((lang, got, code))
    n_ok = sum(per.values())
    print(f"{'tuning' if args.tune else 'held-out'} half: {n_ok}/{len(data)} = {n_ok / len(data):.3f}")
    for lang in sorted(tot):
        print(f"  {lang:11} {per[lang] / tot[lang]:.3f}  ({tot[lang]})")
    print("top confusions:", ", ".join(f"{a}->{b}:{n}" for (a, b), n in conf.most_common(12)))
    for lang, got, code in errs[:args.errors]:
        print(f"\n--- {lang} detected as {got} ---\n{code[:400]}")


if __name__ == "__main__":
    main()
