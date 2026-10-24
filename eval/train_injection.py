"""Train the ai_targeted_instructions text classifier -> models/injection.json.

    python eval/external.py fetch          # once: downloads deepset/prompt-injections
    python eval/injection_data.py fetch    # once: LLMail-Inject + yanismiraoui (optional extra data)
    python eval/train_injection.py [--llmail 4000] [--yanis] [--out PATH]

Positives: deepset/prompt-injections TRAIN split, label 1 (Apache-2.0).
Negatives: the same split's label 0, plus comments / docstrings / string
literals from Python stdlib modules that are NOT used by the benign test set
(eval/external.py PACKAGES), so the model learns what normal code prose looks like.
--llmail N adds N sampled injection attempts from LLMail-Inject's TRAIN slice plus all of its
  train-slice non-attacks and normal emails (MIT). --yanis adds yanismiraoui's TRAIN slice (Apache-2.0).
Test slices (deepset test split, LLMail/yanis hashed test slices) are never seen here.
"""
import argparse
import io
import json
import os
import random
import sys
import sysconfig
import tokenize

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), HERE]

from sklearn.feature_extraction.text import TfidfVectorizer  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import train_test_split  # noqa: E402

from codeguard import textclf  # noqa: E402
from external import RAW  # noqa: E402

NEG_MODULES = ["xml", "unittest", "multiprocessing", "tkinter", "idlelib", "ctypes", "lib2to3", "tomllib",
               "zoneinfo", "wsgiref", "xmlrpc", "dbm", "curses", "venv", "ensurepip"]
TARGET_FPR = 0.002   # on held-out code prose


def code_prose(limit=4000, seed=3):
    stdlib = sysconfig.get_paths()["stdlib"]
    out = []
    for mod in NEG_MODULES:
        for d, _, files in os.walk(os.path.join(stdlib, mod)):
            for fn in files:
                if not fn.endswith(".py"):
                    continue
                try:
                    src = open(os.path.join(d, fn), encoding="utf-8").read()
                    toks = list(tokenize.generate_tokens(io.StringIO(src).readline))
                except Exception:
                    continue
                for t in toks:
                    if t.type in (tokenize.COMMENT, tokenize.STRING):
                        text = t.string.strip("#'\"rbuf \n")
                        if len(text) >= 20 and len(text.split()) >= 4:
                            out.append(text[:500])
    random.Random(seed).shuffle(out)
    return out[:limit]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llmail", type=int, default=0, help="LLMail-Inject injection attempts to sample (0 = none)")
    ap.add_argument("--yanis", action="store_true", help="add yanismiraoui multilingual injections")
    ap.add_argument("--out", default=textclf.MODEL_PATH, help="where to write the model JSON")
    ap.add_argument("--max-features", type=int, default=20000, help="vocabulary size (model size grows with it)")
    ap.add_argument("--deepset-weight", type=int, default=1,
                    help="repeat deepset train rows N times so short direct injections are not drowned out by long emails")
    a = ap.parse_args()

    with open(os.path.join(RAW, "prompt_injections.jsonl"), encoding="utf-8") as f:
        rows = [json.loads(l) for l in f if l.strip()]
    train = [r for r in rows if r["split"] == "train"] * max(1, a.deepset_weight)
    prose = code_prose()
    X = [r["text"] for r in train] + prose
    y = [int(r["label"]) for r in train] + [0] * len(prose)
    is_prose = [0] * len(train) + [1] * len(prose)
    sources = ["deepset/prompt-injections train split (Apache-2.0)", "stdlib code prose"]
    if a.llmail or a.yanis:
        import injection_data
        extra = []
        if a.llmail:
            lm = injection_data.llmail("train")
            pos = [r for r in lm if r[1] == 1]
            random.Random(7).shuffle(pos)
            extra += pos[:a.llmail] + [r for r in lm if r[1] == 0]
            sources.append(f"LLMail-Inject phase 2 train slice: {min(a.llmail, len(pos))} attacks + non-attacks/normal emails (MIT)")
        if a.yanis:
            extra += injection_data.yanis("train")
            sources.append("yanismiraoui/prompt_injections train slice (Apache-2.0)")
        X += [t for t, _ in extra]
        y += [l for _, l in extra]
        is_prose += [0] * len(extra)
    print(f"train: {sum(y)} injections, {len(y) - sum(y)} negatives ({len(prose)} from code prose)")

    def fit(texts, labels):
        vec = TfidfVectorizer(analyzer=textclf.analyzer, sublinear_tf=True, min_df=2, max_features=a.max_features)
        clf = LogisticRegression(C=4.0, class_weight="balanced", max_iter=3000)
        clf.fit(vec.fit_transform(texts), labels)
        return vec, clf

    # 1) pick the threshold on a validation split: keep false alarms on code prose ~TARGET_FPR
    Xtr, Xva, ytr, yva, _, pva = train_test_split(X, y, is_prose, test_size=0.25, random_state=0, stratify=y)
    vec, clf = fit(Xtr, ytr)
    p = clf.predict_proba(vec.transform(Xva))[:, 1]
    prose_scores = sorted((s for s, isp in zip(p, pva) if isp), reverse=True)
    k = max(0, int(len(prose_scores) * TARGET_FPR))
    thr = max(0.5, float(prose_scores[k]) + 1e-3)
    tp = sum(s >= thr and l for s, l in zip(p, yva))
    print(f"validation: threshold={thr:.3f} recall={tp / max(1, sum(yva)):.3f} "
          f"prose_FPR={sum(s >= thr for s in prose_scores) / max(1, len(prose_scores)):.4f}")

    # 2) final fit on everything, export for pure-Python inference
    vec, clf = fit(X, y)
    names = vec.get_feature_names_out()
    model = {"intercept": float(clf.intercept_[0]), "threshold": round(thr, 4),
             "idf": {n: round(float(v), 4) for n, v in zip(names, vec.idf_)},
             "coef": {n: round(float(w), 4) for n, w in zip(names, clf.coef_[0]) if abs(w) > 1e-4},
             "trained_on": len(y), "source": " + ".join(sources)}
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False, separators=(",", ":"))
    print(f"saved {os.path.normpath(a.out)} ({os.path.getsize(a.out) // 1024} KB, {len(names)} features)")


if __name__ == "__main__":
    main()
