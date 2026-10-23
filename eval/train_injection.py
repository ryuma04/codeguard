"""Train the ai_targeted_instructions text classifier -> models/injection.json.

    python eval/external.py fetch          # once: downloads deepset/prompt-injections
    python eval/train_injection.py

Positives: deepset/prompt-injections TRAIN split, label 1 (Apache-2.0).
Negatives: the same split's label 0, plus comments / docstrings / string
literals from Python stdlib modules that are NOT used by the benign test set
(eval/external.py PACKAGES), so the model learns what normal code prose looks like.
The deepset TEST split is never seen here; it is used for evaluation only.
"""
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
    with open(os.path.join(RAW, "prompt_injections.jsonl"), encoding="utf-8") as f:
        rows = [json.loads(l) for l in f if l.strip()]
    train = [r for r in rows if r["split"] == "train"]
    prose = code_prose()
    X = [r["text"] for r in train] + prose
    y = [int(r["label"]) for r in train] + [0] * len(prose)
    is_prose = [0] * len(train) + [1] * len(prose)
    print(f"train: {sum(y)} injections, {len(y) - sum(y)} negatives ({len(prose)} from code prose)")

    def fit(texts, labels):
        vec = TfidfVectorizer(analyzer=textclf.analyzer, sublinear_tf=True, min_df=2, max_features=20000)
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
             "trained_on": len(y), "source": "deepset/prompt-injections train split (Apache-2.0) + stdlib code prose"}
    os.makedirs(os.path.dirname(textclf.MODEL_PATH), exist_ok=True)
    with open(textclf.MODEL_PATH, "w", encoding="utf-8") as f:
        json.dump(model, f, ensure_ascii=False, separators=(",", ":"))
    print(f"saved {os.path.normpath(textclf.MODEL_PATH)} ({os.path.getsize(textclf.MODEL_PATH) // 1024} KB, {len(names)} features)")


if __name__ == "__main__":
    main()
