"""Train the ML stacker (codeguard/ml.py) and export it to models/stacker.json.

    python eval/train_ml.py                              # built-in holdout set only
    python eval/train_ml.py data/extra.jsonl ...         # plus any of your own labelled files

Do NOT pass the organizer dev sample here if you also report dev-sample
metrics: keep it for evaluation only.
Needs scikit-learn at training time only; inference is pure Python.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), HERE]

from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.model_selection import StratifiedKFold, cross_val_predict  # noqa: E402

from codeguard import engine, ml  # noqa: E402
from evaluate import load  # noqa: E402


def main():
    records = load(None)
    for path in sys.argv[1:]:
        records += load(path)
    feats = [engine.features(r["code"]) for r in records]
    names = sorted(feats[0])
    X = [[f[k] for k in names] for f in feats]
    y = [int(r["malicious"]) for r in records]
    print(f"training on {len(y)} samples ({sum(y)} malicious), {len(names)} features")

    clf = LogisticRegression(C=0.5, class_weight="balanced", max_iter=2000)
    folds = min(5, sum(y), len(y) - sum(y))
    if folds >= 2:
        pred = cross_val_predict(clf, X, y, cv=StratifiedKFold(folds, shuffle=True, random_state=0))
        tp = sum(p and t for p, t in zip(pred, y))
        fp = sum(p and not t for p, t in zip(pred, y))
        fn = sum(t and not p for p, t in zip(pred, y))
        print(f"{folds}-fold CV (model alone): precision={tp / max(1, tp + fp):.3f} recall={tp / max(1, tp + fn):.3f}")

    clf.fit(X, y)
    model = {"intercept": float(clf.intercept_[0]),
             "coef": {k: round(float(w), 5) for k, w in zip(names, clf.coef_[0]) if abs(w) > 1e-6},
             "trained_on": len(y), "ambiguous_band": ml.AMBIGUOUS}
    os.makedirs(os.path.dirname(ml.MODEL_PATH), exist_ok=True)
    with open(ml.MODEL_PATH, "w") as f:
        json.dump(model, f, indent=1)
    top = sorted(model["coef"].items(), key=lambda kv: -abs(kv[1]))[:8]
    print("top weights:", ", ".join(f"{k}={v:+.2f}" for k, v in top))
    print(f"saved {os.path.normpath(ml.MODEL_PATH)} ({os.path.getsize(ml.MODEL_PATH)} bytes)")


if __name__ == "__main__":
    main()
