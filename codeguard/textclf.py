"""Small local text classifier for ai_targeted_instructions.

Scores one comment / docstring / string literal: "is this text trying to
instruct an AI reader?". Word 1-2 grams + char 3-5 grams, TF-IDF, logistic
regression. Trained offline (eval/train_injection.py, scikit-learn) and
exported to models/injection.json; inference here is pure Python.
"""
import json
import math
import os
import re
import threading

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "injection.json")
_WORD = re.compile(r"[a-zA-ZäöüßÄÖÜ']+")
_model = None
_loaded = False
_lock = threading.Lock()


def analyzer(text):
    """Shared by training and inference so features match exactly."""
    t = " ".join(text.lower().split())
    words = _WORD.findall(t)
    feats = [f"w:{w}" for w in words]
    feats += [f"b:{a}_{b}" for a, b in zip(words, words[1:])]
    padded = f" {t} "
    for n in (3, 4, 5):
        feats += [f"c:{padded[i:i + n]}" for i in range(len(padded) - n + 1)]
    return feats


def _load():
    # Double-checked under a lock: the HTTP server is threaded, and a request that
    # saw "loaded" before the model was actually assigned would silently skip the
    # classifier and give a different verdict.
    global _model, _loaded
    if not _loaded:
        with _lock:
            if not _loaded:
                try:
                    with open(MODEL_PATH, encoding="utf-8") as fh:
                        _model = json.load(fh)
                except (OSError, ValueError):
                    _model = None
                _loaded = True
    return _model


def available():
    return _load() is not None


def threshold():
    m = _load()
    return m["threshold"] if m else 1.0


def score(text):
    """P(text is an instruction aimed at an AI), or None without a model."""
    m = _load()
    if m is None:
        return None
    counts = {}
    for f in analyzer(text):
        if f in m["idf"]:
            counts[f] = counts.get(f, 0) + 1
    if not counts:
        return 1 / (1 + math.exp(-m["intercept"]))
    vec = {f: (1 + math.log(c)) * m["idf"][f] for f, c in counts.items()}   # sublinear tf * idf
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    z = m["intercept"] + sum(v / norm * m["coef"].get(f, 0.0) for f, v in vec.items())
    return 1 / (1 + math.exp(-z))
