"""Step 5: ML stacker — consulted only for ambiguous snippets.

The model does not read raw code. It reads what the earlier layers found
(per-category threat/capability strength, finding counts, decode depth,
language) plus a few cheap text statistics, and learns when a mid-range rule
score is real and when it is noise.

Trained offline with scikit-learn LogisticRegression (eval/train_ml.py) and
exported to models/stacker.json, so inference is a pure-Python dot product:
no sklearn import at runtime, ~0.02 ms per call.
"""
import json
import math
import os
import re
import threading

from .findings import CATEGORIES, THREAT, CAPABILITY

MODEL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models", "stacker.json")
AMBIGUOUS = (0.3, 0.7)      # only this risk band is handed to the model
CONFIDENT = 0.9             # ...and the model only acts when this sure
LANGS = ["python", "bash", "javascript", "sql", "yaml", "markdown", "php", "powershell", "unknown"]
_model = None
_loaded = False
_lock = threading.Lock()


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def featurize(code, language, findings, decoded_layers=0):
    f = {}
    for cat in CATEGORIES:
        t = [x.weight for x in findings if x.category == cat and x.kind == THREAT]
        c = [x.weight for x in findings if x.category == cat and x.kind == CAPABILITY]
        f[f"t_{cat}"] = max(t, default=0.0)
        f[f"c_{cat}"] = max(c, default=0.0)
    f["n_threat"] = math.log1p(sum(x.kind == THREAT for x in findings))
    f["n_cap"] = math.log1p(sum(x.kind == CAPABILITY for x in findings))
    f["n_threat_cats"] = len({x.category for x in findings if x.kind == THREAT}) / 9
    f["from_ast"] = float(any(x.source.startswith("ast") for x in findings))
    f["from_combo"] = float(any(x.source == "combo" for x in findings))
    f["decoded_layers"] = decoded_layers / 3
    strings = re.findall(r"['\"]([^'\"\n]{12,})['\"]", code)
    f["max_str_entropy"] = max((_entropy(s) for s in strings), default=0.0) / 6
    f["long_token"] = float(bool(re.search(r"[A-Za-z0-9+/=]{60,}", code)))
    f["log_len"] = math.log1p(len(code)) / 10
    f["non_alnum_ratio"] = sum(not ch.isalnum() and not ch.isspace() for ch in code) / max(1, len(code))
    # The model was trained on these nine; newer router labels map to what they used to be detected as.
    language = language if language in LANGS else "javascript" if language == "typescript" else "unknown"
    for lang in LANGS:
        f[f"lang_{lang}"] = float(language == lang)
    return f


def _load():
    # Locked double-check: see textclf._load (threaded server, no half-loaded model).
    global _model, _loaded
    if not _loaded:
        with _lock:
            if not _loaded:
                try:
                    with open(MODEL_PATH) as fh:
                        _model = json.load(fh)
                except (OSError, ValueError):
                    _model = None
                _loaded = True
    return _model


def available():
    return _load() is not None


def predict(features):
    """Probability that the snippet is malicious, or None if no model is trained."""
    m = _load()
    if m is None:
        return None
    z = m["intercept"] + sum(m["coef"].get(k, 0.0) * v for k, v in features.items())
    return 1 / (1 + math.exp(-max(-60.0, min(60.0, z))))  # clamp: exp() overflows past ~709


def adjust(risk, features):
    """Inside the ambiguous band only, let a *confident* model move the risk.

    The model is trained on little data, so it may only tip a borderline
    snippet when it is sure (p >= CONFIDENT or p <= 1 - CONFIDENT); otherwise
    the rule score stands.
    """
    if not (AMBIGUOUS[0] <= risk < AMBIGUOUS[1]):
        return risk, None
    p = predict(features)
    if p is None:
        return risk, None
    if p >= CONFIDENT or p <= 1 - CONFIDENT:
        return round(0.5 * risk + 0.5 * p, 3), round(p, 3)
    return risk, round(p, 3)
