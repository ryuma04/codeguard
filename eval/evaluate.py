"""Evaluate CodeGuard on a labelled snippet set.

    python eval/evaluate.py                         # built-in hand-written holdout set
    python eval/evaluate.py data/dev_sample.jsonl   # organizer dev sample (jsonl / json / csv)
    python eval/evaluate.py data/dev.jsonl --url http://localhost:8000   # test the live endpoint
    python eval/evaluate.py --ablation              # rules-only vs +AST vs +ML

Accepted record fields (first one found wins):
    code:        code | snippet | content | input | text
    label:       label | verdict | expected_verdict | expected | is_malicious | malicious
                 ("block"/"malicious"/"unsafe"/1/true => malicious)
    categories:  categories | category | expected_categories | labels  (list or comma string)

Reports precision / recall / FPR / F1 for the block decision, per-category
recall/precision, schema validity and latency percentiles.
"""
import argparse
import csv
import json
import os
import statistics
import sys
import time
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from codeguard.findings import CATEGORIES  # noqa: E402

_CODE_KEYS = ("code", "snippet", "content", "input", "text")
_LABEL_KEYS = ("label", "verdict", "expected_verdict", "expected", "is_malicious", "malicious")
_CAT_KEYS = ("categories", "category", "expected_categories", "labels")
_MAL = {"block", "malicious", "unsafe", "bad", "1", "true", "yes", "attack"}


def _first(rec, keys, default=None):
    for k in keys:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return default


def normalize(rec, idx):
    if isinstance(rec.get("expected"), dict):  # {"code":..., "expected": {"verdict":..., "categories": [...]}}
        rec = {**rec, **rec["expected"]}
    code = _first(rec, _CODE_KEYS, "")
    cats = _first(rec, _CAT_KEYS, [])
    if isinstance(cats, str):
        cats = [c.strip() for c in cats.replace(";", ",").replace("|", ",").split(",") if c.strip()]
    cats = [c for c in cats if c in CATEGORIES]
    raw = _first(rec, _LABEL_KEYS)
    if raw is None:
        mal = bool(cats)
    else:
        mal = str(raw).strip().lower() in _MAL
    return {"id": rec.get("id", idx), "code": code, "malicious": mal, "categories": cats if mal else [], "raw": rec}


def load(path):
    if path is None:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from holdout import load as load_holdout
        recs = load_holdout()
    elif path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
    elif path.endswith(".csv"):
        with open(path, encoding="utf-8", newline="") as f:
            recs = list(csv.DictReader(f))
    else:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        recs = data if isinstance(data, list) else data.get("items") or data.get("snippets") or data.get("data") or []
    return [normalize(r, i) for i, r in enumerate(recs)]


def valid_schema(r):
    return (r.get("verdict") in ("allow", "block")
            and isinstance(r.get("risk_score"), (int, float)) and 0 <= r["risk_score"] <= 1
            and isinstance(r.get("categories"), list)
            and isinstance(r.get("code_language"), str))


def make_caller(url):
    if not url:
        from codeguard.engine import analyze
        return analyze

    def call(code):
        req = urllib.request.Request(url.rstrip("/") + "/analyze", data=json.dumps({"code": code}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    return call


def pct(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))]


def run(records, call):
    rows = []
    for rec in records:
        t0 = time.perf_counter()
        try:
            res = call(rec["code"])
        except Exception as e:  # count as a schema failure
            res = {"error": repr(e)}
        ms = (time.perf_counter() - t0) * 1000
        rows.append((rec, res, ms))
    return rows


def metrics(rows):
    tp = fp = tn = fn = 0
    bad_schema = 0
    cat_tp = {c: 0 for c in CATEGORIES}
    cat_fn = {c: 0 for c in CATEGORIES}
    cat_fp = {c: 0 for c in CATEGORIES}
    for rec, res, _ in rows:
        if not valid_schema(res):
            bad_schema += 1
        pred = res.get("verdict") == "block"
        if rec["malicious"] and pred:
            tp += 1
        elif rec["malicious"]:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
        got = set(res.get("categories") or [])
        for c in CATEGORIES:
            if c in rec["categories"]:
                cat_tp[c] += c in got
                cat_fn[c] += c not in got
            elif c in got:
                cat_fp[c] += 1
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec_ = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec_ / (prec + rec_) if prec + rec_ else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / max(1, len(rows))
    # Category-level micro F1 (exact category matching on malicious samples).
    ctp, cfp, cfn = sum(cat_tp.values()), sum(cat_fp.values()), sum(cat_fn.values())
    cprec = ctp / (ctp + cfp) if ctp + cfp else 0.0
    crec = ctp / (ctp + cfn) if ctp + cfn else 0.0
    lat = [ms for _, _, ms in rows]
    return {
        "n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": prec, "recall": rec_, "f1": f1, "fpr": fpr, "accuracy": acc,
        "category_micro_precision": cprec, "category_micro_recall": crec,
        "category_micro_f1": 2 * cprec * crec / (cprec + crec) if cprec + crec else 0.0,
        "per_category": {c: {"support": cat_tp[c] + cat_fn[c], "recall": cat_tp[c] / (cat_tp[c] + cat_fn[c]) if cat_tp[c] + cat_fn[c] else None,
                             "false_pos": cat_fp[c]} for c in CATEGORIES},
        "schema_invalid": bad_schema,
        "latency_ms": {"mean": statistics.mean(lat) if lat else 0, "p50": pct(lat, 50), "p95": pct(lat, 95), "max": max(lat, default=0)},
    }


def report(m, title):
    print(f"\n=== {title} ===")
    print(f"samples={m['n']}  TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']}  schema_invalid={m['schema_invalid']}")
    print(f"precision={m['precision']:.3f}  recall={m['recall']:.3f}  F1={m['f1']:.3f}  "
          f"FPR={m['fpr']:.3f}  accuracy={m['accuracy']:.3f}")
    print(f"category micro: precision={m['category_micro_precision']:.3f} recall={m['category_micro_recall']:.3f} "
          f"F1={m['category_micro_f1']:.3f}")
    print(f"latency ms: mean={m['latency_ms']['mean']:.2f} p50={m['latency_ms']['p50']:.2f} "
          f"p95={m['latency_ms']['p95']:.2f} max={m['latency_ms']['max']:.2f}")
    print(f"{'category':<26}{'support':>8}{'recall':>9}{'cat_FP':>8}")
    for c, v in m["per_category"].items():
        r = "-" if v["recall"] is None else f"{v['recall']:.2f}"
        print(f"{c:<26}{v['support']:>8}{r:>9}{v['false_pos']:>8}")


def show_errors(rows, limit=40):
    print("\n--- mistakes ---")
    n = 0
    for rec, res, _ in rows:
        pred = res.get("verdict") == "block"
        missing = set(rec["categories"]) - set(res.get("categories") or [])
        if pred != rec["malicious"] or (pred and missing):
            kind = "FN" if rec["malicious"] and not pred else "FP" if pred and not rec["malicious"] else "CAT"
            snippet = rec["code"].strip().replace("\n", " | ")[:110]
            print(f"[{kind}] id={rec['id']} gold={rec['categories']} got={res.get('categories')} "
                  f"risk={res.get('risk_score')} :: {snippet}")
            n += 1
            if n >= limit:
                break


def by_group(rows, field):
    groups = {}
    for rec, res, _ in rows:
        g = groups.setdefault(str(rec["raw"].get(field, "?")), [0, 0, 0, 0])  # mal, caught, benign, false_pos
        pred = res.get("verdict") == "block"
        if rec["malicious"]:
            g[0] += 1
            g[1] += pred
        else:
            g[2] += 1
            g[3] += pred
    print(f"\n{field:<42}{'malicious':>10}{'caught':>8}{'benign':>8}{'FP':>5}")
    for k in sorted(groups):
        m, c, b, f = groups[k]
        print(f"{k:<42}{m:>10}{c:>8}{b:>8}{f:>5}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", nargs="?", help="jsonl/json/csv file (default: built-in holdout set)")
    ap.add_argument("--url", help="evaluate a running endpoint instead of the in-process engine")
    ap.add_argument("--errors", action="store_true", help="print misclassified samples")
    ap.add_argument("--ablation", action="store_true", help="compare rules-only / +structural / +ML")
    ap.add_argument("--json-out", help="write metrics JSON here")
    ap.add_argument("--group-by", help="also break results down by this record field (e.g. rule)")
    a = ap.parse_args()

    records = load(a.path)
    title = a.path or "built-in holdout set"
    if a.ablation and not a.url:
        from codeguard import engine
        results = {}
        for name, layers in (("rules only", {"structural": False, "ml": False}),
                             ("rules + structural", {"structural": True, "ml": False}),
                             ("full cascade (+ML)", {"structural": True, "ml": True})):
            engine.LAYERS.update(layers)
            m = metrics(run(records, engine.analyze))
            report(m, f"{title} — {name}")
            results[name] = m
        engine.LAYERS.update({"structural": True, "ml": True})
    else:
        rows = run(records, make_caller(a.url))
        results = metrics(rows)
        report(results, title)
        if a.group_by:
            by_group(rows, a.group_by)
        if a.errors:
            show_errors(rows, limit=80)
    if a.json_out:
        with open(a.json_out, "w") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
