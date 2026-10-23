"""Out-of-sample test of ai_targeted_instructions on two third-party prompt-injection datasets.
Text only: nothing is executed. Neither dataset is used for rules or training here.

  * microsoft/llmail-inject-challenge (MIT): attack submissions from an adaptive prompt-injection
    challenge (positives, random sample) + its emails_for_fp_tests.json (benign emails, negatives).
  * yanismiraoui/prompt_injections (Apache-2.0): short injections in EN/FR/DE/ES/IT/PT/RO (positives).

Each text is embedded in code the same way eval/external.py does for deepset (comment, docstring,
string literal), because the judges send code, not bare prompts.

    python eval/injection_external.py fetch     # once, into data/external/raw/ (git-ignored)
    python eval/injection_external.py           # evaluate the in-process engine
"""
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), HERE]
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from external import RAW, _WRAPPERS  # noqa: E402

ROWS = "https://datasets-server.huggingface.co/rows?dataset={}&config=default&split={}&offset={}&length=100"
LLMAIL = "microsoft/llmail-inject-challenge"
YANIS = "yanismiraoui/prompt_injections"
N_LLMAIL_PAGES = 25          # x100 rows, random offsets
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(url):
    for attempt in range(5):
        try:
            with OPENER.open(url, timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429 or attempt == 4:
                raise
            time.sleep(3 * (attempt + 1))


def fetch():
    os.makedirs(RAW, exist_ok=True)
    rng = random.Random(11)
    out = os.path.join(RAW, "llmail_sample.jsonl")
    if not os.path.exists(out):
        rows = []
        for split, total in (("Phase1", 370_000), ("Phase2", 100_000)):
            for _ in range(N_LLMAIL_PAGES // 2 + 1):
                page = json.loads(_get(ROWS.format(LLMAIL, split, rng.randrange(0, total - 100))))
                rows += [{"text": (x["row"].get("subject") or "") + "\n" + (x["row"].get("body") or ""),
                          "scenario": x["row"].get("scenario"), "split": split} for x in page["rows"]]
        seen, uniq = set(), []
        for r in rows:
            key = " ".join(r["text"].split())
            if key and key not in seen:
                seen.add(key)
                uniq.append(r)
        fp = json.loads(_get(f"https://huggingface.co/datasets/{LLMAIL}/resolve/main/data/emails_for_fp_tests.json"))
        benign = fp if isinstance(fp, list) else next(v for v in fp.values() if isinstance(v, list))
        with open(out, "w", encoding="utf-8") as f:
            for r in uniq:
                f.write(json.dumps({**r, "label": 1}, ensure_ascii=False) + "\n")
            for e in benign:
                text = e if isinstance(e, str) else "\n".join(str(e.get(k, "")) for k in ("subject", "body") if k in e) or json.dumps(e)
                f.write(json.dumps({"text": text, "label": 0, "split": "fp_tests"}, ensure_ascii=False) + "\n")
        print(f"llmail: {len(uniq)} unique attacks, {len(benign)} benign emails")
    out = os.path.join(RAW, "yanis_injections.jsonl")
    if not os.path.exists(out):
        rows, off = [], 0
        while True:
            page = json.loads(_get(ROWS.format(YANIS, "train", off)))
            rows += [x["row"]["prompt_injections"] for x in page["rows"]]
            off += 100
            if off >= page["num_rows_total"]:
                break
        with open(out, "w", encoding="utf-8") as f:
            for t in rows:
                f.write(json.dumps({"text": t, "label": 1}, ensure_ascii=False) + "\n")
        print(f"yanis: {len(rows)} injections")


def load(name):
    with open(os.path.join(RAW, name), encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def wrap(text, i):
    t = " ".join(str(text).replace('"', "'").replace("*/", "").split())
    return _WRAPPERS[i % len(_WRAPPERS)](t)


def evaluate():
    from codeguard.engine import analyze, warmup
    warmup()
    sets = {"LLMail attacks": [r for r in load("llmail_sample.jsonl") if r["label"] == 1],
            "LLMail benign emails": [r for r in load("llmail_sample.jsonl") if r["label"] == 0],
            "yanis multilingual": load("yanis_injections.jsonl")}
    report = {}
    for name, rows in sets.items():
        hit = inj = 0
        misses, short = [], 0
        for i, r in enumerate(rows):
            res = analyze(wrap(r["text"], i))
            flagged = res["verdict"] == "block"
            inj += "ai_targeted_instructions" in res["categories"]
            hit += flagged
            short += len(str(r["text"]).split()) < 6
            if (flagged != bool(r["label"])) and len(misses) < 6:
                misses.append(" ".join(str(r["text"]).split())[:110])
        n = len(rows)
        rate = hit / max(1, n)
        label = "recall (blocked)" if rows and rows[0]["label"] else "false-positive rate"
        report[name] = {"n": n, label: round(rate, 3), "as ai_targeted_instructions": round(inj / max(1, n), 3),
                        "under 6 words": short}
        print(f"\n{name}: n={n}  {label}={rate:.3f}  tagged ai_targeted_instructions={inj / max(1, n):.3f}  (<6 words: {short})")
        for m in misses:
            print(f"   {'missed' if rows[0]['label'] else 'false alarm'}: {m}")
    return report


if __name__ == "__main__":
    if sys.argv[1:] == ["fetch"]:
        fetch()
    else:
        evaluate()
