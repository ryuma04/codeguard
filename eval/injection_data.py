"""Extra prompt-injection data for the ai_targeted_instructions classifier.

Sources (downloaded into data/external/raw/, git-ignored; read as text only):
  * microsoft/llmail-inject-challenge (MIT): Phase 2 labelled unique submissions.
    attack_attempt True -> injection, False -> not an attack, "Unclear" -> dropped.
    Plus emails_for_fp_tests.json: 203 normal emails (negatives from the same domain).
  * yanismiraoui/prompt_injections (Apache-2.0): 1,034 short injections in 7 languages
    (positives only).

Every source is split train/test by a hash of the text, so the split is fixed, reproducible and
independent of the order rows arrive in. Test slices are never used for training.

    python eval/injection_data.py fetch      # download (~70 MB)
    python eval/injection_data.py stats      # sizes per split
"""
import csv
import hashlib
import json
import os
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "data", "external", "raw")
LLMAIL = os.path.join(RAW, "llmail")
YANIS = os.path.join(RAW, "yanis")
MAX_CHARS = 2000   # the engine does not classify longer comment blocks, so do not train on them either

URLS = {
    os.path.join(LLMAIL, "phase2.json"): "https://huggingface.co/datasets/microsoft/llmail-inject-challenge/resolve/main/data/labelled_unique_submissions_phase2.json",
    os.path.join(LLMAIL, "fp_emails.json"): "https://huggingface.co/datasets/microsoft/llmail-inject-challenge/resolve/main/data/emails_for_fp_tests.json",
    os.path.join(YANIS, "prompt_injections.csv"): "https://huggingface.co/datasets/yanismiraoui/prompt_injections/resolve/main/prompt_injections.csv",
}


def _in_test(text, fraction):
    h = int(hashlib.sha1(text.encode("utf-8", "replace")).hexdigest()[:8], 16)
    return (h % 1000) < fraction * 1000


def _split(rows, split, fraction):
    return [r for r in rows if _in_test(r[0], fraction) == (split == "test")]


def _clean_email(text):
    # The challenge wraps every email in the same template; drop the template words, keep subject + body.
    text = re.sub(r"^\s*Subject of the email:\s*", "", text)
    text = re.sub(r"\s*Body:\s*", " ", text, count=1)
    return " ".join(text.split())


def llmail(split="train", fraction=0.2):
    """[(text, label)] from LLMail-Inject. label 1 = injection attempt, 0 = not one."""
    with open(os.path.join(LLMAIL, "phase2.json"), encoding="utf-8") as f:
        labelled = json.load(f)
    rows = []
    for text, meta in labelled.items():
        a = str(meta.get("attack_attempt")).strip().lower()
        if a not in ("true", "false"):
            continue  # "Unclear": no reliable label
        t = _clean_email(text)
        if 20 <= len(t) <= MAX_CHARS:
            rows.append((t, int(a == "true")))
    with open(os.path.join(LLMAIL, "fp_emails.json"), encoding="utf-8") as f:
        for text in json.load(f):
            t = _clean_email(str(text))
            if 20 <= len(t) <= MAX_CHARS:
                rows.append((t, 0))
    return _split(rows, split, fraction)


def yanis(split="train", fraction=0.3):
    """[(text, 1)] from yanismiraoui/prompt_injections (all positives)."""
    with open(os.path.join(YANIS, "prompt_injections.csv"), encoding="utf-8") as f:
        rows = [(" ".join(r["prompt_injections"].split()), 1) for r in csv.DictReader(f)]
    rows = [r for r in rows if len(r[0]) >= 12]
    return _split(rows, split, fraction)


def fetch():
    for path, url in URLS.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            urllib.request.urlretrieve(url, path)
    print("downloaded:", ", ".join(os.path.basename(p) for p in URLS))


def stats():
    for name, fn in (("llmail", llmail), ("yanis", yanis)):
        for split in ("train", "test"):
            rows = fn(split)
            pos = sum(l for _, l in rows)
            print(f"{name:7} {split:5} {len(rows):6} rows  {pos:6} injections  {len(rows) - pos:5} negatives")


if __name__ == "__main__":
    {"fetch": fetch, "stats": stats}.get(sys.argv[1] if len(sys.argv) > 1 else "stats", stats)()
