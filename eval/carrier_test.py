"""Carrier robustness test: does detection survive when code is embedded in
another file format?

    python eval/carrier_test.py

Method: take malicious samples that ALREADY exist in our labelled sets (GuardDog
fixtures + the hand-written holdout) and change only their *packaging* — wrap each
in a YAML block value, a JSON config string, a Jupyter notebook cell, and a
Dockerfile step. No new payload text is written. Recall is measured only over
samples that block in plain form, so each number is "fraction still caught after
hiding". Benign samples are wrapped too, to confirm wrapping adds no false
positives. Nothing is executed.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [os.path.join(HERE, ".."), HERE]

from codeguard import analyze  # noqa: E402
import codeguard.engine as engine  # noqa: E402
from evaluate import load  # noqa: E402


def wrap_yaml_key(code):
    return "service:\n  name: worker\n  bootstrap: |\n" + "\n".join("    " + l for l in code.splitlines()) + "\n  port: 80\n"


def wrap_json(code):
    return json.dumps({"job": "sync", "setup": code, "timeout": 30}, indent=2)


def wrap_notebook(code):
    return json.dumps({"cells": [{"cell_type": "code", "source": code.splitlines(keepends=True),
                                  "metadata": {}, "outputs": [], "execution_count": 1}],
                       "metadata": {"kernelspec": {"language": "python", "name": "python3"}},
                       "nbformat": 4, "nbformat_minor": 5}, indent=1)


def wrap_dockerfile(code):
    # Realistic embedding: a heredoc, which preserves multi-line code (unlike && joining).
    return "FROM python:3.12\nWORKDIR /app\nRUN python3 - <<'EOF'\n" + code + "\nEOF\n"


CARRIERS = [("YAML block value", wrap_yaml_key), ("JSON config string", wrap_json),
            ("Jupyter notebook", wrap_notebook), ("Dockerfile heredoc", wrap_dockerfile)]


def main():
    records = load("data/external/guarddog.jsonl") + load(None)
    mal = [r for r in records if r["malicious"]]
    benign = [r for r in records if not r["malicious"]]
    plain_block = [r for r in mal if analyze(r["code"])["verdict"] == "block"]
    base = len(plain_block)
    print(f"{base} malicious samples block in plain form; measuring how many survive each carrier.\n")

    def recall(wrap, enabled):
        saved, engine.extract_embedded = engine.extract_embedded, (engine.extract_embedded if enabled else (lambda *a: iter(())))
        try:
            return sum(analyze(wrap(r["code"]))["verdict"] == "block" for r in plain_block)
        finally:
            engine.extract_embedded = saved

    print(f"{'carrier':22}{'rules only':>14}{'with extractor':>16}")
    for name, wrap in CARRIERS:
        before = recall(wrap, False)
        after = recall(wrap, True)
        print(f"{name:22}{before / base:>13.0%}{after / base:>16.0%}")

    fp = 0
    for name, wrap in CARRIERS:
        fp += sum(analyze(wrap(r["code"]))["verdict"] == "block" for r in benign)
    print(f"\nfalse positives from wrapping {len(benign)} benign samples x {len(CARRIERS)} carriers: {fp}")


if __name__ == "__main__":
    main()
