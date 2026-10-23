# Handoff: what to do next (in priority order)

Done (testing phase):
- third-party test sets (`eval/external.py`): GuardDog fixtures, deepset prompt-injections, real library code;
- injection text classifier (`codeguard/textclf.py` + `eval/train_injection.py` + `models/injection.json`);
- structural fixes found by testing. Results and method are in TESTING.md.
- package reputation from user-suggested datasets: top-15k PyPI names + DataDog malicious/compromised name lists
  (`eval/build_pkg_lists.py` → `codeguard/data/`); SecurityEval + CyberNative as a vulnerable-code false-positive test.

Done earlier:
- `eval/evaluate.py`: metrics, per-category, latency, `--url`, `--ablation`, `--group-by`;
- `eval/holdout.py`: 76 hand-written cases;
- ML stacker (`codeguard/ml.py` + `eval/train_ml.py` + `models/stacker.json`), with layer toggles in `engine.LAYERS`.

1. **Organizer dev sample**: save it to `data/dev_sample.jsonl` and run `python eval/evaluate.py data/dev_sample.jsonl --errors`.
   Fix *general* gaps only. Never paste dev snippets into rules or training data.
2. **More training data for the stacker**: add your own labelled snippets (jsonl: code, label, categories) and run
   `python eval/train_ml.py data/extra.jsonl`. Hard benign examples matter most.
3. **Injection recall** (0.72 on the unseen test split): add English code-comment style injections and multilingual data, then retrain.
4. **Minimal UI**: a single HTML page that POSTs to /analyze and shows verdict, score, categories, reason, latency.
5. **npm typosquatting**: add a top-npm-packages list (the PyPI side uses 15k names, npm only ~50).
6. **JS parser**: add `esprima` (BSD-2) for JS taint, like the Python analyzer.
7. **Write-up** (2–3 pages): architecture, capability/threat scoring, cascade, ablation table, testing story from TESTING.md.
8. Optional: Go CLI gate, PEP 578 audit hook in guard.py, PHP/composer.json pack.

Sanity: `python demo/intercept_check.py` must print PASS.
