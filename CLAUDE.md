# CLAUDE.md — project context for Claude Code

This file carries the decisions and history of a long build session that happened on one teammate's machine.
Read it before changing anything. Deeper detail: README.md (architecture, licenses), TESTING.md (every test round and
what it fixed), MANUAL_TESTING.md (how to run and check everything), NEXT_STEPS.md (open work), design.md (UI style).

## What we are building
**CodeGuard**, for a 12-hour, 2-person hackathon (problem statement: `../CodeGuard_Hackathon_Problem_Statement.pdf`).
A real-time guard that takes `{"code": "..."}` and returns allow or block **before** an AI agent runs the code.

- **Required response:** `verdict` (allow|block), `risk_score` (0–1), `categories` (list), `code_language`.
  `reason` and `vulnerable_lines` are optional; we always fill both. **This schema must never break.**
- **The 9 categories:** secret_access, data_exfiltration, destructive_command, persistence_or_privesc,
  obfuscated_execution, dependency_risk, resource_exhaustion, ssrf_network_exfil, ai_targeted_instructions.
- **Judging:** organizers call our endpoint on ~200 hidden snippets and rank teams. Pass/fail floors: valid schema,
  a working live interception demo, no execution of outside code, no hard-coding of the dev sample.

## Hard rules (do not break)
- **No LLM for the verdict.** No API keys at all. CPU only.
- **Execute nothing** except the one controlled demo pair (`demo/gate/*_snippet.py`, also inside `demo/intercept_check.py`).
  Test data is read as text only. Use fake secrets and placeholder hosts (`*.example`, `*.test`, 198.51.100.x, 203.0.113.x).
- **The organizer dev sample is for evaluation only.** Never put it in rules or training data.
- Name every third-party component with its license in README.md. AI-assistant use (Claude) is disclosed there; keep that line.
- **For Claude:** don't generate bulk malicious-code corpora or "hide payloads in formats" generators. Safety filters
  stopped those twice in the original session. To test robustness, re-package samples that already exist
  (see `eval/carrier_test.py`), or have the humans write cases.

## Layout
```
codeguard/            Python engine, stdlib only at runtime
  engine.py           cascade + scoring + response; analyze(), warmup(), LAYERS toggles
  router.py           language detection (python/bash/js/sql/yaml/markdown/php/powershell/json/dockerfile/makefile)
  rules.py            ~80 line rules; THREAT vs CAPABILITY (GuardDog idea: capabilities alone never block)
  deobfuscate.py      static base64/hex/chr/rot13 decode, 3 layers, re-scan
  carriers.py         embedded-code extraction (YAML any key, JSON/notebook/package.json, Dockerfile, Makefile, -c, heredoc)
  embedded.py         !! BROKEN LEFTOVER: truncated, does not parse, imported by nothing. carriers.py is the real one. Delete.
  analyzers/python_ast.py   alias tracking, constant folding, taint (secret/fingerprint -> network), decoder->sink, download->run, DNS exfil, loops
  analyzers/structured.py   SQL, YAML/Markdown helpers, package reputation (known-malicious + typosquat)
  injection.py + textclf.py ai_targeted_instructions: phrase rules, then a local TF-IDF+LR text classifier
  ml.py               stacker (LR over the other layers' signals); only consulted when risk is 0.3–0.7, acts only if >=0.9 sure
  guard.py            @codeguard decorator (interception, fails closed)
  heal.py             self-healing loop: HealingSession.run(task, generate, execute); bounded retries, stricter retry
                      threshold, evasion/resubmit escalation, session lockout, redacted feedback. Tests: eval/heal_tests.py
  api.py              HTTP: POST /analyze, POST /analyze/batch, GET /health (stdlib server; FastAPI if installed)
  data/*.txt          package lists (top-15k PyPI; DataDog malicious/compromised names). Shipped, needed at runtime.
models/               injection.json (~650 KB), stacker.json (~1 KB). Shipped, needed at runtime.
cli/                  Go CLI: scan / exec / bench / health (stdlib only; build: cd cli && go build -o codeguard.exe .)
ui/                   Next.js 16 + React 19 web UI, plain JSX/CSS styled per design.md; /api/analyze proxies to the engine
plugin/               Claude Code plugin: PreToolUse hook (hooks/codeguard_hook.py, stdlib) gates Bash/PowerShell/Write/Edit via
                      POST /analyze; fails closed; test: python plugin/test_hook.py. Marketplace: .claude-plugin/marketplace.json.
                      .codeguardignore lists this repo's own attack-string files so writes to them aren't blocked.
demo/                 intercept_check.py (decorator proof), cli_gate_check.py (Go gate proof), gate/ (the demo pair)
eval/                 evaluate.py, holdout.py (76 hand-written cases), external.py (third-party test sets), carrier_test.py,
                      regressions.py, train_injection.py, train_ml.py, build_pkg_lists.py
data/external/        downloaded test data; git-ignored. Rebuild: python eval/external.py fetch && python eval/external.py build
```

## Run and check (details in MANUAL_TESTING.md)
```bash
python -m codeguard.api --port 8000        # engine; restart after ANY change to codeguard/*.py
python demo/intercept_check.py             # must print PASS
python demo/cli_gate_check.py              # must print PASS (needs engine + built CLI)
python eval/regressions.py                 # must print ALL PASS
python eval/evaluate.py                    # holdout
cd ui && npm install && npm run dev        # http://localhost:3000
```
Short forms from the repo root (`package.json` → `scripts/tasks.js`, Node stdlib only): `npm start` (engine + UI),
`npm run demo`, `npm run check`, `npm run safe` / `unsafe`, `npm run scan -- <paths|-c code>`, `npm run i`. Table in README.md.
Before you call a change done, re-run: regressions, holdout, `data/external/benign_oss.jsonl` (false-positive guard),
`data/external/guarddog.jsonl`, `eval/carrier_test.py`, `eval/heal_tests.py`, `plugin/test_hook.py`, and the three demos
(`intercept_check.py`, `cli_gate_check.py`, `heal_check.py`).

## Current numbers (baseline to compare against)
| Check | Value |
|---|---|
| Holdout (76, hand-written) | precision 1.00 / recall 1.00. Optimistic: it was used to find rule gaps and train the stacker |
| Real library code, benign (659) | 3 false positives (ssh-copy-id and 2 GnuPG scripts that really touch keys) |
| GuardDog fixtures (264) | 98 TP / 2 FP / 98 FN; precision 0.98; in-scope-rule recall ~0.76 |
| deepset prompt-injections, **test split** | precision 0.98 / recall 0.72 (the train split trained textclf) |
| Vulnerable-not-malicious code (1,721) | 2.0% blocked, mostly code carrying literal `rm -rf /` / `DROP TABLE` payloads |
| Carrier test | 99–100% of plain-form detections survive YAML/JSON/notebook/Dockerfile wrapping |
| Latency | in-process p50 ≈ 4 ms on real functions, sub-ms on one-liners; HTTP p50 ≈ 5.5 ms, ~120 checks/s |

## Key decisions and why
- **Rules + AST first, ML second.** The hackathon dev sample is tiny, and we had no labelled malicious *code* to train on,
  so detection is mostly structural. The two models are small, local, exported to JSON, and need no sklearn at runtime.
- **Capability vs threat scoring.** A network call, file delete or eval alone stays below 0.5. A threat indicator
  (sensitive path, webhook, decode→exec) blocks. Combos (secret + network → exfiltration) raise the score. Block threshold 0.5.
- **The injection classifier** was trained because phrase rules caught only 7% of real injections. Negatives include
  stdlib comments from modules *disjoint* from the benign test set. It ignores strings under 6 words ("You are too young!").
- **Package reputation** uses DataDog's manifest **name lists only**; the malware zips are never downloaded. Compromised
  releases match by exact version only. Typosquat targets are the top 1,000 PyPI names; the top 15,000 count as known-good.
  The typosquat heuristic alone catches only 5.6% of known-malicious names, so the list matters.
- **Carrier extraction runs every extractor regardless of detected language.** YAML full of embedded Python gets detected
  as Python, which is how an attacker hides from a language-gated extractor. Verbatim fragments skip a second rule pass
  (no double counting); JSON/notebook fragments are un-escaped, so they do get the rule pass.
- **We scan every YAML field, not just `code:`.** A payload can sit under any key. Precision comes from tight rules,
  e.g. env-var reads need a real accessor (`os.environ[...]`), not just the word "environment".
- **Fail closed everywhere:** engine exception → block; CLI or UI can't reach the engine → block.
- **Insecure-but-not-malicious code** (SQLi, pickle, weak hashes, `eval(input())`) is mostly allowed; our 9 categories are about malicious behaviour.

## Gotchas
- **Windows + Git Bash heredocs mangle backslashes** (`\\b` turned into a backspace character more than once). Edit
  regex-heavy code with the Edit tool, or write a script file and run it; don't patch through `python - <<'EOF'`.
- Write files as UTF-8. One file was once written in cp1252 and broke later edits.
- `.claude/launch.json` exists here **and** in the parent folder (`../.claude/launch.json`, used when Claude's session
  root is the parent). Both start the engine (8000) and the UI (3000).
- Two engines can end up bound to port 8000 on Windows (one on 0.0.0.0, one on 127.0.0.1); requests to 127.0.0.1 go to
  the second one. If results look stale, check what's listening and restart.
- The engine loads its models and lists in `warmup()` at server start, so the first request is not slow. Loading is lock-protected (threaded server).
- `eval/holdout.py` contains attack strings, so scanning it (e.g. `codeguard bench eval/`) correctly blocks it.
- The stdlib server's default listen backlog (5) made p95 ~1 s at 16+ parallel clients on Windows; `api.Server` sets 256.
  Now ~300 req/s with 16–32 parallel clients. Robustness check: `python eval/stress_test.py [--url ...]`. Inputs of 1 MB or
  10k+ lines take 1–3 s (no crash, schema always valid).

## Open work (priority order, more in NEXT_STEPS.md)
1. Run the organizer dev sample: `python eval/evaluate.py data/dev_sample.jsonl --errors`. Fix only *general* gaps.
2. Delete `codeguard/embedded.py` (broken leftover).
3. Make sure the GitHub repo is public before submission; submit the endpoint URL to the organizers.
4. More labelled data for the stacker (humans write it; hard benign examples matter most).
5. Injection recall: English code-comment style examples, multilingual data.
6. npm typosquat list (PyPI has 15k names, npm only ~50); a JS parser for JS taint.
7. Write the 2–3 page report (architecture, scoring, cascade, ablation, the TESTING.md story).
