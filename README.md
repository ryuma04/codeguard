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
| Injection text classifier: word 1–2 grams + char 3–5 grams, TF-IDF, logistic regression | `models/injection.json` | ~650 KB, 20k features | `deepset/prompt-injections` **train split** (Apache-2.0) + 4,000 comments/docstrings from stdlib modules not used in testing | scores comment/string text for `ai_targeted_instructions` |
| Stacker: logistic regression, 37 features | `models/stacker.json` | ~1 KB | 76-snippet hand-written holdout | tie-breaker for ambiguous risk 0.3–0.7 |

Retrain: `python eval/train_injection.py` and `python eval/train_ml.py`.

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

Efficiency: pure Python, no GPU, no network. Median latency 0.5–3 ms per snippet, p95 7–12 ms. The slowest cases are 300–800-line shell scripts, up to ~110 ms. Model files total ~650 KB, and the package-reputation lists in `codeguard/data/` ~1.3 MB (loaded once, on first use).

## Components & licenses
| Component | Use | License |
|---|---|---|
| Python stdlib (ast, tokenize, re, http.server) | parsing, server | PSF |
| FastAPI / uvicorn (optional) | HTTP | MIT / BSD-3 |
| scikit-learn | trains both models offline (not needed at runtime) | BSD-3 |
| DataDog GuardDog | capability/threat idea + rule ideas, adapted not copied; its rule-test fixtures used **as a test set only** | Apache-2.0 |
| deepset/prompt-injections (Hugging Face) | train split trains the injection classifier; test split for evaluation | Apache-2.0 |
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
