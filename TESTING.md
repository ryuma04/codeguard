# Testing CodeGuard on third-party data

Goal: measure the detector on code **we did not write**, then fix weaknesses with general logic, not per-sample patches.
Kaggle was not used because it needs a signed-in account with an API token. All sources below are public, need no login, and have permissive licenses.

## Test sets (`python eval/external.py fetch && python eval/external.py build`)

| File | Source | License | How it is built |
|---|---|---|---|
| `data/external/benign_oss.jsonl` | Python stdlib + installed packages (fastapi, starlette, pydantic, sklearn, pip, uvicorn, anyio, click, joblib); Git for Windows shell scripts | PSF / each package's OSS license | 600 random functions (6–60 lines) + 59 whole `#!/bin/sh` scripts, all labelled benign |
| `data/external/guarddog.jsonl` | [DataDog/guarddog](https://github.com/DataDog/guarddog) `tests/analyzer/sourcecode` | Apache-2.0 | fixtures split into blocks; `# ruleid:` → malicious, `# ok:` → benign; `threat-*` files are whole-file positives |
| `data/external/prompt_injections.jsonl` | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 | each text placed in a comment / docstring / string of a small harmless function (5 wrappers, Python and JS) |

Downloaded data lives in `data/external/raw/` (git-ignored). It is only read as text. Nothing from it is imported or executed.

Separation rules:
- GuardDog fixtures and library code are **test only**. They were never used to train either model.
- The deepset **train** split trains the injection classifier. Only its **test** split counts as an unseen score.
- The classifier's code-prose negatives come from stdlib modules (`xml`, `unittest`, `tkinter`, …) that are **disjoint** from the benign test set's modules.

## Round 1: baseline (before any change)

| Set | Precision | Recall | FPR |
|---|---|---|---|
| benign_oss (659) | – | – | 1.4% (9) |
| GuardDog (264) | 0.88 | 0.26 | 10.3% |
| prompt injections (662, all) | 0.85 | 0.07 | 0.8% |

## Weaknesses found and how they were fixed

| Weakness (from `--errors`) | Fix | Type |
|---|---|---|
| Comments mentioning "cookies" flagged as browser credential theft | browser-store rule made case-sensitive and path-anchored; fixed a broken character class | rule |
| Prose like "the host task …" with a backtick flagged as DNS exfil | DNS rule requires command position | rule |
| `id_*.pub` (public keys) treated as secrets | public keys excluded from the SSH-key rule | rule |
| `os.dup2(logfile.fileno())` flagged as a reverse shell | requires a socket-like object | rule |
| "you're inheriting from the model" flagged as AI role-play | role-switch phrases only ("you are now", "act as", …) | rule |
| **Real-world prompt injections almost all missed** (only 7% recall) | **trained a local text classifier** (`textclf.py`, `eval/train_injection.py`), threshold set for ≤0.2% false alarms on code prose | **ML** |
| `os.system(b64decode(..))`, `subprocess.run(["python","-c", b64decode(..)])` missed | decoder-into-shell-sink detection | AST |
| `exec(payload)` where `payload = requests.get(..).content` missed | variables holding downloaded data are tracked; executing them blocks | AST taint |
| `exec("".join(chr(c) for c in [...]))` not folded | folding through methods on literals and call results | AST |
| `exec("<base64 literal>")`, `eval("\145\166\141\154")` missed | exec/eval of encoded/escaped literals | AST |
| `__import__("os").__dict__["startfile"]`, `os.__getattribute__(..)` missed | dunder-lookup obfuscation rule; `os.startfile` as a shell sink | rule + AST |
| download → write `wb` → `chmod`/`system`/`Popen` missed | snippet-level download-save-run detection; `urlretrieve` of executables | AST |
| `getaddrinfo(f"{hostname}.evil…")`, `resolver.resolve(f"{token}…")` missed | DNS-exfiltration via f-string lookups | AST |
| hostname/username collected and POSTed missed | host fingerprint as a taint source (Python); fingerprint + network combo (JS/PowerShell) | AST + combo |
| `JSON.stringify(process["env"])`, `push({..process.env})` missed | env-serialisation rule widened | rule |
| JS `spawn(.., {detached: true, stdio: 'ignore'}).unref()` missed | hidden detached process → persistence | combo |
| `exec(open("version.py").read())` (common in setup.py) flagged | reading a *local file* no longer counts as "fetched code" | AST |

## Round 2: after fixes

| Set | Precision | Recall | FPR |
|---|---|---|---|
| benign_oss (659) | – | – | **0.5% (3)** |
| GuardDog, all rules (264) | **0.98** | 0.51 | 2.9% |
| GuardDog, rules within our 9 categories (114 malicious) | – | **0.76** | – |
| deepset **test split** only (116, never trained on) | **0.98** | **0.72** | 1.8% |
| hand-written holdout (76) | 1.00 | 1.00 | 0% |

The interception demo still passes (`python demo/intercept_check.py` prints PASS).

## Round 3: user-suggested datasets

| Dataset | Decision | Why |
|---|---|---|
| hugovk/top-pypi-packages | **runtime**: top-15k known-good, top-1k typosquat targets | replaces a ~90-name list |
| DataDog/malicious-software-packages-dataset | **runtime, names only** (`manifest.json`) | 1,816 PyPI + 46,546 npm malicious names, 2,092 compromised releases matched by version only. Samples are real malware in password-protected zips: not downloaded |
| deepset/prompt-injections | already used | trains the injection classifier |
| CyberNative/Code_Vulnerability_Security_DPO | **test only** | vulnerable vs fixed code written by an LLM: buggy, not malicious, so it can't teach "malicious" |
| s2e-lab/SecurityEval | **test only** | insecure code by CWE, no license declared |

Built by `python eval/build_pkg_lists.py` (package lists) and `python eval/external.py fetch && build` → `data/external/vulnerable_code.jsonl`.

**Vulnerable-code block rate** (all labelled benign, because the intent isn't malicious):

| Group | Blocked |
|---|---|
| CyberNative, fixed versions (800) | 2.0% |
| CyberNative, vulnerable versions (800) | 2.4% |
| SecurityEval insecure code (121) | 0% |

Weaknesses found and fixed:
- The injection classifier fired on short UI strings ("You are too young!"), so it now needs ≥ 6 words.
- Any `ldap://` URL counted as SSRF. It's now limited to gopher/dict/tftp, `file:///` system paths, and `${jndi:…}` lookups.
- Binary data written as `\x..` escapes counted as obfuscated execution. It's now below the block threshold on its own.

Most remaining blocks are code that literally contains `system('rm -rf /')` or `'; DROP TABLE users; --` as a payload fed to `eval`/SQL. Running that in an agent sandbox could really cause damage, so we keep blocking it.

**Package reputation check**:
- Known-malicious and compromised names: exact match, so not a measure of generalization.
- Typosquat heuristic alone, as if the name were new: 102/1,816 (5.6%) of known-malicious PyPI names. Most malicious packages use fresh names rather than look-alikes, which is why the name list matters.
- Legit mid-popularity names (ranks 1,000–15,000) the heuristic would flag if they weren't on the known-good list: 3.0%. At runtime they *are* on the list, so they're allowed.
- Latency for an unknown package name: 80 ms down to ~2 ms (early-exit edit distance, precomputed targets).

Re-check after round 3: library-code false alarms 0.5% (unchanged), GuardDog precision 0.98 / recall 0.50, deepset test split precision 0.98 / recall 0.72 (unchanged), holdout 1.00 / 1.00, demo PASS.

## What is still missed, and why

- **GuardDog out-of-scope rules** (12/82 caught): screenshots, clipboard, steganography, `cmd-overwrite`, and DLL hijacking via ctypes. Their "malicious" cases are often harmless commands like `os.system("ls")` in a `setup.py`, which GuardDog flags because of *where* they run. Our task judges what the code does, so these stay allowed on purpose.
- **GuardDog fragments without context**: some blocks are a single line referring to undefined names (`exec(decode("bar"))`). We score these 0.4 (allow): suspicious, but not enough to block alone.
- **Injection misses**: mostly German-language and indirect prompts ("now you are Ted, the devout Muslim…"). More multilingual training data would help.
- **Remaining false positives**: `ssh-copy-id` and two GnuPG admin scripts. They really do read `~/.ssh` / `~/.gnupg`, so blocking them inside an AI agent is defensible.

## Reproduce
```bash
pip install scikit-learn            # training only
python eval/external.py fetch       # ~1 MB download: GuardDog sparse clone + HF rows API
python eval/external.py build
python eval/train_injection.py
python eval/train_ml.py
python eval/evaluate.py data/external/benign_oss.jsonl --errors
python eval/evaluate.py data/external/guarddog.jsonl --group-by rule --errors
python eval/evaluate.py data/external/prompt_injections.jsonl
python eval/evaluate.py --ablation
```
