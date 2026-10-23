CodeGuard — Hackathon Build Plan
23 Oct 2026 · @Euphatics
Goal and ground rules
We build CodeGuard: a warm, in-memory service that takes {"code": "..."} and returns allow or block in milliseconds. A Go CLI sits in front of it as a single-binary client and execution gate. We are ranked against other teams on a hidden set of about 160 snippets, so precision and recall on unseen code decide the result.
Response contract (must never break): verdict, risk_score (0–1), categories, code_language are required. reason and vulnerable_lines are optional, and we fill both.
Pass/fail floors:
• The response schema is valid on every call, including on garbage input.
• The interception demo works live.
• No code runs except the one controlled demo pair. This is why the Docker sandbox is out (see the last section).
• Nothing is hard-coded to the public dev sample.
Hard constraints: no LLM API at any point, CPU only, every borrowed component named with its license in the README, and a keyword blocklist alone is not enough.
Architecture
The detection engine stays in Python, and Go is the client and execution gate. The organizers call an HTTP endpoint, and Python gives us ast, scikit-learn and the parsers for free. Rewriting the analyzers in Go would cost most of the 10 hours. The Go CLI talks to the warm engine over localhost, so we avoid the slow per-check subprocess the problem statement warns about.
Cheap steps run first. Step 5 runs only when the rules and the AST disagree or the score sits near the threshold. The comment stream feeds the decision directly.
Go CLI commands: codeguard scan <file|-> prints the verdict JSON. codeguard exec -- <cmd> <file> gates and then runs the command. codeguard bench <dir> replays a folder of snippets and prints latency. If Go falls behind, the Python decorator alone still satisfies the demo floor.
Language coverage
The organizers named six languages, so each gets a structural analyzer. Anything else falls through to the shared rule layer and the ML model, which are language-agnostic. That covers the "works for all languages" note.
Language
Detected by
Structural analyzer
What it catches best
Python
ast.parse succeeds, imports, def
stdlib ast visitor with alias tracking and constant folding
taint flows, eval/exec chains, getattr tricks, unbounded loops
Bash
shebang, $, pipes, common binaries
stdlib shlex tokens per pipeline stage
curl | sh, rm -rf, fork bombs, crontab, /dev/tcp
JavaScript
require, const, =>, function
esprima parser, with regex fallback
child_process, eval/Function, fetch to webhooks, _0x mangling
SQL
leading SELECT/DROP/INSERT etc.
sqlparse statements
DROP, TRUNCATE, DELETE/UPDATE without WHERE, INTO OUTFILE, xp_cmdshell
YAML
key: value lines, yaml.safe_load works
yaml.safe_load then walk keys
CI run: steps, privileged: true, hostPath: /, cron, secrets in env
Markdown
headings, fenced blocks
extract fenced code (re-routed to its language) + HTML comments + prose
hidden AI instructions, curl | bash install lines
PHP (optional)
<?php
regex and token rules (no parser needed)
eval(base64_decode()), system(), $_GET into eval
Markdown and YAML are carriers: we extract the code inside them and send it back through the router. One snippet can then report several languages' findings, and code_language reports the outer one.
Detection features
Scoring follows GuardDog's split. A capability (spawns a process, opens a socket, reads a file) adds a little risk. A threat indicator (a sensitive path, a webhook domain, base64 into exec) adds a lot. A capability and a threat together in one snippet push it over the block line. This is the main lever against false positives on scary-looking but benign code.
Category
Capability signals
Threat signals (high weight)
Idea borrowed from
secret_access
file read, env read
~/.ssh, .aws/credentials, .env, /etc/shadow, key-shaped strings with high entropy
Gitleaks / detect-secrets patterns
data_exfiltration
outbound HTTP, socket
sensitive source flows into a network sink, webhook and paste hosts, DNS-encoded data
GuardDog exfil rules
destructive_command
file delete, SQL write
rm -rf / or ~, shutil.rmtree on root or home, mkfs, dd of=/dev/sd*, DROP, unbounded DELETE
GuardDog destruction
persistence_or_privesc
file write, process spawn
.bashrc, crontab, systemd units, Run keys, sudo, chmod +s, privileged: true
GuardDog autostart
obfuscated_execution
eval or exec present
decode (base64, hex, chr chain, codecs) feeding exec, _0x names, homoglyphs
GuardDog obfuscation, Bandit
dependency_risk
pip/npm install
name within edit distance 1–2 of a top package, install from raw URL or IP
GuardDog typosquatting
resource_exhaustion
loops, fork
while True with no break or sleep, fork bomb, os.fork in a loop, huge allocations
smolagents loop guard
ssrf_network_exfil
outbound request
169.254.169.254, metadata.google.internal, private ranges, localhost admin ports, file://
our own list
ai_targeted_instructions
comments and strings exist
"ignore previous instructions", "mark as safe", "you are an AI", hidden HTML comments, zero-width characters
LlamaFirewall idea, our own rules
Our own additions on top:
1. Recursive deobfuscation. Base64, hex, and chr() literals are decoded statically, never executed, and the result is re-scanned up to 3 levels deep.
2. Constant folding and alias tracking. Resolves "r"+"m", import os as o, and getattr(os, "sys"+"tem") before matching.
3. Two streams. Executable code goes to the analyzers. Comments, docstrings, and string literals go to the AI-instruction detector.
4. Line evidence. Every hit records its line, which feeds vulnerable_lines and reason.
ML layer, data and evaluation
The model is a tie-breaker, not the main detector. It sees the rule and AST outputs as features (stacking), so it learns when a rule hit is real and when it is noise.
Model. scikit-learn, multi-label (one output per category):
• Character 3–5-gram TF-IDF on normalized code.
• Plus about 30 engineered features: which rules fired, capability and threat counts, taint flag, max string entropy, longest encoded blob, decode depth, language.
• Logistic regression first, because it trains in seconds. Try LightGBM only if time allows.
• Export with skl2onnx if latency needs it.
Decision. risk_score = max(rule score, model probability), blended when both fire. The block threshold is tuned on held-out data to favour precision. Code that doesn't parse falls back to rules and ML, and never crashes the endpoint.
Data (the real differentiator). The dev sample is about 40 snippets, so we generate our own from templates:
• Malicious: each category written in Python, bash and JS, then mutated by variable renaming, string splitting, import aliasing, base64 or hex wrapping, and inserted junk comments.
• Hard benign: rm of a temp dir, requests.get to a public API, pip install requests, while True with a break, SQL DELETE ... WHERE id=, normal CI YAML, READMEs with install commands.
• Fake secrets and placeholder domains only. Nothing is copied verbatim from public datasets.
• The dev sample is kept out of training. It is only for evaluation, so we never hard-code it.
Evaluation script. Reports precision, recall, false-positive rate and F1, overall and per category, p50/p95 latency per layer, and an ablation (rules only, then plus AST, then plus ML). These numbers go straight into the write-up.
Interception proof
We prove blocking at two gates, and both use only the one controlled safe/unsafe pair.
1. Python gate. demo/intercept_check.py wraps an execute_code() function with @codeguard. The safe snippet writes marker_safe.txt. The unsafe snippet would write marker_unsafe.txt. The script deletes old markers, runs both, then asserts that marker_safe.txt exists and marker_unsafe.txt does not. It prints PASS or FAIL with the verdict and latency.
2. Go CLI gate. codeguard exec -- python snippet.py sends the file to the engine and calls exec only on allow. On block it exits with code 2 and never starts the child process. The same marker check is run from the shell.
Optional extra (last hour only). A PEP 578 sys.addaudithook inside the Python gate refuses os.system, subprocess.Popen and socket.connect at runtime. This is defence in depth if something slips past static analysis, demonstrated only on the controlled unsafe snippet.
Fail-closed rule. If the engine is unreachable or times out, both gates block. A guard that fails open isn't a guard.
PHP angle
We assume "the PHP scene" means this year's Packagist supply-chain attacks. They map almost one-to-one onto our categories, which makes them a strong story for the pitch and the write-up.
• Laravel-Lang compromise (May 22–23, 2026). Over 700 malicious tags were pushed to laravel-lang/lang, http-statuses, attributes and actions. A src/helpers.php loaded through Composer autoload.files ran on every request. It fingerprinted the host, pulled a payload, stole cloud tokens, wallets, browser and Slack/Discord sessions, encrypted the data, exfiltrated it, then deleted itself (SC Media, The Hacker News).
• Fake Laravel helper packages (Mar 4, 2026) delivered a cross-platform RAT (The Hacker News).
• Eight Packagist packages (May 23, 2026) had a postinstall script that downloaded a Linux binary (The Hacker News).
What we build for it (about 1 hour, Person A after the core is green):
• Route <?php to a PHP rule pack. Covered patterns include eval/assert of base64_decode/gzinflate/str_rot13, system/shell_exec/passthru/backticks, $_GET/$_POST flowing into exec, file_get_contents of .env or ~/.aws followed by curl_exec, and fsockopen reverse shells.
• A composer.json / package.json check (it is JSON, close to our YAML handling). Flag autoload.files pointing at unusual helpers, scripts hooks (post-install-cmd, postinstall) that download and run, and dependencies from raw URLs. This hits dependency_risk and persistence_or_privesc.
• In the demo, show one fake Laravel-style dropper (fake domain, fake secrets) being blocked with its categories and lines. Judges remember a real attack from this year.
PHP is not in the organizers' list, so it gets no weight in tuning. It is a bonus that shows the router generalises.
10-hour timeline
A owns everything that decides the verdict. B owns everything that measures, demonstrates or wraps it, so neither blocks the other after hour 1.
Sync points:
• Hour 1: the schema endpoint returns valid JSON, so B tests against the real thing from then on.
• Hour 5: merge, then a first full eval run that picks which categories A fixes next.
• Hour 9: freeze. After that, only bug fixes.
The PDF says 12 hours. If you really have 12, the two extra hours go to LightGBM vs logistic regression, the audit-hook extra, and a minimal UI, in that order.
Deliverables, licenses and what we left out
[ ] Public GitHub repo: engine, Go CLI, .env.example (no secrets, no LLM key), run instructions
[ ] Endpoint URL sent to organizers before the evaluation window
[ ] demo/intercept_check.py plus the codeguard exec demo
[ ] Eval results on the dev sample: precision, recall, false positives, per-layer latency, model size
[ ] README: architecture, components and licenses, assumptions, known limitations, AI-assistant disclosure
[ ] 2–3 page write-up (PDF)
[ ] Minimal UI or terminal view showing code, verdict, score, categories, reason, latency
Component
Role
License
Python ast, tokenize, shlex
parsing (stdlib)
PSF
FastAPI, uvicorn
HTTP engine
MIT, BSD-3
scikit-learn
classifier
BSD-3
sqlparse
SQL parsing
BSD-3
esprima (Python port)
JS parsing
BSD-2
PyYAML
YAML parsing
MIT
GuardDog
rule ideas, adapted (not imported)
Apache-2.0
Gitleaks / detect-secrets
secret pattern ideas, adapted
MIT / Apache-2.0
Go stdlib + cobra (if used)
CLI
BSD-3 / Apache-2.0
Check each license on the repo page before submitting. Avoid bashlex, which is GPL.
Left out on purpose:
• Docker sandbox. Running hidden-set snippets, even in the background, breaks the "no execution outside the controlled pair" floor and adds seconds of latency. It goes in the README as future work.
• Large transformer models. The ProtectAI prompt-injection ONNX model is an optional experiment, kept only if it measurably improves ai_targeted_instructions on our data.