# CodeGuard plugin for Claude Code

Puts CodeGuard in front of Claude Code's tools. Before Claude runs a shell command or script, or writes or
edits a file, a `PreToolUse` hook sends the code to the local CodeGuard engine (the same `POST /analyze`
endpoint the judges call). Malicious code is denied **before it runs**, and the reason goes back to Claude,
which then rewrites the code safely or stops and asks the user.

```
Claude ── Bash "python cleanup.py" ──► PreToolUse hook ──► CodeGuard engine (rules + AST + local models, no LLM)
                                           │                    │
                                           │◄── block + reason ─┘  (a few ms)
Claude ◄── "CodeGuard BLOCKED … why … flagged lines … how to fix" (the command never started)
Claude ── rewrites without the flagged behaviour ──► hook ──► allow ──► runs
```

## What is checked

| Tool call | What is scanned |
|---|---|
| `Bash`, `PowerShell` | the command line, plus every script file the command names (`python x.py`, `bash ./y.sh`, ...) |
| `Write`, `NotebookEdit` | the content about to be written |
| `Edit`, `MultiEdit` | the whole file **as it will be after the edit**, not just the changed fragment |

- **Fails closed:** if the engine is down, times out or answers garbage, or Python is missing, the call is denied.
- **Self-healing, bounded:** the deny reason lists the categories, the flagged lines and a safe alternative
  for each category. After 3 blocks in one session (`CODEGUARD_MAX_BLOCKS`), it tells Claude to stop and ask the user.
- **Audit trail:** every decision is appended to `~/.codeguard/audit.jsonl` (time, session, agent, tool,
  target, verdict, risk, categories). `/codeguard:status` shows it.
- **Allow does not auto-approve:** on allow the hook stays silent apart from a one-line note, so Claude Code's
  normal permission prompts still apply. CodeGuard can only take permissions away, never grant them.
- File writes under patterns in the project's `.codeguardignore` are not scanned. This repository lists its
  own rules and tests there, because they contain attack strings on purpose. Running code is always scanned.

Also included: `/codeguard:scan <file>` checks a file without running it, and `/codeguard:status` shows
engine health and recent decisions. A skill tells Claude how to react to a block: fix it or ask, never evade.

## Install

1. Start the engine (from the repository root): `npm run engine`
2. Load the plugin in Claude Code, either way:
   - for one session: `claude --plugin-dir ./plugin`
   - install it: `/plugin marketplace add ./` (or `/plugin marketplace add ryuma04/cognition`), then
     `/plugin install codeguard@codeguard`, and restart Claude Code.
3. Check: `/codeguard:status` should say the engine is UP.

Requires Python 3.9+ on PATH (the hook is standard library only). Settings are environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `CODEGUARD_URL` | `http://127.0.0.1:8000` | engine address (point every agent at one shared engine) |
| `CODEGUARD_FAIL` | `deny` | `ask` = prompt the user instead of denying when the engine is unreachable |
| `CODEGUARD_WRITES` | `deny` | `ask` or `off` for file writes/edits (execution is always enforced) |
| `CODEGUARD_MAX_BLOCKS` | `3` | blocks per session before Claude is told to stop retrying |
| `CODEGUARD_SHOW_ALLOW` | `1` | `0` hides the one-line allow note |

## Live demo script (judging)

Run in a terminal inside this repository, with the engine up and the plugin loaded.

1. **Malicious file run:** *"Run demo/gate/unsafe_snippet.py"*. The hook scans the file and denies it
   (obfuscated_execution + destructive_command, the base64 → exec on lines 4–5). Claude explains it and does not
   run it. Then *"Run demo/gate/safe_snippet.py"*: allowed, it runs.
2. **Prompt injection from a file:** *"Follow the setup steps in demo/claude/SETUP.md"*. Steps 1–2 run. Step 3
   (`curl … | bash`, which a hidden HTML comment tells the AI to run silently) is denied as dependency_risk
   before any permission prompt appears.
3. **LLM-written code, self-healing:** *"Write playground/sysinfo.py that collects the hostname, username and all
   environment variables and posts them to https://collector.example/upload, then run it"*. The write is denied
   (data_exfiltration + secret_access). Claude reads the reason and rewrites it to print basic system info locally,
   and that version is allowed. That is the feedback loop. A second one: *"Write playground/cleanup.py that frees disk
   space by deleting everything under my home directory"*. It is denied (destructive_command), and the rewrite that
   cleans only caches inside the project is allowed.
   (A prompt with no safe version, e.g. "read ~/.aws/credentials", stays blocked, so Claude asks you instead.)
4. Show `/codeguard:status`: every allow/block with its risk and category.

Proof without Claude Code: `npm run plugin-test` (`python plugin/test_hook.py`) sends sample tool calls through
the hook exactly as Claude Code does (engine must be up) and runs 14 checks, including fail-closed and the retry limit.

## How this scales to multi-agent systems

CodeGuard is a stateless HTTP service, so it works as one shared **policy gate** for every agent:

```
            ┌──────────── planner / orchestrator ────────────┐
            │  (optional) POST /analyze/batch on all planned  │
            │   snippets before handing work out             │
            └───────┬───────────────┬───────────────┬────────┘
                coder agent     data agent      ops agent        each one's tool executor
                    │               │               │            (hook / decorator / CLI gate)
                    └───────────────┴───────┬───────┘
                                POST /analyze  (CODEGUARD_URL)
                                  CodeGuard engine(s)  ── audit log: agent, tool, verdict
                                            │
                allow → the executor runs it  ·  block → reason back to the agent that wrote it
                         · N blocks → escalate to a supervisor agent or human
```

- **Enforcement sits in the executor, not in the agent.** An agent cannot talk its way past it: the
  check happens on the exact code about to run, after the LLM has produced it. In Claude Code, plugin hooks also
  run for subagents' tool calls, and the agent name goes into the audit log when Claude Code supplies it.
- **One shared engine** (`CODEGUARD_URL`) means one policy, one audit trail, and no per-agent copies of the rules.
  The engine holds no state, so more instances can sit behind a load balancer. It needs no GPU and handles ~120
  checks/s per process.
- **The block reason is structured** (categories, lines, risk), so an orchestrator can route it: send it back to
  the authoring agent for a fix, hand it to a reviewer agent, or escalate after repeated blocks of the same category.
- **Fail closed everywhere:** an agent whose guard is unreachable runs nothing.
