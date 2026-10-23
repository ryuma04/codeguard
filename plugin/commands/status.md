---
description: Show whether the CodeGuard engine is up and the recent allow/block decisions
allowed-tools: Bash(sh:*), Bash(python:*), Bash(python3:*), Read
---

1. Run `sh "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --health` and report whether the engine is up.
2. Read the last 15 lines of `~/.codeguard/audit.jsonl` (the hook's audit trail; it may not exist yet).
   Show them as a table: time, agent, tool, target, verdict, risk, categories.
   Then give the totals of allow / block / error for the current session if you can tell it apart.
