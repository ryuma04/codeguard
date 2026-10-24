---
description: Re-check code you fixed yourself after CodeGuard blocked it
argument-hint: <quarantine .json record or file>
allowed-tools: Bash(sh:*), Read
---

The user fixed code that CodeGuard blocked and wants it verified. Never execute the code during this check.

Arguments: $ARGUMENTS

1. If no argument was given, list `.codeguard/quarantine/*.json` in the project and use the newest record.
2. Run: `sh "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --recheck <the record or file>`
3. If it prints **ALLOW**, tell the user, then do the `NEXT:` step it prints (that step is checked again).
   If it prints **STILL BLOCKED**, show the reasons, flagged lines and fix hints, and ask the user whether to
   edit again, let you fix it, or block it.
