---
description: Check files or a code snippet with CodeGuard without running anything
argument-hint: <file ...> | (paste code after the command)
allowed-tools: Bash(sh:*), Bash(python:*), Bash(python3:*)
---

Check code with the CodeGuard engine. Never execute the code being checked.

Arguments: $ARGUMENTS

1. If the arguments name one or more existing files, run:
   `sh "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --scan <the files>`
2. Otherwise treat the arguments as a code snippet: write it to a temporary file in the system temp folder
   (not in the project), run the same command on that file, then delete the temporary file.

Present the result as a short verdict card:

- **ALLOW** or **BLOCK**, risk score, language, engine latency
- the reasons as bullets
- the categories with their scores
- each flagged line with its line number, in a code block

If the engine is unreachable, say so and tell the user to start it with `npm run engine`
(or `python -m codeguard.api --port 8000`) in the CodeGuard repository.
