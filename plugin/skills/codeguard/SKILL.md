---
name: codeguard
description: How to respond when CodeGuard blocks a tool call. Use whenever a Bash, PowerShell, Write or Edit call is denied with a message starting "CodeGuard BLOCKED", or when the user asks whether code is safe to run.
---

# Working with the CodeGuard guard

A PreToolUse hook sends every command you run and every file you write to the local CodeGuard engine
before it happens. The engine is static analysis plus small local models; it never executes the code.

## When a call is denied with "CodeGuard BLOCKED"

1. Read the reason: categories, the "Why" bullets, the flagged lines and the "How to fix" hints.
2. Decide whether the flagged behaviour is actually needed for the user's task.
   - **Not needed** (the usual case: an over-broad delete, an unneeded network call, a hard-coded path
     to a credentials file): rewrite the code without it and try again. Tell the user in one line what
     CodeGuard caught and what you changed.
   - **Needed, or you are not sure**: stop and ask the user. Do not retry.
3. Never try to get past the guard: no base64/hex/char-code encoding, string splitting, renaming,
   moving the payload into another file or tool, or running it through a different interpreter.
   That is exactly what the guard detects (obfuscated_execution), and it defeats the purpose.
4. If the message says to stop retrying (the session block limit), stop and explain to the user what was
   blocked and why.

## When CodeGuard is unavailable

"CodeGuard unavailable ... blocked (fail closed)" means the engine is not running. Tell the user to start it
(`npm run engine` in the CodeGuard repository) and wait; do not look for a way around the hook.

## Checking code on request

Use `/codeguard:scan <file>` (or the scan command it describes) to check code without running it.
