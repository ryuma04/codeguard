---
name: codeguard
description: How to respond when CodeGuard blocks a tool call. Use whenever a Bash, PowerShell, Write or Edit call is denied with a message starting "CodeGuard BLOCKED", when the user says they fixed blocked code, or when the user asks whether code is safe to run.
---

# Working with the CodeGuard guard

A PreToolUse hook sends every command you run and every file you write to the local CodeGuard engine
before it happens. The engine is static analysis plus small local models; it never executes the code.

## When a call is denied with "CodeGuard BLOCKED"

Follow the block message. By default (`CODEGUARD_ON_BLOCK=ask`) it ends with **ACTION REQUIRED**:

1. Ask the user with the **AskUserQuestion** tool. Put a one-line summary of what was blocked and why in the
   question, show the blocked code (the `--show` output from the message) in each option's preview, and offer
   exactly the options the message lists:
   - **Ask Claude to fix it**: rewrite the code following the "How to fix" hints and try again. The rewrite is
     checked again by the hook. Tell the user in one line what you changed.
   - **I'll fix it myself**: ask how they want to edit.
     - *Type the fix here*: they type or paste the corrected code. Save exactly their text, unchanged, to the
       quarantine path from the message, then run the `--recheck` command.
     - *Open in my editor*: run the `--edit` command from the message (Bash timeout 600000 ms). It opens their
       editor, waits until they close it, and re-checks automatically.
     On **ALLOW**, do the `NEXT:` step it prints. On **STILL BLOCKED**, show the reasons and flagged lines and
     offer the options again. Never "improve" the user's version yourself in this path.
   - **Block it**: run the `--decline` command from the message, tell the user it is blocked, and continue
     the rest of the task without that code. Never retry it or a variant in this session.
2. If the message does not offer "Ask Claude to fix it" (after a retry limit, a resubmission or an evasion),
   do not rewrite it yourself; only the user's options remain.
3. If the message says the user already chose to block this kind of code, stop. Do not ask again.

Never try to get past the guard: no base64/hex/char-code encoding, string splitting, renaming, moving the
payload into another file or tool, or running it through a different interpreter. That is exactly what the
guard detects (obfuscated_execution), and it defeats the purpose.

## When CodeGuard is unavailable

"CodeGuard unavailable ... blocked (fail closed)" means the engine is not running. Tell the user to start it
(`codeguard engine` in the CodeGuard repository) and wait; do not look for a way around the hook.

## Commands

- `/codeguard:scan <file>`: check code without running it.
- `/codeguard:recheck [record]`: verify code the user fixed (defaults to the newest quarantine record).
- `/codeguard:status`: engine health and recent decisions.
