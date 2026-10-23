#!/bin/sh
# Finds a Python 3 and runs the CodeGuard hook. If none is found, deny (fail closed):
# a hook that crashes would otherwise let the tool call through.
DIR="$(dirname "$0")"
for py in "$CODEGUARD_PYTHON" python3 python py; do
  [ -n "$py" ] || continue
  if "$py" -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)" >/dev/null 2>&1; then
    exec "$py" "$DIR/codeguard_hook.py" "$@"
  fi
done
if [ $# -eq 0 ]; then
  printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"CodeGuard could not find Python 3 to run its check, so this call was blocked (fail closed). Ask the user to install Python 3 or set CODEGUARD_PYTHON."},"systemMessage":"CodeGuard: Python 3 not found, blocked (fail closed)"}'
  exit 0
fi
echo "CodeGuard: Python 3 not found (set CODEGUARD_PYTHON)" >&2
exit 1
