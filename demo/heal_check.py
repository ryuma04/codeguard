"""Self-healing proof: the guard blocks the agent's first attempt, the agent uses the feedback to
fix it, and only the fixed code runs.

The "agent" is scripted (no LLM API keys are allowed in this track): its first answer is the unsafe
half of the controlled demo pair, and once it has feedback it answers with the safe half. These two
snippets are the only code ever executed. Each writes a marker file, so the folder shows what ran.
In Claude Code the same loop runs with a real model: see plugin/README.md.
"""
import os
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
from codeguard.heal import HealingSession  # noqa: E402

GATE = os.path.join(ROOT, "demo", "gate")
OUT = tempfile.mkdtemp(prefix="codeguard_heal_")
os.environ["CODEGUARD_DEMO_OUT"] = OUT


def read(name):
    with open(os.path.join(GATE, name), encoding="utf-8") as f:
        return f.read()


def scripted_agent(task, feedback):
    if feedback is None:
        print("agent  > attempt 1: unsafe_snippet.py (base64 -> exec)")
        return read("unsafe_snippet.py")
    print("agent  < feedback from CodeGuard:")
    print("\n".join("         " + l for l in feedback.text.splitlines()))
    print(f"agent  > attempt {feedback.attempt + 1}: safe_snippet.py (plain code, no decode/exec)")
    return read("safe_snippet.py")


def execute(code):
    exec(compile(code, "<agent-code>", "exec"), {})


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(f"Working folder: {OUT}\n")
    result = HealingSession().run("write a marker file", scripted_agent, execute)
    print()
    for a in result.attempts:
        print(f"attempt {a.n}: {a.verdict.upper():5} risk={a.risk} categories={a.categories} sha={a.code_sha}")
    print(f"status: {result.status}  executed: {result.executed}  ({result.message})")
    safe = os.path.exists(os.path.join(OUT, "marker_safe.txt"))
    unsafe = os.path.exists(os.path.join(OUT, "marker_unsafe.txt"))
    print(f"\nmarker_safe.txt exists:   {safe}")
    print(f"marker_unsafe.txt exists: {unsafe}")
    ok = result.status == "healed" and safe and not unsafe and result.attempts[0].verdict == "block"
    print("\nPASS: attempt 1 blocked and never ran; the agent fixed it and only the fixed code ran."
          if ok else "\nFAIL")
    sys.exit(0 if ok else 1)
