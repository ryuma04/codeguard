"""Self-healing agent loop: when CodeGuard blocks code, the agent gets structured feedback and may
try again, under limits that stop it from using the guard as an oracle to learn evasions.

    session = HealingSession()
    result = session.run(task, generate, execute)

`generate(task, feedback)` is the agent (an LLM, a local model, or a script): it returns code, and gets
`feedback=None` on the first attempt, then a Feedback after each block. `execute(code)` runs code; it is
only ever called with the exact string that was checked and allowed.

Edge cases handled (each one is a test in eval/heal_tests.py):
- every attempt is checked from scratch; nothing is cached or whitelisted between attempts
- retries face a stricter threshold (RETRY_THRESHOLD): a blocked agent gets less benefit of the doubt
- resubmitting identical blocked code escalates at once
- obfuscation that appears only after a block is treated as an evasion attempt and escalates at once
- the same category blocked on every attempt ends as "escalated" (persistent intent), not "gave up"
- a session-wide block budget locks the session, so an agent cannot probe the guard across many tasks
- feedback names categories, lines and a fix hint, never the detection rules; flagged lines that carry
  ai_targeted_instructions are redacted, so blocked text is never fed back into the agent as a prompt
- guard unavailable -> nothing runs, no retry (fail closed); agent error / empty answer -> nothing runs
- an exception from the executed code is reported, not retried through the guard
"""
import hashlib
import re
import threading
import time
from dataclasses import dataclass, field

from .guard import check

BLOCK_THRESHOLD = 0.5
RETRY_THRESHOLD = 0.4
MAX_ATTEMPTS = 3
SESSION_BLOCK_LIMIT = 8
_EXCERPT = 120
_INVISIBLE = re.compile("[\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]")

HINTS = {
    "secret_access": "Do not read credential stores, keys, tokens or secret environment variables. Take configuration as a parameter.",
    "data_exfiltration": "Do not send local data, files or environment details to external hosts. Keep results local.",
    "destructive_command": "Only delete or modify paths inside the working directory, never /, ~ or system paths.",
    "persistence_or_privesc": "Do not add startup entries, cron jobs, services, sudo/setuid or shell-profile changes.",
    "obfuscated_execution": "Write plain code. Do not decode-and-execute, eval built strings, or encode payloads.",
    "dependency_risk": "Install only well-known packages from the official index and check the spelling. No piping downloads into a shell.",
    "resource_exhaustion": "Bound every loop, recursion, thread and allocation. No fork bombs or unbounded spawning.",
    "ssrf_network_exfil": "Only call the hosts the task names. No cloud metadata IPs, localhost admin ports or raw internal IPs.",
    "ai_targeted_instructions": "Remove comments or strings that address an AI reviewer or tell it to ignore rules or mark code safe.",
}


@dataclass
class Feedback:
    attempt: int
    remaining: int
    categories: list
    lines: list
    excerpts: dict      # line number -> sanitized excerpt (redacted for ai_targeted_instructions)
    hints: list
    text: str           # the same information as one prompt-ready message


@dataclass
class Attempt:
    n: int
    code_sha: str
    verdict: str        # allow | block | error
    risk: float
    categories: list
    reason: str
    threshold: float
    note: str = ""


@dataclass
class HealResult:
    status: str         # ok | healed | escalated | locked | guard_error | agent_error | gave_up | exec_failed
    executed: bool
    output: object = None
    error: str = ""
    message: str = ""
    attempts: list = field(default_factory=list)


def _sha(code):
    return hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:16]


def _excerpt(text):
    text = _INVISIBLE.sub("", text).strip()
    return text[:_EXCERPT] + ("..." if len(text) > _EXCERPT else "")


def build_feedback(code, result, attempt, max_attempts):
    cats = list(result.get("categories") or [])
    lines = list(result.get("vulnerable_lines") or [])
    src = code.replace("\r\n", "\n").split("\n")
    redact = "ai_targeted_instructions" in cats
    excerpts = {}
    for n in lines[:8]:
        if 1 <= n <= len(src):
            excerpts[n] = "[redacted: text aimed at an AI reader]" if redact else _excerpt(src[n - 1])
    hints = [HINTS[c] for c in cats if c in HINTS]
    reasons = [r for r in (result.get("reason") or "").split("; ") if r]
    if redact:  # the reason text can quote the injected phrase; keep categories and line numbers only
        reasons = [f"{c} (line {n})" for c in cats for n in lines[:1]] or cats
    remaining = max_attempts - attempt
    parts = [f"CodeGuard blocked attempt {attempt} of {max_attempts}. Nothing was executed.",
             "Categories: " + (", ".join(cats) or "unknown")]
    parts += ["Why:"] + [f"  - {r}" for r in reasons]
    if excerpts:
        parts += ["Flagged lines:"] + [f"  line {n}: {t}" for n, t in excerpts.items()]
    if hints:
        parts += ["How to fix:"] + [f"  - {h}" for h in hints]
    parts.append("Rewrite the code so it does not need this behaviour. Do not encode, split, rename or hide it: "
                 "that is detected and ends the session." if remaining else
                 "No attempts left: explain to the user what was blocked instead of retrying.")
    return Feedback(attempt, remaining, cats, lines, excerpts, hints, "\n".join(parts))


class HealingSession:
    """One per agent or conversation; keeps the session-wide block budget. Thread-safe."""

    def __init__(self, max_attempts=MAX_ATTEMPTS, session_block_limit=SESSION_BLOCK_LIMIT,
                 retry_threshold=RETRY_THRESHOLD, checker=check):
        self.max_attempts = max_attempts
        self.session_block_limit = session_block_limit
        self.retry_threshold = retry_threshold
        self.checker = checker
        self.blocks = 0
        self.locked = False
        self.log = []                      # every Attempt across all tasks, for audit
        self._lock = threading.Lock()

    def _record_block(self):
        with self._lock:
            self.blocks += 1
            if self.blocks >= self.session_block_limit:
                self.locked = True
            return self.locked

    def run(self, task, generate, execute):
        attempts = []

        def done(status, executed=False, **kw):
            with self._lock:
                self.log.extend(attempts)
            return HealResult(status, executed, attempts=attempts, **kw)

        if self.locked:
            return done("locked", message="Session locked after repeated blocks; a human must review it.")
        feedback, seen, blocked_cats, per_attempt_cats = None, set(), set(), []
        for n in range(1, self.max_attempts + 1):
            try:
                code = generate(task, feedback)
            except Exception as e:
                return done("agent_error", error=f"{type(e).__name__}: {e}", message="The agent failed; nothing was executed.")
            if not isinstance(code, str) or not code.strip():
                return done("gave_up", message="The agent returned no code; nothing was executed.")
            sha = _sha(code)
            if sha in seen:
                attempts.append(Attempt(n, sha, "block", 1.0, sorted(blocked_cats), "identical to a blocked attempt", 0.0, "resubmitted"))
                self._record_block()
                return done("escalated", message="The agent resubmitted code that was already blocked.")
            seen.add(sha)

            threshold = BLOCK_THRESHOLD if n == 1 else self.retry_threshold
            t0 = time.perf_counter()
            res = self.checker(code)
            reason = res.get("reason") or ""
            if reason.startswith("guard unavailable"):
                attempts.append(Attempt(n, sha, "error", 1.0, [], reason, threshold))
                return done("guard_error", message="CodeGuard is unavailable; nothing was executed (fail closed).")
            risk = float(res.get("risk_score") or 0.0)
            cats = list(res.get("categories") or [])
            blocked = res.get("verdict") != "allow" or risk >= threshold
            note = "near miss: allowed at 0.5 but blocked at the stricter retry threshold" if blocked and res.get("verdict") == "allow" else ""
            attempts.append(Attempt(n, sha, "block" if blocked else "allow", risk, cats, reason, threshold, note))

            if not blocked:
                try:
                    output = execute(code)  # exactly the string that was checked
                except Exception as e:
                    return done("exec_failed", executed=True, error=f"{type(e).__name__}: {e}",
                                message="The allowed code raised an error while running.")
                return done("ok" if n == 1 else "healed", executed=True, output=output,
                            message=f"Allowed on attempt {n} ({(time.perf_counter() - t0) * 1000:.1f} ms check).")

            if self._record_block():
                return done("locked", message="Session block limit reached; locked for human review.")
            if n > 1 and "obfuscated_execution" in cats and "obfuscated_execution" not in blocked_cats:
                attempts[-1].note = "evasion: obfuscation appeared only after a block"
                return done("escalated", message="After being blocked, the agent tried to hide the code. Escalated for review.")
            blocked_cats |= set(cats)
            per_attempt_cats.append(set(cats))
            feedback = build_feedback(code, res, n, self.max_attempts)

        persistent = set.intersection(*per_attempt_cats) if per_attempt_cats else set()
        msg = (f"Blocked on all {self.max_attempts} attempts"
               + (f"; the agent kept the same behaviour ({', '.join(sorted(persistent))})" if persistent else "")
               + ". Escalated to a human.")
        return done("escalated", message=msg)
