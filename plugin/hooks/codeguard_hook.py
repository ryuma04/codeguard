"""CodeGuard PreToolUse hook for Claude Code.

Claude Code calls this before every Bash / PowerShell / Write / Edit / MultiEdit / NotebookEdit
tool call, with the call as JSON on stdin. We send the code that is about to run (or be written)
to the CodeGuard engine (POST /analyze, the same endpoint the judges call) and:

  allow -> exit 0, optional one-line note for the user; Claude Code's normal permission flow continues
  block -> permissionDecision "deny"; the reason goes back to Claude, which then rewrites the code
  engine unreachable / error -> deny (fail closed), or "ask" with CODEGUARD_FAIL=ask

Standard library only. Also usable by hand: python codeguard_hook.py --scan <file>
"""
import fnmatch
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

URL = os.environ.get("CODEGUARD_URL", "http://127.0.0.1:8000").rstrip("/")
TIMEOUT = float(os.environ.get("CODEGUARD_TIMEOUT", "3"))
FAIL_MODE = os.environ.get("CODEGUARD_FAIL", "deny")            # deny | ask
WRITE_MODE = os.environ.get("CODEGUARD_WRITES", "deny")         # deny | ask | off  (file writes/edits)
SHOW_ALLOW = os.environ.get("CODEGUARD_SHOW_ALLOW", "1") != "0"  # one-line note to the user on allow
MAX_BLOCKS = int(os.environ.get("CODEGUARD_MAX_BLOCKS", "3"))    # after this many blocks in a session: stop retrying
STATE_DIR = os.environ.get("CODEGUARD_STATE_DIR", os.path.join(os.path.expanduser("~"), ".codeguard"))
AUDIT = os.path.join(STATE_DIR, "audit.jsonl")
MAX_FILE = 512 * 1024

SHELL_TOOLS = {"Bash", "PowerShell"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
IGNORE_FILE = ".codeguardignore"

# Short, safe-alternative guidance per category, so the retry is a fix and not an evasion.
HINTS = {
    "secret_access": "Do not read credential stores, keys, tokens or env secrets. Take configuration as a parameter.",
    "data_exfiltration": "Do not send local data, files or environment details to external hosts.",
    "destructive_command": "Only delete or modify paths inside the project/working directory, never /, ~ or system paths.",
    "persistence_or_privesc": "Do not add startup entries, cron jobs, services, sudo/setuid or shell-profile changes.",
    "obfuscated_execution": "Write plain code. Do not decode-and-execute, eval built strings, or encode payloads.",
    "dependency_risk": "Install only well-known packages from the official index; check the spelling. No curl | sh.",
    "resource_exhaustion": "Bound loops, recursion, threads and allocations; no fork bombs or unbounded spawning.",
    "ssrf_network_exfil": "Only call the hosts the task names. No cloud metadata IPs, localhost admin ports or raw internal IPs.",
    "ai_targeted_instructions": "Remove comments/strings that address an AI reviewer or tell it to ignore rules or mark code safe.",
}


# ------------------------------------------------------------------ engine
# No proxies: code under review must only go to the engine (and the Windows proxy lookup costs ~80 ms per call).
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def analyze(code):
    req = urllib.request.Request(URL + "/analyze?debug=1", data=json.dumps({"code": code}).encode(),
                                 headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with _OPENER.open(req, timeout=TIMEOUT) as r:
        res = json.loads(r.read())
    if res.get("verdict") not in ("allow", "block"):
        raise ValueError(f"bad verdict {res.get('verdict')!r}")
    res["roundtrip_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return res


# ------------------------------------------------------------------ what is about to run / be written
def _read(path):
    try:
        if os.path.isfile(path) and os.path.getsize(path) <= MAX_FILE:
            with open(path, encoding="utf-8", errors="replace") as f:
                return f.read()
    except OSError:
        pass
    return None


def _apply_edits(original, edits):
    text = original
    for e in edits:
        old, new = e.get("old_string", ""), e.get("new_string", "")
        if old and old in text:
            text = text.replace(old, new) if e.get("replace_all") else text.replace(old, new, 1)
        else:  # cannot place it: scan the new text on its own
            text += "\n" + new
    return text


# Programs that execute the file they are given. Anything else (grep, cat, diff, ls, git, sed -n ...) only
# reads its file arguments, so their contents are not code that is about to run.
INTERPRETERS = {"python", "python3", "python2", "py", "pythonw", "node", "nodejs", "deno", "bun", "ts-node", "tsx",
                "bash", "sh", "zsh", "dash", "ksh", "fish", "ruby", "perl", "php", "lua", "rscript",
                "pwsh", "powershell", "cmd", "source", ".", "&", "call", "start"}
_WRAPPERS = {"sudo", "env", "time", "nohup", "exec", "command", "nice", "xargs", "doas"}
_INLINE = {"-c", "-e", "-m", "-r", "-command", "-encodedcommand", "-enc"}   # code/module given inline, not a file
_RUNNABLE = re.compile(r"\.(sh|bash|py|ps1|psm1|bat|cmd|js|mjs|cjs|ts|rb|pl|php)$", re.I)


def executed_files(cmd, cwd):
    """Files a shell command will RUN: `python x.py`, `bash -x y.sh`, `./z.sh`, `source a.sh`, `& .\\b.ps1`."""
    found = []
    for seg in re.split(r"\|\||&&|[|;\n]", cmd):
        toks = [next(t for t in m if t) for m in re.findall(r"""(?:"([^"]+)"|'([^']+)'|(\S+))""", seg)]
        while toks and (toks[0] in _WRAPPERS or re.match(r"^[A-Za-z_]\w*=", toks[0])):
            toks.pop(0)  # sudo / env / VAR=1 prefixes
        if not toks:
            continue
        prog = os.path.basename(toks[0].replace("\\", "/")).lower()
        prog = prog[:-4] if prog.endswith(".exe") else prog
        if prog in INTERPRETERS:
            for t in toks[1:]:
                if t.lower() in _INLINE:
                    break  # python -c "...", node -e "...", python -m pkg: the command text is the code
                if t.startswith("-"):
                    continue
                if os.path.isfile(t if os.path.isabs(t) else os.path.join(cwd, t)):
                    found.append(t)
                    break
        elif toks[0].startswith(("./", ".\\", "/", "~/")) or _RUNNABLE.search(toks[0]):
            found.append(toks[0])  # the file itself is the program
    return found


def targets(tool, ti, cwd):
    """Return [(label, code)] to scan for this tool call."""
    if tool in SHELL_TOOLS:
        cmd = ti.get("command", "")
        out = [(f"{tool}: {cmd[:120]}", cmd)]
        # Also scan the script files the command RUNS. Files it only reads (grep x.py, cat y.sh) are data.
        for tok in dict.fromkeys(executed_files(cmd, cwd)):
            code = _read(tok if os.path.isabs(tok) else os.path.join(cwd, tok))
            if code is not None:
                out.append((tok, code))
        return out
    path = ti.get("file_path") or ti.get("notebook_path") or ""
    if tool == "Write":
        return [(path, ti.get("content", ""))]
    if tool == "NotebookEdit":
        return [(path, ti.get("new_source", ""))]
    edits = ti.get("edits") if tool == "MultiEdit" else [ti]
    original = _read(path if os.path.isabs(path) else os.path.join(cwd, path))
    if original is None:
        return [(path, "\n".join(e.get("new_string", "") for e in edits or []))]
    return [(path, _apply_edits(original, edits or []))]  # the file as it will look after the edit


def _matches(ign, rel):
    with open(ign, encoding="utf-8") as f:
        for pat in (l.strip() for l in f):
            if not pat or pat.startswith("#"):
                continue
            if pat.endswith("/") and (rel + "/").startswith(pat):
                return True
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
                return True
    return False


def ignored(path, root):
    """File writes matching a .codeguardignore are not scanned (execution always is).

    Like .gitignore: every .codeguardignore from the file's folder up to the drive root applies, with
    patterns relative to the folder it sits in. So a repo's ignore file works even when Claude's project
    root is a parent folder. The ignore file itself is never ignored (see hook()).
    """
    if not path:
        return False
    full = os.path.abspath(path if os.path.isabs(path) else os.path.join(root, path))
    if os.path.basename(full) == IGNORE_FILE:
        return False
    d = os.path.dirname(full)
    while True:
        ign = os.path.join(d, IGNORE_FILE)
        if os.path.isfile(ign):
            rel = os.path.relpath(full, d).replace("\\", "/")
            if _matches(ign, rel):
                return True
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


# ------------------------------------------------------------------ audit trail + per-session retry count
def audit(rec):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def session_history(session):
    """(blocks so far, categories blocked so far, hashes of blocked code) for this session."""
    n, cats, shas = 0, set(), set()
    try:
        with open(AUDIT, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("session") == session and r.get("verdict") == "block":
                    n += 1
                    cats |= set(r.get("categories") or [])
                    shas.add(r.get("sha"))
    except OSError:
        pass
    return n, cats, shas


# ------------------------------------------------------------------ messages
_INVISIBLE = re.compile("[​-‏ -‮⁠-⁩﻿\U000e0000-\U000e007f]")


def flagged_lines(code, lines, redact=False):
    """Excerpts of flagged lines. Text aimed at an AI reader is redacted, so a blocked prompt
    injection is never fed straight back into Claude's context."""
    src = code.replace("\r\n", "\n").split("\n")
    out = []
    for n in (lines or [])[:8]:
        if 1 <= n <= len(src):
            text = "[redacted: text aimed at an AI reader]" if redact else _INVISIBLE.sub("", src[n - 1]).strip()
            out.append(f"  line {n}: {text[:160] + ('…' if len(text) > 160 else '')}")
    return out


def deny_reason(label, code, res, attempt, flag=""):
    cats = res.get("categories") or []
    redact = "ai_targeted_instructions" in cats
    msg = [f"CodeGuard BLOCKED this {label!r} before it ran.",
           f"verdict=block  risk_score={res.get('risk_score')}  categories={cats}  language={res.get('code_language')}",
           "Why:"]
    reasons = [r for r in (res.get("reason") or "").split("; ") if r]
    msg += [f"  - {r}" for r in (reasons if not redact else [f"{c} (see flagged lines)" for c in cats])]
    fl = flagged_lines(code, res.get("vulnerable_lines"), redact)
    if fl:
        msg += ["Flagged lines:"] + fl
    hints = [HINTS[c] for c in cats if c in HINTS]
    if hints:
        msg += ["How to fix:"] + [f"  - {h}" for h in hints]
    if flag == "evasion":
        msg.append("After an earlier block in this session, this attempt hides its code (obfuscated_execution). That is "
                   "treated as an attempt to get around the guard. STOP: do not retry. Tell the user what was blocked.")
    elif flag == "resubmit":
        msg.append("This exact code was already blocked in this session. STOP: do not resubmit it. "
                   "Tell the user what was blocked and ask how to proceed.")
    elif attempt >= MAX_BLOCKS:
        msg.append(f"This is block #{attempt} in this session. STOP retrying: explain to the user what was blocked "
                   "and why, and ask how they want to proceed. Do not attempt another variant.")
    else:
        msg.append(f"(block {attempt}/{MAX_BLOCKS}) Rewrite the code so it does not need the flagged behaviour, then try again. "
                   "Do not encode, split, rename or obfuscate it: the guard decodes payloads and blocks that as "
                   "obfuscated_execution. If the user truly needs this behaviour, stop and ask them instead.")
    return "\n".join(msg)


def emit(decision=None, reason="", user_msg=""):
    out = {}
    if decision:
        out["hookSpecificOutput"] = {"hookEventName": "PreToolUse", "permissionDecision": decision,
                                     "permissionDecisionReason": reason}
    if user_msg:
        out["systemMessage"] = user_msg
    if out:
        sys.stdout.write(json.dumps(out))
    sys.exit(0)


# ------------------------------------------------------------------ hook entry point
def hook():
    try:
        event = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace") or "{}")
    except ValueError:
        emit("deny", "CodeGuard could not parse the tool call; failing closed.", "CodeGuard: unreadable tool call, blocked")
    tool, ti = event.get("tool_name", ""), event.get("tool_input") or {}
    if tool not in SHELL_TOOLS | WRITE_TOOLS:
        sys.exit(0)
    cwd = event.get("cwd") or os.getcwd()
    root = os.environ.get("CLAUDE_PROJECT_DIR") or cwd
    is_write = tool in WRITE_TOOLS
    target = ti.get("file_path") or ti.get("notebook_path") or ""
    if is_write and os.path.basename(target) == IGNORE_FILE:
        # An agent that could write .codeguardignore could switch scanning off for itself: always ask the user.
        emit("ask", f"This edits {IGNORE_FILE}, which turns CodeGuard scanning off for the paths it lists. "
                    "Only the user should change it.",
             f"🛡 CodeGuard: confirm the change to {IGNORE_FILE} (it disables scanning for listed paths)")
    if is_write and (WRITE_MODE == "off" or ignored(target, root)):
        sys.exit(0)

    session = event.get("session_id", "")
    agent = event.get("agent_type") or event.get("agent_id") or "main"
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "session": session, "agent": agent, "tool": tool}
    last = None
    try:
        items = targets(tool, ti, cwd)
        for label, code in items:
            if not code.strip():
                continue
            res = last = analyze(code)
            if res["verdict"] == "block":
                prior, prior_cats, prior_shas = session_history(session)
                sha = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:16]
                flag = ("resubmit" if sha in prior_shas else
                        "evasion" if prior and "obfuscated_execution" in res.get("categories", [])
                        and "obfuscated_execution" not in prior_cats else "")
                audit(rec | {"target": label[:200], "verdict": "block", "risk": res.get("risk_score"),
                             "categories": res.get("categories"), "sha": sha, "flag": flag})
                cats = ", ".join(res.get("categories") or []) or "unknown"
                user = (f"🛡 CodeGuard BLOCKED {tool} ({label[:80]}): {cats}, risk {res.get('risk_score')}, "
                        f"{res.get('roundtrip_ms')} ms" + (f" [{flag}]" if flag else ""))
                decision = "ask" if is_write and WRITE_MODE == "ask" else "deny"
                emit(decision, deny_reason(label, code, res, prior + 1, flag), user)
        audit(rec | {"target": items[0][0][:200], "verdict": "allow"})
        note = f"🛡 CodeGuard allow {tool} (risk {last['risk_score']}, {last['roundtrip_ms']} ms)" if SHOW_ALLOW and last else ""
        emit(user_msg=note)
    except SystemExit:
        raise
    except Exception as e:  # engine down, timeout, bad answer: fail closed
        audit(rec | {"verdict": "error", "error": f"{type(e).__name__}: {e}"})
        emit("ask" if FAIL_MODE == "ask" else "deny",
             f"CodeGuard could not check this call ({type(e).__name__}: {e}), so it was blocked (fail closed). "
             f"Tell the user to start the engine (npm run engine, or python -m codeguard.api --port 8000) at {URL}.",
             f"🛡 CodeGuard unavailable at {URL}: blocked (fail closed)")


# ------------------------------------------------------------------ manual scan (slash command)
def scan(paths):
    worst = 0
    for p in paths or ["-"]:
        code = sys.stdin.read() if p == "-" else _read(p)
        if code is None:
            print(f"{p}: cannot read")
            worst = max(worst, 1)
            continue
        try:
            res = analyze(code)
        except Exception as e:
            print(f"{p}: engine unavailable at {URL} ({type(e).__name__}); start it with: npm run engine")
            return 1
        mark = "BLOCK" if res["verdict"] == "block" else "ALLOW"
        print(f"{mark}  {p}  risk={res['risk_score']}  language={res['code_language']}  "
              f"engine={res.get('latency_ms')} ms  round-trip={res['roundtrip_ms']} ms")
        if res.get("categories"):
            print("  categories: " + ", ".join(f"{c} ({res.get('category_scores', {}).get(c, '')})" for c in res["categories"]))
        for r in (res.get("reason") or "").split("; "):
            if r:
                print(f"  - {r}")
        for l in flagged_lines(code, res.get("vulnerable_lines")):
            print(l)
        worst = max(worst, 2 if res["verdict"] == "block" else 0)
    return worst


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252
    if len(sys.argv) > 1 and sys.argv[1] == "--scan":
        sys.exit(scan(sys.argv[2:]))
    if len(sys.argv) > 1 and sys.argv[1] == "--health":
        try:
            with _OPENER.open(URL + "/health", timeout=TIMEOUT) as r:
                print(f"CodeGuard engine UP at {URL} (HTTP {r.status})")
            sys.exit(0)
        except Exception as e:
            print(f"CodeGuard engine DOWN at {URL}: {e}. Start it with: npm run engine")
            sys.exit(1)
    hook()
