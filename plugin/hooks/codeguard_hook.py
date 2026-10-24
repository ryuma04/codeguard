"""CodeGuard PreToolUse hook for Claude Code.

Claude Code calls this before every Bash / PowerShell / Write / Edit / MultiEdit / NotebookEdit
tool call, with the call as JSON on stdin. We send the code that is about to run (or be written)
to the CodeGuard engine (POST /analyze, the same endpoint the judges call) and:

  allow -> exit 0, optional one-line note for the user; Claude Code's normal permission flow continues
  block -> permissionDecision "deny"; the blocked code is saved to <project>/.codeguard/quarantine/ and,
           with CODEGUARD_ON_BLOCK=ask (default), Claude is told to ask the user to choose:
             1. Ask Claude to fix it   -> Claude rewrites it; the rewrite is checked again by this hook
             2. I'll fix it myself     -> the user edits the quarantined file; --recheck verifies it
             3. Block it               -> --decline records it; further attempts this session are refused
           CODEGUARD_ON_BLOCK=fix skips the question (Claude fixes); =deny is a hard stop.
  engine unreachable / error -> deny (fail closed), or "ask" with CODEGUARD_FAIL=ask

Standard library only. Also: --scan <file>, --recheck <meta.json|file>, --decline <meta.json>, --health
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
ON_BLOCK = os.environ.get("CODEGUARD_ON_BLOCK", "ask")           # ask | fix | deny
RUN_SH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run.sh").replace("\\", "/")
# CodeGuard's own maintenance commands (no shell chaining): the files they name are read, never run.
_OWN_CMD = re.compile(r"codeguard_hook\.py|hooks/run\.sh")
_OWN_FLAG = re.compile(r"\s--(scan|recheck|decline|health|edit|show)\b")
_CHAINING = re.compile(r"[;&|`$<>\n]")
STATE_DIR = os.environ.get("CODEGUARD_STATE_DIR", os.path.join(os.path.expanduser("~"), ".codeguard"))
AUDIT = os.path.join(STATE_DIR, "audit.jsonl")
MAX_FILE = 512 * 1024

SHELL_TOOLS = {"Bash", "PowerShell"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}

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


def targets(tool, ti, cwd):
    """Return [(label, code)] to scan for this tool call."""
    if tool in SHELL_TOOLS:
        cmd = ti.get("command", "")
        out = [(f"{tool}: {cmd[:120]}", cmd)]
        if _OWN_CMD.search(cmd) and _OWN_FLAG.search(cmd) and not _CHAINING.search(cmd):
            return out  # e.g. --recheck on a quarantined file: it is analysed, not executed
        # Also scan script files the command runs (python x.py, bash ./y.sh, node z.js, & .\a.ps1 ...).
        seen = set()
        for tok in re.findall(r"""(?:"([^"]+)"|'([^']+)'|(\S+))""", cmd):
            tok = next(t for t in tok if t).strip("&;|()")
            if not tok or tok.startswith("-") or tok in seen:
                continue
            path = tok if os.path.isabs(tok) else os.path.join(cwd, tok)
            code = _read(path)
            if code is not None:
                seen.add(tok)
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


def ignored(path, root):
    """File writes under patterns in <project>/.codeguardignore are not scanned (execution always is)."""
    ign = os.path.join(root, ".codeguardignore")
    if not path or not os.path.isfile(ign):
        return False
    try:
        rel = os.path.relpath(os.path.abspath(os.path.join(root, path)), root).replace("\\", "/")
    except ValueError:
        return False
    if rel.startswith("../"):
        return False
    with open(ign, encoding="utf-8") as f:
        for pat in (l.strip() for l in f):
            if not pat or pat.startswith("#"):
                continue
            if pat.endswith("/") and (rel + "/").startswith(pat):
                return True
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(os.path.basename(rel), pat):
                return True
    return False


# ------------------------------------------------------------------ audit trail + per-session retry count
def audit(rec):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def session_history(session):
    """Blocks so far, categories and hashes blocked so far, and categories the user chose to block."""
    n, cats, shas, declined = 0, set(), set(), set()
    try:
        with open(AUDIT, encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("session") != session:
                    continue
                if r.get("verdict") == "block":
                    n += 1
                    cats |= set(r.get("categories") or [])
                    shas.add(r.get("sha"))
                elif r.get("verdict") == "declined":
                    declined |= set(r.get("categories") or [])
    except OSError:
        pass
    return n, cats, shas, declined


# ------------------------------------------------------------------ quarantine (option 2: the user fixes it)
_EXT = {"Bash": ".sh", "PowerShell": ".ps1"}


def in_quarantine(path, root):
    if not path:
        return False
    qdir = os.path.normcase(os.path.abspath(os.path.join(root, ".codeguard", "quarantine")))
    p = os.path.normcase(os.path.abspath(path if os.path.isabs(path) else os.path.join(root, path)))
    return os.path.dirname(p) == qdir


def quarantine(code, tool, ti, label, session, res, sha, root, cwd):
    """Save the blocked code where the user can edit it, plus a meta file saying what to do once it passes.
    Returns the meta dict, or None if the folder cannot be written."""
    qdir = os.path.join(root, ".codeguard", "quarantine").replace("\\", "/")  # forward slashes: pasted into bash commands
    try:
        os.makedirs(qdir, exist_ok=True)
        ign = os.path.join(root, ".codeguard", ".gitignore")
        if not os.path.exists(ign):
            with open(ign, "w", encoding="utf-8") as f:
                f.write("*\n")  # never commit quarantined code
    except OSError:
        return None
    qid = sha[:12]
    meta = {"id": qid, "session": session, "tool": tool, "categories": res.get("categories") or [], "sha": sha,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
    if tool in SHELL_TOOLS:
        cmd = ti.get("command", "")
        if not label.startswith(tool + ":"):  # a script file the command runs: the user edits that file itself
            meta["edit_path"] = os.path.abspath(label if os.path.isabs(label) else os.path.join(cwd, label)).replace("\\", "/")
            meta["next"] = f"re-run the original command: {cmd}"
        else:
            meta["edit_path"] = f"{qdir}/{qid}{_EXT[tool]}"
            runner = "bash" if tool == "Bash" else "powershell -NoProfile -File"
            meta["next"] = f"run the reviewed command with: {runner} \"{meta['edit_path']}\""
    else:
        dest = ti.get("file_path") or ti.get("notebook_path") or ""
        meta["edit_path"] = f"{qdir}/{qid}{os.path.splitext(dest)[1] or '.txt'}"
        meta["dest"] = dest
        meta["next"] = f"write the reviewed content of \"{meta['edit_path']}\" to \"{dest}\" with the Write tool"
    meta["meta_path"] = f"{qdir}/{qid}.json"
    try:
        if meta["edit_path"].startswith(qdir):
            with open(meta["edit_path"], "w", encoding="utf-8") as f:
                f.write(code)
        with open(meta["meta_path"], "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=1)
    except OSError:
        return None
    return meta


# ------------------------------------------------------------------ messages
_INVISIBLE = re.compile("[\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\U000e0000-\U000e007f]")


def flagged_lines(code, lines, redact=False):
    """Excerpts of flagged lines. Text aimed at an AI reader is redacted, so a blocked prompt
    injection is never fed straight back into Claude's context."""
    src = code.replace("\r\n", "\n").split("\n")
    out = []
    for n in (lines or [])[:8]:
        if 1 <= n <= len(src):
            text = "[redacted: text aimed at an AI reader]" if redact else _INVISIBLE.sub("", src[n - 1]).strip()
            out.append(f"  line {n}: {text[:160] + ('...' if len(text) > 160 else '')}")
    return out


def options_text(meta, can_fix):
    """Option 1-3 instructions for Claude (CODEGUARD_ON_BLOCK=ask)."""
    opts = (["\"Ask Claude to fix it\""] if can_fix else []) + ["\"I'll fix it myself\"", "\"Block it\""]
    msg = ["",
           "ACTION REQUIRED: do not retry yet. Ask the user how to proceed with the AskUserQuestion tool. "
           f"Summarise what was blocked in the question, and offer exactly these options: {', '.join(opts)}."]
    if meta:
        msg.append(f"Show the blocked code in the question: put the output of  sh \"{RUN_SH}\" --show \"{meta['meta_path']}\"  "
                   "(numbered lines, >> marks flagged lines) in the 'preview' of each option.")
    msg.append("Then do what they chose:")
    if can_fix:
        msg.append("- Ask Claude to fix it: rewrite the code following 'How to fix' and try again. The rewrite is "
                   "checked again automatically. Never encode, split, rename or hide the flagged behaviour.")
    if meta:
        msg += ["- I'll fix it myself: ask the user (AskUserQuestion) how they want to edit, with two options:",
                "    \"Type the fix here\": the user types or pastes the corrected code (in the question's free-text answer "
                f"or their next message). Save EXACTLY what they typed, with no changes of your own, to {meta['edit_path']} "
                f"with the Write tool, then run: sh \"{RUN_SH}\" --recheck \"{meta['meta_path']}\"",
                f"    \"Open in my editor\": run  sh \"{RUN_SH}\" --edit \"{meta['meta_path']}\"  with the Bash tool and a "
                "timeout of 600000 ms. It opens the file in the user's editor, waits until they save and close it, "
                "and re-checks it automatically.",
                f"  If the re-check prints ALLOW, {meta['next']}. If it prints STILL BLOCKED, show the user the reasons "
                "and flagged lines and offer the options again.",
                f"- Block it: run: sh \"{RUN_SH}\" --decline \"{meta['meta_path']}\" and then stop. "
                "Do not retry this or similar code in this session; continue with the rest of the task without it."]
    else:
        msg += ["- I'll fix it myself: show the user the flagged lines and let them change the code; whatever they "
                "produce is checked again when it runs.",
                "- Block it: stop, and do not retry this or similar code in this session."]
    return msg


def deny_reason(label, code, res, attempt, flag="", meta=None):
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
    if flag == "declined":
        msg.append("The user already chose to BLOCK this kind of code in this session. STOP: do not retry it or a "
                   "variant, and do not ask again. Tell the user it was blocked and continue without it.")
        return "\n".join(msg)
    if ON_BLOCK == "deny":
        msg.append("Policy is to block without retries (CODEGUARD_ON_BLOCK=deny). STOP: do not retry. Tell the user what was blocked.")
        return "\n".join(msg)
    can_fix = True
    if flag == "evasion":
        can_fix = False
        msg.append("After an earlier block in this session, this attempt hides its code (obfuscated_execution). That is "
                   "treated as an attempt to get around the guard. STOP: do not retry it yourself.")
    elif flag == "resubmit":
        can_fix = False
        msg.append("This exact code was already blocked in this session. STOP: do not resubmit it.")
    elif attempt >= MAX_BLOCKS:
        can_fix = False
        msg.append(f"This is block #{attempt} in this session. STOP retrying: do not attempt another variant yourself.")
    elif ON_BLOCK == "fix":
        msg.append(f"(block {attempt}/{MAX_BLOCKS}) Rewrite the code so it does not need the flagged behaviour, then try again. "
                   "Do not encode, split, rename or obfuscate it: the guard decodes payloads and blocks that as "
                   "obfuscated_execution. If the user truly needs this behaviour, stop and ask them instead.")
        return "\n".join(msg)
    if ON_BLOCK == "fix":  # a stop flag in fix mode: hand back to the user without the options menu
        msg.append("Explain to the user what was blocked and why, and ask how they want to proceed.")
        return "\n".join(msg)
    msg += options_text(meta, can_fix)
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
    if is_write and (WRITE_MODE == "off" or ignored(ti.get("file_path") or ti.get("notebook_path"), root)):
        sys.exit(0)
    if is_write and in_quarantine(ti.get("file_path") or "", root):
        # Saving the user's typed fix into quarantine: --recheck verifies it, and running it later is checked again.
        emit(user_msg="🛡 CodeGuard: saved your edit to quarantine (not run; it is re-checked next)" if SHOW_ALLOW else "")

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
                prior, prior_cats, prior_shas, declined = session_history(session)
                sha = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:16]
                cat_list = res.get("categories") or []
                flag = ("declined" if declined & set(cat_list) else
                        "resubmit" if sha in prior_shas else
                        "evasion" if prior and "obfuscated_execution" in cat_list
                        and "obfuscated_execution" not in prior_cats else "")
                audit(rec | {"target": label[:200], "verdict": "block", "risk": res.get("risk_score"),
                             "categories": cat_list, "sha": sha, "flag": flag})
                meta = (quarantine(code, tool, ti, label, session, res, sha, root, cwd)
                        if ON_BLOCK == "ask" and flag != "declined" else None)
                cats = ", ".join(cat_list) or "unknown"
                user = (f"🛡 CodeGuard BLOCKED {tool} ({label[:80]}): {cats}, risk {res.get('risk_score')}, "
                        f"{res.get('roundtrip_ms')} ms" + (f" [{flag}]" if flag else "")
                        + (" (Claude will ask you how to proceed)" if meta else ""))
                decision = "ask" if is_write and WRITE_MODE == "ask" else "deny"
                emit(decision, deny_reason(label, code, res, prior + 1, flag, meta), user)
        audit(rec | {"target": items[0][0][:200], "verdict": "allow"})
        note = f"🛡 CodeGuard allow {tool} (risk {last['risk_score']}, {last['roundtrip_ms']} ms)" if SHOW_ALLOW and last else ""
        emit(user_msg=note)
    except SystemExit:
        raise
    except Exception as e:  # engine down, timeout, bad answer: fail closed
        audit(rec | {"verdict": "error", "error": f"{type(e).__name__}: {e}"})
        emit("ask" if FAIL_MODE == "ask" else "deny",
             f"CodeGuard could not check this call ({type(e).__name__}: {e}), so it was blocked (fail closed). "
             f"Tell the user to start the engine (codeguard engine, or python -m codeguard.api --port 8000) at {URL}.",
             f"🛡 CodeGuard unavailable at {URL}: blocked (fail closed)")


# ------------------------------------------------------------------ manual commands (slash commands, options 2 and 3)
def print_result(p, code, res):
    mark = "BLOCK" if res["verdict"] == "block" else "ALLOW"
    print(f"{mark}  {p}  risk={res['risk_score']}  language={res['code_language']}  "
          f"engine={res.get('latency_ms')} ms  round-trip={res['roundtrip_ms']} ms")
    if res.get("categories"):
        print("  categories: " + ", ".join(f"{c} ({res.get('category_scores', {}).get(c, '')})" for c in res["categories"]))
    redact = "ai_targeted_instructions" in (res.get("categories") or [])
    for r in (res.get("reason") or "").split("; "):
        if r and not redact:
            print(f"  - {r}")
    for l in flagged_lines(code, res.get("vulnerable_lines"), redact):
        print(l)
    for c in res.get("categories") or []:
        if c in HINTS:
            print(f"  fix: {HINTS[c]}")


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
            print(f"{p}: engine unavailable at {URL} ({type(e).__name__}); start it with: codeguard engine")
            return 1
        print_result(p, code, res)
        worst = max(worst, 2 if res["verdict"] == "block" else 0)
    return worst


def _load_meta(arg):
    if arg.endswith(".json") and os.path.isfile(arg):
        with open(arg, encoding="utf-8") as f:
            return json.load(f)
    return None


def recheck(arg):
    """Option 2: verify the user's edited version. Exit 0 = allowed (prints NEXT), 2 = still blocked."""
    meta = _load_meta(arg)
    path = meta["edit_path"] if meta else arg
    code = _read(path)
    if code is None:
        print(f"{path}: cannot read")
        return 1
    try:
        res = analyze(code)
    except Exception as e:
        print(f"engine unavailable at {URL} ({type(e).__name__}); nothing was approved. Start it with: codeguard engine")
        return 1
    print_result(path, code, res)
    sha = hashlib.sha256(code.encode("utf-8", "replace")).hexdigest()[:16]
    audit({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "session": (meta or {}).get("session", ""), "agent": "user",
           "tool": "recheck", "target": path[:200], "verdict": "recheck_" + res["verdict"],
           "categories": res.get("categories"), "sha": sha})
    if res["verdict"] == "block":
        print("\nSTILL BLOCKED: the edited code is not safe yet. Nothing was run.")
        return 2
    print("\nALLOW: the edited code passed CodeGuard.")
    if meta:
        print(f"NEXT: {meta['next']} (that step is checked again when it runs).")
    return 0


def _editor_cmd(path):
    """The user's editor as an argv list that waits until the file is closed."""
    import shlex
    import shutil
    for env in ("CODEGUARD_EDITOR", "VISUAL", "EDITOR"):
        if os.environ.get(env):
            parts = shlex.split(os.environ[env], posix=os.name != "nt")
            # non-POSIX split keeps quotes: "C:\Program Files\x\editor.exe" -w  ->  strip them
            parts = [p[1:-1] if len(p) > 1 and p[0] == p[-1] == '"' else p for p in parts]
            exe = shutil.which(parts[0]) or parts[0]
            return [exe, *parts[1:], path]
    code = shutil.which("code")
    if code:
        return [code, "--wait", path]
    if os.name == "nt":
        return ["notepad.exe", path]
    if sys.platform == "darwin":
        return ["open", "-W", "-t", path]
    for e in ("gedit", "kate", "xdg-open"):
        if shutil.which(e):
            return [shutil.which(e), path]
    return None


def show(meta):
    """Print the quarantined code with line numbers, flagged lines marked."""
    code = _read(meta["edit_path"]) or ""
    flagged = set()
    try:
        flagged = set(analyze(code).get("vulnerable_lines") or [])
    except Exception:
        pass
    print(f"--- {meta['edit_path']}")
    for i, line in enumerate(code.replace("\r\n", "\n").split("\n"), 1):
        print(f"{'>>' if i in flagged else '  '} {i:4} | {_INVISIBLE.sub('', line)}")
    print("(>> = flagged by CodeGuard)")


def edit(arg):
    """Option 2 in an editor: open the quarantined code, wait until it is closed, then recheck it."""
    import subprocess
    meta = _load_meta(arg)
    if not meta:
        print(f"{arg}: not a CodeGuard quarantine record")
        return 1
    show(meta)
    cmd = _editor_cmd(meta["edit_path"])
    if not cmd:
        print("No editor found. Set CODEGUARD_EDITOR (e.g. \"code --wait\"), or type the corrected code in the chat.")
        return 1
    print(f"\nOpening {meta['edit_path']} in {os.path.basename(cmd[0])}. Save and close it to continue...", flush=True)
    try:
        subprocess.run(cmd, check=False)
    except OSError as e:
        print(f"Could not start the editor ({e}). Set CODEGUARD_EDITOR, or type the corrected code in the chat.")
        return 1
    print("\nEditor closed. Re-checking your version:\n")
    return recheck(arg)


def decline(arg):
    """Option 3: the user blocks it. Recorded for the session; the quarantined copy is deleted."""
    meta = _load_meta(arg)
    if not meta:
        print(f"{arg}: not a CodeGuard quarantine record")
        return 1
    audit({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "session": meta.get("session", ""), "agent": "user",
           "tool": "decline", "target": meta.get("edit_path", "")[:200], "verdict": "declined",
           "categories": meta.get("categories"), "sha": meta.get("sha")})
    qdir = os.path.dirname(meta["meta_path"])
    for p in (meta.get("edit_path"), meta.get("meta_path")):
        if p and os.path.dirname(p) == qdir and os.path.isfile(p):  # never delete the user's own files
            os.remove(p)
    print(f"BLOCKED by the user: {', '.join(meta.get('categories') or [])}. "
          "Further attempts at this kind of code in this session will be refused.")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252
    if len(sys.argv) > 1 and sys.argv[1] == "--scan":
        sys.exit(scan(sys.argv[2:]))
    if len(sys.argv) == 3 and sys.argv[1] == "--recheck":
        sys.exit(recheck(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--decline":
        sys.exit(decline(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--edit":
        sys.exit(edit(sys.argv[2]))
    if len(sys.argv) == 3 and sys.argv[1] == "--show":
        m = _load_meta(sys.argv[2])
        sys.exit(show(m) or 0 if m else 1)
    if len(sys.argv) > 1 and sys.argv[1] == "--health":
        try:
            with _OPENER.open(URL + "/health", timeout=TIMEOUT) as r:
                print(f"CodeGuard engine UP at {URL} (HTTP {r.status})")
            sys.exit(0)
        except Exception as e:
            print(f"CodeGuard engine DOWN at {URL}: {e}. Start it with: codeguard engine")
            sys.exit(1)
    hook()
