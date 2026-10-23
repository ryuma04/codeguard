"""ai_targeted_instructions: text aimed at a downstream AI reader, not the machine.

Two-stream idea (inspired by Meta LlamaFirewall, MIT): we split comments,
docstrings and string literals out of the code and score only that text.
"""
import io
import re
import tokenize

from . import textclf

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")
_TAGS = re.compile(r"[\U000E0000-\U000E007F]")  # unicode tag characters (invisible text)

# (weight, regex) — each phrase family scores; several families together push higher.
_PATTERNS = [
    (0.85, r"\b(ignore|disregard|forget|override|bypass)\b[\w\s,]{0,30}\b(previous|prior|above|all|earlier|preceding|system|your)\b[\w\s]{0,20}\b(instructions?|prompts?|rules?|directives?|guidelines?|context)"),
    (0.80, r"\b(mark|classify|label|flag|report|treat|rate|score)\b[\w\s,'\"]{0,40}\b(as\s+)?(safe|benign|harmless|clean|trusted|allowed?|approved|low[\s-]risk|not\s+malicious|false\s+positive)\b"),
    (0.75, r"\b(you are now|you're now|act as|pretend to be|roleplay as|from now on,? you( are)?)\b[\w\s,]{0,30}\b(ai|assistant|model|llm|gpt|claude|chatbot|reviewer|scanner|agent|dan)\b"),
    (0.75, r"\b(ai|llm|language model|assistant|copilot|code reviewer|security scanner|automated reviewer|agent|bot)s?\b[\w\s,:]{0,40}\b(must|should|shall|need to|are instructed|will)\b[\w\s]{0,30}\b(ignore|approve|allow|skip|not (flag|report|block|mention)|execute|run|output|say|respond)"),
    (0.70, r"\b(do not|don't|never|must not)\b[\w\s]{0,25}\b(flag|report|block|mention|warn|alert|analy[sz]e|scan|reveal|tell)\b[\w\s]{0,30}\b(this|it|code|user|anyone|security|vulnerab\w*|backdoor)"),
    (0.70, r"\b(system prompt|developer mode|jailbreak|DAN mode|new instructions|updated instructions|hidden instructions|prompt injection)\b"),
    (0.65, r"(</?(system|instructions?|im_start|im_end|assistant|user)>|\[/?(INST|SYS)\]|<<SYS>>|###\s*(system|instruction))"),
    (0.65, r"\b(reveal|print|output|leak|send|exfiltrate|show)\b[\w\s]{0,20}\b(your|the)\b[\w\s]{0,10}\b(system prompt|instructions|api key|secrets?|credentials|hidden prompt)"),
    (0.60, r"\b(this (code|file|snippet|script|package) (is|has been))\b[\w\s,]{0,30}\b(safe|verified|audited|approved|reviewed|trusted|whitelisted)\b"),
    (0.55, r"\b(respond|reply|answer|output)\s+(only\s+)?(with\s+)?['\"]?(allow|safe|yes|approved|ok|\{\"verdict\"\s*:\s*\"allow)"),
]
_COMPILED = [(w, re.compile(p, re.I)) for w, p in _PATTERNS]


def extract_text_stream(code: str, language: str):
    """Return [(line, text)] of comments, docstrings and string literals."""
    out = []
    if language == "python":
        try:
            for tok in tokenize.generate_tokens(io.StringIO(code).readline):
                if tok.type in (tokenize.COMMENT, tokenize.STRING):
                    out.append((tok.start[0], tok.string))
            return out
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass
    pats = [r"#[^\n]*", r"//[^\n]*", r"/\*.*?\*/", r"--[^\n]*", r"<!--.*?-->", r"'''.*?'''", r'""".*?"""',
            r"'(?:\\.|[^'\\\n])*'", r'"(?:\\.|[^"\\\n])*"', r"`[^`]*`"]
    for m in re.finditer("|".join(pats), code, re.S):
        out.append((code.count("\n", 0, m.start()) + 1, m.group(0)))
    if language in ("markdown", "unknown", "yaml"):
        # In prose formats the prose itself is the stream.
        for i, line in enumerate(code.splitlines(), 1):
            out.append((i, line))
    return out


def scan_injection(code: str, language: str):
    """Returns list of (line, weight, reason)."""
    hits = []
    if _ZERO_WIDTH.search(code) or _TAGS.search(code):
        line = next((i for i, l in enumerate(code.splitlines(), 1) if _ZERO_WIDTH.search(l) or _TAGS.search(l)), 1)
        hits.append((line, 0.55, "contains invisible/bidi unicode characters"))
    seen = set()
    stream = extract_text_stream(code, language)
    for line, text in stream:
        t = _ZERO_WIDTH.sub("", text)
        for w, rx in _COMPILED:
            if rx.search(t) and (line, w) not in seen:
                seen.add((line, w))
                hidden = "<!--" in text
                hits.append((line, min(0.95, w + (0.1 if hidden else 0)),
                             "instruction aimed at an AI reader" + (" hidden in an HTML comment" if hidden else "")))
    if not hits and textclf.available():
        hits += _classify(stream)
    return hits


def _classify(stream):
    """Learned second opinion: score comment blocks / strings with the local text classifier."""
    blocks, cur, last = [], [], -9
    for line, text in stream:  # glue consecutive comment lines into one block
        t = _ZERO_WIDTH.sub("", re.sub(r"^\s*(#+|//+|/\*+|\*+/?|<!--|-->|--|'''|\"\"\"|[rbuf]*['\"`])|(\*/|-->|'''|\"\"\"|['\"`])\s*$", "", text)).strip()
        if line - last > 1 and cur:
            blocks.append(cur)
            cur = []
        cur.append((line, t))
        last = line + text.count("\n")
    if cur:
        blocks.append(cur)
    thr, hits = textclf.threshold(), []
    for block in blocks:
        text = " ".join(t for _, t in block)
        if len(text.split()) < 4 or len(text) > 2000:
            continue
        p = textclf.score(text)
        if p is not None and p >= thr:
            w = round(0.55 + 0.4 * (p - thr) / max(1e-6, 1 - thr), 3)
            hits.append((block[0][0], w, f"text classifier: likely instruction aimed at an AI reader (p={p:.2f})"))
    return hits
