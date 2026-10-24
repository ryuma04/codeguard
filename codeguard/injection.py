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
_INVISIBLE_RUN = re.compile("(?:" + _ZERO_WIDTH.pattern + "){4,}")
_PROSE_LANGS = ("markdown", "unknown", "yaml", "html")  # formats whose prose is itself read by the AI

# (weight, regex) — each phrase family scores; several families together push higher.
_PATTERNS = [
    (0.85, r"\b(ignore|disregard|forget|override|bypass)\b[\w\s,']{0,30}\b(previous|prior|above|all|earlier|preceding|system|your|the user's|user|safety|security)\b[\w\s']{0,20}\b(instructions?|prompts?|rules?|directives?|guidelines?|context|polic(y|ies)|safeguards?|restrictions?|constraints?)"),
    # Addressed to the AI reader, then an imperative: "AI reviewer: ignore ...", "Agent, reveal ...".
    (0.80, r"\b(ai|llm|gpt|claude|assistant|agent|copilot|chatbot|bot|(ai|code|security|automated)\s+(reviewer|scanner|agent|assistant))\s*[:,\-]\s*(please\s+)?(ignore|disregard|forget|override|bypass|approve|reveal|leak|exfiltrate|execute|run|mark|classify|treat|output|print|send|respond|reply|delete|disable)\b"),
    (0.70, r"\b(reveal|leak|exfiltrate|dump|disclose)\b\s+(all\s+|any\s+)?(the\s+|your\s+)?(secrets?|credentials|api[\s_-]?keys?|tokens?|passwords?|system prompt)\b"),
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
    if language in _PROSE_LANGS:
        # In prose formats the prose itself is the stream.
        for i, line in enumerate(code.splitlines(), 1):
            out.append((i, line))
    return out


# Text a human reader does not see: HTML comments, and elements hidden by CSS or attributes.
_HIDDEN_BLOCK = re.compile(
    r"<!--.*?-->|<(?P<tag>[a-z][\w-]*)\b[^>]*(style\s*=\s*[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|"
    r"font-size\s*:\s*0(?![.\d]*[1-9])|opacity\s*:\s*0(?![.\d]*[1-9])|color\s*:\s*(white|#fff\b|#ffffff\b|transparent))"
    r"|\shidden(\s|>|=)|aria-hidden\s*=\s*[\"']true)[^>]*>.*?</(?P=tag)\s*>", re.S | re.I)
# The phrase is visibly presented as a quoted example / test data, not addressed to the reader. Letter
# boundaries (not \b) so `prompt_injection_example` and `detector-test.txt` count.
# Not "test": real jailbreaks say "created as a means to test ...", "ersten Test bestanden".
_MENTION = re.compile(r"(?<![a-z])(examples?|fixtures?|samples?|detectors?|quoted|quotes?|quotations?|phrases?|"
                      r"expected_label|security finding|not an instruction|suspicious string|should be (quoted|analy[sz]ed))(?![a-z])", re.I)
MENTION_CAP = 0.4


def _hidden_lines(code):
    out = {}
    for m in _HIDDEN_BLOCK.finditer(code):
        how = "an HTML comment" if m.group(0).startswith("<!--") else "visually hidden HTML"
        for n in range(code.count("\n", 0, m.start()) + 1, code.count("\n", 0, m.end()) + 2):
            out.setdefault(n, how)
    return out


MENTION_WINDOW = 150  # chars either side of the match: a long jailbreak can say "example" far from its directive


def _is_mention(lines, line, text=None, span=None):
    """Words around the match, plus the nearest non-blank line on each side (a quote is often followed by a
    blank line). Neighbour lines only count for short lines; inside a long paragraph only the window does."""
    i = line - 1
    if text is not None and span is not None:
        window = text[max(0, span[0] - MENTION_WINDOW):span[1] + MENTION_WINDOW]
        if len(text) > 2 * MENTION_WINDOW:
            return bool(_MENTION.search(window))
    # the stream item may be just a string literal: its own line holds the context (`fixture = "..."`)
    near = [lines[i]] if 0 <= i < len(lines) and len(lines[i]) <= 2 * MENTION_WINDOW + 200 else []
    for step in (-1, 1):
        j = i + step
        while 0 <= j < len(lines) and not lines[j].strip():
            j += step
        if 0 <= j < len(lines):
            near.append(lines[j])
    return bool(_MENTION.search(" ".join(near)))


def scan_injection(code: str, language: str):
    """Returns list of (line, weight, reason)."""
    hits = []
    if _ZERO_WIDTH.search(code) or _TAGS.search(code):
        line = next((i for i, l in enumerate(code.splitlines(), 1) if _ZERO_WIDTH.search(l) or _TAGS.search(l)), 1)
        # Scattered zero-width/bidi characters are ordinary in web text and documents (emoji joiners, ZWSP):
        # on BrowseSafe they occur in benign and injected pages alike. In documents they only count when they
        # form a run (text encoded in invisible characters) or are unicode tag characters (ASCII smuggling).
        doc = language in ("html", "markdown", "yaml")  # not "unknown": unidentified text may well be code
        if not doc or _TAGS.search(code) or _INVISIBLE_RUN.search(code):
            hits.append((line, 0.55, "contains invisible/bidi unicode characters"))
        else:
            hits.append((line, 0.3, "contains scattered invisible unicode characters (common in web text)"))
    seen = set()
    hidden_at = _hidden_lines(code) if "<" in code else {}
    lines = code.splitlines()
    stream = extract_text_stream(code, language)
    found = []
    for line, text in stream:
        t = _ZERO_WIDTH.sub("", text)
        for w, rx in _COMPILED:
            m = rx.search(t)
            if m and (line, w) not in seen:
                seen.add((line, w))
                found.append((line, w, "instruction aimed at an AI reader", t, m.span()))
    if not found and textclf.available():
        found = [(line, w, reason, None, None) for line, w, reason in _classify(stream)]
    for line, w, reason, text, span in found:
        hidden = hidden_at.get(line)
        if hidden:
            hits.append((line, min(0.95, w + 0.1), f"{reason} hidden in {hidden}"))
        elif _is_mention(lines, line, text, span):
            hits.append((line, min(w, MENTION_CAP), f"{reason}, quoted as an example/test data"))
        else:
            hits.append((line, w, reason))
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
        if len(text.split()) < 6 or len(text) > 2000:  # short UI strings ("You are too young!") are not instructions
            continue
        p = textclf.score(text)
        if p is not None and p >= thr:
            w = round(0.55 + 0.4 * (p - thr) / max(1e-6, 1 - thr), 3)
            hits.append((block[0][0], w, f"text classifier: likely instruction aimed at an AI reader (p={p:.2f})"))
    return hits
