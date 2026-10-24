"""Embedded-code extraction: pull real code out of carrier formats.

A payload can hide in a file that is not itself a script: a JSON string, a
Jupyter notebook cell, a package.json `postinstall`, a Dockerfile `RUN`, a
Makefile recipe, a YAML value under any key, or a `python -c "..."` /
heredoc inside a shell command. The rule layer still scans the raw text line
by line, but the deep Python/SQL analysis only sees code that is handed to it
as code. This module finds those embedded pieces and yields them so the engine
can re-route each through the full cascade.

Yields (line_no, language_or_None, code). Nothing is executed; only text is
parsed and sliced. Line numbers are 1-based in the original input.
"""
import json
import re

_INTERP = {"python": "python", "python3": "python", "py": "python", "node": "javascript",
           "nodejs": "javascript", "bash": "bash", "sh": "bash", "zsh": "bash", "ruby": "bash", "perl": "bash", "php": "bash"}


def _line_at(text, idx):
    return text.count("\n", 0, idx) + 1


# ---------------------------------------------------------------- shell -c / -e / heredoc
_DASH_C = re.compile(r"""\b(python3?|py|node(?:js)?|bash|sh|zsh|ruby|perl|php)\b[^\n|;&]*?\s-(?:c|e)\s+(?P<q>['"])(?P<body>.*?)(?<!\\)(?P=q)""", re.S)
_HEREDOC = re.compile(r"""\b(python3?|py|node(?:js)?|bash|sh|zsh|ruby|perl|php)\b[^\n]*?<<-?\s*(?P<q>['"]?)(?P<tag>[A-Za-z_]\w*)(?P=q)\s*\n(?P<body>.*?)\n[ \t]*(?P=tag)\b""", re.S)


def extract_shell_embedded(text):
    """`python -c "..."`, `node -e '...'`, and `<<EOF` heredocs inside shell."""
    for m in _DASH_C.finditer(text):
        lang = _INTERP.get(m.group(1).lower())
        body = m.group("body").encode().decode("unicode_escape", "replace") if '"' == m.group("q") else m.group("body")
        if len(body.strip()) >= 4:
            yield _line_at(text, m.start("body")), lang, body
    for m in _HEREDOC.finditer(text):
        lang = _INTERP.get(m.group(1).lower())
        if len(m.group("body").strip()) >= 4:
            yield _line_at(text, m.start("body")), lang, m.group("body")


# ---------------------------------------------------------------- JSON (config, package.json, notebooks)
_SCRIPT_KEY = re.compile(r"(preinstall|postinstall|install|prepare|prepublish|prestart|start|build|setup|entry|exec|cmd|command|script|run|bootstrap|init)", re.I)


def _notebook_cells(obj):
    cells = obj.get("cells")
    if not isinstance(cells, list):
        return None
    out, lang = [], "python"
    meta_lang = (obj.get("metadata", {}).get("kernelspec", {}) or {}).get("language")
    if isinstance(meta_lang, str):
        lang = _INTERP.get(meta_lang.lower(), "python")
    for cell in cells:
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            src = cell.get("source")
            body = "".join(src) if isinstance(src, list) else src if isinstance(src, str) else ""
            m = re.match(r"\s*%%(bash|sh|python|ruby|perl|js|javascript|node)\b", body)
            out.append((_INTERP.get(m.group(1).lower(), lang) if m else lang,
                        body[m.end():] if m else body))
    return out


def _walk_json(node, path=""):
    """Yield (json_path, key, string_value) for every string in the structure."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str):
                yield path, k, v
            else:
                yield from _walk_json(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, str):
                yield path, None, v
            else:
                yield from _walk_json(v, f"{path}[{i}]")


def extract_json_embedded(text):
    """Code stored inside JSON strings: notebook cells, npm scripts, config values."""
    stripped = text.lstrip()
    if not stripped[:1] in "{[":
        return
    try:
        obj = json.loads(text)
    except ValueError:
        return
    cells = _notebook_cells(obj) if isinstance(obj, dict) else None
    if cells is not None:
        for lang, body in cells:
            if len(body.strip()) >= 4:
                yield _find_json_fragment(text, body), lang, body
        return
    for _, key, val in _walk_json(obj):
        if len(val) < 8:
            continue
        looks_like_code = bool(re.search(r"[;(){}=]|\b(import|require|def|curl|wget|rm|eval|exec|os\.|subprocess|child_process)\b", val))
        if (key and _SCRIPT_KEY.fullmatch(key)) or (looks_like_code and ("\n" in val or re.search(r"\b(curl|wget|bash|sh|eval|exec|rm|import|require|subprocess|child_process|os\.system)\b", val))):
            yield _find_json_fragment(text, val), None, val


def _find_json_fragment(text, body):
    probe = body.strip().splitlines()[0][:24] if body.strip() else ""
    for cand in (probe, json.dumps(probe)[1:-1][:24] if probe else ""):
        if cand:
            i = text.find(cand)
            if i != -1:
                return _line_at(text, i)
    return 1


# ---------------------------------------------------------------- YAML (any key, not just run:)
_YAML_BLOCK = re.compile(r"^(?P<indent>\s*)(?:-\s*)?(?P<key>[\w.\-]+)\s*:\s*[|>][+-]?\s*$", re.M)
_YAML_INLINE = re.compile(r"^(?P<indent>\s*)(?:-\s*)?(?P<key>[\w.\-]+)\s*:\s*(?P<val>\S.*)$", re.M)
_CODE_KEY = re.compile(r"(run|script|cmd|command|commands|args|entrypoint|exec|install|setup|bootstrap|init|before_script|after_script|post_?install|pre_?install|user[\-_]?data|startup)", re.I)
_CODEISH = re.compile(r"[;|&]|\$\(|`|\b(curl|wget|bash|sh|eval|exec|rm|chmod|pip|npm|import|subprocess|os\.system|base64|python3?|node)\b")


def extract_yaml_embedded(text):
    """Block scalars (| and >) and code-looking inline values under ANY key."""
    lines = text.splitlines()
    consumed = set()
    for m in _YAML_BLOCK.finditer(text):
        start_line = _line_at(text, m.start())
        indent = len(m.group("indent"))
        block, j = [], start_line  # start_line is 1-based index of the key line
        while j < len(lines):
            ln = lines[j]
            if ln.strip() and (len(ln) - len(ln.lstrip())) <= indent:
                break
            block.append(ln)
            consumed.add(j)
            j += 1
        body = _dedent(block)
        if len(body.strip()) >= 4 and (_CODE_KEY.search(m.group("key")) or _CODEISH.search(body)):
            yield start_line + 1, None, body
    for m in _YAML_INLINE.finditer(text):
        li = _line_at(text, m.start()) - 1
        if li in consumed:
            continue
        val = m.group("val").strip()
        if val in ("|", ">", "|-", ">-", "|+", ">+"):
            continue
        val = val.strip("'\"")
        if len(val) >= 8 and (_CODE_KEY.search(m.group("key")) or _CODEISH.search(val)):
            yield li + 1, None, val


def _dedent(block):
    indents = [len(l) - len(l.lstrip()) for l in block if l.strip()]
    pad = min(indents) if indents else 0
    return "\n".join(l[pad:] if len(l) >= pad else l for l in block)


# ---------------------------------------------------------------- Dockerfile / Makefile
_DOCKER_RUN = re.compile(r"^\s*(?:RUN|CMD|ENTRYPOINT)\s+(.+?)(?<!\\)$", re.M | re.I)


def extract_dockerfile_embedded(text):
    if not re.search(r"^\s*FROM\s+\S", text, re.M | re.I):
        return
    for m in _DOCKER_RUN.finditer(text):
        cmd = m.group(1)
        # join line-continuations
        cmd = re.sub(r"\\\s*\n\s*", " ", cmd)
        if cmd.strip().startswith("["):  # exec form JSON array
            try:
                parts = json.loads(cmd)
                cmd = " ".join(parts) if isinstance(parts, list) else cmd
            except ValueError:
                pass
        if len(cmd.strip()) >= 4:
            yield _line_at(text, m.start(1)), "bash", cmd


def extract_makefile_embedded(text):
    if not re.search(r"^[\w.\-]+\s*:(?!=)", text, re.M):
        return
    # Group each target's consecutive tab-indented recipe lines into one fragment,
    # so a multi-line payload is analysed as a whole (and language-detected), not line by line.
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("\t"):
            start = i
            block = []
            while i < len(lines) and (lines[i].startswith("\t") or not lines[i].strip()):
                block.append(lines[i][1:].lstrip("@-+") if lines[i].startswith("\t") else "")
                i += 1
            body = "\n".join(block).strip("\n")
            if len(body.strip()) >= 4:
                yield _line_at(text, sum(len(l) + 1 for l in lines[:start])), None, body
        else:
            i += 1


# ---------------------------------------------------------------- HTML
_SCRIPT = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(?P<body>.*?)</script\s*>", re.S | re.I)
_ON_ATTR = re.compile(r"\son(?:load|error|click|mouseover|focus|submit)\s*=\s*(?P<q>['\"])(?P<body>.*?)(?P=q)", re.S | re.I)


def extract_html_embedded(text):
    """Inline <script> blocks and on*= event-handler attributes, as JavaScript."""
    if not re.search(r"<\s*(script|[a-z]+\s[^>]*\son\w+\s*=)", text, re.I):
        return
    for rx in (_SCRIPT, _ON_ATTR):
        for m in rx.finditer(text):
            if len(m.group("body").strip()) >= 4:
                yield _line_at(text, m.start("body")), "javascript", m.group("body")


# ---------------------------------------------------------------- dispatcher
_EXTRACTORS = (extract_json_embedded, extract_yaml_embedded, extract_dockerfile_embedded,
               extract_makefile_embedded, extract_shell_embedded, extract_html_embedded)


def extract_embedded(text, language):
    """Yield (line, language_or_None, code) for every code fragment hidden in a carrier.

    Every extractor runs regardless of the *detected* language, because language
    detection is exactly what an attacker fools by burying Python in a YAML value
    (the file then looks like Python, or like nothing). Each extractor guards
    itself on structure (valid JSON, a `FROM` line, a `key: |` block, a tab
    recipe), so running them all is cheap and evasion-resistant. Identical
    fragments, and fragments equal to the whole input, are dropped.
    """
    seen = set()
    whole = text.strip()
    for run in _EXTRACTORS:
        # JSON/notebook bodies are UN-escaped out of string literals, so the top-level
        # rule scan (which saw "\n" etc.) did NOT already cover them: keep rules on.
        # Every other carrier yields a verbatim slice the rule layer already scanned.
        verbatim = run is not extract_json_embedded
        try:
            fragments = list(run(text))
        except Exception:
            continue
        for line, lang, body in fragments:
            b = body.strip()
            key = (lang, b)
            if b and b != whole and key not in seen:
                seen.add(key)
                yield line, lang, body, verbatim
