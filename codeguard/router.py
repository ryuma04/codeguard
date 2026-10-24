"""Step 1: language detection (cheap heuristics, no dependencies)."""
import ast
import re

from .languages import SIGNALS as _LANG_SIGNALS, CASE_INSENSITIVE as _LANG_CI

_SIGNALS = {
    "python": [
        (r"^\s*(import|from)\s+[\w\.]+", 3), (r"^\s*def\s+\w+\(.*\)\s*:", 3),
        (r"^\s*class\s+\w+.*:\s*$", 2), (r"\bprint\(", 1), (r"\bself\.", 2),
        (r"^\s*(if|for|while|with|try|elif|else)\b.*:\s*$", 2), (r"__\w+__", 1),
        (r"\bos\.(system|environ|popen)", 2), (r"#!.*python", 5),
    ],
    "bash": [
        (r"^#!.*\b(ba|z|da)?sh\b", 6), (r"^\s*(sudo|apt|apt-get|yum|chmod|chown|curl|wget|echo|export|cd|ls|rm|mkdir|cat|grep|nc|crontab|systemctl|dd|mkfs)\b", 2),
        (r"\$\{?\w+\}?", 1), (r"\|\s*(ba)?sh\b", 3), (r"\bfi\b|\bdone\b|\besac\b", 3),
        (r"&&|\|\|", 1), (r":\(\)\s*\{", 6), (r"/dev/(tcp|null|zero|sd)", 2),
    ],
    "javascript": [
        (r"\b(const|let|var)\s+\w+\s*=", 3), (r"\brequire\(['\"]", 4), (r"=>", 2),
        (r"\bfunction\s+\w*\s*\(", 2), (r"\bconsole\.log\(", 3), (r"\bmodule\.exports\b", 4),
        (r"\bprocess\.(env|argv)", 3), (r"\bawait\s+fetch\(", 3), (r"^\s*import\s+.*\s+from\s+['\"]", 4),
        (r";\s*$", 1), (r"\bdocument\.|\bwindow\.", 2),
    ],
    "sql": [
        (r"^\s*(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE|WITH|EXEC|COPY|LOAD\s+DATA)\s+[\w*@`\"\[]", 5),
        (r"(?<![.\w])(FROM|WHERE|TABLE|INTO|VALUES|JOIN)\s+[\w`\"\[(]", 2),
    ],
    "yaml": [
        (r"^\s*[\w\-\.]+:\s*(\S.*)?$", 1), (r"^\s*-\s+[\w\-\.]+:\s", 2), (r"^---\s*$", 3),
        (r"^\s*(apiVersion|kind|jobs|steps|runs-on|services|image|on):", 4),
    ],
    "markdown": [
        (r"^#{1,6}\s+\S", 3), (r"^```", 4), (r"^\s*[-*]\s+\S", 1), (r"\[[^\]]+\]\([^)]+\)", 2),
        (r"<!--", 2), (r"\*\*[^*]+\*\*", 1),
    ],
    "php": [(r"<\?php", 10), (r"\$_(GET|POST|REQUEST|SERVER|COOKIE)\b", 4), (r"\$\w+\s*=", 1), (r"->\w+\(", 1)],
    "powershell": [(r"\b(Invoke-\w+|Get-\w+|Set-\w+|New-Object|Remove-Item|Start-Process)\b", 4), (r"-EncodedCommand|-enc\b", 4)],
    "dockerfile": [(r"^\s*FROM\s+\S+", 6), (r"^\s*(RUN|CMD|ENTRYPOINT|COPY|ADD|WORKDIR|ENV|EXPOSE|ARG|LABEL|USER)\s+\S", 3)],
    "json": [(r"^\s*\{", 2), (r'"\w+"\s*:', 1), (r'"(cells|nbformat|scripts|dependencies)"\s*:', 5)],
    "makefile": [(r"^[\w.\-]+\s*:(?!=)[^\n]*\n\t", 6), (r"^\.PHONY\s*:", 5), (r"^\t@?\S", 1)],
}

_COMPILED = {lang: [(re.compile(p, re.I | re.M), w) for p, w in sigs] for lang, sigs in _SIGNALS.items()}
# SQL keywords are case-insensitive but Python/JS signals should not be. Dockerfile
# instructions are upper-case by convention; case-insensitive `FROM` would match
# every Python `from x import y`.
_CASE_SENSITIVE = {"python", "javascript", "dockerfile"}
_YAML_TOP = re.compile(r"""^(?:[\w.\-]+|"[^"]*"|'[^']*')\s*:(\s|$)|^-\s""")
_COMPILED.update({lang: [(re.compile(p, re.M), w) for p, w in _SIGNALS[lang]] for lang in _CASE_SENSITIVE})
# Languages beyond the original eleven (languages.py): case-sensitive unless listed otherwise.
_COMPILED.update({lang: [(re.compile(p, re.M | (re.I if lang in _LANG_CI else 0)), w) for p, w in sigs]
                  for lang, sigs in _LANG_SIGNALS.items() if sigs})
# TypeScript only refines a JavaScript verdict; its signals never compete on their own.
_TS = _COMPILED.pop("typescript")
_SHEBANG = re.compile(r"#!\s*\S*/(?:env\s+(?:-\S+\s+)*)?([\w.\-]+)")
_SHEBANG_LANG = {"sh": "bash", "bash": "bash", "zsh": "bash", "dash": "bash", "ksh": "bash", "ash": "bash",
                 "python": "python", "pypy": "python", "node": "javascript", "nodejs": "javascript", "deno": "javascript",
                 "bun": "javascript", "ts-node": "typescript", "perl": "perl", "ruby": "ruby", "php": "php", "lua": "lua",
                 "pwsh": "powershell", "powershell": "powershell", "Rscript": "r", "elixir": "elixir", "julia": "julia",
                 "ocaml": "ocaml", "runhaskell": "haskell", "swift": "swift", "groovy": "groovy", "kotlin": "kotlin",
                 "scala": "scala", "dart": "dart", "make": "makefile"}
_HTML_TAG = re.compile(r"</?[a-zA-Z][\w-]*(\s[^<>]*)?/?>")
_CPP_ONLY = re.compile(r"\bstd::|#include\s*<\w+>(?!\.h)|\busing\s+namespace\b|\b(cout|cin|cerr)\b|\bnullptr\b|\btemplate\s*<", re.M)


def detect_language(code: str) -> str:
    text = code.strip()
    if not text:
        return "unknown"
    m = _SHEBANG.match(text)
    if m and m.group(1).rstrip("0123456789.") in _SHEBANG_LANG:  # the author telling us the language
        return _SHEBANG_LANG[m.group(1).rstrip("0123456789.")]
    # Starts with a tag and is mostly markup: HTML, whatever its CSS (`100%` looks like batch) or prose
    # ("from your" looks like SQL) suggests. Not <?php / <?xml.
    if text[:1] == "<" and text[1:2] not in "?" and len(_HTML_TAG.findall(text[:20000])) >= max(5, text[:20000].count("\n") // 4):
        return "html"
    scores = {lang: 0.0 for lang in _COMPILED}
    for lang, rules in _COMPILED.items():
        for rx, w in rules:
            hits = len(rx.findall(text))
            if hits:
                scores[lang] += w * min(hits, 5)
    # A clean Python parse is strong evidence (but trivial one-liners parse too).
    try:
        ast.parse(text)
        if len(text.splitlines()) > 1 or re.search(r"\(|import|=", text):
            scores["python"] += 4
    except SyntaxError:
        scores["python"] -= 3
        # Structure beats keyword counts: a document whose top-level (column-0) lines are
        # mostly `key:` / `- item` is YAML, even when its values are full of embedded
        # Python (a test suite, a CI file). Keyword scoring alone calls that "python".
        top = [l for l in text.splitlines() if l.strip() and not l[0].isspace() and not l.startswith("#")]
        if len(top) >= 2 and not re.search(r"^\t\S", text, re.M) and text[:1] not in "{[":
            if sum(bool(_YAML_TOP.match(l)) for l in top) / len(top) >= 0.6:
                return "yaml"
    # YAML signal is generic; only trust it when nothing code-like wins.
    scores["yaml"] *= 0.8
    # JSON and YAML both match brace/colon lines; a clean JSON parse settles it.
    if scores["json"] or text[:1] in "{[":
        try:
            import json as _json
            _json.loads(text)
            scores["json"] += 5
            scores["yaml"] *= 0.5
        except (ValueError, RecursionError):
            scores["json"] *= 0.3
    best = max(scores, key=scores.get)
    if scores[best] <= 1:
        return "unknown"
    if best == "javascript" and sum(w * min(len(rx.findall(text)), 5) for rx, w in _TS) >= 4:
        return "typescript"
    if best == "c" and _CPP_ONLY.search(text):
        return "cpp"
    return best
