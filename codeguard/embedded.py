"""Embedded-code extraction: find code carried inside other formats.

A snippet is often not a plain script: CI YAML, a Jupyter notebook, a
package.json, a Dockerfile, a shell heredoc or a `python -c "..."` argument all
carry code. This module pulls each embedded piece out with its starting line
and a language hint, so the engine can run the *full* analysis (AST, taint,
SQL, deobfuscation) on it instead of only the line-level rules.

extract(text, language) -> [(start_line, language_or_None, body)]
Nothing here executes anything; it only parses text.
"""
import json
import re

from .analyzers.structured import extract_yaml_shell, _RUN_KEYS

MAX_PIECES = 200
_INTERP = {"python": "python", "python3": "python", "python2": "python", "node": "javascript", "nodejs": "javascript",
           "bash": "bash", "sh": "bash", "zsh": "bash", "dash": "bash", "ash": "bash"}
_HEREDOC = re.compile(r"^([^\n]*?)<<-?\s*(['\"]?)([A-Za-z_]\w*)\2[^\n]*\n(.*?)\n[ \t]*\3[ \t]*$", re.M | re.S)
_INLINE = re.compile(r"\b(python[23]?|node|nodejs|bash|sh|zsh)\s+(?:-\w+\s+)*-(?:c|e)\s+(?:'([^']*)'|\"((?:\\.|[^\"\\])*)\")")
_RUN = re.compile(r"^[ \t]*RUN[ \t]+((?:[^\n]*\\\n)*[^\n]*)", re.M | re.I)
_BLOCK = re.compile(r"^([ \t]*)(?:-[ \t]+)?([\w.\-]+)[ \t]*:[ \t]*[|>][-+]?[ \t]*$", re.M)
_CODEISH = re.compile(r"[;|&(){}=$`]|\b(import|def|function|require|curl|wget|rm|echo|sudo|exec|eval)\b")


def _line_at(text, pos):
