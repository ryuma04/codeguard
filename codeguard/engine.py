"""The cascade: route -> deobfuscate -> rules -> structural analysis -> decide.

analyze(code) -> dict matching the fixed hackathon schema.
"""
import re
import time

from .findings import CATEGORIES, Context, Finding, THREAT, CAPABILITY
from .router import detect_language
from . import languages
from .rules import scan_text
from .deobfuscate import unwrap
from .carriers import extract_embedded
from .injection import scan_injection
from .analyzers.python_ast import analyze_python
from . import ml
from .analyzers.structured import analyze_sql, analyze_ci_yaml, extract_yaml_shell, extract_markdown_code, check_typosquats

BLOCK_THRESHOLD = 0.5
CAPABILITY_CAP = 0.45      # capabilities alone can never block
MAX_CODE = 200_000         # bytes analysed; larger input is truncated (and flagged)
LAYERS = {"structural": True, "ml": True}   # toggles for ablation runs (eval/evaluate.py --ablation)


def _scan_shell_like(text, line_offset, ctx, source, depth):
    """Rules + typosquat check on a chunk of text (any language)."""
    hits = scan_text(text, line_offset, source)
    for f in check_typosquats(text):
        f.line += line_offset
        hits.append(f)
    return hits


_SQL_STRING = re.compile(r"'(?:[^']|'')*'")


def _blank_sql_strings(text):
    """Blank the inside of '...' literals, keeping line breaks so line numbers stay right."""
    return _SQL_STRING.sub(lambda m: "'" + re.sub(r"[^\n]", " ", m.group(0)[1:-1]) + "'", text)


def _analyze_chunk(text: str, language: str, line_offset: int, ctx: Context, depth: int = 0, skip_rules: bool = False):
    """Analyze one piece of code; recursion handles payloads, embedded code, decoded layers.

    skip_rules: the caller already ran the rule layer over these exact characters
    (a carrier fragment that is a verbatim slice of the parent). We still want the
    structural/decoding layers on it, but re-running the line rules would double-count.
    """
    if depth > 4 or not text.strip():
        return
    if not skip_rules:
        # In SQL a quoted string is data ('Example: DROP TABLE users'); analyze_sql still sees the whole
        # statement, so commands run *from* SQL (COPY ... TO PROGRAM '...', xp_cmdshell '...') stay covered.
        rule_text = _blank_sql_strings(text) if language == "sql" else text
        ctx.findings.extend(_scan_shell_like(rule_text, line_offset, ctx, "rule", depth))
    if not LAYERS["structural"]:
        return

    if language == "python":
        def rescan(sub, line, kind):
            # A folded/decoded/shell string discovered inside Python.
            local = Context(sub)
            sub_lang = detect_language(sub) if kind == "payload" else ("bash" if kind == "shell" else detect_language(sub))
            _analyze_chunk(sub, sub_lang if sub_lang != "unknown" else "bash", 0, local, depth + 1)
            for f in local.findings:
                f.line = line + 1 if line >= 0 else 0  # report the line of the call site
                f.source = f"ast:{kind}"
                f.chain = []  # steps were numbered inside the decoded text; the caller attaches the outer chain
            return [f for f in local.findings if f.kind == THREAT]
        res = analyze_python(text, line_offset, depth, rescan)
        if res is not None:
            ctx.findings.extend(res)
    elif language == "sql":
        for f in analyze_sql(text):
            f.line += line_offset
            ctx.add(f)
    elif language == "yaml":
        for f in analyze_ci_yaml(text):
            f.line += line_offset
            f.chain = [dict(s, line=s["line"] + line_offset) for s in f.chain]
            ctx.add(f)
        for line, shell in extract_yaml_shell(text):
            sub = Context(shell)
            _analyze_chunk(shell, "bash", line - 1 + line_offset, sub, depth + 1)
            ctx.findings.extend(sub.findings)
    elif language == "markdown":
        for line, lang, body in extract_markdown_code(text):
            lang = lang or detect_language(body)
            sub = Context(body)
            _analyze_chunk(body, lang, line - 1 + line_offset, sub, depth + 1)
            ctx.findings.extend(sub.findings)

    # Carrier extraction: code embedded in JSON/YAML/Dockerfile/Makefile/heredoc/-c.
    # Each fragment is re-routed through the full cascade in its own language.
    if depth < 3:
        for line, lang, body, verbatim in extract_embedded(text, language):
            sub_lang = lang or detect_language(body)
            if sub_lang == "unknown":
                sub_lang = "bash"
            sub = Context(body)
            _analyze_chunk(body, sub_lang, line - 1 + line_offset, sub, depth + 1, skip_rules=verbatim)
            carrier = {"line": line + line_offset, "role": "carrier",
                       "label": f"{sub_lang} code embedded in {language}" if sub_lang != language else f"embedded {sub_lang} block"}
            for f in sub.findings:
                if f.source == "rule":
                    f.source = "carrier"
                if f.kind == THREAT:
                    f.chain = [carrier] + (f.chain or [{"line": f.line, "role": "sink", "label": f.reason}])
            ctx.findings.extend(sub.findings)

    # Deobfuscation: decode blobs statically and analyse the plaintext.
    if depth < 3:
        for layer, kind, plain in unwrap(text):
            ctx.decoded_layers = max(ctx.decoded_layers, layer + depth)
            sub = Context(plain)
            _analyze_chunk(plain, detect_language(plain) if detect_language(plain) != "unknown" else "bash", 0, sub, depth + 1)
            threats = [f for f in sub.findings if f.kind == THREAT]
            if threats:
                line = _line_of(text, plain, kind) + line_offset
                preview = " ".join(plain.split())
                preview = preview[:60] + ("…" if len(preview) > 60 else "")
                found = list(dict.fromkeys(f.reason for f in threats))[:2]
                chain = [{"line": line, "role": "encoded", "label": f"{kind} blob" + (f" ({layer} layers)" if layer > 1 else "")},
                         {"line": line, "role": "decoded", "label": f"decodes to: {preview}"},
                         {"line": line, "role": "sink", "label": "; ".join(found)}]
                for f in threats:
                    f.line = line
                    f.source = f"deobf:{kind}"
                    f.reason = f"{f.reason} (hidden in {kind})"
                    f.chain = [dict(s) for s in chain]
                ctx.findings.extend(threats)
                ctx.add(Finding("obfuscated_execution", THREAT, 0.7 if layer == 1 else 0.85, line,
                                f"malicious code hidden behind {kind} encoding ({layer} layer{'s' if layer > 1 else ''})", "deobf",
                                [dict(s) for s in chain]))


def _line_of(text, plain, kind):
    # Best effort: the first line holding a long encoded-looking token.
    for i, l in enumerate(text.splitlines(), 1):
        if re.search(r"[A-Za-z0-9+/=]{16,}|\\x[0-9a-f]{2}|chr\(|fromCharCode|[0-9a-f]{20,}", l, re.I):
            return i
    return 1


def _combine(ctx: Context):
    """GuardDog-style correlation: capability + threat in one snippet => real risk."""
    f = ctx.findings
    cats = {x.category for x in f if x.kind == THREAT}
    has_net = any(x.category == "data_exfiltration" and x.kind == CAPABILITY for x in f) or \
        any(x.category in ("data_exfiltration", "ssrf_network_exfil") and x.kind == THREAT for x in f)
    if "secret_access" in cats and has_net and "data_exfiltration" not in cats:
        secret = min((x for x in f if x.category == "secret_access" and x.kind == THREAT), key=lambda x: x.line or 10**9, default=None)
        net = next((x for x in f if x.category in ("data_exfiltration", "ssrf_network_exfil") and x.line), None)
        line = secret.line if secret else 0
        chain = [{"line": secret.line, "role": "source", "label": secret.reason}] if secret and secret.line else []
        if net:
            chain.append({"line": net.line, "role": "sink", "label": net.reason})
        ctx.add(Finding("data_exfiltration", THREAT, 0.8, line, "reads secrets and makes a network call in the same snippet", "combo",
                        chain if len(chain) > 1 else []))
    if any(x.category == "obfuscated_execution" and x.kind == THREAT for x in f) and has_net:
        ctx.add(Finding("obfuscated_execution", THREAT, 0.6, 0, "obfuscated code combined with network access", "combo"))
    # Python gets precise taint tracking in the AST layer; this coarse combo is for JS / PowerShell.
    if ctx.language in ("javascript", "powershell") and any(x.reason == "collects host fingerprint" for x in f) and has_net:
        line = min(x.line for x in f if x.reason == "collects host fingerprint")
        ctx.add(Finding("data_exfiltration", THREAT, 0.65, line, "collects user/host fingerprint and makes a network call", "combo"))
    if ctx.language in ("javascript", "typescript"):
        _js_variable_flows(ctx)
    m = re.search(r"detached\s*:\s*true", ctx.code)
    if m and re.search(r"\.unref\(\)", ctx.code) and re.search(r"stdio\s*:\s*['\"]ignore", ctx.code):
        ctx.add(Finding("persistence_or_privesc", THREAT, 0.65, ctx.code.count("\n", 0, m.start()) + 1,
                        "spawns a hidden, detached background process", "combo"))
    if "ssrf_network_exfil" in cats and any("metadata" in x.reason for x in f) and has_net:
        ctx.add(Finding("secret_access", THREAT, 0.6, 0, "pulls cloud credentials from the metadata service", "combo"))


_JS_ASSIGN = r"(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?"


def _js_variable_flows(ctx):
    """Two JS flows the line rules miss because a variable sits between source and sink:
    a decoded value later evaluated, and a remote URL later dynamically imported."""
    code = ctx.code

    def line(i):
        return code.count("\n", 0, i) + 1
    for m in re.finditer(_JS_ASSIGN + r"(atob\s*\(|Buffer\.from\s*\([^)]*['\"](base64|hex)['\"]|decodeURIComponent\s*\(|unescape\s*\()", code):
        sink = re.search(rf"\b(eval|Function|vm\.run\w*|setTimeout|setInterval)\s*\(\s*{m.group(1)}\b", code[m.end():])
        if sink:
            chain = [{"line": line(m.start()), "role": "encoded", "label": f"'{m.group(1)}' holds decoded data"},
                     {"line": line(m.end() + sink.start()), "role": "sink", "label": f"{sink.group(1)}() executes it", "via": m.group(1)}]
            ctx.add(Finding("obfuscated_execution", THREAT, 0.85, chain[1]["line"], f"{sink.group(1)}() runs a decoded payload", "combo", chain))
    for m in re.finditer(_JS_ASSIGN + r"['\"`](https?://[^'\"`]+)['\"`]", code):
        sink = re.search(rf"\bimport\s*\(\s*{m.group(1)}\s*\)", code[m.end():])
        if sink:
            chain = [{"line": line(m.start()), "role": "source", "label": f"remote URL {m.group(2)[:60]}"},
                     {"line": line(m.end() + sink.start()), "role": "sink", "label": "import() loads and runs it", "via": m.group(1)}]
            ctx.add(Finding("dependency_risk", THREAT, 0.75, chain[1]["line"], "imports and runs a module from a remote URL", "combo", chain))


def _score(findings):
    per_cat = {}
    for cat in CATEGORIES:
        threats = [x.weight for x in findings if x.category == cat and x.kind == THREAT]
        caps = [x.weight for x in findings if x.category == cat and x.kind == CAPABILITY]
        p_safe = 1.0
        for w in sorted(set(threats), reverse=True)[:4]:
            p_safe *= (1 - w)
        t_score = 1 - p_safe
        c_score = min(CAPABILITY_CAP, max(caps, default=0) + 0.05 * max(0, len(set(caps)) - 1))
        score = t_score if t_score >= c_score else c_score
        if caps and max(threats, default=0) >= 0.5:
            score = min(0.99, score + 0.05)  # capability corroborates an already-strong threat
        if score > 0:
            per_cat[cat] = round(score, 3)
    return per_cat


def run_layers(code):
    """Rules + structural layers. Returns (ctx, per-category scores)."""
    if not isinstance(code, str):
        code = "" if code is None else str(code)
    truncated = len(code) > MAX_CODE
    code = code[:MAX_CODE]
    ctx = Context(code)
    ctx.language = detect_language(code)

    try:
        _analyze_chunk(code, ctx.language, 0, ctx)
        for line, w, reason in scan_injection(code, ctx.language):
            ctx.add(Finding("ai_targeted_instructions", THREAT, w, line, reason, "injection"))
        _combine(ctx)
    except Exception as e:  # never crash the endpoint: fail closed
        ctx.add(Finding("obfuscated_execution", THREAT, 0.6, 0, f"analysis error, failing closed ({type(e).__name__})", "error"))
    if truncated:
        ctx.add(Finding("resource_exhaustion", THREAT, 0.3, 0, "input truncated: very large snippet", "size"))

    return ctx, _score(ctx.findings)


def features(code):
    """Stacker features for one snippet (used by eval/train_ml.py)."""
    ctx, _ = run_layers(code)
    return ml.featurize(ctx.code, ctx.language, ctx.findings, ctx.decoded_layers)


def warmup():
    """Load models and package lists before serving, so the first live request
    does not pay the one-off load (~650 KB model + ~48k package names)."""
    from .analyzers.structured import _load_lists
    from . import textclf
    _load_lists()
    textclf.available()
    ml.available()
    analyze("import os\n# warm-up\nprint(os.getcwd())")


MAX_EVIDENCE = 6


def _evidence(code, threats):
    """Why it was blocked, as chains of steps for the UI graph and `codeguard scan --graph`.

    Multi-step chains first (source -> sink, encoded -> decoded -> exec, carrier -> embedded code),
    then single findings. Identical chains are merged; each step carries its line of code.
    Debug output only: the fixed response schema is unchanged.
    """
    src = code.splitlines()

    def text(n):
        return src[n - 1].strip()[:160] if 0 < n <= len(src) else ""

    out, seen, covered = [], set(), []
    for x in sorted(threats, key=lambda x: (-(len(x.chain) > 1), -len(x.chain), -x.weight)):
        steps = x.chain if len(x.chain) > 1 else [{"line": x.line, "role": "finding", "label": x.reason}]
        key = tuple((s.get("line"), s.get("role"), s.get("label")) for s in steps)
        lines = {s.get("line") for s in steps}
        # Skip repeats, and anything whose lines a longer chain already explains (it would only restate it).
        if key in seen or any(lines <= c and lines != c or (lines == c and len(steps) == 1) for c in covered):
            continue
        seen.add(key)
        covered.append(lines)
        out.append({"category": x.category, "weight": x.weight, "reason": x.reason,
                    "steps": [dict(s, code=text(s.get("line", 0))) for s in steps]})
        if len(out) >= MAX_EVIDENCE:
            break
    return out


def _support_note(language, support):
    """Say plainly when a verdict rests on less than full analysis (see languages.py for the tiers)."""
    if support == "unsupported":
        if language == "unknown":
            return "language could not be identified: language support not present, only generic rules were applied"
        return f"language support not present for {languages.display(language)}: only generic rules were applied"
    if support == "light":
        return f"light (rule-based) analysis for {languages.display(language)}"
    return ""


def analyze(code, threshold: float = BLOCK_THRESHOLD) -> dict:
    t0 = time.perf_counter()
    if isinstance(code, str) and code.startswith("﻿"):  # a file-encoding BOM, not hidden text
        code = code[1:]
    ctx, per_cat = run_layers(code)
    rule_risk = max(per_cat.values(), default=0.0)
    risk, ml_prob = rule_risk, None
    if LAYERS["ml"]:  # cascade: the model only sees the ambiguous band
        risk, ml_prob = ml.adjust(rule_risk, ml.featurize(ctx.code, ctx.language, ctx.findings, ctx.decoded_layers))
    verdict = "block" if risk >= threshold else "allow"
    cats = sorted([c for c, s in per_cat.items() if s >= threshold], key=lambda c: -per_cat[c]) if verdict == "block" else []
    if verdict == "block" and not cats and per_cat:  # model tipped it over: report the strongest signal
        cats = [max(per_cat, key=per_cat.get)]

    # Weak capability notes only explain a block when the model, not the rules, decided it
    # (rule score below the threshold, model pushed it over). Otherwise list threats only.
    model_decided = rule_risk < threshold <= risk
    threats = sorted({x.key(): x for x in ctx.findings if x.category in cats and (x.kind == THREAT or model_decided)}.values(),
                     key=lambda x: -x.weight)
    if verdict == "block":
        uniq = list({(x.category, x.reason.replace(" (hidden in base64)", "")): x for x in threats}.values())[:4]
        reason = "; ".join(f"{x.category}: {x.reason}" + (f" (line {x.line})" if x.line else "") for x in uniq)
        # A chain's source line is as vulnerable as its sink (the line that reads the secret, not only the one that sends it).
        lines = sorted({x.line for x in threats if x.line > 0} | {s["line"] for x in threats for s in x.chain if s.get("line", 0) > 0})
        evidence = _evidence(ctx.code, threats)
    else:
        caps = sorted({x.reason for x in ctx.findings if x.kind == CAPABILITY})
        reason = "no high-risk pattern found" + (f"; capabilities seen: {', '.join(caps[:4])}" if caps else "")
        lines = []
        evidence = []
    support = languages.support(ctx.language)
    note = _support_note(ctx.language, support)
    if note:
        reason = f"{note}; {reason}"

    return {
        "verdict": verdict,
        "risk_score": round(float(risk), 3),
        "categories": cats,
        "code_language": ctx.language,
        "reason": reason,
        "vulnerable_lines": lines,
        "category_scores": per_cat,
        "language_support": support,
        "decoded_layers": ctx.decoded_layers,
        "evidence": evidence,
        "rule_risk": round(float(rule_risk), 3),
        "ml_prob": ml_prob,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
