"""The cascade: route -> deobfuscate -> rules -> structural analysis -> decide.

analyze(code) -> dict matching the fixed hackathon schema.
"""
import re
import time

from .findings import CATEGORIES, Context, Finding, THREAT, CAPABILITY
from .router import detect_language
from .rules import scan_text
from .deobfuscate import unwrap
from .carriers import extract_embedded
from .injection import scan_injection
from .analyzers.python_ast import analyze_python
from . import ml
from .analyzers.structured import analyze_sql, extract_yaml_shell, extract_markdown_code, check_typosquats

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


def _analyze_chunk(text: str, language: str, line_offset: int, ctx: Context, depth: int = 0, skip_rules: bool = False):
    """Analyze one piece of code; recursion handles payloads, embedded code, decoded layers.

    skip_rules: the caller already ran the rule layer over these exact characters
    (a carrier fragment that is a verbatim slice of the parent). We still want the
    structural/decoding layers on it, but re-running the line rules would double-count.
    """
    if depth > 4 or not text.strip():
        return
    if not skip_rules:
        ctx.findings.extend(_scan_shell_like(text, line_offset, ctx, "rule", depth))
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
            return [f for f in local.findings if f.kind == THREAT]
        res = analyze_python(text, line_offset, depth, rescan)
        if res is not None:
            ctx.findings.extend(res)
    elif language == "sql":
        for f in analyze_sql(text):
            f.line += line_offset
            ctx.add(f)
    elif language == "yaml":
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
            for f in sub.findings:
                if f.source == "rule":
                    f.source = "carrier"
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
                for f in threats:
                    f.line = line
                    f.source = f"deobf:{kind}"
                    f.reason = f"{f.reason} (hidden in {kind})"
                ctx.findings.extend(threats)
                ctx.add(Finding("obfuscated_execution", THREAT, 0.7 if layer == 1 else 0.85, line,
                                f"malicious code hidden behind {kind} encoding ({layer} layer{'s' if layer > 1 else ''})", "deobf"))


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
        line = min((x.line for x in f if x.category == "secret_access" and x.kind == THREAT), default=0)
        ctx.add(Finding("data_exfiltration", THREAT, 0.8, line, "reads secrets and makes a network call in the same snippet", "combo"))
    if any(x.category == "obfuscated_execution" and x.kind == THREAT for x in f) and has_net:
        ctx.add(Finding("obfuscated_execution", THREAT, 0.6, 0, "obfuscated code combined with network access", "combo"))
    # Python gets precise taint tracking in the AST layer; this coarse combo is for JS / PowerShell.
    if ctx.language in ("javascript", "powershell") and any(x.reason == "collects host fingerprint" for x in f) and has_net:
        line = min(x.line for x in f if x.reason == "collects host fingerprint")
        ctx.add(Finding("data_exfiltration", THREAT, 0.65, line, "collects user/host fingerprint and makes a network call", "combo"))
    m = re.search(r"detached\s*:\s*true", ctx.code)
    if m and re.search(r"\.unref\(\)", ctx.code) and re.search(r"stdio\s*:\s*['\"]ignore", ctx.code):
        ctx.add(Finding("persistence_or_privesc", THREAT, 0.65, ctx.code.count("\n", 0, m.start()) + 1,
                        "spawns a hidden, detached background process", "combo"))
    if "ssrf_network_exfil" in cats and any("metadata" in x.reason for x in f) and has_net:
        ctx.add(Finding("secret_access", THREAT, 0.6, 0, "pulls cloud credentials from the metadata service", "combo"))


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


def analyze(code, threshold: float = BLOCK_THRESHOLD) -> dict:
    t0 = time.perf_counter()
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
        lines = sorted({x.line for x in threats if x.line > 0})
    else:
        caps = sorted({x.reason for x in ctx.findings if x.kind == CAPABILITY})
        reason = "no high-risk pattern found" + (f"; capabilities seen: {', '.join(caps[:4])}" if caps else "")
        lines = []

    return {
        "verdict": verdict,
        "risk_score": round(float(risk), 3),
        "categories": cats,
        "code_language": ctx.language,
        "reason": reason,
        "vulnerable_lines": lines,
        "category_scores": per_cat,
        "decoded_layers": ctx.decoded_layers,
        "rule_risk": round(float(rule_risk), 3),
        "ml_prob": ml_prob,
        "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
