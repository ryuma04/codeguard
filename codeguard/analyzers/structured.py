"""Step 4 (other languages): SQL, YAML, Markdown carriers, dependency typosquatting."""
import os
import re
from ..findings import Finding, THREAT as T

# ---------------- SQL ----------------
_SQL_STMT = re.compile(r"[^;]+;?", re.S)


def analyze_sql(code: str):
    out = []
    pos = 0
    for m in _SQL_STMT.finditer(code):
        stmt = m.group(0)
        line = code.count("\n", 0, m.start() + (len(stmt) - len(stmt.lstrip()))) + 1
        s = re.sub(r"--[^\n]*|/\*.*?\*/", " ", stmt, flags=re.S).strip()
        u = s.upper()
        if re.match(r"DELETE\s+FROM\s+\S+\s*;?$", u) or (u.startswith("DELETE") and " WHERE " not in f" {u} "):
            out.append(Finding("destructive_command", T, 0.8, line, "DELETE without a WHERE clause", "sql"))
        if re.match(r"UPDATE\s+\S+\s+SET\b", u) and " WHERE " not in f" {u} ":
            out.append(Finding("destructive_command", T, 0.6, line, "UPDATE without a WHERE clause", "sql"))
        if re.search(r"\bWHERE\s+(1\s*=\s*1|TRUE|'1'\s*=\s*'1')\s*;?$", u) and u.startswith(("DELETE", "UPDATE")):
            out.append(Finding("destructive_command", T, 0.75, line, "mass DELETE/UPDATE with always-true WHERE", "sql"))
        if re.search(r"\bINTO\s+(OUT|DUMP)FILE\b|\bCOPY\b.+\bTO\s+'", u):
            out.append(Finding("data_exfiltration", T, 0.7, line, "writes query results to a file", "sql"))
        if re.search(r"\bLOAD_FILE\s*\(|\bPG_READ_(BINARY_)?FILE\s*\(|\bLOAD\s+DATA\s+(LOCAL\s+)?INFILE\b", u):
            out.append(Finding("secret_access", T, 0.65, line, "reads server files from SQL", "sql"))
        if re.search(r"\bXP_CMDSHELL\b|\bCOPY\b.+\b(FROM|TO)\s+PROGRAM\b|\bSYS_EXEC\s*\(|\bLO_EXPORT\b", u):
            out.append(Finding("persistence_or_privesc", T, 0.85, line, "runs OS commands from the database", "sql"))
        if re.search(r"\bGRANT\s+ALL\b.*\bTO\b|\b(CREATE|ALTER)\s+(USER|ROLE)\b.*\b(SUPERUSER|SYSADMIN|WITH\s+GRANT\s+OPTION)\b|\bSP_ADDSRVROLEMEMBER\b", u):
            out.append(Finding("persistence_or_privesc", T, 0.75, line, "grants database superuser rights", "sql"))
        if re.search(r"\b(SELECT|FROM)\b.*\b(PASSWORD|PASSWD|PWD_HASH|API_KEY|SECRET|CREDIT_CARD|SSN)\w*\b", u) and re.search(r"\bUNION\b|\bINTO\s+OUTFILE\b", u):
            out.append(Finding("secret_access", T, 0.6, line, "selects credential columns via UNION/outfile", "sql"))
        if re.search(r"\bUNION\s+(ALL\s+)?SELECT\b.*\b(INFORMATION_SCHEMA|PG_SHADOW|MYSQL\.USER|SYS\.)", u):
            out.append(Finding("secret_access", T, 0.65, line, "UNION-based system catalog dump", "sql"))
        if re.search(r"\bSLEEP\s*\(\s*\d{3,}|\bBENCHMARK\s*\(\s*\d{6,}|\bPG_SLEEP\s*\(\s*\d{3,}|WITH\s+RECURSIVE\b(?!.*\bLIMIT\b)(?!.*\bWHERE\b)", u):
            out.append(Finding("resource_exhaustion", T, 0.6, line, "long sleep / runaway recursive query", "sql"))
        if re.search(r"\b(UTL_HTTP|UTL_INADDR|DBMS_LDAP|HTTPURITYPE)\b|\bMASTER\.\.XP_DIRTREE\b", u):
            out.append(Finding("ssrf_network_exfil", T, 0.75, line, "database makes outbound network requests", "sql"))
    return out


# ---------------- YAML: pull out the shell inside CI/k8s configs ----------------
_RUN_KEYS = re.compile(r"^(\s*)(-\s*)?(run|script|command|commands|args|entrypoint|cmd|before_script|after_script|postStart|preStop|ExecStart)\s*:\s*(.*)$", re.I)


def extract_yaml_shell(code: str):
    """Yield (line_no, shell_text) for run:/command:/script: values, including | blocks."""
    lines = code.splitlines()
    i = 0
    while i < len(lines):
        m = _RUN_KEYS.match(lines[i])
        if m:
            indent, val = len(m.group(1)), m.group(4).strip()
            if val in ("|", ">", "|-", ">-", "|+", ""):
                block, j = [], i + 1
                while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
                    block.append(lines[j].strip().lstrip("- ").strip())
                    j += 1
                yield i + 2, "\n".join(block)
                i = j
                continue
            yield i + 1, val.strip("[]\"'").replace('", "', " ").replace("', '", " ")
        i += 1


# ---------------- Markdown: fenced code + hidden HTML comments ----------------
_FENCE = re.compile(r"^(```|~~~)\s*([\w+\-]*)[^\n]*\n(.*?)^\1\s*$", re.M | re.S)
_LANG_MAP = {"py": "python", "python": "python", "python3": "python", "sh": "bash", "bash": "bash", "shell": "bash",
             "zsh": "bash", "console": "bash", "js": "javascript", "javascript": "javascript", "node": "javascript",
             "ts": "javascript", "sql": "sql", "yaml": "yaml", "yml": "yaml", "php": "php", "powershell": "powershell", "ps1": "powershell"}


def extract_markdown_code(code: str):
    """Yield (start_line, language_or_None, body)."""
    for m in _FENCE.finditer(code):
        start = code.count("\n", 0, m.start(3)) + 1
        body = re.sub(r"^\s*[$>#]\s(?=\S)", "", m.group(3), flags=re.M) if (m.group(2) or "").lower() in ("console", "shell", "sh", "bash") else m.group(3)
        yield start, _LANG_MAP.get((m.group(2) or "").lower()), body
    # Inline commands in prose such as: run `curl x | bash`
    for m in re.finditer(r"`([^`\n]{8,})`", code):
        if re.search(r"\b(curl|wget|rm|chmod|sudo|pip|npm|bash|sh|python|eval|nc)\b", m.group(1)):
            yield code.count("\n", 0, m.start()) + 1, "bash", m.group(1)


# ---------------- Dependency reputation: known-malicious + typosquatting ----------------
# Lists built by eval/build_pkg_lists.py from hugovk/top-pypi-packages (names only) and the
# manifest name lists of DataDog/malicious-software-packages-dataset (Apache-2.0).
_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
TOP_NPM = """react react-dom lodash express axios chalk commander debug moment uuid typescript webpack vue next jquery
dotenv cors body-parser mongoose socket.io jsonwebtoken bcrypt nodemon eslint prettier jest mocha yargs inquirer
underscore request async bluebird rxjs tslib core-js classnames prop-types redux react-redux styled-components
@babel/core babel-loader node-fetch ws glob minimist semver colors cross-env electron puppeteer discord.js""".split()
_FALLBACK_PYPI = """requests numpy pandas boto3 urllib3 setuptools six python-dateutil certifi idna pyyaml cryptography
flask django fastapi pillow matplotlib scipy scikit-learn tensorflow torch beautifulsoup4 colorama selenium""".split()
_lists = None


def _norm(name):
    return re.sub(r"[-_.]+", "-", name.lower())


def _read(fn):
    try:
        with open(os.path.join(_DATA, fn), encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]
    except OSError:
        return []


def _load_lists():
    global _lists
    if _lists is None:
        top_pypi = _read("top_pypi.txt") or _FALLBACK_PYPI
        comp = {}
        for eco in ("pypi", "npm"):
            for line in _read(f"compromised_{eco}.txt"):
                name, *vers = line.split()
                comp[(eco, name)] = set(vers)
        _lists = {
            "good": {"pypi": set(top_pypi), "npm": set(TOP_NPM)},
            # popular enough to be worth squatting: (name, sorted letters) precomputed once
            "targets": {eco: [(t, sorted(t)) for t in names] for eco, names in (("pypi", top_pypi[:1000]), ("npm", TOP_NPM))},
            "bad": {"pypi": set(_read("malicious_pypi.txt")), "npm": set(_read("malicious_npm.txt"))},
            "compromised": comp,
        }
    return _lists


def _lev(a, b, cap=3):
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > cap:  # every alignment already exceeds the cap
            return cap + 1
        prev = cur
    return prev[-1]


_SQUAT_SUFFIXES = {"py", "js", "dev", "lib", "api", "official", "new", "2", "3"}


_INSTALL = re.compile(r"\b(pip3?|python3?\s+-m\s+pip|uv\s+pip|poetry|npm|yarn|pnpm)\s+(install|add|i)\b([^\n;&|]*)", re.I)


def _parse_token(tok, eco):
    """'requests==2.0' -> ('requests', '2.0'); '@scope/pkg@1.2' -> ('@scope/pkg', '1.2')."""
    if eco == "npm":
        scoped = tok.startswith("@")
        body = tok[1:] if scoped else tok
        name, _, ver = body.partition("@")
        return ("@" if scoped else "") + name.lower(), ver or None
    m = re.match(r"([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?\s*(?:==\s*([\w.\-]+)|[<>=!~].*)?$", tok)
    return (_norm(m.group(1)), m.group(2)) if m else (None, None)


def check_typosquats(code: str):
    lists = _load_lists()
    out = []
    for lineno, line in enumerate(code.splitlines(), 1):
        for m in _INSTALL.finditer(line):
            eco = "npm" if m.group(1).lower() in ("npm", "yarn", "pnpm") else "pypi"
            for tok in m.group(3).split():
                tok = tok.strip("`'\",;()")
                if not tok or tok.startswith("-") or "://" in tok or (eco == "pypi" and "/" in tok) or tok.startswith(".") \
                        or re.search(r"\.(txt|whl|tar\.gz|zip|tgz|cfg|toml)$", tok):
                    continue
                name, ver = _parse_token(tok, eco)
                if not name or len(name) < 2:
                    continue
                if name in lists["bad"][eco]:
                    out.append(Finding("dependency_risk", T, 0.95, lineno, f"'{name}' is a known malicious {eco} package", "pkg-intel"))
                    continue
                if ver and ver in lists["compromised"].get((eco, name), ()):
                    out.append(Finding("dependency_risk", T, 0.9, lineno, f"{name} {ver} is a known compromised release", "pkg-intel"))
                    continue
                if name in lists["good"][eco] or len(name) < 4:
                    continue
                srt = sorted(name)
                for good, good_srt in lists["targets"][eco]:
                    limit = 1 if len(good) <= 6 else 2
                    if (len(name) == len(good) and srt == good_srt) or _lev(name, good, limit) <= limit or                             (name.startswith(good) and name[len(good):].lstrip("-_") in _SQUAT_SUFFIXES):
                        out.append(Finding("dependency_risk", T, 0.85, lineno,
                                           f"'{name}' looks like a typosquat of popular package '{good}'", "typosquat"))
                        break
    return out
