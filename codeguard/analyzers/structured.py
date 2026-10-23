"""Step 4 (other languages): SQL, YAML, Markdown carriers, dependency typosquatting."""
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


# ---------------- Dependency typosquatting ----------------
TOP_PYPI = """requests numpy pandas boto3 urllib3 setuptools six python-dateutil certifi idna charset-normalizer
pyyaml typing-extensions botocore s3transfer packaging pip wheel cryptography pydantic attrs jinja2 markupsafe click
protobuf pytest flask django fastapi uvicorn sqlalchemy psycopg2 pillow matplotlib scipy scikit-learn tensorflow torch
transformers beautifulsoup4 lxml selenium openai anthropic langchain aiohttp httpx colorama tqdm rich pyjwt paramiko
redis pymongo celery gunicorn werkzeug jsonschema docutils tornado websocket-client grpcio google-api-core opencv-python
keras xgboost lightgbm nltk spacy sympy networkx pyarrow pytz tzdata filelock virtualenv black isort mypy pylint coverage""".split()
TOP_NPM = """react react-dom lodash express axios chalk commander debug moment uuid typescript webpack vue next jquery
dotenv cors body-parser mongoose socket.io jsonwebtoken bcrypt nodemon eslint prettier jest mocha yargs inquirer
underscore request async bluebird rxjs tslib core-js classnames prop-types redux react-redux styled-components
@babel/core babel-loader node-fetch ws glob minimist semver colors cross-env electron puppeteer discord.js""".split()
_TOP = {p.lower(): eco for eco, lst in (("pypi", TOP_PYPI), ("npm", TOP_NPM)) for p in lst}


def _lev(a, b, cap=3):
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_INSTALL = re.compile(r"\b(pip3?|python3?\s+-m\s+pip|npm|yarn|pnpm)\s+(install|add|i)\b([^\n;&|]*)", re.I)


def check_typosquats(code: str):
    out = []
    for lineno, line in enumerate(code.splitlines(), 1):
        for m in _INSTALL.finditer(line):
            for tok in m.group(3).split():
                tok = tok.strip("`'\",;()")
                if tok.startswith("-") or "://" in tok or "/" in tok and not tok.startswith("@"):
                    continue
                name = re.split(r"[=<>!~\[@]", tok.lstrip("@"), maxsplit=1)[0].lower() if not tok.startswith("@") else tok.lower()
                if not name or name in _TOP or len(name) < 4:
                    continue
                norm = name.replace("_", "-").replace(".", "-")
                if norm in _TOP:
                    continue
                for good in _TOP:
                    d = _lev(norm, good)
                    limit = 1 if len(good) <= 6 else 2
                    swapped = sorted(norm) == sorted(good)
                    if d <= limit or swapped or re.fullmatch(re.escape(good) + r"[-_]?(py|js|dev|lib|api|official|new|2|3)", norm):
                        out.append(Finding("dependency_risk", T, 0.85, lineno,
                                           f"'{name}' looks like a typosquat of popular package '{good}'", "typosquat"))
                        break
    return out
