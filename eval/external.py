"""Build labelled test sets from third-party open-source material (testing only).

    python eval/external.py fetch      # download sources into data/external/raw/  (needs git + network)
    python eval/external.py build      # write data/external/*.jsonl
    python eval/evaluate.py data/external/guarddog.jsonl --errors

Sources (used ONLY to measure the detector, never for rules or training):
  * DataDog GuardDog rule-test fixtures, tests/analyzer/sourcecode (Apache-2.0).
    Semgrep convention: a "# ruleid: X" comment marks code the rule must flag,
    "# ok: X" marks code it must not. We split files into blocks and label each.
  * deepset/prompt-injections on Hugging Face (Apache-2.0): text labelled
    injection / not. Each text is placed in a comment or docstring of a small
    harmless function, so it tests ai_targeted_instructions in a code setting.
  * Real library code already installed on this machine (Python stdlib: PSF;
    site-packages: each package's own OSS license): functions sampled as
    benign snippets, to measure false positives on code nobody wrote for us.

Every file is read as text. Nothing downloaded is imported or executed.
"""
import ast
import json
import os
import random
import re
import subprocess
import sys
import sysconfig
import time
import urllib.error
import urllib.request

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
EXT = os.path.join(ROOT, "data", "external")
RAW = os.path.join(EXT, "raw")
GD_DIR = os.path.join(RAW, "guarddog", "tests", "analyzer", "sourcecode")
HF_API = "https://datasets-server.huggingface.co/rows?dataset={}&config=default&split={}&offset={}&length=100"

# GuardDog rule -> our categories ([] = we only score the verdict for it)
GD_CATS = {
    "exec-base64": ["obfuscated_execution"], "npm-exec-base64": ["obfuscated_execution"],
    "obfuscation": ["obfuscated_execution"], "npm-obfuscation": ["obfuscated_execution"],
    "api-obfuscation": ["obfuscated_execution"], "npm-api-obfuscation": ["obfuscated_execution"],
    "steganography": ["obfuscated_execution"], "npm-steganography": ["obfuscated_execution"],
    "exfiltrate-sensitive-data": ["data_exfiltration"], "npm-exfiltrate-sensitive-data": ["data_exfiltration"],
    "npm-serialize-environment": ["secret_access"],
    "download-executable": ["dependency_risk"],
    "shady-links": ["data_exfiltration"],
    "dll-hijacking": ["persistence_or_privesc"], "npm-dll-hijacking": ["persistence_or_privesc"],
    "threat-filesystem-read": ["secret_access"], "threat-filesystem-autostart": ["persistence_or_privesc"],
    "threat-network-exfiltration": ["data_exfiltration"], "threat-process-download-exec": ["dependency_risk"],
    "threat-runtime-obfuscation": ["obfuscated_execution"], "threat-runtime-obfuscation-base64exec": ["obfuscated_execution"],
    "threat-runtime-obfuscation-dynamic-eval": ["obfuscated_execution"],
    "threat-runtime-obfuscation-general": ["obfuscated_execution"],
    "threat-runtime-obfuscation-hidden-code": ["obfuscated_execution"],
    "threat-runtime-obfuscation-js-mangling": ["obfuscated_execution"],
}
_ANNOT = re.compile(r"^\s*(#|//)\s*(ruleid|ok|todoruleid|todook)\s*:\s*([\w\-]+)", re.I)


# ---------------------------------------------------------------- fetch
def fetch():
    os.makedirs(RAW, exist_ok=True)
    gd = os.path.join(RAW, "guarddog")
    if not os.path.isdir(gd):
        subprocess.check_call(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse",
                               "https://github.com/DataDog/guarddog.git", gd])
        subprocess.check_call(["git", "-C", gd, "sparse-checkout", "set", "tests/analyzer/sourcecode"])
    counts = {}
    for name, dataset, splits, raw_file in (
            ("prompt_injections", "deepset/prompt-injections", ("train", "test"), None),
            ("securityeval", "s2e-lab/SecurityEval", ("train",), "dataset.jsonl"),
            ("cybernative", "CyberNative/Code_Vulnerability_Security_DPO", ("train",), "secure_programming_dpo.json")):
        out = os.path.join(RAW, f"{name}.jsonl")
        if os.path.exists(out):
            continue
        if raw_file:  # one request for the whole file instead of paging the (rate-limited) rows API
            url = f"https://huggingface.co/datasets/{dataset}/resolve/main/{raw_file}"
            with urllib.request.urlopen(url, timeout=120) as r:
                text = r.read().decode("utf-8")
            try:
                rows = json.loads(text)
            except ValueError:  # JSON-lines (CyberNative ships .json that is really .jsonl)
                rows = [json.loads(l) for l in text.splitlines() if l.strip()]
        else:
            rows = _hf_rows(dataset, splits)
        with open(out, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        counts[name] = len(rows)
    print(f"guarddog fixtures: {len(os.listdir(GD_DIR))} files; HF rows fetched: {counts or 'already cached'}")


def _hf_rows(dataset, splits):
    rows = []
    for split in splits:
        off = 0
        while True:
            for attempt in range(5):  # the rows API returns occasional 5xx under load
                try:
                    with urllib.request.urlopen(HF_API.format(dataset, split, off), timeout=60) as r:
                        page = json.loads(r.read())
                    break
                except urllib.error.HTTPError as e:
                    if e.code < 500 or attempt == 4:
                        raise
                    time.sleep(2 * (attempt + 1))
            rows += [dict(x["row"], split=split) for x in page["rows"]]
            off += 100
            if off >= page["num_rows_total"]:
                break
    return rows


# ---------------------------------------------------------------- GuardDog fixtures
def _balanced(text):
    return text.count("{") <= text.count("}") and text.count("(") <= text.count(")") and text.count("[") <= text.count("]")


def _blocks(text):
    """Split a fixture into blank-line blocks, gluing context/unbalanced pieces forward."""
    out, cur = [], []
    for part in re.split(r"\n\s*\n", text):
        if not part.strip():
            continue
        if re.fullmatch(r'\s*""".*?"""\s*', part, re.S):  # section header docstring: starts a new group
            cur = []
            continue
        cur.append(part)
        joined = "\n\n".join(cur)
        if not _has_annot(joined):
            continue  # context only so far: glue onto the annotated statement that follows
        if not _balanced(joined) or _ANNOT.match(joined.rstrip().splitlines()[-1]):
            continue  # statement continues in the next block
        out.append(joined)
        cur = []
    if cur and _has_annot("\n\n".join(cur)):
        out.append("\n\n".join(cur))
    return out


def _has_annot(text):
    return any(_ANNOT.match(l) for l in text.splitlines())


def _clean(block):
    lines = [l for l in block.splitlines() if not _ANNOT.match(l)]
    text = "\n".join(lines)
    text = re.sub(r'^\s*"""\s*(OK|RULEID)[^"]*"""\s*$', "", text, flags=re.M | re.I)
    return text.strip("\n")


def build_guarddog():
    recs = []
    for name in sorted(os.listdir(GD_DIR)):
        stem, ext = os.path.splitext(name)
        if ext not in (".py", ".js") or name.startswith("test_"):
            continue
        with open(os.path.join(GD_DIR, name), encoding="utf-8", errors="replace") as f:
            text = f.read()
        if not _has_annot(text):
            if stem.startswith("threat-"):  # whole-file positive fixtures
                recs.append({"id": f"gd/{name}", "code": text, "label": "malicious",
                             "categories": GD_CATS.get(stem, []), "rule": stem})
            continue
        text = re.sub(r'\A\s*""".*?"""', "", text, count=1, flags=re.S)  # module docstring lists the cases
        for i, block in enumerate(_blocks(text)):
            marks = [m.group(2).lower() for m in map(_ANNOT.match, block.splitlines()) if m]
            if not marks or all(m.startswith("todo") for m in marks):
                continue
            mal = "ruleid" in marks
            code = _clean(block)
            if len(code.strip()) < 6:
                continue
            recs.append({"id": f"gd/{name}#{i}", "code": code, "label": "malicious" if mal else "benign",
                         "categories": GD_CATS.get(stem, []) if mal else [], "rule": stem})
    return recs


# ---------------------------------------------------------------- prompt injections in code
_WRAPPERS = [
    lambda t: f"# {t}\ndef scale(values, k=2):\n    return [v * k for v in values]\n",
    lambda t: f'def parse_row(row):\n    """{t}"""\n    return row.strip().split(",")\n',
    lambda t: f"// {t}\nfunction total(items) {{\n  return items.reduce((a, b) => a + b, 0);\n}}\n",
    lambda t: f"/* {t} */\nconst greet = (name) => `Hello, ${{name}}`;\n",
    lambda t: f'NOTE = "{t}"\n\ndef area(r):\n    return 3.14159 * r * r\n',
]


def build_injections():
    path = os.path.join(RAW, "prompt_injections.jsonl")
    recs = []
    with open(path, encoding="utf-8") as f:
        rows = [json.loads(l) for l in f if l.strip()]
    for i, r in enumerate(rows):
        text = " ".join(str(r["text"]).replace('"', "'").replace("*/", "").split())
        code = _WRAPPERS[i % len(_WRAPPERS)](text)
        mal = int(r["label"]) == 1
        recs.append({"id": f"pi/{r['split']}/{i}", "code": code, "label": "malicious" if mal else "benign",
                     "categories": ["ai_targeted_instructions"] if mal else [], "rule": "prompt-injection"})
    return recs


# ---------------------------------------------------------------- real benign library code
PACKAGES = ["", "json", "http", "email", "logging", "concurrent", "asyncio", "urllib", "sqlite3", "importlib",
            "site-packages/fastapi", "site-packages/starlette", "site-packages/pydantic", "site-packages/sklearn/utils",
            "site-packages/sklearn/model_selection", "site-packages/pip/_internal", "site-packages/uvicorn",
            "site-packages/anyio", "site-packages/click", "site-packages/joblib"]


def build_benign(n=600, seed=7):
    rng = random.Random(seed)
    stdlib = sysconfig.get_paths()["stdlib"]
    pool = []
    for pkg in PACKAGES:
        base = os.path.join(stdlib, *pkg.split("/")) if pkg else stdlib
        if not os.path.isdir(base):
            continue
        walk = [(base, [], [f for f in os.listdir(base) if f.endswith(".py")])] if pkg == "" else os.walk(base)
        for d, _, files in walk:
            if re.search(r"[\\/](tests?|_vendor)[\\/]?", d):
                continue
            for fn in files:
                if not fn.endswith(".py") or fn.startswith("test"):
                    continue
                p = os.path.join(d, fn)
                try:
                    src = open(p, encoding="utf-8").read()
                    tree = ast.parse(src)
                except Exception:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and 6 <= node.end_lineno - node.lineno <= 60:
                        pool.append((os.path.relpath(p, stdlib), node.lineno, ast.get_source_segment(src, node, padded=True)))
    rng.shuffle(pool)
    recs = []
    for path, line, seg in pool[:n]:
        import textwrap
        recs.append({"id": f"lib/{path}:{line}", "code": textwrap.dedent(seg), "label": "benign", "categories": [],
                     "rule": "library-code"})
    # Shell scripts that ship with Git for Windows (real-world bash).
    for d in (r"C:\Program Files\Git\usr\bin", r"C:\Program Files\Git\mingw64\libexec\git-core", "/usr/bin"):
        if os.path.isdir(d):
            for fn in sorted(os.listdir(d)):
                p = os.path.join(d, fn)
                try:
                    if os.path.getsize(p) > 40_000:
                        continue
                    with open(p, "rb") as fh:
                        head = fh.read(64)
                    if not head.startswith(b"#!") or b"sh" not in head.split(b"\n")[0]:
                        continue
                    text = open(p, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                recs.append({"id": f"sh/{fn}", "code": text, "label": "benign", "categories": [], "rule": "shell-script"})
    return recs


# ---------------------------------------------------------------- vulnerable (not malicious) code
def _strip_fence(code):
    m = re.search(r"```[\w+#-]*\n(.*?)(```|$)", code, re.S)
    return (m.group(1) if m else code).strip("\n")


def build_vulnerable():
    """SecurityEval insecure code + CyberNative vulnerable/fixed pairs.

    These are insecure-but-not-malicious (CWE bugs). Labelled benign: a guard for
    *malicious* behaviour should mostly let them run. The `group` field says which
    source/variant a record is, so block rates can be read per group.
    """
    recs = []
    with open(os.path.join(RAW, "securityeval.jsonl"), encoding="utf-8") as f:
        for r in map(json.loads, f):
            recs.append({"id": f"se/{r['ID']}", "code": r["Insecure_code"], "label": "benign", "categories": [],
                         "rule": f"securityeval/{r['ID'].split('_')[0]}", "group": "securityeval-insecure"})
    rng = random.Random(11)
    with open(os.path.join(RAW, "cybernative.jsonl"), encoding="utf-8") as f:
        rows = [json.loads(l) for l in f]
    rng.shuffle(rows)
    for i, r in enumerate(rows[:800]):
        for variant in ("chosen", "rejected"):
            recs.append({"id": f"cn/{i}/{variant}", "code": _strip_fence(r[variant]), "label": "benign", "categories": [],
                         "rule": f"cybernative/{r['lang']}",
                         "group": "cybernative-fixed" if variant == "chosen" else "cybernative-vulnerable"})
    return recs


def build():
    os.makedirs(EXT, exist_ok=True)
    for name, fn in (("guarddog", build_guarddog), ("prompt_injections", build_injections), ("benign_oss", build_benign),
                     ("vulnerable_code", build_vulnerable)):
        recs = fn()
        with open(os.path.join(EXT, f"{name}.jsonl"), "w", encoding="utf-8") as f:
            for r in recs:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        mal = sum(r["label"] == "malicious" for r in recs)
        print(f"{name}.jsonl: {len(recs)} snippets ({mal} malicious, {len(recs) - mal} benign)")


if __name__ == "__main__":
    {"fetch": fetch, "build": build}.get(sys.argv[1] if len(sys.argv) > 1 else "build", build)()
