"""Step 4 (Python): AST analyzer — the core differentiator.

* alias tracking        import os as o; from subprocess import Popen as P; __import__('os')
* constant folding      'r'+'m -rf /', ''.join([...]), 'x'[::-1], chr(..), f-strings,
                        bytes.fromhex(..), base64.b64decode(..), codecs.decode(.., 'rot13')
* payload re-analysis   exec/eval of a folded/decoded string is analyzed recursively
* shell bridging        os.system / subprocess args are folded and scanned as bash
* taint tracking        secret source  ->  network sink  = data_exfiltration
* loop analysis         while True without break/return; fork inside loops
Nothing is executed: only literal values are evaluated by our own folder.
"""
import ast
import base64
import binascii
import codecs
import re

from ..findings import Finding, THREAT as T, CAPABILITY as C

EXEC_SINKS = {"exec", "eval", "compile", "builtins.exec", "builtins.eval"}
SHELL_SINKS = {
    "os.system", "os.popen", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp",
    "os.spawnl", "os.spawnv", "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "commands.getoutput", "pty.spawn", "os.startfile", "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
}
NET_SINKS = {
    "requests.post", "requests.put", "requests.patch", "requests.get", "requests.request", "requests.Session",
    "urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve", "httpx.post", "httpx.get",
    "httpx.Client", "http.client.HTTPConnection", "http.client.HTTPSConnection", "smtplib.SMTP", "ftplib.FTP",
    "socket.create_connection", "aiohttp.ClientSession",
}
NET_METHOD_SINKS = {"send", "sendall", "sendto", "sendmail", "send_message", "storbinary", "request", "post", "put", "connect"}
FINGERPRINT = {"getpass.getuser", "socket.gethostname", "platform.node", "os.getlogin", "os.uname", "platform.uname"}
DECODERS = {"b64decode", "b32decode", "b16decode", "a85decode", "b85decode", "decodebytes", "urlsafe_b64decode", "unhexlify",
            "a2b_hex", "fromhex", "decompress", "decrypt", "loads", "decode"}
EXE_EXT = re.compile(r"\.(exe|bin|sh|msi|dll|scr|ps1|bat|elf|run|appimage)(\?|$)", re.I)
SECRET_SOURCES = {"os.getenv", "os.environ.get", "os.environ.copy", "keyring.get_password", "getpass.getpass"}
DELETE_CALLS = {"shutil.rmtree", "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "pathlib.Path.unlink"}
SENSITIVE_PATH = re.compile(r"(\.ssh|\.aws|\.gnupg|\.kube|\.docker/config|\.netrc|\.git-credentials|/etc/shadow|/etc/passwd|\.env\b|id_rsa|id_ed25519|Login Data|Cookies|wallet|\.npmrc|\.pypirc|credentials)", re.I)
ROOTISH = re.compile(r"^\s*(/|/\*|~|~/|~/\*|/home/?|/root/?|/etc/?|/usr/?|/var/?|/boot/?|[A-Za-z]:\\?\\?)\s*$")
_SECRET_NAME = re.compile(r"(secret|token|passw|api_?key|private_?key|credential|aws_|auth)", re.I)
# A file whose *name* says it holds a secret (token.txt, api_key, secrets.json, server.pem). Whole-word match,
# so tokenizer.json or passwordless_setup.md do not count. Weaker than SENSITIVE_PATH: reading alone does not block.
_SECRET_FILE = re.compile(r"(?<![a-z])(tokens?|secrets?|credentials?|api[_-]?keys?|passwords?|passwd)(?![a-z])|\.(pem|key|p12|pfx|kdbx)$", re.I)
# Wrapping a secret in these leaks nothing: bool(os.getenv("TOKEN")) only says whether it is set.
_NON_LEAKING = {"bool", "len", "isinstance", "callable", "hasattr", "type", "id", "hash"}


def _secret_file(path):
    return bool(_SECRET_FILE.search(path.replace("\\", "/").rsplit("/", 1)[-1]))
_UNSET = object()


def _qual(node):
    """Dotted name of an expression like os.path.join -> 'os.path.join'."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):  # __import__('os').system
        inner = _qual(node.func)
        if inner in ("__import__", "importlib.import_module") and node.args and isinstance(node.args[0], ast.Constant):
            parts.append(str(node.args[0].value))
            return ".".join(reversed(parts))
    return None


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self, line_offset=0, depth=0, rescan=None):
        self.aliases = {}       # local name -> qualified module/function
        self.consts = {}        # variable -> folded literal
        self.tainted = {}       # variable -> reason (secret/file data)
        self.findings = []
        self.offset = line_offset
        self.depth = depth
        self.src = ""
        self.rescan = rescan    # callback(text, line, kind) -> findings (rules / recursive analysis)
        self.loop_stack = []
        self.fetched = set()    # variables holding data downloaded at runtime
        self.flags = set()      # snippet-level facts: download / write_bin / run
        self.origin = {}        # variable -> evidence step where its secret/decoded/downloaded value came from

    # ---------------- helpers ----------------
    def add(self, cat, kind, w, node, reason, chain=None):
        line = getattr(node, "lineno", 0) + self.offset if node is not None else 0
        self.findings.append(Finding(cat, kind, w, line, reason, "ast", list(chain or [])))

    def _step(self, node, role, label, via=None):
        s = {"line": getattr(node, "lineno", 0) + self.offset, "role": role, "label": label}
        if via:
            s["via"] = via
        return s

    def _origin_of(self, expr):
        """(origin step, variable) for the first variable in expr whose value we traced back, else (None, None)."""
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in self.origin:
                return self.origin[n.id], n.id
        return None, None

    def _flow(self, expr, why, sink_node, sink_label):
        """source -> sink chain for secret data reaching a sink (network call, print)."""
        src, var = self._origin_of(expr)
        steps = [dict(src)] if src else [self._step(expr, "source", f"reads {why}")]
        steps.append(self._step(sink_node, "sink", sink_label, via=var))
        return steps

    def _exec_chain(self, node, arg, payload, short, dec, hits):
        """encoded -> decoded -> exec chain for dynamic execution of hidden code."""
        steps = []
        src, var = self._origin_of(arg) if arg is not None else (None, None)
        if src:
            steps.append(dict(src))
        elif dec:
            steps.append(self._step(arg, "encoded", f"{dec}() decodes hidden data"))
        if isinstance(payload, str):
            preview = " ".join(payload.split())
            preview = preview[:44] + ("…" if len(preview) > 44 else "")  # short, so "⇒ what it does" stays visible
            found = list(dict.fromkeys(h.reason for h in hits))[:2]
            steps.append({"line": steps[0]["line"] if steps else node.lineno + self.offset, "role": "decoded",
                          "label": f"decodes to: {preview}" + (f"  ⇒ {'; '.join(found)}" if found else "")})
        steps.append(self._step(node, "sink", f"{short}() executes it", via=var))
        return steps if len(steps) > 1 else []

    def resolve(self, node):
        q = _qual(node)
        if not q:
            return None
        head, _, rest = q.partition(".")
        if head in self.aliases:
            base = self.aliases[head]
            return f"{base}.{rest}" if rest else base
        return q

    def fold(self, node, depth=0):
        """Statically evaluate string-building expressions. Returns str/bytes/int/list or _UNSET."""
        if depth > 12 or node is None:
            return _UNSET
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            return self.consts.get(node.id, _UNSET)
        if isinstance(node, ast.JoinedStr):
            out = ""
            for v in node.values:
                if isinstance(v, ast.Constant):
                    out += str(v.value)
                elif isinstance(v, ast.FormattedValue):
                    inner = self.fold(v.value, depth + 1)
                    out += str(inner) if inner is not _UNSET else "{?}"
            return out
        if isinstance(node, ast.BinOp):
            l, r = self.fold(node.left, depth + 1), self.fold(node.right, depth + 1)
            if l is _UNSET or r is _UNSET:
                return _UNSET
            try:
                if isinstance(node.op, ast.Div) and isinstance(l, str) and isinstance(r, str):
                    return l.rstrip("/") + "/" + r  # pathlib: Path.home() / ".ssh"
                if isinstance(node.op, ast.Add) and type(l) == type(r):
                    return l + r
                if isinstance(node.op, ast.Mult) and isinstance(l, (str, bytes)) and isinstance(r, int) and r < 10_000:
                    return l * r
                if isinstance(node.op, ast.Mod) and isinstance(l, str):
                    return l % r
            except Exception:
                return _UNSET
            return _UNSET
        if isinstance(node, (ast.List, ast.Tuple)):
            vals = [self.fold(e, depth + 1) for e in node.elts]
            return _UNSET if any(v is _UNSET for v in vals) else vals
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            base = self.fold(node.value, depth + 1)
            s = node.slice
            if isinstance(base, (str, bytes)) and s.lower is None and s.upper is None and isinstance(s.step, ast.UnaryOp) \
                    and isinstance(s.step.op, ast.USub) and isinstance(s.step.operand, ast.Constant) and s.step.operand.value == 1:
                return base[::-1]
            return _UNSET
        if isinstance(node, ast.Call):
            return self._fold_call(node, depth)
        return _UNSET

    def _fold_call(self, node, depth):
        fn = self.resolve(node.func) or ""
        args = [self.fold(a, depth + 1) for a in node.args]
        a0 = args[0] if args else _UNSET
        try:
            if fn == "chr" and isinstance(a0, int):
                return chr(a0)
            if fn in ("str",) and a0 is not _UNSET:
                return str(a0)
            meth = node.func.attr if isinstance(node.func, ast.Attribute) else ""
            if meth == "join":
                sep = self.fold(node.func.value, depth + 1)
                if isinstance(sep, str) and isinstance(a0, list) and all(isinstance(x, str) for x in a0):
                    return sep.join(a0)
                if isinstance(sep, str) and isinstance(node.args[0], (ast.GeneratorExp, ast.ListComp)):
                    return self._fold_chr_comp(node.args[0], sep, depth)
            if meth == "decode":
                inner = self.fold(node.func.value, depth + 1)
                if isinstance(inner, bytes):
                    return inner.decode("utf-8", "replace")
            if meth == "encode":
                inner = self.fold(node.func.value, depth + 1)
                if isinstance(inner, str):
                    return inner.encode()
            if meth == "replace" and len(args) >= 2:
                inner = self.fold(node.func.value, depth + 1)
                if isinstance(inner, str) and isinstance(args[0], str) and isinstance(args[1], str):
                    return inner.replace(args[0], args[1])
            if fn in ("base64.b64decode", "base64.decodebytes", "base64.urlsafe_b64decode", "base64.b32decode", "base64.b16decode") \
                    and isinstance(a0, (str, bytes)):
                data = a0.encode() if isinstance(a0, str) else a0
                dec = {"base64.b32decode": base64.b32decode, "base64.b16decode": base64.b16decode}.get(fn, base64.b64decode)
                return dec(data + b"=" * (-len(data) % 4) if "b64" in fn or "decodebytes" in fn else data)
            if fn in ("bytes.fromhex", "binascii.unhexlify", "binascii.a2b_hex") and isinstance(a0, (str, bytes)):
                return binascii.unhexlify(a0 if isinstance(a0, bytes) else a0.encode())
            if fn == "codecs.decode" and isinstance(a0, str) and len(args) > 1 and str(args[1]).lower().replace("_", "") in ("rot13",):
                return codecs.decode(a0, "rot_13")
            if fn in ("zlib.decompress",) and isinstance(a0, bytes):
                import zlib
                return zlib.decompress(a0)
            if fn in ("os.path.expanduser",) and isinstance(a0, str):
                return a0  # keep '~' so ROOTISH/HOME checks still see it
            if fn in ("os.path.join",) and all(isinstance(a, str) for a in args) and args:
                return "/".join(args)
            if fn in ("pathlib.Path.home", "Path.home"):
                return "~"
            if meth == "joinpath" and args and all(isinstance(a, str) for a in args):
                base = self.fold(node.func.value, depth + 1)  # Path.home().joinpath(".ssh", "id_rsa")
                if isinstance(base, str):
                    return base.rstrip("/") + "/" + "/".join(args)
            if fn in ("pathlib.Path", "Path", "pathlib.PurePath") and args and all(isinstance(a, str) for a in args):
                return "/".join(args)
            if fn == "bytes" and isinstance(a0, list) and all(isinstance(x, int) for x in a0):
                return bytes(a0)
        except Exception:
            return _UNSET
        return _UNSET

    def _fold_chr_comp(self, comp, sep, depth):
        # ''.join(chr(c) for c in [104, 105])
        if len(comp.generators) == 1 and isinstance(comp.elt, ast.Call) and self.resolve(comp.elt.func) == "chr":
            seq = self.fold(comp.generators[0].iter, depth + 1)
            if isinstance(seq, list) and all(isinstance(x, int) for x in seq):
                try:
                    return sep.join(chr(x) for x in seq)
                except ValueError:
                    return _UNSET
        return _UNSET

    def _is_download(self, node):
        for c in ast.walk(node):
            if isinstance(c, ast.Call):
                fn = self.resolve(c.func) or ""
                if fn in NET_SINKS or fn.endswith(("urlopen", "urlretrieve")) or fn in ("requests.get", "httpx.get"):
                    self.flags.add("download")
                    return True
            if isinstance(c, ast.Name) and c.id in self.fetched:
                return True
        return False

    def _has_decoder(self, node):
        for c in ast.walk(node):
            if isinstance(c, ast.Call):
                name = c.func.attr if isinstance(c.func, ast.Attribute) else c.func.id if isinstance(c.func, ast.Name) else ""
                if name in DECODERS and not (name == "loads" and "json" in (self.resolve(c.func) or "")):
                    return name
        return None

    def _mentions_secret(self, node):
        """Does this expression touch a secret-looking name (env var / variable / key)?"""
        for sub in ast.walk(node):
            txt = sub.value if isinstance(sub, ast.Constant) and isinstance(sub.value, str) else \
                sub.id if isinstance(sub, ast.Name) else sub.attr if isinstance(sub, ast.Attribute) else None
            if txt and _SECRET_NAME.search(txt):
                return True
            if isinstance(sub, ast.Name) and not self.tainted.get(sub.id, "file contents").startswith(("file contents", "non-secret")):
                return True
        return False

    def _env_key(self, sub):
        """The variable name an env read asks for, if it is a literal: os.environ["X"] / .get("X") / getenv("X")."""
        if isinstance(sub, ast.Subscript):
            k = self.fold(sub.slice)
        elif isinstance(sub, ast.Call) and sub.args:
            k = self.fold(sub.args[0])
        else:
            return None
        return k if isinstance(k, str) else None

    def _names_in(self, node):
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def _is_secret_source(self, node):
        """Does this expression read secrets / sensitive files?

        Returns the strongest reason found. Weak reasons ("file contents", "non-secret env var X")
        only count if nothing stronger is in the expression.
        """
        if isinstance(node, ast.Compare) or isinstance(node, ast.Call) and (self.resolve(node.func) or "") in _NON_LEAKING:
            return None  # bool(os.getenv("TOKEN")), len(...), x is None: a yes/no, not the secret
        # os.environ used only for its names (.keys(), `k in os.environ`) reveals no values.
        names_only = {id(n.value) for n in ast.walk(node) if isinstance(n, ast.Attribute) and n.attr == "keys"}
        names_only |= {id(c) for n in ast.walk(node) if isinstance(n, ast.Compare)
                       and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops) for c in n.comparators}
        weak = None
        skip = set()  # sub-nodes of an env read already judged non-secret (its inner `os.environ` must not re-count)
        for sub in ast.walk(node):
            if id(sub) in skip:
                continue
            env_key = None
            if isinstance(sub, ast.Subscript) and self.resolve(sub.value) == "os.environ":
                env_key = self._env_key(sub)
                if env_key is not None and not _SECRET_NAME.search(env_key):
                    weak = weak or f"non-secret env var {env_key}"
                    skip |= {id(x) for x in ast.walk(sub)}
                    continue
                return "environment variable"
            if isinstance(sub, ast.Call):
                fn = self.resolve(sub.func) or ""
                if fn in ("os.getenv", "os.environ.get"):
                    env_key = self._env_key(sub)
                    if env_key is not None and not _SECRET_NAME.search(env_key):
                        weak = weak or f"non-secret env var {env_key}"
                        skip |= {id(x) for x in ast.walk(sub)}
                        continue
                if fn in SECRET_SOURCES or fn == "dict" and sub.args and self.resolve(sub.args[0]) == "os.environ":
                    return "secret/environment"
                if fn in FINGERPRINT:
                    return "host fingerprint (user/hostname)"
                if fn in ("open", "io.open", "pathlib.Path", "builtins.open", "codecs.open") or fn.endswith((".read_text", ".read_bytes")):
                    p = self.fold(sub.args[0]) if sub.args else _UNSET
                    if isinstance(p, str) and (SENSITIVE_PATH.search(p) or _secret_file(p)):
                        return f"sensitive file {p}"
                    if p is _UNSET or isinstance(p, str):
                        weak = "file contents"
            if isinstance(sub, ast.Attribute) and self.resolve(sub) == "os.environ" and id(sub) not in names_only:
                return "environment"
            if isinstance(sub, ast.Name) and sub.id in self.tainted:
                why = self.tainted[sub.id]
                if why.startswith(("file contents", "non-secret")):
                    weak = weak if weak == "file contents" else why
                    continue
                return why
        return weak

    # ---------------- visitors ----------------
    def visit_Import(self, node):
        for a in node.names:
            self.aliases[(a.asname or a.name).split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
        self.generic_visit(node)

    def visit_Assign(self, node):
        val = self.fold(node.value)
        src = self._is_secret_source(node.value)
        # x = __import__('os')  /  x = importlib.import_module('o'+'s')
        imported = None
        if isinstance(node.value, ast.Call) and self.resolve(node.value.func) in ("__import__", "importlib.import_module"):
            mod = self.fold(node.value.args[0]) if node.value.args else _UNSET
            if isinstance(mod, str):
                imported = mod
                if not isinstance(node.value.args[0], ast.Constant):
                    self.add("obfuscated_execution", T, 0.7, node, f"imports module '{mod}' via a computed name")
        if isinstance(node.value, ast.Call) and self.resolve(node.value.func) == "getattr":
            target = self._getattr_target(node.value)
            if target:
                imported = target
        downloaded = self._is_download(node.value)
        dec = self._has_decoder(node.value) if isinstance(val, (str, bytes)) else None
        inherited, _ = self._origin_of(node.value)
        origin = (self._step(node, "source", f"reads {src}") if src and not src.startswith("non-secret") else
                  self._step(node, "encoded", f"{dec}() decodes a hidden payload") if dec else
                  self._step(node, "source", "downloaded at runtime") if downloaded else inherited)
        for t in node.targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name):
                    if downloaded:
                        self.fetched.add(n.id)
                    if val is not _UNSET:
                        self.consts[n.id] = val
                    if src:
                        self.tainted[n.id] = src
                    if imported:
                        self.aliases[n.id] = imported
                    if origin:
                        self.origin[n.id] = origin
        self._check_folded(node.value, val)
        self.generic_visit(node)

    def _getattr_target(self, call):
        if len(call.args) < 2:
            return None
        base = self.resolve(call.args[0]) or ""
        name = self.fold(call.args[1])
        if isinstance(name, str):
            if not isinstance(call.args[1], ast.Constant) and name in ("system", "popen", "exec", "eval", "spawn", "Popen", "run", "remove", "rmtree", "__import__"):
                self.add("obfuscated_execution", T, 0.8, call, f"resolves '{base}.{name}' through a computed getattr")
            return f"{base}.{name}" if base else name
        if base in ("os", "subprocess", "builtins", "__builtins__", "shutil", "socket"):
            self.add("obfuscated_execution", T, 0.6, call, f"getattr on '{base}' with an unknown name")
        return None

    def _check_folded(self, node, val):
        """If a non-literal expression folds to a string, re-scan the plaintext."""
        if self.rescan and isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call, ast.Subscript)) and isinstance(val, (str, bytes)):
            text = val.decode("utf-8", "replace") if isinstance(val, bytes) else val
            if len(text) >= 4:
                hits = self.rescan(text, getattr(node, "lineno", 1) + self.offset - 1, "folded")
                if hits:
                    self.add("obfuscated_execution", T, 0.55, node, "builds a dangerous string at runtime")
                    self.findings.extend(hits)

    def visit_Call(self, node):
        fn = self.resolve(node.func) or ""
        short = fn.rsplit(".", 1)[-1]

        if fn == "getattr":
            self._getattr_target(node)

        # --- dynamic code execution ---
        if fn in EXEC_SINKS or short in ("exec", "eval") and fn.startswith(("builtins", "__builtins__")):
            arg = node.args[0] if node.args else None
            payload = self.fold(arg) if arg is not None else _UNSET
            if isinstance(payload, bytes):
                payload = payload.decode("utf-8", "replace")
            literal = isinstance(arg, ast.Constant)
            dec = self._has_decoder(arg) if arg is not None else None
            seg = ast.get_source_segment(self.src, arg) or "" if arg is not None and self.src else ""
            # What the hidden code does, found by re-analysing it; computed first so the chain can say so.
            hits = self.rescan(payload, node.lineno + self.offset - 1, "payload") if isinstance(payload, str) and self.rescan else []
            chain = self._exec_chain(node, arg, payload, short, dec, hits)
            for h in hits:
                if not h.chain:
                    h.chain = [dict(s) for s in chain]
            if arg is not None and (self._is_download(arg) or any(isinstance(n, ast.Name) and n.id in self.fetched for n in ast.walk(arg))):
                self.add("obfuscated_execution", T, 0.85, node, f"{short}() runs code downloaded at runtime", chain)
                self.add("dependency_risk", T, 0.7, node, "downloads and executes remote code", chain)
            elif dec and payload is _UNSET:
                self.add("obfuscated_execution", T, 0.85, node, f"{short}() runs data passed through {dec}()", chain)
            if literal and isinstance(payload, str) and (re.fullmatch(r"[A-Za-z0-9+/=\s]{40,}", payload)
                                                         or len(re.findall(r"\\[0-7]{3}|\\x[0-9a-fA-F]{2}", seg)) >= 4):
                self.add("obfuscated_execution", T, 0.8, node, f"{short}() of an encoded/escaped literal")
            if isinstance(payload, str) and not literal:
                self.add("obfuscated_execution", T, 0.9, node, f"{short}() runs a decoded/assembled payload", chain)
            elif isinstance(payload, str) and literal:
                self.add("obfuscated_execution", C, 0.35, node, f"{short}() of a literal string")
            elif arg is not None:
                fetched = any(isinstance(c, ast.Call) and ((self.resolve(c.func) or "") in NET_SINKS | {"input", "sys.stdin.read"}
                                                           or isinstance(c.func, ast.Attribute) and c.func.attr in ("recv", "urlopen"))
                              or isinstance(c, ast.Attribute) and c.attr in ("text", "content")
                              for c in ast.walk(arg))
                if fetched:
                    self.add("obfuscated_execution", T, 0.85, node, f"{short}() runs code fetched/received at runtime")
                else:
                    self.add("obfuscated_execution", T, 0.4, node, f"{short}() of a value only known at runtime")
            self.findings.extend(hits)

        # --- shell commands: fold the command and scan it as bash ---
        if fn in SHELL_SINKS:
            first = self.fold(node.args[0]) if node.args else _UNSET
            first = " ".join(map(str, first)) if isinstance(first, list) else first
            if not (isinstance(first, str) and re.match(r"\s*(echo|printf|ls|dir|cat|type)\b", first)):
                self.flags.add("run")
            dec = self._has_decoder(node.args[0]) if node.args else None
            if dec:
                self.add("obfuscated_execution", T, 0.85, node, f"runs a command decoded with {dec}()")
            cmd = self.fold(node.args[0]) if node.args else _UNSET
            if isinstance(cmd, list):
                cmd = " ".join(str(c) for c in cmd)
            shell_kw = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in node.keywords)
            if isinstance(cmd, str) and self.rescan:
                hits = self.rescan(cmd, node.lineno + self.offset - 1, "shell")
                self.findings.extend(hits)
            elif cmd is _UNSET and (shell_kw or fn in ("os.system", "os.popen")):
                arg = node.args[0] if node.args else None
                if arg is not None and self._is_secret_source(arg) is None and not isinstance(arg, ast.Constant):
                    self.add("obfuscated_execution", C, 0.3, node, "shell command built from runtime data")

        # --- download and run an executable ---
        if fn.endswith("urlretrieve") and node.args:
            self.flags.add("download")
            dst = [self.fold(a) for a in node.args[:2]]
            if any(isinstance(d, str) and EXE_EXT.search(d) for d in dst):
                self.add("dependency_risk", T, 0.8, node, "downloads an executable file")
                self.flags.add("write_bin")
        if fn in ("open", "builtins.open", "io.open") and len(node.args) > 1 and self.fold(node.args[1]) in ("wb", "w+b", "ab"):
            self.flags.add("write_bin")
        if fn in ("os.chmod", "os.rename", "os.startfile"):
            self.flags.add("run")
        if fn in ("requests.get", "httpx.get", "urllib.request.urlopen") and node.args:
            url = self.fold(node.args[0])
            if isinstance(url, str) and EXE_EXT.search(url):
                self.add("dependency_risk", T, 0.45, node, "downloads an executable file")

        # --- DNS exfiltration: local data encoded into a hostname lookup ---
        if fn.rsplit(".", 1)[-1] in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "resolve", "query") and node.args \
                and isinstance(node.args[0], ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.args[0].values) \
                and any(isinstance(v, ast.Constant) and re.search(r"\.[a-z]{2,}", str(v.value)) for v in node.args[0].values):
            self.add("data_exfiltration", T, 0.75, node, "encodes local data into a DNS lookup")

        # --- reading credential files ---
        is_open = fn in ("open", "builtins.open", "io.open", "codecs.open")
        if is_open or (isinstance(node.func, ast.Attribute) and node.func.attr in ("read_text", "read_bytes", "open")):
            target = (node.args[0] if node.args else None) if is_open else \
                (node.func.value if isinstance(node.func, ast.Attribute) else None)
            p = self.fold(target) if target is not None else _UNSET
            if isinstance(p, str) and SENSITIVE_PATH.search(p) and not re.search(r"\.env\.(example|sample|template)", p):
                self.add("secret_access", T, 0.8, node, f"reads credential file '{p}'")
            elif isinstance(p, str) and _secret_file(p):
                # Name-based only (token.txt, api_key): an app may read its own token. Below the block line
                # on its own; printing or sending it (taint sinks) is what blocks.
                self.add("secret_access", T, 0.45, node, f"reads secret-named file '{p}'")

        # --- leaking secrets to stdout/logs/files ---
        if fn in ("print", "logging.info", "logging.warning", "logging.debug", "pprint.pprint") or \
                (isinstance(node.func, ast.Attribute) and node.func.attr in ("write", "info", "warning", "debug")):
            for e in list(node.args) + [k.value for k in node.keywords]:
                why = self._is_secret_source(e)
                if why and why.startswith(("environment", "secret", "sensitive")) and self._mentions_secret(node):
                    self.add("secret_access", T, 0.7, node, f"prints/writes {why}",
                             self._flow(e, why, node, "printed / written out"))
                    break

        # --- destructive filesystem calls ---
        if fn in DELETE_CALLS or fn.endswith((".rmtree", ".unlink")) and "shutil" in fn:
            p = self.fold(node.args[0]) if node.args else _UNSET
            if isinstance(p, str) and (ROOTISH.match(p) or re.match(r"^(~|/home/[^/]+|/root)/?$", p)):
                self.add("destructive_command", T, 0.9, node, f"deletes '{p}' recursively")

        # --- persistence / privilege from Python ---
        if fn in ("os.setuid", "os.setgid", "os.seteuid") and node.args and self.fold(node.args[0]) == 0:
            self.add("persistence_or_privesc", T, 0.8, node, "switches to uid/gid 0")
        if fn in ("os.chmod",) and len(node.args) > 1:
            mode = self.fold(node.args[1])
            if isinstance(mode, int) and mode & 0o6000:
                self.add("persistence_or_privesc", T, 0.8, node, "sets setuid/setgid bit")
        if fn in ("open", "builtins.open", "io.open") and len(node.args) > 1:
            p, mode = self.fold(node.args[0]), self.fold(node.args[1])
            if isinstance(p, str) and isinstance(mode, str) and any(c in mode for c in "wa") and \
                    re.search(r"(\.bashrc|\.profile|\.zshrc|authorized_keys|/etc/cron|crontab|/etc/systemd|rc\.local|sudoers|/etc/passwd|autostart|LaunchAgents)", p):
                self.add("persistence_or_privesc", T, 0.85, node, f"writes to autostart/privilege file '{p}'")

        # --- taint: secret data reaching the network ---
        is_net = fn in NET_SINKS or (isinstance(node.func, ast.Attribute) and node.func.attr in NET_METHOD_SINKS
                                     and (self.resolve(node.func.value) or "").split(".")[0] in ("requests", "s", "sock", "socket", "client", "conn", "session", "smtp", "server", "httpx", "ftp")) \
            or fn.endswith((".sendall", ".sendto", ".sendmail"))
        if is_net:
            exprs = list(node.args) + [k.value for k in node.keywords]
            for e in exprs:
                why = self._is_secret_source(e)
                if why and not why.startswith("non-secret"):  # sending APP_MODE out is config, not exfiltration
                    w = 0.7 if why == "file contents" else 0.65 if why.startswith("host") else 0.9
                    flow = self._flow(e, why, node, "sent over the network")
                    self.add("data_exfiltration", T, w, node, f"sends {why} over the network", flow)
                    if why.startswith(("environment", "secret", "sensitive")):
                        self.add("secret_access", T, 0.7, node, f"reads {why}", flow)
                    break

        # --- process explosion inside a loop ---
        if self.loop_stack and fn in ("os.fork", "multiprocessing.Process", "subprocess.Popen", "threading.Thread"):
            self.add("resource_exhaustion", T, 0.85 if fn == "os.fork" else 0.55, node, f"{fn} inside a loop")

        self.generic_visit(node)

    def _unbounded(self, loop):
        for n in ast.walk(loop):
            if n is loop:
                continue
            if isinstance(n, (ast.Break, ast.Return, ast.Raise)):
                return False
            if isinstance(n, ast.Call) and (self.resolve(n.func) or "") in ("sys.exit", "exit", "quit", "os._exit"):
                return False
        return True

    def visit_While(self, node):
        test = self.fold(node.test)
        if test not in (_UNSET, None) and bool(test) and self._unbounded(node):
            body_calls = {(self.resolve(c.func) or "") for c in ast.walk(node) if isinstance(c, ast.Call)}
            waits = any(x.endswith(("sleep", "recv", "accept", "get", "wait", "input", "read", "select", "poll")) for x in body_calls)
            grows = any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("append", "extend") for n in ast.walk(node))
            if not waits or grows:
                self.add("resource_exhaustion", T, 0.75 if not grows else 0.85, node,
                         "infinite loop with no exit" + (" that keeps allocating memory" if grows else ""))
        self.loop_stack.append(node)
        self.generic_visit(node)
        self.loop_stack.pop()

    def visit_With(self, node):
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name):
                why = self._is_secret_source(item.context_expr)
                if why:
                    self.tainted[item.optional_vars.id] = why
                    if not why.startswith("non-secret"):
                        self.origin[item.optional_vars.id] = self._step(node, "source", f"reads {why}")
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_For(self, node):
        # for k, v in os.environ.items(): if "TOKEN" in k ...  -> harvesting secrets
        it = node.iter.func.value if isinstance(node.iter, ast.Call) and isinstance(node.iter.func, ast.Attribute) else node.iter
        if self.resolve(it) == "os.environ" and any(isinstance(c, ast.Constant) and isinstance(c.value, str)
                                                     and _SECRET_NAME.search(c.value) for c in ast.walk(node)):
            self.add("secret_access", T, 0.75, node, "harvests secret-looking environment variables")
            for n in ast.walk(node.target):
                if isinstance(n, ast.Name):
                    self.tainted[n.id] = "environment"
                    self.origin[n.id] = self._step(node, "source", "reads secret-looking environment variables")
        self.loop_stack.append(node)
        self.generic_visit(node)
        self.loop_stack.pop()

    def visit_FunctionDef(self, node):
        # unconditional self-recursion: def f(): f()
        direct = [s for s in node.body if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
                  and isinstance(s.value.func, ast.Name) and s.value.func.id == node.name]
        has_if = any(isinstance(s, (ast.If, ast.Return)) for s in ast.walk(node) if s is not node)
        if direct and not has_if:
            self.add("resource_exhaustion", T, 0.65, node, f"function '{node.name}' recurses without a base case")
        self.generic_visit(node)


def analyze_python(code: str, line_offset=0, depth=0, rescan=None):
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError):
        return None  # caller falls back to rules only
    a = PythonAnalyzer(line_offset, depth, rescan)
    a.src = code
    a.visit(tree)
    if {"download", "write_bin", "run"} <= a.flags:
        a.findings.append(Finding("dependency_risk", T, 0.8, line_offset + 1, "downloads a file, saves it and executes it", "ast"))
    return a.findings
