"""Step 2: static deobfuscation. NOTHING here is ever executed.

Finds encoded blobs (base64, hex, \\x escapes, chr()/fromCharCode sequences,
reversed strings), decodes them statically, and returns the plaintext layers
so the pipeline can re-scan them (up to MAX_DEPTH layers deep).
"""
import base64
import binascii
import codecs
import re
import zlib

MAX_DEPTH = 3
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9a-fA-F])((?:[0-9a-fA-F]{2}){10,})(?![0-9a-fA-F])")
_XESC = re.compile(r"((?:\\x[0-9a-fA-F]{2}){6,})")
_CHR = re.compile(r"((?:chr\(\s*\d+\s*\)\s*\+?\s*){4,})")
_FCC = re.compile(r"fromCharCode\(\s*((?:\d+\s*,\s*){3,}\d+)\s*\)")
_ROT = re.compile(r"(?:rot13|rot_13|str_rot13)\W+['\"]([^'\"]{6,})['\"]", re.I)
_REV = re.compile(r"['\"]([^'\"]{8,})['\"]\s*\[\s*::\s*-1\s*\]|strrev\(\s*['\"]([^'\"]{8,})['\"]")


def _printable(s: str) -> bool:
    if not s or len(s) < 4:
        return False
    good = sum(ch.isprintable() or ch in "\n\r\t" for ch in s)
    return good / len(s) > 0.92


def _try_bytes(b: bytes):
    for fn in (lambda x: x, zlib.decompress, lambda x: zlib.decompress(x, -15)):
        try:
            raw = fn(b)
            s = raw.decode("utf-8")
            if _printable(s):
                return s
        except Exception:
            continue
    return None


def decode_blobs(text: str):
    """Return list of (kind, decoded_text) found in `text` (one layer)."""
    out = []
    for m in _B64.finditer(text):
        blob = m.group(1)
        if len(set(blob)) < 6 or blob.isalpha() and blob.islower():
            continue  # plain words / identifiers
        try:
            dec = _try_bytes(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False))
        except (binascii.Error, ValueError):
            dec = None
        if dec and re.search(r"[\s(){}=;:/.|$]", dec):
            out.append(("base64", dec))
    for m in _HEX.finditer(text):
        try:
            dec = _try_bytes(bytes.fromhex(m.group(1)))
        except ValueError:
            dec = None
        if dec:
            out.append(("hex", dec))
    for m in _XESC.finditer(text):
        try:
            dec = _try_bytes(bytes.fromhex(m.group(1).replace("\\x", "")))
        except ValueError:
            dec = None
        if dec:
            out.append(("hex-escape", dec))
    for m in _CHR.finditer(text):
        nums = re.findall(r"\d+", m.group(1))
        try:
            dec = "".join(chr(int(n)) for n in nums)
            if _printable(dec):
                out.append(("chr-chain", dec))
        except ValueError:
            pass
    for m in _FCC.finditer(text):
        try:
            dec = "".join(chr(int(n)) for n in re.findall(r"\d+", m.group(1)))
            if _printable(dec):
                out.append(("fromCharCode", dec))
        except ValueError:
            pass
    for m in _ROT.finditer(text):
        out.append(("rot13", codecs.decode(m.group(1), "rot_13")))
    for m in _REV.finditer(text):
        s = m.group(1) or m.group(2)
        out.append(("reversed", s[::-1]))
    return out


def unwrap(text: str, depth: int = 0):
    """Recursively decode. Yields (depth, kind, plaintext)."""
    if depth >= MAX_DEPTH:
        return
    seen = set()
    for kind, dec in decode_blobs(text):
        if dec in seen:
            continue
        seen.add(dec)
        yield depth + 1, kind, dec
        yield from unwrap(dec, depth + 1)
