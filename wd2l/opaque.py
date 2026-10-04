"""Spot opaque content (likely encrypted or compressed) inside log text.

A log line is text, so binary data can only travel in it encoded: base64 (or base64url), hex, or
inside an armor block such as PGP's. inspect() finds long runs of those, decodes them and
classifies the bytes:

  encrypted     a marker says so (PGP / age armor, OpenSSL "Salted__", the age header)
  compressed    a compression format's magic bytes (gzip, zlib, zip, bzip2, xz, zstd)
  high-entropy  no marker, but the bytes look random: likely encrypted, possibly compressed
                data or key material

Limits, by design:
* Short random strings are normal in logs (hashes, GUIDs, session ids, signatures). Only blobs
  of at least MIN_BYTES decoded bytes are judged; armor blocks are flagged at any size.
* Data hidden in ordinary-looking text (word choice, spacing, split across many events, timing)
  is not found. This is a tripwire for blobs, not proof that nothing is hidden.
* Other encodings (base32, base85, ...) are not decoded.
"""

import base64
import binascii
import math
import re
from collections import Counter
from typing import List, NamedTuple, Optional

MIN_BYTES = 256


class Finding(NamedTuple):
    kind: str     # "encrypted", "compressed" or "high-entropy"
    nbytes: int   # decoded size of the blob (approximate for armor blocks)


RANK = {"encrypted": 3, "compressed": 2, "high-entropy": 1}

ARMOR = re.compile(r"-----BEGIN (PGP MESSAGE|ENCRYPTED PRIVATE KEY|AGE ENCRYPTED FILE)-----"
                   r"(.*?)(?:-----END \1-----|\Z)", re.S)
# Base64 or base64url, possibly wrapped over several lines; "=" only as padding at a line end.
_LINE = r"[A-Za-z0-9+/_-]{16,}={0,2}"
B64_RUN = re.compile(r"%s(?:\r?\n%s)*" % (_LINE, _LINE))
MIN_B64_CHARS = -(-MIN_BYTES * 4 // 3)
HEX_RUN = re.compile(r"[0-9a-fA-F]{%d,}" % (2 * MIN_BYTES))
HEX_ONLY = re.compile(r"[0-9a-fA-F]+")

ENCRYPTED_MAGIC = (b"Salted__", b"age-encryption.org/")
COMPRESSED_MAGIC = (b"\x1f\x8b", b"PK\x03\x04", b"BZh", b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd")


def _is_zlib(b: bytes) -> bool:
    return b[0] & 0x0F == 8 and b[0] >> 4 <= 7 and (b[0] << 8 | b[1]) % 31 == 0


def _readable(b: bytes) -> bool:
    """Mostly text: UTF-8 (any language), or UTF-16LE ASCII such as PowerShell -EncodedCommand."""
    try:
        s = b.decode("utf-8")
        if sum(c.isprintable() or c in "\t\r\n\x00" for c in s) >= 0.9 * len(s):
            return True
    except UnicodeDecodeError:
        pass
    try:
        s = b.decode("utf-16-le")
    except UnicodeDecodeError:
        return False
    return sum(c < "\x80" and (c.isprintable() or c in "\t\r\n") for c in s) >= 0.9 * len(s)


def _entropy(b: bytes) -> float:
    n = len(b)
    return -sum(c / n * math.log2(c / n) for c in Counter(b).values())


def _classify(b: bytes) -> Optional[str]:
    if len(b) < MIN_BYTES or _readable(b):
        return None
    if b.startswith(ENCRYPTED_MAGIC):
        return "encrypted"
    if b.startswith(COMPRESSED_MAGIC) or _is_zlib(b):
        return "compressed"
    # Random bytes score about 8 - 184/n bits per byte (the estimate is low for short blobs).
    if _entropy(b) >= 8 - 184 / len(b) - 0.4:
        return "high-entropy"
    return None


def _b64_decode(run: str) -> Optional[bytes]:
    body = re.sub(r"\s", "", run).rstrip("=")
    if len(body) < MIN_B64_CHARS or HEX_ONLY.fullmatch(body):
        return None   # too short to judge, or hex (decoded by the hex path)
    std, url = any(c in "+/" for c in body), any(c in "-_" for c in body)
    if std and url:
        return None
    if not (any(c.isupper() for c in body) and any(c.islower() for c in body)
            and any(c.isdigit() for c in body)):
        return None   # words, base32, "ZZZZ..." and the like
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), altchars=b"-_" if url else None,
                                validate=True)
    except (binascii.Error, ValueError):
        return None


def inspect(text: str) -> Optional[Finding]:
    """The most serious opaque blob in text (then the largest), or None."""
    found: List[Finding] = []
    for m in ARMOR.finditer(text):
        body = re.sub(r"[^A-Za-z0-9+/]", "", m.group(2))
        found.append(Finding("encrypted", len(body) * 3 // 4))
    for m in B64_RUN.finditer(text):
        b = _b64_decode(m.group())
        kind = _classify(b) if b else None
        if kind:
            found.append(Finding(kind, len(b)))
    for m in HEX_RUN.finditer(text):
        h = m.group()
        b = bytes.fromhex(h[:len(h) // 2 * 2])
        kind = _classify(b)
        if kind:
            found.append(Finding(kind, len(b)))
    return max(found, key=lambda f: (RANK[f.kind], f.nbytes)) if found else None
