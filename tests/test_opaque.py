"""Opaque (likely encrypted or compressed) content inside log text."""

import base64
import gzip
import hashlib
import json
import os
import random
import uuid

import pytest

from wd2l import opaque

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "samples", "logs")


def rand(n, seed=1):
    return random.Random(seed).randbytes(n)


def b64(data):
    return base64.b64encode(data).decode()


def b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ---------------------------------------------------------------- found


def test_random_base64_blob_is_high_entropy():
    assert opaque.inspect("GET /beacon?d=%s HTTP/1.1" % b64(rand(600))) == \
        opaque.Finding("high-entropy", 600)


def test_base64url_blob_is_found():
    assert opaque.inspect("token=" + b64url(rand(400, seed=2))) == \
        opaque.Finding("high-entropy", 400)


def test_line_wrapped_blob_is_joined():
    body = b64(rand(1024, seed=3))
    wrapped = "\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    assert opaque.inspect("dump:\n" + wrapped + "\nend") == opaque.Finding("high-entropy", 1024)


def test_random_hex_blob_is_found():
    assert opaque.inspect("Binary: " + rand(300, seed=4).hex()) == \
        opaque.Finding("high-entropy", 300)


def test_gzip_blob_is_compressed():
    data = gzip.compress(rand(500, seed=5), mtime=0)
    assert opaque.inspect("payload=" + b64(data)) == opaque.Finding("compressed", len(data))


def test_openssl_salted_blob_is_encrypted():
    data = b"Salted__" + rand(400, seed=6)
    assert opaque.inspect(b64(data)) == opaque.Finding("encrypted", len(data))


def test_pgp_armor_is_encrypted_even_when_short():
    msg = "-----BEGIN PGP MESSAGE-----\n\nhQEMA1x2y3z4AQf/abcdEFGH\n=Xy12\n-----END PGP MESSAGE-----"
    assert opaque.inspect("mail body: " + msg).kind == "encrypted"


def test_the_most_serious_finding_wins():
    text = "a=%s b=%s" % (b64(rand(2000, seed=7)), b64(b"Salted__" + rand(300, seed=8)))
    assert opaque.inspect(text) == opaque.Finding("encrypted", 308)


# ---------------------------------------------------------------- normal content


def jwt():
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": "admin", "iat": 1790000000}).encode())
    return "%s.%s.%s" % (header, payload, b64url(rand(32, seed=9)))


@pytest.mark.parametrize("text", [
    "sha256=" + hashlib.sha256(b"x").hexdigest(),
    "session %s user %s" % (uuid.UUID(int=1), uuid.UUID(int=2)),
    "Authorization: Bearer " + jwt(),
    "csrf=" + b64(rand(48, seed=10)),
    "note=" + b64(("The quick brown fox jumps over the lazy dog. " * 30).encode()),
    "powershell -EncodedCommand " + b64(("Get-Process | Where-Object { $_.CPU -gt 100 }; " * 12)
                                       .encode("utf-16-le")),
    "Binary: " + (b"\x00" * 200 + bytes(range(100))).hex(),
    "Z" * 300000,
    "A2B3" * 200,
], ids=["sha256", "guids", "jwt", "short-token", "base64-text", "powershell", "structured-hex",
        "one-letter", "uppercase-digits"])
def test_normal_log_content_is_not_flagged(text):
    assert opaque.inspect(text) is None


def test_real_sample_logs_have_no_findings():
    lines = 0
    for name in ("messages", "secure", "audit.log"):
        with open(os.path.join(SAMPLES, name), encoding="utf-8", errors="replace") as f:
            for line in f:
                lines += 1
                assert opaque.inspect(line) is None, (name, line[:120])
    assert lines > 17000
