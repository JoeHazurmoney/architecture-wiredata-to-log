"""Runs inside the image: the OpenSSL FIPS provider is in force, MD5 is refused, and what wd2l
uses (SHA-256, a TLS context) works (docs/decisions/0004-container-base-image.md).
    podman run --rm -v ./packaging/container/fips_check.py:/fips_check.py:ro IMAGE python3 /fips_check.py"""
import _hashlib
import hashlib
import ssl
import sys

problems = []
if _hashlib.get_fips_mode() != 1:
    problems.append("OpenSSL is not in FIPS mode")
try:
    hashlib.md5(b"x")
    problems.append("MD5 is allowed")
except ValueError:
    pass
hashlib.sha256(b"wd2l").hexdigest()
ssl.create_default_context()
print("\n".join(problems) or "FIPS: ok (%s)" % ssl.OPENSSL_VERSION)
sys.exit(1 if problems else 0)
