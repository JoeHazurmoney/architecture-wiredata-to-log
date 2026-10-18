#!/usr/bin/env python3
"""RPM headers, read with the standard library (#190, docs/decisions/0009-sbom-content.md): an RPM
file's signature and main headers, and the headers an RPM database (rpmdb.sqlite) keeps for each
installed package. The SBOMs take package identity, files, requirements and digests from them:
Syft records neither an RPM's requirements nor any package-level digest.

An RPM file is a 96-byte lead, the signature header (padded to 8 bytes), the main header, then the
compressed payload. A header is a magic (8 bytes; absent in the database), the index's entry count
and the store's size, the index (tag, type, offset, count; 16 bytes each), then the store.

    rpm_header.py FILE.rpm|rpmdb.sqlite      print what it read, as JSON"""

import json
import sqlite3
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

LEAD = b"\xed\xab\xee\xdb"
MAGIC = b"\x8e\xad\xe8\x01"
INT16, INT32, STRING, BIN, STRING_ARRAY, I18N = 3, 4, 6, 7, 8, 9
SHA256 = 8                          # PGPHASHALGO_SHA256, the file and payload digests' algorithm
TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1004: "summary",
        1011: "vendor", 1014: "license", 1020: "url", 1022: "arch", 1030: "filemodes",
        1035: "filedigests", 1044: "sourcerpm", 1047: "providename", 1048: "requireflags",
        1049: "requirename", 1050: "requireversion", 1116: "dirindexes", 1117: "basenames",
        1118: "dirnames", 5011: "filedigestalgo", 5092: "payloaddigest", 5093: "payloaddigestalgo",
        273: "sha256header"}       # RPMSIGTAG_SHA256 in a file's signature header; kept in the db


def parse(data: bytes, start: int = 0, magic: bool = True) -> Tuple[Dict[str, Any], int]:
    """The tags TAGS names, and where the header ends."""
    pos = start
    if magic:
        if data[pos:pos + 4] != MAGIC:
            raise ValueError("not an RPM header at byte %d" % pos)
        pos += 8
    il, dl = struct.unpack(">II", data[pos:pos + 8])
    index, store = pos + 8, pos + 8 + 16 * il
    out: Dict[str, Any] = {}
    for i in range(il):
        tag, typ, off, cnt = struct.unpack(">iiii", data[index + 16 * i:index + 16 * i + 16])
        name = TAGS.get(tag)
        if not name:
            continue
        at = store + off
        if typ == INT32:
            out[name] = list(struct.unpack(">%di" % cnt, data[at:at + 4 * cnt]))
        elif typ == INT16:                    # unsigned: file modes are, e.g. 0o100644
            out[name] = list(struct.unpack(">%dH" % cnt, data[at:at + 2 * cnt]))
        elif typ in (STRING, I18N, STRING_ARRAY):
            parts = data[at:store + dl].split(b"\0")
            vals = [p.decode("utf-8", "replace") for p in parts[:cnt if typ == STRING_ARRAY else 1]]
            out[name] = vals if typ == STRING_ARRAY else vals[0]
    return out, store + dl


def _package(h: Dict[str, Any]) -> Dict[str, Any]:
    epoch = h.get("epoch")
    return {"name": h.get("name"), "version": h.get("version"), "release": h.get("release"),
            "epoch": epoch[0] if epoch else None, "arch": h.get("arch")}


def read_rpm(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != LEAD:
        raise ValueError("%s: not an RPM file" % path)
    sig, end = parse(data, 96)
    main, _ = parse(data, end + (-end % 8))
    if main.get("basenames") and (main.get("filedigestalgo") or [SHA256])[0] != SHA256:
        raise ValueError("%s: its file digests aren't SHA-256" % path)
    dirs = main.get("dirnames") or []
    files = [{"path": dirs[d] + b, "mode": m, "sha256": s}
             for d, b, m, s in zip(main.get("dirindexes") or [], main.get("basenames") or [],
                                   main.get("filemodes") or [], main.get("filedigests") or [])]
    pay = main.get("payloaddigest") or []
    out = _package(main)
    out.update({
        "summary": main.get("summary"), "license": main.get("license"), "url": main.get("url"),
        "vendor": main.get("vendor"), "sourcerpm": main.get("sourcerpm"),
        "requires": [{"name": n, "flags": f, "version": v} for n, f, v in zip(
            main.get("requirename") or [], main.get("requireflags") or [], main.get("requireversion") or [])],
        "provides": main.get("providename") or [], "files": files,
        "payload_sha256": pay[0] if pay and (main.get("payloaddigestalgo") or [SHA256])[0] == SHA256 else None,
        "header_sha256": sig.get("sha256header")})
    return out


def read_rpmdb(path: str) -> List[Dict[str, Any]]:
    """Each installed package: its identity and its header's SHA-256 (None for rpm's gpg-pubkey
    entries, which have none)."""
    con = sqlite3.connect("file:%s?mode=ro" % path, uri=True)
    try:
        rows = con.execute("SELECT blob FROM Packages ORDER BY hnum").fetchall()
    finally:
        con.close()
    out = []
    for (blob,) in rows:
        h, _ = parse(bytes(blob), 0, magic=False)
        p = _package(h)
        p["header_sha256"] = h.get("sha256header")
        out.append(p)
    return out


def main(argv: Optional[List[str]] = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    got = read_rpmdb(args[0]) if args[0].endswith(".sqlite") else read_rpm(args[0])
    json.dump(got, sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
