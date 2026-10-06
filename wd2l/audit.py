"""Audit records: one JSON object per line, hash-chained, in append-only files.

Every record has the common fields of docs/audit-and-health-plan.md section 5, plus `n` (1, 2,
3, ... in its directory's chain), `prev_hash` and `hash`. `hash` is the SHA-256 of the record as
canonical JSON (keys sorted, no spaces, UTF-8) without `hash`. The first record's `prev_hash` is
64 zeros. Editing, removing or reordering a record breaks the chain.

    python3 -m wd2l.audit verify DIR [--upto N --upto-hash H]     (the daily self-check)
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

GENESIS = "0" * 64
FILE_GLOB = "audit-*.jsonl"


def canonical(rec: Dict[str, Any]) -> bytes:
    """The record as canonical JSON: keys sorted, no spaces, UTF-8. NaN and infinity refused."""
    return json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_hash(rec: Dict[str, Any]) -> str:
    """SHA-256 of the record without its `hash` field."""
    return sha256_hex(canonical({k: v for k, v in rec.items() if k != "hash"}))


def utc_ts(t: float) -> str:
    """Epoch seconds as 2026-10-05T14:03:22.418213Z."""
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ts_epoch(ts: str) -> float:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc).timestamp()


def split_lines(data: bytes) -> List[bytes]:
    """Lines with their newline. A last piece without one is a torn line (partial write)."""
    parts = data.split(b"\n")
    out = [p + b"\n" for p in parts[:-1]]
    if parts[-1]:
        out.append(parts[-1])
    return out


# ---------------------------------------------------------------- verification

class VerifyResult:
    def __init__(self) -> None:
        self.files: List[str] = []
        self.records = 0
        self.first_n: Optional[int] = None
        self.last_n: Optional[int] = None
        self.last_hash: Optional[str] = None
        self.problems: List[str] = []   # chain breaks: edited, removed, reordered, junk
        self.torn: List[str] = []       # partial last lines (crash or full disk mid-write)
        self.unchained = 0              # forwarded copies of records the file never held

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_json(self) -> Dict[str, Any]:
        return {"result": "ok" if self.ok else "failed", "files": self.files,
                "records": self.records, "first_n": self.first_n, "last_n": self.last_n,
                "last_hash": self.last_hash, "problem_count": len(self.problems),
                "problems": self.problems[:100], "torn": self.torn, "unchained": self.unchained}


class ChainChecker:
    """Checks records one at a time, in the order they were written. The first record seen
    anchors the chain: older files may have been deleted after a year."""

    def __init__(self, result: VerifyResult):
        self.res = result
        self.prev: Optional[Tuple[int, str]] = None

    def add(self, where: str, rec: Dict[str, Any]) -> None:
        res = self.res
        n, h, ph = rec.get("n"), rec.get("hash"), rec.get("prev_hash")
        if n is None and h is None:
            res.unchained += 1
            return
        if not isinstance(n, int) or isinstance(n, bool) or not isinstance(h, str):
            res.problems.append("%s: record has no valid n and hash" % where)
            return
        res.records += 1
        try:
            computed_hash = record_hash(rec)
        except (ValueError, RecursionError):
            res.problems.append("%s: n=%d can't be hashed (not canonical JSON: NaN, Infinity or too deeply nested)" % (where, n))
        else:
            if computed_hash != h:
                res.problems.append("%s: n=%d content does not match its hash (edited)" % (where, n))
        if self.prev is None:
            res.first_n = n
            if n == 1 and ph != GENESIS:
                res.problems.append("%s: n=1 does not start from the genesis hash" % where)
        else:
            pn, phash = self.prev
            if n != pn + 1:
                res.problems.append("%s: n jumps from %d to %d (records removed, reordered or "
                                    "replaced)" % (where, pn, n))
            elif ph != phash:
                res.problems.append("%s: n=%d does not link to n=%d (removed, reordered or "
                                    "edited)" % (where, n, pn))
        self.prev = (n, h)
        res.last_n, res.last_hash = n, h


def verify_lines(files: Iterable[Tuple[str, List[bytes]]], upto: Optional[int] = None,
                 upto_hash: Optional[str] = None) -> VerifyResult:
    """Check a chain given as (file name, lines) in write order. With `upto`, stop at record
    n=upto and require it (and its hash, if given): records cut from the end show up."""
    res = VerifyResult()
    chk = ChainChecker(res)
    done = False
    for name, file_lines in files:
        res.files.append(name)
        for i, line in enumerate(file_lines, 1):
            where = "%s:%d" % (name, i)
            if not line.endswith(b"\n"):
                res.torn.append(where)
                continue
            try:
                rec = json.loads(line)
            except (ValueError, RecursionError):
                res.problems.append("%s: not JSON" % where)
                continue
            if not isinstance(rec, dict):
                res.problems.append("%s: not a JSON object" % where)
                continue
            chk.add(where, rec)
            if upto is not None and rec.get("n") == upto:
                done = True
                break
        if done:
            break
    if upto is not None:
        if res.last_n != upto:
            res.problems.append("chain ends at n=%s, expected n=%d (records cut from the end)"
                                % (res.last_n, upto))
        elif upto_hash and res.last_hash != upto_hash:
            res.problems.append("n=%d has hash %s, expected %s" % (upto, res.last_hash, upto_hash))
    return res


def audit_files(directory: str) -> List[str]:
    """This directory's audit files, oldest first (names sort by start time)."""
    return sorted(glob.glob(os.path.join(directory, FILE_GLOB)))


def verify_dir(directory: str, upto: Optional[int] = None,
               upto_hash: Optional[str] = None) -> VerifyResult:
    def files() -> Iterable[Tuple[str, List[bytes]]]:
        for path in audit_files(directory):
            with open(path, "rb") as f:
                yield os.path.basename(path), split_lines(f.read())
    return verify_lines(files(), upto, upto_hash)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="python3 -m wd2l.audit",
                                description="Check an audit directory's hash chain.")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check the chain; JSON result on stdout")
    v.add_argument("directory")
    v.add_argument("--upto", type=int, help="stop at this record and require it")
    v.add_argument("--upto-hash", help="the hash record --upto must have")
    a = p.parse_args(argv)
    res = verify_dir(a.directory, a.upto, a.upto_hash)
    print(json.dumps(res.to_json(), sort_keys=True))
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
