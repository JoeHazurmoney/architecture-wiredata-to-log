# Phase 1: audit records on both sides

Part of the [audit and health implementation plan](README.md). Read its **Global constraints**
first. Spec: [docs/audit-and-health-plan.md](../../../audit-and-health-plan.md) §4–§6, §10, §11.

**Delivers:** with `--audit-dir`, the sender and the receiver (and an archive replay) write the
§6 catalog as hash-chained records (§5) to append-only files, check their own chain at start and
daily, record time quality, log JSON with `--log-format json`, and toggle debug with `SIGUSR1`.
The receiver also sends its audit records to the SIEM with their own token and index. Nothing
crosses the link yet; that is Phase 2.

Run tests with `T` from the plan README ("Running tests on this machine").

---

### Task 1.1: Record format and chain verification

**Files:**
- Create: `wd2l/audit.py`
- Create: `tests/test_audit.py`

**Interfaces:**
- Produces:
  - `audit.GENESIS: str` (64 zeros), `audit.FILE_GLOB = "audit-*.jsonl"`
  - `audit.canonical(rec: dict) -> bytes`, `audit.sha256_hex(data: bytes) -> str`,
    `audit.record_hash(rec: dict) -> str`
  - `audit.utc_ts(t: float) -> str` (`2026-10-05T14:03:22.500000Z`), `audit.ts_epoch(ts: str) -> float`
  - `audit.split_lines(data: bytes) -> List[bytes]` (lines keep their `\n`; a last piece without
    one is a torn line)
  - `audit.VerifyResult` with `files, records, first_n, last_n, last_hash, problems, torn,
    unchained, ok, to_json()`
  - `audit.ChainChecker(result).add(where: str, rec: dict)`
  - `audit.verify_lines(files: Iterable[Tuple[str, List[bytes]]], upto=None, upto_hash=None) -> VerifyResult`
  - `audit.audit_files(directory) -> List[str]` (sorted), `audit.verify_dir(directory, upto=None, upto_hash=None) -> VerifyResult`
  - `python3 -m wd2l.audit verify DIR [--upto N] [--upto-hash H]` → JSON on stdout, exit 0 ok / 1 not

- [ ] **Step 1: Write the failing tests**

`tests/test_audit.py`:

```python
import hashlib
import json

import pytest

from wd2l import audit


def chain(n, start=1, prev=audit.GENESIS):
    """n records chained the way the writer chains them."""
    out = []
    for i in range(start, start + n):
        rec = {"event": "e%d" % i, "n": i, "prev_hash": prev, "ts": "2026-10-05T00:00:00.000000Z"}
        rec["hash"] = audit.record_hash(rec)
        prev = rec["hash"]
        out.append(rec)
    return out


def lines(recs):
    return [audit.canonical(r) + b"\n" for r in recs]


def test_canonical_is_sorted_compact_utf8():
    assert audit.canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode("utf-8")


def test_canonical_refuses_nan():
    with pytest.raises(ValueError):
        audit.canonical({"x": float("nan")})


def test_record_hash_covers_everything_but_the_hash():
    rec = {"n": 1, "prev_hash": audit.GENESIS, "event": "start"}
    want = hashlib.sha256(('{"event":"start","n":1,"prev_hash":"%s"}' % audit.GENESIS)
                          .encode()).hexdigest()
    assert audit.record_hash(rec) == want
    assert audit.record_hash(dict(rec, hash="f" * 64)) == want


def test_timestamps_are_utc_with_microseconds():
    assert audit.utc_ts(1791209002.5) == "2026-10-05T14:03:22.500000Z"
    assert audit.ts_epoch("2026-10-05T14:03:22.500000Z") == 1791209002.5


def test_split_lines_keeps_a_torn_last_piece():
    assert audit.split_lines(b"a\nb\nc") == [b"a\n", b"b\n", b"c"]
    assert audit.split_lines(b"a\n") == [b"a\n"]
    assert audit.split_lines(b"") == []


def test_good_chain_verifies():
    res = audit.verify_lines([("f", lines(chain(5)))])
    assert res.ok and res.records == 5 and (res.first_n, res.last_n) == (1, 5)
    assert res.to_json()["result"] == "ok"


def test_edited_record_is_detected():
    recs = chain(5)
    recs[2]["event"] = "tampered"
    res = audit.verify_lines([("f", lines(recs))])
    assert not res.ok and any("n=3" in p and "edited" in p for p in res.problems)


def test_removed_record_is_detected():
    recs = chain(5)
    del recs[2]
    res = audit.verify_lines([("f", lines(recs))])
    assert any("n jumps from 2 to 4" in p for p in res.problems)


def test_reordered_records_are_detected():
    recs = chain(5)
    recs[1], recs[2] = recs[2], recs[1]
    assert not audit.verify_lines([("f", lines(recs))]).ok


def test_relinked_forgery_is_detected_by_the_next_link():
    recs = chain(4)
    recs[1]["event"] = "forged"
    recs[1]["hash"] = audit.record_hash(recs[1])     # the forger recomputes its own hash
    res = audit.verify_lines([("f", lines(recs))])
    assert any("n=3 does not link to n=2" in p for p in res.problems)


def test_n1_must_start_from_genesis():
    recs = chain(2)
    recs[0]["prev_hash"] = "1" * 64
    recs[0]["hash"] = audit.record_hash(recs[0])
    assert any("genesis" in p for p in audit.verify_lines([("f", lines(recs))]).problems)


def test_chain_may_start_later_after_old_files_are_deleted():
    res = audit.verify_lines([("f", lines(chain(5)[2:]))])
    assert res.ok and res.first_n == 3


def test_torn_last_line_is_reported_not_a_break():
    first = chain(3)
    a = lines(first)
    a[-1] = a[-1][:20]                                  # crash or full disk mid-write
    b = lines(chain(2, start=3, prev=first[1]["hash"]))  # the writer resumes in a new file
    res = audit.verify_lines([("a", a), ("b", b)])
    assert res.ok and res.torn == ["a:3"] and res.last_n == 4


def test_unchained_records_are_counted_not_checked():
    recs = chain(2)
    recs.insert(1, {"event": "gap", "n": None, "prev_hash": None, "hash": None})
    res = audit.verify_lines([("f", lines(recs))])
    assert res.ok and res.unchained == 1


def test_junk_line_is_a_problem():
    res = audit.verify_lines([("f", [b"not json\n"] + lines(chain(1)))])
    assert any("f:1: not JSON" in p for p in res.problems)


def test_upto_stops_at_the_writers_position_and_catches_a_cut_tail():
    recs = chain(5)
    assert audit.verify_lines([("f", lines(recs))], upto=3, upto_hash=recs[2]["hash"]).ok
    cut = audit.verify_lines([("f", lines(recs[:2]))], upto=3)
    assert any("records cut from the end" in p for p in cut.problems)
    wrong = audit.verify_lines([("f", lines(recs))], upto=3, upto_hash="0" * 64)
    assert any("n=3 has hash" in p for p in wrong.problems)


def test_verify_dir_reads_files_in_name_order(tmp_path):
    recs = chain(4)
    (tmp_path / "audit-20261005T000000.000000Z.jsonl").write_bytes(b"".join(lines(recs[:2])))
    (tmp_path / "audit-20261005T010000.000000Z.jsonl").write_bytes(b"".join(lines(recs[2:])))
    (tmp_path / "other.jsonl").write_bytes(b"ignored\n")
    res = audit.verify_dir(str(tmp_path))
    assert res.ok and res.records == 4 and len(res.files) == 2


def test_verify_cli(tmp_path, capsys):
    (tmp_path / "audit-20261005T000000.000000Z.jsonl").write_bytes(b"".join(lines(chain(3))))
    assert audit.main(["verify", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "ok" and out["records"] == 3
    assert audit.main(["verify", str(tmp_path), "--upto", "9"]) == 1
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_audit.py -q`
Expected: collection error, `ModuleNotFoundError` / `ImportError` for `wd2l.audit`.

- [ ] **Step 3: Write the implementation**

`wd2l/audit.py`:

```python
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
        if record_hash(rec) != h:
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
            except ValueError:
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
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_audit.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/audit.py tests/test_audit.py
git commit -m "Audit records: canonical form, hash chain and verification" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.2: Host and process facts

**Files:**
- Create: `wd2l/hostinfo.py`
- Create: `tests/test_hostinfo.py`

**Interfaces:**
- Produces:
  - `hostinfo.PKG_DIR: str`, `hostinfo.hostname() -> str`
  - `hostinfo.actor(proc="/proc/self", uid=None, environ=None) -> str`
  - `hostinfo.signal_actor(pid: int, uid: int, proc_root="/proc") -> str`
  - `hostinfo.build_id(environ=None, pkg_dir=PKG_DIR) -> str`, `hostinfo.code_sha256(pkg_dir=PKG_DIR) -> str`
  - `hostinfo.parse_chronyc_tracking(text) -> {"stratum", "offset_ms", "synced", "source"}`
  - `hostinfo.time_alarm(q: dict, max_stratum=3, max_offset_ms=100.0) -> Optional[str]`
  - `hostinfo.TimeQuality(cmd=("chronyc","-c","tracking"), every=60.0, timeout=2.0, max_stratum=3, max_offset_ms=100.0, clock=time.monotonic)` with `.read() -> dict` and `.alarm(q=None) -> Optional[str]`
  - `hostinfo.ProcStats(clock=time.monotonic, statm="/proc/self/statm")` with `.read() -> {"cpu_pct", "rss_mb"}`

- [ ] **Step 1: Write the failing tests**

`tests/test_hostinfo.py`:

```python
import sys
import time

import pytest

from wd2l import hostinfo

SYNCED = ("A29FC87B,162.159.200.123,3,1791209000.123456789,0.000012345,-0.000001000,"
          "0.000020000,-12.345,-0.001,0.050,0.012345678,0.000987654,1024.5,Normal")
UNSYNCED = ("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,"
            "1.000000000,1.000000000,0.0,Not synchronised")


def prints(text):
    return [sys.executable, "-c", "print(%r)" % text]


def test_parse_synced_chronyc():
    assert hostinfo.parse_chronyc_tracking(SYNCED) == {
        "stratum": 3, "offset_ms": 0.012, "synced": True, "source": "162.159.200.123"}


def test_parse_unsynced_chronyc():
    q = hostinfo.parse_chronyc_tracking(UNSYNCED)
    assert q["synced"] is False and q["stratum"] == 0


def test_parse_rejects_other_output():
    with pytest.raises(ValueError):
        hostinfo.parse_chronyc_tracking("506 Cannot talk to daemon")


def test_time_quality_reads_then_caches_for_a_minute():
    t = [0.0]
    tq = hostinfo.TimeQuality(prints(SYNCED), clock=lambda: t[0])
    assert tq.read()["stratum"] == 3
    tq.cmd = prints(UNSYNCED)
    t[0] = 30
    assert tq.read()["synced"] is True
    t[0] = 61
    assert tq.read()["synced"] is False


def test_missing_or_hanging_chronyc_is_unavailable_not_fatal():
    assert hostinfo.TimeQuality(["/nonexistent/chronyc"]).read()["source"] == "unavailable"
    t0 = time.monotonic()
    q = hostinfo.TimeQuality([sys.executable, "-c", "import time; time.sleep(5)"],
                             timeout=0.3).read()
    assert q["synced"] is None and time.monotonic() - t0 < 3


@pytest.mark.parametrize("q, want", [
    ({"synced": None}, "unavailable"),
    ({"synced": False, "stratum": 0, "offset_ms": 0.0}, "unsynced"),
    ({"synced": True, "stratum": 4, "offset_ms": 0.1}, "stratum 4 > 3"),
    ({"synced": True, "stratum": 3, "offset_ms": -150.0}, "offset -150.0 ms > 100 ms"),
    ({"synced": True, "stratum": 3, "offset_ms": 0.2}, None),
])
def test_time_alarm(q, want):
    assert hostinfo.time_alarm(q) == want


def fake_proc(tmp_path, **files):
    d = tmp_path / "proc"
    d.mkdir()
    for name, text in files.items():
        (d / name).write_text(text)
    return str(d)


def test_actor_for_a_service(tmp_path):
    p = fake_proc(tmp_path, cgroup="0::/system.slice/wd2l-sender.service\n",
                  loginuid="4294967295")
    assert hostinfo.actor(p, uid=0, environ={}) == "uid=0(root) unit=wd2l-sender.service"


def test_actor_for_a_person_via_sudo(tmp_path):
    p = fake_proc(tmp_path, cgroup="0::/user.slice/user-0.slice/session-3.scope\n",
                  loginuid="0")
    assert hostinfo.actor(p, uid=0, environ={"SUDO_USER": "jdoe"}) == \
        "uid=0(root) auid=0(root) via sudo"


def test_signal_actor_while_the_sender_exists_and_after_it_is_gone(tmp_path):
    root = tmp_path / "proc"
    (root / "4242").mkdir(parents=True)
    (root / "4242" / "comm").write_text("kill\n")
    (root / "4242" / "loginuid").write_text("0")
    assert hostinfo.signal_actor(4242, 0, str(root)) == "uid=0(root) pid=4242 comm=kill auid=0(root)"
    assert hostinfo.signal_actor(4343, 0, str(root)) == "uid=0(root) pid=4343"


def test_build_id_prefers_the_environment_then_the_build_file(tmp_path):
    assert hostinfo.build_id({"WD2L_BUILD": "abc"}, str(tmp_path)) == "abc"
    assert hostinfo.build_id({}, str(tmp_path)) == "unknown"
    (tmp_path / "BUILD").write_text("0123456789abcdef\n")
    assert hostinfo.build_id({}, str(tmp_path)) == "0123456789abcdef"


def test_code_hash_changes_with_the_code(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "notes.txt").write_text("not code")
    h1 = hostinfo.code_sha256(str(tmp_path))
    (tmp_path / "notes.txt").write_text("still not code")
    assert hostinfo.code_sha256(str(tmp_path)) == h1
    (tmp_path / "a.py").write_text("x = 2\n")
    assert hostinfo.code_sha256(str(tmp_path)) != h1


def test_proc_stats():
    ps = hostinfo.ProcStats()
    sum(range(10 ** 6))
    r = ps.read()
    assert r["cpu_pct"] >= 0 and r["rss_mb"] > 1
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_hostinfo.py -q`
Expected: `ModuleNotFoundError: No module named 'wd2l.hostinfo'`.

- [ ] **Step 3: Write the implementation**

`wd2l/hostinfo.py`:

```python
"""Facts about this host and process for audit and health records: who runs us or signals us,
which build, chrony's view of the clock, and CPU and memory. Anything that can't be read comes
back as None or "unavailable"; nothing here raises."""

from __future__ import annotations

import hashlib
import os
import pwd
import resource
import socket
import subprocess
import time
from typing import Any, Callable, Dict, Optional, Sequence

UNSET_AUID = 4294967295
PKG_DIR = os.path.dirname(os.path.abspath(__file__))
LEAP_UNSYNCED = "Not synchronised"


def hostname() -> str:
    return socket.gethostname()


def _read(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        return None


def _user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return "?"


def loginuid(proc: str = "/proc/self") -> Optional[int]:
    """The audit login uid (auid): who logged in, kept across sudo. None when unset (services)."""
    v = _read(os.path.join(proc, "loginuid"))
    if v is None or not v.isdigit() or int(v) == UNSET_AUID:
        return None
    return int(v)


def systemd_unit(proc: str = "/proc/self") -> Optional[str]:
    for line in (_read(os.path.join(proc, "cgroup")) or "").splitlines():
        last = line.rsplit("/", 1)[-1]
        if last.endswith(".service"):
            return last
    return None


def actor(proc: str = "/proc/self", uid: Optional[int] = None,
          environ: Optional[Dict[str, str]] = None) -> str:
    """Who runs this process: "uid=987(wd2l) unit=wd2l-sender.service", or
    "uid=987(wd2l) auid=1001(jdoe) via sudo" when a person started it."""
    uid = os.getuid() if uid is None else uid
    env = os.environ if environ is None else environ
    parts = ["uid=%d(%s)" % (uid, _user(uid))]
    auid = loginuid(proc)
    if auid is not None:
        parts.append("auid=%d(%s)" % (auid, _user(auid)))
    unit = systemd_unit(proc)
    if unit:
        parts.append("unit=" + unit)
    if env.get("SUDO_USER"):
        parts.append("via sudo")
    return " ".join(parts)


def signal_actor(pid: int, uid: int, proc_root: str = "/proc") -> str:
    """Who sent a signal (from sigwaitinfo): "uid=0(root) pid=4242 comm=kill auid=1001(jdoe)".
    The sending process is often gone already; then only uid and pid are known."""
    parts = ["uid=%d(%s)" % (uid, _user(uid)), "pid=%d" % pid]
    base = os.path.join(proc_root, str(pid))
    comm = _read(os.path.join(base, "comm"))
    if comm:
        parts.append("comm=" + comm)
    auid = loginuid(base)
    if auid is not None:
        parts.append("auid=%d(%s)" % (auid, _user(auid)))
    return " ".join(parts)


def build_id(environ: Optional[Dict[str, str]] = None, pkg_dir: str = PKG_DIR) -> str:
    """The build (git commit): $WD2L_BUILD, else the BUILD file the install step writes next to
    the code, else "unknown"."""
    env = os.environ if environ is None else environ
    return env.get("WD2L_BUILD") or _read(os.path.join(pkg_dir, "BUILD")) or "unknown"


def code_sha256(pkg_dir: str = PKG_DIR) -> str:
    """One SHA-256 over the package's .py files (names and contents): which code is running."""
    h = hashlib.sha256()
    for name in sorted(os.listdir(pkg_dir)):
        if name.endswith(".py"):
            with open(os.path.join(pkg_dir, name), "rb") as f:
                h.update(name.encode() + b"\0" + hashlib.sha256(f.read()).digest())
    return h.hexdigest()


# ---------------------------------------------------------------- time quality (chrony)

def parse_chronyc_tracking(text: str) -> Dict[str, Any]:
    """`chronyc -c tracking`, one CSV line: reference id, reference name, stratum, reference
    time, system time offset (s), last offset, RMS offset, frequency, residual frequency, skew,
    root delay, root dispersion, update interval, leap status."""
    f = text.strip().split(",")
    if len(f) < 14:
        raise ValueError("unexpected chronyc output: %r" % text[:200])
    stratum = int(f[2])
    synced = f[13] != LEAP_UNSYNCED and 0 < stratum < 16 and f[0].strip("0") != ""
    return {"stratum": stratum, "offset_ms": round(float(f[4]) * 1000.0, 3), "synced": synced,
            "source": f[1] or f[0]}


def time_alarm(q: Dict[str, Any], max_stratum: int = 3,
               max_offset_ms: float = 100.0) -> Optional[str]:
    """Why time quality is out of bounds (§11), or None when it is fine."""
    if q.get("synced") is None:
        return "unavailable"
    if not q["synced"]:
        return "unsynced"
    if q["stratum"] > max_stratum:
        return "stratum %d > %d" % (q["stratum"], max_stratum)
    if abs(q["offset_ms"]) > max_offset_ms:
        return "offset %.1f ms > %g ms" % (q["offset_ms"], max_offset_ms)
    return None


class TimeQuality:
    """chrony's view of this host's clock, read at most every `every` seconds."""

    def __init__(self, cmd: Sequence[str] = ("chronyc", "-c", "tracking"), every: float = 60.0,
                 timeout: float = 2.0, max_stratum: int = 3, max_offset_ms: float = 100.0,
                 clock: Callable[[], float] = time.monotonic):
        self.cmd = list(cmd)
        self.every = every
        self.timeout = timeout
        self.max_stratum = max_stratum
        self.max_offset_ms = max_offset_ms
        self.clock = clock
        self._at: Optional[float] = None
        self._last: Dict[str, Any] = {}

    def read(self) -> Dict[str, Any]:
        now = self.clock()
        if self._at is None or now - self._at >= self.every:
            self._at = now
            try:
                out = subprocess.run(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=self.timeout, check=True).stdout
                self._last = parse_chronyc_tracking(out.decode("utf-8", "replace"))
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                self._last = {"synced": None, "source": "unavailable", "error": str(e)[:200]}
        return dict(self._last)

    def alarm(self, q: Optional[Dict[str, Any]] = None) -> Optional[str]:
        return time_alarm(self.read() if q is None else q, self.max_stratum, self.max_offset_ms)


# ---------------------------------------------------------------- this process

class ProcStats:
    """This process's CPU % since the previous read() (all threads) and its resident memory."""

    def __init__(self, clock: Callable[[], float] = time.monotonic,
                 statm: str = "/proc/self/statm"):
        self.clock = clock
        self.statm = statm
        self._t = clock()
        self._cpu = self._cpu_s()

    @staticmethod
    def _cpu_s() -> float:
        r = resource.getrusage(resource.RUSAGE_SELF)
        return r.ru_utime + r.ru_stime

    def read(self) -> Dict[str, Any]:
        now, cpu = self.clock(), self._cpu_s()
        dt = now - self._t
        pct = round(100.0 * (cpu - self._cpu) / dt, 1) if dt > 0 else 0.0
        self._t, self._cpu = now, cpu
        rss = None
        v = _read(self.statm)
        if v:
            rss = round(int(v.split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576.0, 1)
        return {"cpu_pct": pct, "rss_mb": rss}
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_hostinfo.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/hostinfo.py tests/test_hostinfo.py
git commit -m "Host facts for audit and health: actor, build, chrony time quality, CPU and memory" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.3: The audit writer

**Files:**
- Modify: `wd2l/audit.py` (add imports, constants, `AuditLocked`, `AuditLog`, helpers)
- Modify: `tests/test_audit.py` (append)
- Modify: `tests/helpers.py` (add `read_audit`)

**Interfaces:**
- Consumes: Task 1.1 functions; `hostinfo.hostname/actor/build_id/PKG_DIR`, `hostinfo.TimeQuality` (duck-typed: `read()`, `alarm()`).
- Produces:
  - `audit.AuditLocked(RuntimeError)`
  - `audit.AuditLog(directory, component, enclave, *, segment=None, host=None, actor=None, build=None, time_quality=None, forward=True, max_bytes=64 MiB, min_free_bytes=256 MiB, outbox_max=10000, clock=time.time)`
    - `.write(event, outcome="info", **fields) -> dict` (`outcome` in `success|failure|info`; `None` fields left out; `fields` may override `segment` and `actor`)
    - `.take_outbox() -> List[dict]`, `.status() -> {"audit_ok", "audit_n", "audit_hash",
      "audit_verify"}` (`audit_verify`: `"ok"`, `"failed"` or `None` before the first self-check;
      health records carry it so operators, who can't read the audit index, see the self-check)
    - `.check_time()`, `.check_space()`, `.start_verify()`, `.poll_verify(wait=False) -> Optional[dict]`, `.maybe_verify(every=86400.0)`, `.close()`
    - attributes `dir, host, component, n, last_hash, ok, missed, outbox_dropped`
  - `audit.HOME_SEGMENT = {"sender": "e1-sender", "receiver": "e2-receiver", "replay": "e2-receiver"}`
  - `helpers.read_audit(directory) -> List[dict]` (all records on disk, oldest first, torn lines skipped)

- [ ] **Step 1: Add the test helper**

Append to `tests/helpers.py`:

```python
def read_audit(directory):
    """Every audit record on disk in this directory, oldest first (torn lines skipped)."""
    import json as _json
    from wd2l import audit as _audit
    out = []
    for path in _audit.audit_files(str(directory)):
        with open(path, "rb") as f:
            for line in _audit.split_lines(f.read()):
                if line.endswith(b"\n"):
                    out.append(_json.loads(line))
    return out
```

- [ ] **Step 2: Write the failing tests**

Append to `tests/test_audit.py`:

```python
import collections
import errno
import os
import re

import wd2l
from wd2l import hostinfo

from helpers import read_audit

Usage = collections.namedtuple("Usage", "total used free")


def new_log(tmp_path, **kw):
    kw.setdefault("host", "logsrv01")
    kw.setdefault("actor", "uid=987(wd2l) unit=wd2l-sender.service")
    kw.setdefault("build", "abc123")
    return audit.AuditLog(str(tmp_path / "a"), "sender", 1, **kw)


class FakeTQ:
    def __init__(self):
        self.q = {"stratum": 3, "offset_ms": 0.2, "synced": True, "source": "gps"}

    def read(self):
        return dict(self.q)

    def alarm(self, q=None):
        return hostinfo.time_alarm(self.read() if q is None else q)


def test_records_carry_the_common_fields_and_chain(tmp_path):
    a = new_log(tmp_path, clock=lambda: 1791209002.5, time_quality=FakeTQ())
    r1 = a.write("start", "success", pid=42, absent=None)
    r2 = a.write("config", settings={"listen": "127.0.0.1:10070"})
    assert r1["ts"] == "2026-10-05T14:03:22.500000Z"
    assert {k: r1[k] for k in ("host", "enclave", "component", "segment", "version", "build",
                               "event", "outcome", "actor", "pid")} == {
        "host": "logsrv01", "enclave": 1, "component": "sender", "segment": "e1-sender",
        "version": wd2l.__version__, "build": "abc123", "event": "start", "outcome": "success",
        "actor": "uid=987(wd2l) unit=wd2l-sender.service", "pid": 42}
    assert r1["time_quality"] == {"stratum": 3, "offset_ms": 0.2, "synced": True, "source": "gps"}
    assert "absent" not in r1
    assert (r1["n"], r1["prev_hash"], r2["n"], r2["prev_hash"]) == (1, audit.GENESIS, 2, r1["hash"])
    assert read_audit(tmp_path / "a") == [r1, r2]
    a.close()
    assert audit.verify_dir(str(tmp_path / "a")).ok


def test_one_canonical_line_per_record_in_a_0640_file(tmp_path):
    a = new_log(tmp_path)
    r = a.write("start", "success")
    [path] = audit.audit_files(a.dir)
    assert re.fullmatch(r"audit-\d{8}T\d{6}\.\d{6}Z\.jsonl", os.path.basename(path))
    assert os.stat(path).st_mode & 0o777 == 0o640
    with open(path, "rb") as f:
        assert f.read() == audit.canonical(r) + b"\n"


def test_bad_outcome_is_refused(tmp_path):
    with pytest.raises(ValueError):
        new_log(tmp_path).write("start", "maybe")


def test_restart_continues_the_chain_in_the_same_file(tmp_path):
    a = new_log(tmp_path)
    r1 = a.write("start", "success")
    a.close()
    b = new_log(tmp_path)
    r2 = b.write("start", "success")
    assert (r2["n"], r2["prev_hash"]) == (2, r1["hash"])
    assert len(audit.audit_files(b.dir)) == 1


def test_a_full_file_continues_the_chain_in_a_new_file(tmp_path):
    a = new_log(tmp_path, max_bytes=900)
    for i in range(6):
        a.write("gap", "failure", count=i)
    files = audit.audit_files(a.dir)
    assert len(files) >= 2 and all(os.path.getsize(f) <= 900 for f in files)
    res = audit.verify_dir(a.dir)
    assert res.ok and res.records == 6


def test_new_files_sort_after_old_ones_even_if_the_clock_goes_back(tmp_path):
    t = [1791209002.5]
    a = new_log(tmp_path, max_bytes=500, clock=lambda: t[0])
    a.write("start", "success")
    t[0] -= 3600
    for _ in range(3):
        a.write("gap", "failure")
    assert audit.verify_dir(a.dir).ok


def test_a_second_writer_is_locked_out(tmp_path):
    a = new_log(tmp_path)
    with pytest.raises(audit.AuditLocked, match="in use by another wd2l process"):
        new_log(tmp_path)
    a.close()
    new_log(tmp_path).close()


def test_torn_last_line_starts_a_new_file_and_is_recorded(tmp_path):
    a = new_log(tmp_path)
    r1 = a.write("start", "success")
    a.close()
    [path] = audit.audit_files(str(tmp_path / "a"))
    with open(path, "ab") as f:
        f.write(b'{"event":"gap","n":2,"pre')          # power lost mid-write
    b = new_log(tmp_path)
    note = read_audit(tmp_path / "a")[-1]
    assert note["event"] == "audit_failure" and note["reason"] == "torn_write"
    assert (note["n"], note["prev_hash"]) == (2, r1["hash"])
    assert len(audit.audit_files(b.dir)) == 2
    res = audit.verify_dir(b.dir)
    assert res.ok and len(res.torn) == 1


def test_write_failure_keeps_going_and_chain_still_verifies(tmp_path):
    """Review focus 1: a full disk must not stop anything or break the chain."""
    a = new_log(tmp_path)
    a.write("start", "success")
    real = a._write

    def full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")
    a._write = full
    r2 = a.write("gap", "failure", count=3)
    r3 = a.write("gap", "failure", count=4)
    assert r2["n"] is None and r2["hash"] is None and r3["n"] is None
    assert a.status()["audit_ok"] is False and a.missed == 2
    a._write = real
    r4 = a.write("stop", "success")
    assert a.ok and r4["n"] == 3
    on_disk = read_audit(tmp_path / "a")
    assert [r["event"] for r in on_disk] == ["start", "audit_failure", "stop"]
    assert on_disk[1]["reason"] == "recovered" and on_disk[1]["missed"] == 2
    assert [(r["event"], r.get("reason")) for r in a.take_outbox()] == [
        ("start", None), ("audit_failure", "write_failed"), ("gap", None), ("gap", None),
        ("audit_failure", "recovered"), ("stop", None)]
    assert audit.verify_dir(a.dir).ok


def test_a_short_write_moves_on_to_a_new_file(tmp_path):
    a = new_log(tmp_path)
    a.write("start", "success")
    real = a._write
    a._write = lambda fd, data: real(fd, data[:10])     # the disk filled part way
    assert a.write("gap", "failure")["n"] is None
    a._write = real
    a.write("stop", "success")
    res = audit.verify_dir(a.dir)
    assert res.ok and len(res.torn) == 1 and res.last_n == 3
    assert len(audit.audit_files(a.dir)) == 2


def test_fsync_failure_keeps_the_record_but_flags_the_trail(tmp_path):
    a = new_log(tmp_path)

    def bad_fsync(fd):
        raise OSError(errno.EIO, "I/O error")
    a._fsync = bad_fsync
    assert a.write("start", "success")["n"] == 1
    assert not a.ok
    a._fsync = os.fsync
    a.write("stop", "success")
    assert [r["event"] for r in read_audit(a.dir)] == ["start", "audit_failure", "stop"]
    assert a.ok


def test_outbox_is_bounded_and_off_when_not_forwarding(tmp_path):
    a = new_log(tmp_path, outbox_max=2)
    for _ in range(3):
        a.write("gap", "failure")
    assert len(a.take_outbox()) == 2 and a.outbox_dropped == 1 and a.take_outbox() == []
    a.close()
    b = new_log(tmp_path, forward=False)
    b.write("gap", "failure")
    assert b.take_outbox() == []


def test_low_space_is_reported_once_and_clears(tmp_path):
    a = new_log(tmp_path, min_free_bytes=1000)
    free = [10 ** 9]
    a._disk_usage = lambda path: Usage(0, 0, free[0])
    a.check_space()
    free[0] = 10
    a.check_space()
    a.check_space()
    assert a.status()["audit_ok"] is False
    free[0] = 10 ** 9
    a.check_space()
    notes = [(r["reason"], r["outcome"]) for r in read_audit(a.dir) if r["event"] == "audit_failure"]
    assert notes == [("low_space", "failure"), ("space_ok", "info")]
    assert a.status()["audit_ok"] is True


def test_time_quality_is_recorded_first_and_on_each_change(tmp_path):
    tq = FakeTQ()
    a = new_log(tmp_path, time_quality=tq)
    a.check_time()
    a.check_time()
    tq.q = {"stratum": 0, "offset_ms": 0.0, "synced": False, "source": ""}
    a.check_time()
    got = [(r["outcome"], r["reason"]) for r in read_audit(a.dir) if r["event"] == "time_quality"]
    assert got == [("success", "ok"), ("failure", "unsynced")]


def test_self_check_passes_on_a_good_chain(tmp_path):
    a = new_log(tmp_path)
    for e in ("start", "config", "state_loaded"):
        a.write(e)
    assert a.status()["audit_verify"] is None
    a.start_verify()
    res = a.poll_verify(wait=True)
    assert res["result"] == "ok" and a.status()["audit_verify"] == "ok"
    last = read_audit(a.dir)[-1]
    assert (last["event"], last["outcome"], last["records"], last["upto"]) == \
        ("audit_verify", "success", 3, 3)


def test_self_check_fails_on_an_edited_file(tmp_path):
    a = new_log(tmp_path)
    for e in ("start", "config", "stop"):
        a.write(e)
    a.close()
    [path] = audit.audit_files(str(tmp_path / "a"))
    with open(path, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:
        f.write(data.replace(b'"event":"config"', b'"event":"c0nfig"'))
    b = new_log(tmp_path)
    b.start_verify()
    assert b.poll_verify(wait=True)["result"] == "failed"
    assert b.status()["audit_verify"] == "failed"
    last = read_audit(b.dir)[-1]
    assert last["event"] == "audit_verify" and last["outcome"] == "failure"
    assert any("edited" in p for p in last["problems"])


def test_self_check_runs_at_start_then_daily(tmp_path):
    t = [1000.0]
    a = new_log(tmp_path, clock=lambda: t[0])
    a.write("start", "success")
    a.maybe_verify()
    assert a.verify_proc is not None
    a.poll_verify(wait=True)
    t[0] += 3600
    a.maybe_verify()
    assert a.verify_proc is None
    t[0] += 86400
    a.maybe_verify()
    assert a.verify_proc is not None
    a.close()
```

- [ ] **Step 3: Run them to see them fail**

Run: `T tests/test_audit.py -q`
Expected: the new tests fail with `AttributeError: module 'wd2l.audit' has no attribute 'AuditLog'`; Task 1.1's tests still pass.

- [ ] **Step 4: Write the implementation**

In `wd2l/audit.py`, replace the import block with:

```python
from __future__ import annotations

import argparse
import calendar
import errno
import fcntl
import glob
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__, hostinfo

log = logging.getLogger("wd2l.audit")
```

After `FILE_GLOB = ...` add:

```python
DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MIN_FREE = 256 * 1024 * 1024
TAIL_BYTES = 1024 * 1024
OUTCOMES = ("success", "failure", "info")
HOME_SEGMENT = {"sender": "e1-sender", "receiver": "e2-receiver", "replay": "e2-receiver"}
_UNSET = object()
```

Before `def main(` add:

```python
# ---------------------------------------------------------------- writing

class AuditLocked(RuntimeError):
    """Another process is writing to this audit directory."""


def _file_us(path: str) -> int:
    """Start time in microseconds from a name like audit-20261005T140322.418213Z.jsonl."""
    stamp = os.path.basename(path)[len("audit-"):-len("Z.jsonl")]
    try:
        secs = calendar.timegm(time.strptime(stamp[:15], "%Y%m%dT%H%M%S"))
        return secs * 1000000 + int(stamp[16:22])
    except ValueError:
        return 0


def _last_record(path: str) -> Tuple[Optional[Dict[str, Any]], bool]:
    """(last complete record, whether the file ends in a torn line)."""
    with open(path, "rb") as f:
        f.seek(0, os.SEEK_END)
        f.seek(max(0, f.tell() - TAIL_BYTES))
        tail = f.read()
    torn = bool(tail) and not tail.endswith(b"\n")
    for line in reversed(tail.split(b"\n")[:-1]):
        try:
            rec = json.loads(line)
        except ValueError:
            continue    # the first line of the tail may be cut off by the seek
        if isinstance(rec, dict) and isinstance(rec.get("n"), int) and isinstance(rec.get("hash"), str):
            return rec, torn
    return None, torn


class AuditLog:
    """This process's audit trail: <directory>/audit-<UTC start>.jsonl, hash-chained (§10).

    * One record is one write() and one fsync(). Files are only ever appended to. Past
      max_bytes the next record starts a new file and the chain carries on. Nothing is renamed
      or truncated, so no log rotation tool is involved.
    * A lock file keeps a second writer out, e.g. an archive replay while the live receiver runs.
    * If a write fails (disk full, I/O error) the transfer keeps going: the record is still
      queued for forwarding, with n/prev_hash/hash null; `ok` turns False (health shows
      audit_ok=false); the first record written afterwards is an audit_failure saying how many
      records the file missed. After a short write (a partial line on disk) writing resumes in a
      new file, so nothing is ever appended to a partial line.
    * Every record also goes to `outbox`, for the owner to forward (in-band, or to the SIEM).
    """

    def __init__(self, directory: str, component: str, enclave: int, *,
                 segment: Optional[str] = None, host: Optional[str] = None,
                 actor: Optional[str] = None, build: Optional[str] = None,
                 time_quality: Optional[Any] = None, forward: bool = True,
                 max_bytes: int = DEFAULT_MAX_BYTES, min_free_bytes: int = DEFAULT_MIN_FREE,
                 outbox_max: int = 10000, clock: Callable[[], float] = time.time):
        os.makedirs(directory, exist_ok=True)
        self.dir = directory
        self.component = component
        self.enclave = enclave
        self.segment = segment or HOME_SEGMENT.get(component, component)
        self.host = host or hostinfo.hostname()
        self.actor = actor or hostinfo.actor()
        self.build = build or hostinfo.build_id()
        self.tq = time_quality
        self.forward = forward
        self.max_bytes = max_bytes
        self.min_free = min_free_bytes
        self.outbox_max = outbox_max
        self.clock = clock
        self._write, self._fsync, self._disk_usage = os.write, os.fsync, shutil.disk_usage
        self.lock = threading.Lock()
        self.outbox: Deque[Dict[str, Any]] = deque()
        self.outbox_dropped = 0
        self.ok = True
        self.error: Optional[str] = None
        self.missed = 0
        self.low_space = False
        self.time_state: Any = _UNSET
        self.verify_proc: Optional[subprocess.Popen] = None
        self.verify_result: Optional[str] = None
        self.verify_upto = 0
        self.last_verify: Optional[float] = None
        self.fd: Optional[int] = None
        self.path: Optional[str] = None
        self.size = 0
        self.last_file_us = 0
        self._lockfd: Optional[int] = self._take_lock()
        self.n, self.last_hash, torn = self._recover()
        if torn:
            self.write("audit_failure", "failure", reason="torn_write", file=torn)

    # -- setup

    def _take_lock(self) -> int:
        fd = os.open(os.path.join(self.dir, ".lock"), os.O_RDWR | os.O_CREAT, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            raise AuditLocked("audit directory %s is in use by another wd2l process (stop "
                              "wd2l-receiver before an archive replay)" % self.dir)
        return fd

    def _recover(self) -> Tuple[int, str, Optional[str]]:
        """Where the chain stands: the last complete record of the newest file holding one. The
        newest file is appended to unless it ends in a torn line or is full."""
        files = audit_files(self.dir)
        if files:
            self.last_file_us = _file_us(files[-1])
        torn = None
        for i, path in enumerate(reversed(files)):
            rec, is_torn = _last_record(path)
            if i == 0:
                if is_torn:
                    torn = os.path.basename(path)
                elif os.path.getsize(path) < self.max_bytes:
                    self.fd = os.open(path, os.O_WRONLY | os.O_APPEND)
                    self.path, self.size = path, os.path.getsize(path)
            if rec is not None:
                return rec["n"], rec["hash"], torn
        return 0, GENESIS, torn

    # -- writing

    def _base(self, event: str, outcome: str) -> Dict[str, Any]:
        rec: Dict[str, Any] = {
            "ts": utc_ts(self.clock()), "host": self.host, "enclave": self.enclave,
            "component": self.component, "segment": self.segment, "version": __version__,
            "build": self.build, "event": event, "outcome": outcome, "actor": self.actor}
        if self.tq is not None:
            rec["time_quality"] = self.tq.read()
        return rec

    def write(self, event: str, outcome: str = "info", **fields: Any) -> Dict[str, Any]:
        """Write one record (the common fields plus `fields`; None values are left out), queue
        it for forwarding, and return it."""
        if outcome not in OUTCOMES:
            raise ValueError("outcome must be one of %s" % (OUTCOMES,))
        with self.lock:
            rec = self._base(event, outcome)
            rec.update((k, v) for k, v in fields.items() if v is not None)
            if not self.ok:
                note = self._base("audit_failure", "info")
                note.update(reason="recovered", error=self.error, missed=self.missed)
                if self._append(note):
                    log.warning("audit file writable again; %d records exist only in forwarded "
                                "copies", self.missed)
                    self.ok, self.error, self.missed = True, None, 0
                    self._queue(note)
            if not self._append(rec):
                self.missed += 1
            self._queue(rec)
            return rec

    def _append(self, rec: Dict[str, Any]) -> bool:
        """Chain the record and append it to the file. Returns False if it isn't in the file."""
        rec["n"], rec["prev_hash"] = self.n + 1, self.last_hash
        rec["hash"] = record_hash(rec)
        line = canonical(rec) + b"\n"
        try:
            if self.fd is None or (self.size and self.size + len(line) > self.max_bytes):
                self._new_file()
            written = self._write(self.fd, line)
        except OSError as e:
            return self._failed(rec, e)
        if written != len(line):
            self._close_file()      # a partial line is on disk: never append after it
            return self._failed(rec, OSError(errno.EIO, "short write: %d of %d bytes"
                                             % (written, len(line))))
        self.n, self.last_hash = rec["n"], rec["hash"]
        self.size += len(line)
        try:
            self._fsync(self.fd)
        except OSError as e:
            self._failed(None, e)   # the line is written but may not be on disk
        return True

    def _failed(self, rec: Optional[Dict[str, Any]], e: OSError) -> bool:
        if rec is not None:
            rec["n"] = rec["prev_hash"] = rec["hash"] = None
        if self.ok:
            self.ok, self.error = False, str(e)
            log.error("audit file write failed (%s); the transfer continues and records are "
                      "still forwarded", e)
            fail = self._base("audit_failure", "failure")
            fail.update(reason="write_failed", error=str(e), n=None, prev_hash=None, hash=None)
            self._queue(fail)
        return False

    def _new_file(self) -> None:
        self._close_file()
        us = max(int(self.clock() * 1e6), self.last_file_us + 1)
        while True:
            name = "audit-%s.%06dZ.jsonl" % (
                datetime.fromtimestamp(us // 1000000, timezone.utc).strftime("%Y%m%dT%H%M%S"),
                us % 1000000)
            path = os.path.join(self.dir, name)
            try:
                self.fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL, 0o640)
                break
            except FileExistsError:
                us += 1
        os.chmod(path, 0o640)   # whatever the umask
        self.path, self.size, self.last_file_us = path, 0, us

    def _close_file(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    def _queue(self, rec: Dict[str, Any]) -> None:
        if not self.forward:
            return
        if len(self.outbox) >= self.outbox_max:
            self.outbox.popleft()
            self.outbox_dropped += 1
        self.outbox.append(rec)

    def take_outbox(self) -> List[Dict[str, Any]]:
        with self.lock:
            out = list(self.outbox)
            self.outbox.clear()
        return out

    def status(self) -> Dict[str, Any]:
        """For health records: is the trail being written, and where does the chain stand."""
        with self.lock:
            return {"audit_ok": self.ok and not self.low_space, "audit_n": self.n,
                    "audit_hash": self.last_hash, "audit_verify": self.verify_result}

    # -- checks the owner calls about once a minute

    def check_time(self) -> None:
        """A time_quality record at the first call, then whenever the alarm state changes."""
        if self.tq is None:
            return
        alarm = self.tq.alarm()
        if alarm != self.time_state:
            self.time_state = alarm
            self.write("time_quality", "failure" if alarm else "success", reason=alarm or "ok")

    def check_space(self) -> None:
        try:
            free = self._disk_usage(self.dir).free
        except OSError:
            return
        low = free < self.min_free
        if low != self.low_space:
            self.low_space = low
            if low:
                log.error("audit directory %s: %d bytes free, below %d", self.dir, free, self.min_free)
                self.write("audit_failure", "failure", reason="low_space", free_bytes=free,
                           min_free_bytes=self.min_free)
            else:
                self.write("audit_failure", "info", reason="space_ok", free_bytes=free)

    def start_verify(self) -> None:
        """Check the chain in a child process (`python3 -m wd2l.audit verify`), up to where it
        stands now. A child keeps the capture loop's interpreter free."""
        if self.verify_proc is not None:
            return
        with self.lock:
            n, h = self.n, self.last_hash
        self.last_verify = self.clock()
        if n == 0:
            return
        env = dict(os.environ)
        root = os.path.dirname(hostinfo.PKG_DIR)
        env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        self.verify_upto = n
        self.verify_proc = subprocess.Popen(
            [sys.executable, "-m", "wd2l.audit", "verify", self.dir, "--upto", str(n),
             "--upto-hash", h], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)

    def poll_verify(self, wait: bool = False) -> Optional[Dict[str, Any]]:
        """Collect a finished self-check and record it as audit_verify."""
        p = self.verify_proc
        if p is None or (not wait and p.poll() is None):
            return None
        out, err = p.communicate()
        self.verify_proc = None
        try:
            res = json.loads(out)
        except ValueError:
            res = {"result": "failed", "files": [], "problems": [
                "verifier failed: %s" % err.decode("utf-8", "replace")[-300:]]}
        ok = res.get("result") == "ok"
        self.verify_result = "ok" if ok else "failed"
        if not ok:
            log.error("audit chain self-check failed: %s", res.get("problems", [])[:3])
        self.write("audit_verify", "success" if ok else "failure", upto=self.verify_upto,
                   files=len(res.get("files", [])), records=res.get("records"),
                   first_n=res.get("first_n"), torn=res.get("torn") or None,
                   problems=res.get("problems", [])[:10] or None)
        return res

    def maybe_verify(self, every: float = 86400.0) -> None:
        """Collect a finished self-check; start one at the first call and then once a day."""
        self.poll_verify()
        if self.verify_proc is None and (self.last_verify is None
                                         or self.clock() - self.last_verify >= every):
            self.start_verify()

    def close(self) -> None:
        with self.lock:
            p = self.verify_proc
            if p is not None and p.poll() is None:
                p.terminate()
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
            self.verify_proc = None
            self._close_file()
            if self._lockfd is not None:
                os.close(self._lockfd)
                self._lockfd = None
```

- [ ] **Step 5: Run the tests**

Run: `T tests/test_audit.py -q`
Expected: all pass. If `test_one_canonical_line_per_record_in_a_0640_file` fails on the mode,
check that `_new_file` calls `os.chmod` (the container's umask may differ).

- [ ] **Step 6: Commit**

```bash
git add wd2l/audit.py tests/test_audit.py tests/helpers.py
git commit -m "Audit writer: append-only files, lock, rotation, failure handling, self-check" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.4: Per-minute summaries for frequent events

**Files:**
- Modify: `wd2l/audit.py` (add `Summarizer`, `MIN_FIELDS`)
- Modify: `tests/test_audit.py` (append)

**Interfaces:**
- Produces: `audit.Summarizer(max_keys=100)` with `.note(event, key=None, count=1, **values)` and
  `.drain() -> List[Tuple[str, dict]]`. Values: numbers keep the maximum, except names in
  `audit.MIN_FIELDS = {"seq_first"}`, which keep the minimum; strings are collected into a sorted
  list. Past `max_keys` keys for one event, further keys go to one `{"overflow": True}` bucket.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_audit.py`:

```python
import threading


def test_summarizer_counts_per_key_and_keeps_extremes():
    s = audit.Summarizer()
    s.note("truncated", {"host": "h1", "source": "s"}, max_original_bytes=300000)
    s.note("truncated", {"host": "h1", "source": "s"}, max_original_bytes=900000)
    s.note("truncated", {"host": "h2", "source": "s"}, max_original_bytes=1)
    s.note("opaque_content", {"host": "h1", "source": "s"}, kinds="encrypted")
    s.note("opaque_content", {"host": "h1", "source": "s"}, kinds="compressed")
    s.note("gap_filled", {"stream": "ab"}, seq_first=9, seq_last=9)
    s.note("gap_filled", {"stream": "ab"}, seq_first=4, seq_last=4)
    got = s.drain()
    assert ("truncated", {"host": "h1", "source": "s", "count": 2,
                          "max_original_bytes": 900000}) in got
    assert ("opaque_content", {"host": "h1", "source": "s", "count": 2,
                               "kinds": ["compressed", "encrypted"]}) in got
    assert ("gap_filled", {"stream": "ab", "count": 2, "seq_first": 4, "seq_last": 9}) in got
    assert len(got) == 4 and s.drain() == []


def test_summarizer_caps_keys_per_event():
    s = audit.Summarizer(max_keys=2)
    for i in range(5):
        s.note("auth_failure", {"client": "10.0.0.%d" % i})
    got = dict((tuple(sorted(f.items())), e) for e, f in s.drain())
    assert (("count", 3), ("overflow", True)) in got and len(got) == 3


def test_summarizer_is_thread_safe():
    s = audit.Summarizer()

    def worker():
        for _ in range(1000):
            s.note("send_failure", {"error": "ENOBUFS"})
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert s.drain() == [("send_failure", {"error": "ENOBUFS", "count": 4000})]
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_audit.py -q -k summarizer`
Expected: `AttributeError: module 'wd2l.audit' has no attribute 'Summarizer'`.

- [ ] **Step 3: Write the implementation**

In `wd2l/audit.py`, after `_UNSET = object()` add `MIN_FIELDS = {"seq_first"}`, and before the
`# ---- writing` comment add:

```python
class Summarizer:
    """Counts frequent events (bad input, truncation, send errors, gap fills...) so the owner
    writes one audit record per event and key a minute instead of one per occurrence (§6)."""

    def __init__(self, max_keys: int = 100):
        self.max_keys = max_keys
        self.lock = threading.Lock()
        self.items: Dict[Tuple[str, Tuple[Tuple[str, Any], ...]], Dict[str, Any]] = {}

    def note(self, event: str, key: Optional[Dict[str, Any]] = None, count: int = 1,
             **values: Any) -> None:
        """`key`: the fields that split the summary (host, source, reason...). `values`: numbers
        keep the maximum (or the minimum, for MIN_FIELDS); strings are collected."""
        key = dict(key or {})
        k = (event, tuple(sorted(key.items())))
        with self.lock:
            item = self.items.get(k)
            if item is None and sum(1 for e, _ in self.items if e == event) >= self.max_keys:
                key = {"overflow": True}
                k = (event, (("overflow", True),))
                item = self.items.get(k)
            if item is None:
                item = self.items[k] = {"key": key, "count": 0, "num": {}, "sets": {}}
            item["count"] += count
            for name, v in values.items():
                if v is None:
                    continue
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    old = item["num"].get(name, v)
                    item["num"][name] = min(old, v) if name in MIN_FIELDS else max(old, v)
                else:
                    item["sets"].setdefault(name, set()).add(str(v))

    def drain(self) -> List[Tuple[str, Dict[str, Any]]]:
        with self.lock:
            items, self.items = self.items, {}
        out = []
        for (event, _), item in sorted(items.items(), key=lambda kv: (kv[0][0], repr(kv[0][1]))):
            fields = dict(item["key"], count=item["count"])
            fields.update(item["num"])
            fields.update((n, sorted(s)) for n, s in item["sets"].items())
            out.append((event, fields))
        return out
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_audit.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/audit.py tests/test_audit.py
git commit -m "Audit: per-minute summaries for frequent events" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.5: JSON operational logs and the SIGUSR1 debug toggle

**Files:**
- Create: `wd2l/logsetup.py`
- Create: `tests/test_logsetup.py`

**Interfaces:**
- Consumes: `audit.utc_ts`, `hostinfo.signal_actor`; an audit object with `.write(event, outcome, **fields)`.
- Produces:
  - `logsetup.segment_for(logger_name) -> Optional[str]` (`wd2l.sender.input` → `e1-input`,
    `wd2l.sender` → `e1-sender`, `wd2l.receiver` → `e2-receiver`, `wd2l.outputs` → `e2-siem`)
  - `logsetup.JsonFormatter`, `logsetup.setup(fmt="text"|"json", verbose=False)`
  - `logsetup.toggle_debug() -> str` (`"DEBUG"` or `"INFO"`)
  - `logsetup.SignalWatcher(handlers: Dict[int, Callable[[signo, pid, uid], None]]).start()`
  - `logsetup.debug_toggle_handler(audit=None) -> Callable[[int, int, int], None]`

- [ ] **Step 1: Write the failing tests**

`tests/test_logsetup.py`:

```python
import io
import json
import logging
import os
import subprocess
import sys

from wd2l import logsetup

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def capture(name):
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(logsetup.JsonFormatter())
    lg = logging.getLogger(name)
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    return lg, buf, h


def test_json_lines_keep_the_message_and_add_the_segment():
    lg, buf, h = capture("wd2l.sender")
    try:
        lg.info("final: last_seq=%d %s", 7, "{}")
        lg.warning("GAP", extra={"stream": "00ab", "seq": 5})
    finally:
        lg.removeHandler(h)
    a, b = [json.loads(x) for x in buf.getvalue().splitlines()]
    assert a["msg"] == "final: last_seq=7 {}" and a["segment"] == "e1-sender"
    assert a["level"] == "INFO" and a["ts"].endswith("Z")
    assert (b["stream"], b["seq"]) == ("00ab", 5)


def test_segments_by_logger():
    assert logsetup.segment_for("wd2l.sender.input") == "e1-input"
    assert logsetup.segment_for("wd2l.sender") == "e1-sender"
    assert logsetup.segment_for("wd2l.receiver") == "e2-receiver"
    assert logsetup.segment_for("wd2l.outputs") == "e2-siem"
    assert logsetup.segment_for("wd2l.audit") is None


def test_toggle_debug_flips_the_root_level():
    root = logging.getLogger()
    old = root.level
    try:
        root.setLevel(logging.INFO)
        assert logsetup.toggle_debug() == "DEBUG" and root.level == logging.DEBUG
        assert logsetup.toggle_debug() == "INFO" and root.level == logging.INFO
    finally:
        root.setLevel(old)


class FakeAudit:
    def __init__(self):
        self.written = []

    def write(self, event, outcome="info", **fields):
        self.written.append(dict(fields, event=event, outcome=outcome))


def test_debug_toggle_is_an_audit_event_naming_who_sent_it():
    root = logging.getLogger()
    old = root.level
    a = FakeAudit()
    try:
        root.setLevel(logging.INFO)
        logsetup.debug_toggle_handler(a)(10, os.getpid(), os.getuid())
    finally:
        root.setLevel(old)
    [w] = a.written
    assert w["event"] == "debug_toggled" and w["level"] == "DEBUG"
    assert "pid=%d" % os.getpid() in w["actor"]


SCRIPT = r"""
import os, signal, sys, time
sys.path.insert(0, sys.argv[1])
from wd2l import logsetup
got = []
logsetup.SignalWatcher({signal.SIGUSR1: lambda s, pid, uid: got.append((s, pid, uid))}).start()
os.kill(os.getpid(), signal.SIGUSR1)
for _ in range(500):
    if got:
        break
    time.sleep(0.01)
print(got[0][0] == signal.SIGUSR1, got[0][1] == os.getpid(), got[0][2] == os.getuid())
"""


def test_signal_watcher_knows_who_sent_the_signal():
    r = subprocess.run([sys.executable, "-c", SCRIPT, REPO], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30)
    assert r.stdout.decode().split() == ["True", "True", "True"], r.stderr.decode()
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_logsetup.py -q`
Expected: `ModuleNotFoundError: No module named 'wd2l.logsetup'`.

- [ ] **Step 3: Write the implementation**

`wd2l/logsetup.py`:

```python
"""Operational logs and signals.

Operational logs go to stderr (journald) as text, or with --log-format json as one JSON object
per line, tagged with the segment it is about (docs/audit-and-health-plan.md §4, §8). The message
texts are the same either way, so runbook checks such as `final: last_seq=` still match.

SIGUSR1 switches between INFO and DEBUG without a restart. It is an audit event
(debug_toggled) that names who sent the signal, which only sigwaitinfo() can tell."""

from __future__ import annotations

import json
import logging
import signal
import threading
from typing import Any, Callable, Dict, Optional

from . import hostinfo
from .audit import utc_ts

log = logging.getLogger("wd2l")

SEGMENT_BY_LOGGER = (("wd2l.sender.input", "e1-input"), ("wd2l.sender", "e1-sender"),
                     ("wd2l.receiver", "e2-receiver"), ("wd2l.outputs", "e2-siem"))
TEXT_FORMAT = "%(asctime)s %(name)s %(levelname)s %(message)s"


def segment_for(logger_name: str) -> Optional[str]:
    for prefix, seg in SEGMENT_BY_LOGGER:
        if logger_name == prefix or logger_name.startswith(prefix + "."):
            return seg
    return None


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: Dict[str, Any] = {"ts": utc_ts(record.created), "level": record.levelname,
                               "logger": record.name, "msg": record.getMessage()}
        seg = getattr(record, "segment", None) or segment_for(record.name)
        if seg:
            out["segment"] = seg
        for k in ("stream", "seq"):
            v = getattr(record, k, None)
            if v is not None:
                out[k] = v
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, ensure_ascii=False, sort_keys=True)


def setup(fmt: str = "text", verbose: bool = False) -> None:
    """Like logging.basicConfig (a no-op if logging is already set up, e.g. under pytest)."""
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter() if fmt == "json" else logging.Formatter(TEXT_FORMAT))
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO, handlers=[handler])


def toggle_debug() -> str:
    root = logging.getLogger()
    new = logging.INFO if root.level <= logging.DEBUG else logging.DEBUG
    root.setLevel(new)
    return logging.getLevelName(new)


class SignalWatcher:
    """Handles signals in a thread of its own with sigwaitinfo(), which says who sent each one
    (si_pid, si_uid). Call start() before any other thread starts: threads inherit the blocked
    signal mask, so only this thread receives these signals."""

    def __init__(self, handlers: Dict[int, Callable[[int, int, int], None]]):
        self.handlers = dict(handlers)

    def start(self) -> None:
        sigs = set(self.handlers)
        signal.pthread_sigmask(signal.SIG_BLOCK, sigs)
        threading.Thread(target=self._run, args=(sigs,), name="signals", daemon=True).start()

    def _run(self, sigs: set) -> None:
        while True:
            info = signal.sigwaitinfo(sigs)
            try:
                self.handlers[info.si_signo](info.si_signo, info.si_pid, info.si_uid)
            except Exception:
                log.exception("handling signal %d failed", info.si_signo)


def debug_toggle_handler(audit: Any = None) -> Callable[[int, int, int], None]:
    """SIGUSR1: switch INFO <-> DEBUG and record who asked (debug_toggled)."""
    def handle(_sig: int, pid: int, uid: int) -> None:
        level = toggle_debug()
        who = hostinfo.signal_actor(pid, uid)
        log.warning("SIGUSR1 from %s: log level now %s", who, level)
        if audit is not None:
            audit.write("debug_toggled", "info", actor=who, level=level)
    return handle
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_logsetup.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/logsetup.py tests/test_logsetup.py
git commit -m "JSON operational logs tagged by segment; SIGUSR1 debug toggle that knows who sent it" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.6: The sender writes the catalog

**Files:**
- Modify: `wd2l/sender.py`
- Create: `tests/test_sender_audit.py`

**Interfaces:**
- Consumes: `audit.AuditLog`, `audit.Summarizer`, `audit.canonical`, `audit.sha256_hex`,
  `audit.AuditLocked`; `hostinfo.TimeQuality`, `hostinfo.code_sha256`;
  `logsetup.setup`, `logsetup.SignalWatcher`, `logsetup.debug_toggle_handler`.
- Produces:
  - `sender.new_stream_id() -> int`
  - `Sender(..., stream_id=None, audit=None, config_sha256=None)`; `Sender.summary`
    (`Summarizer`); `Sender.count_bad_input(reason="bad_json")`; `Sender.flush_summaries()`;
    `Sender.periodic()`
  - `sender.build_parser() -> argparse.ArgumentParser` with new flags `--audit-dir`,
    `--audit-min-free-mb`, `--chronyc`, `--log-format`
  - `sender.config_settings(a) -> dict`; logger `wd2l.sender.input`
  - Sender state file gains `config_sha256`

Events written: `start`, `config`, `time_quality`, `state_loaded` / `state_reset`,
`config_changed`, `auth_failure`, `input_rejected`, `truncated`, `opaque_content`,
`send_failure` (all five summarised per minute), `debug_toggled`, `audit_failure`,
`audit_verify`, `stop`.

- [ ] **Step 1: Write the failing tests**

`tests/test_sender_audit.py`:

```python
import errno
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

from wd2l import audit as auditlog
from wd2l import wire
from wd2l.sender import InputServer, Sender

from helpers import FakeSock, read_audit

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CHRONYC = "print('47505300,GPS,3,0,0.000004,0,0,0,0,0,0,0,16,Normal')"


def make(tmp_path, **kw):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="logsrv01", actor="me",
                          build="b", forward=False)
    sock = kw.pop("sock", FakeSock())
    kw.setdefault("rate_pps", 0)
    return Sender(("10.255.255.2", 5514), sock=sock, audit=a, **kw), a, sock


def events(a, name):
    return [r for r in read_audit(a.dir) if r["event"] == name]


def wait_for(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_first_start_records_the_missing_state_file(tmp_path):
    _, a, _ = make(tmp_path, state_path=str(tmp_path / "s.json"))
    [r] = events(a, "state_reset")
    assert (r["outcome"], r["reason"], r["path"]) == ("info", "missing", str(tmp_path / "s.json"))


def test_next_start_records_the_state_it_loaded(tmp_path):
    state = str(tmp_path / "s.json")
    s1, a1, _ = make(tmp_path, state_path=state)
    s1.send_heartbeat()
    a1.close()
    with open(state, "rb") as f:
        body = f.read()
    _, a2, _ = make(tmp_path, state_path=state)
    [r] = events(a2, "state_loaded")
    assert r["file_sha256"] == hashlib.sha256(body).hexdigest() and r["boot"] == 1


def test_unreadable_state_is_a_failed_reset(tmp_path):
    state = tmp_path / "s.json"
    state.write_text("{oops")
    _, a, _ = make(tmp_path, state_path=str(state))
    [r] = events(a, "state_reset")
    assert r["outcome"] == "failure" and r["reason"].startswith("unreadable")


def test_config_change_between_runs_is_recorded(tmp_path):
    state = str(tmp_path / "s.json")
    s, a, _ = make(tmp_path, state_path=state, config_sha256="a" * 64)
    a.close()
    s, a, _ = make(tmp_path, state_path=state, config_sha256="a" * 64)
    assert events(a, "config_changed") == []
    a.close()
    _, a, _ = make(tmp_path, state_path=state, config_sha256="b" * 64)
    [r] = events(a, "config_changed")
    assert (r["old_config_sha256"], r["config_sha256"]) == ("a" * 64, "b" * 64)


def test_truncation_and_opaque_content_are_summarised(tmp_path):
    import base64
    s, a, _ = make(tmp_path, max_event=4096)
    s.send_event({"_raw": "x" * 10000, "host": "fw01", "source": "udp:514"})
    s.send_event({"_raw": "x" * 20000, "host": "fw01", "source": "udp:514"})
    s.send_event({"_raw": "blob " + base64.b64encode(os.urandom(900)).decode(), "host": "ws1",
                  "source": "app"})
    s.flush_summaries()
    [t] = events(a, "truncated")
    assert (t["count"], t["host"], t["max_original_bytes"], t["outcome"]) == (2, "fw01", 20000, "info")
    [o] = events(a, "opaque_content")
    assert o["count"] == 1 and o["host"] == "ws1" and o["kinds"]
    assert "x" * 100 not in json.dumps(read_audit(a.dir))      # never any log content


class FailingSock:
    def sendto(self, data, addr):
        raise OSError(errno.EMSGSIZE, "Message too long")


def test_send_failures_are_summarised(tmp_path):
    s, a, _ = make(tmp_path, sock=FailingSock())
    s.send_event({"_raw": "a"})
    s.flush_summaries()
    [r] = events(a, "send_failure")
    assert (r["error"], r["count"], r["outcome"]) == ("EMSGSIZE", 1, "failure")


def test_bad_input_and_auth_failures_are_summarised(tmp_path):
    s, a, _ = make(tmp_path)
    srv = InputServer(("127.0.0.1", 0), s, "s3cret")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for payload in (b'{"authToken":"wrong"}\n', b'{"authToken":"s3cret"}\nnot json\n[1]\n'):
            c = socket.create_connection(srv.server_address)
            c.sendall(payload)
            c.close()
        assert wait_for(lambda: s.counters["bad_input"] == 2)
        assert wait_for(lambda: any(e == "auth_failure" for e, _ in list(s.summary.items)))
    finally:
        srv.shutdown()
        srv.server_close()
    s.flush_summaries()
    [af] = events(a, "auth_failure")
    assert (af["client"], af["reason"], af["segment"], af["outcome"]) == \
        ("127.0.0.1", "bad token", "e1-input", "failure")
    got = {r["reason"]: r["count"] for r in events(a, "input_rejected")}
    assert got == {"bad_json": 1, "not_object": 1}


def test_without_audit_nothing_changes(tmp_path):
    s = Sender(("10.255.255.2", 5514), sock=FakeSock(), rate_pps=0)
    s.send_event({"_raw": "a"})
    s.flush_summaries()
    s.periodic()


def free_port():
    with socket.socket() as t:
        t.bind(("127.0.0.1", 0))
        return t.getsockname()[1]


def test_a_sender_run_leaves_a_verifiable_trail(tmp_path):
    chronyc = tmp_path / "chronyc.py"
    chronyc.write_text(CHRONYC)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    port = free_port()
    adir = tmp_path / "audit"
    env = dict(os.environ, PYTHONPATH=REPO)
    p = subprocess.Popen(
        [sys.executable, "-m", "wd2l.sender", "--listen", "127.0.0.1:%d" % port,
         "--dst", "127.0.0.1:%d" % udp.getsockname()[1], "--state", str(tmp_path / "s.json"),
         "--audit-dir", str(adir), "--chronyc", "%s %s" % (sys.executable, chronyc),
         "--log-format", "json", "--heartbeat", "0.2", "--drain-timeout", "0.5"],
        stderr=subprocess.PIPE, env=env)
    try:
        assert wait_for(lambda: socket.socket().connect_ex(("127.0.0.1", port)) == 0)
        c = socket.create_connection(("127.0.0.1", port))
        c.sendall(b'{"_raw":"hello","host":"h1"}\n')
        c.close()

        def got_data():   # the data stream's event (flags 0), not a records-stream frame
            try:
                f = wire.decode(udp.recv(65535))
                return f.type == wire.TYPE_DATA and f.flags == 0
            except socket.timeout:
                return False
        assert wait_for(got_data)
        p.send_signal(signal.SIGUSR1)
        assert wait_for(lambda: any(r["event"] == "debug_toggled" for r in read_audit(adir)))
        p.send_signal(signal.SIGTERM)
        _, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
    recs = read_audit(adir)
    names = [r["event"] for r in recs]
    assert names[:4] == ["start", "config", "time_quality", "state_reset"]
    assert names[-1] == "stop"
    dbg = recs[names.index("debug_toggled")]
    assert "pid=%d" % os.getpid() in dbg["actor"] and dbg["level"] == "DEBUG"
    assert recs[-1]["signal"] == "SIGTERM" and recs[-1]["last_seq"] == 1
    assert recs[0]["config_sha256"] == recs[1]["config_sha256"]
    assert recs[1]["settings"]["state"] == str(tmp_path / "s.json")
    assert recs[2]["outcome"] == "success" and recs[0]["time_quality"]["stratum"] == 3
    assert auditlog.verify_dir(str(adir)).ok
    lines = [json.loads(x) for x in err.decode().splitlines() if x.startswith("{")]
    assert any(x["msg"].startswith("final: last_seq=1 ") and x["segment"] == "e1-sender"
               for x in lines)
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_sender_audit.py -q`
Expected: failures with `TypeError: __init__() got an unexpected keyword argument 'audit'`.

- [ ] **Step 3: Implement**

All edits in `wd2l/sender.py`.

(a) Imports and module constants. Replace the import lines from `import argparse` through
`from . import opaque, wire` with:

```python
import argparse
import errno
import fcntl
import hashlib
import json
import logging
import os
import platform
import select
import shlex
import signal
import socket
import socketserver
import struct
import termios
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from . import audit as auditlog
from . import hostinfo, logsetup, opaque, wire

log = logging.getLogger("wd2l.sender")
log_input = logging.getLogger("wd2l.sender.input")
```

(remove the old `log = ...` line) and after `ERROR_LOG_EVERY = 10.0` add:

```python
# Frequent events become one audit record per kind and key a minute (§6).
SUMMARY_OUTCOME = {"auth_failure": "failure", "input_rejected": "failure",
                   "send_failure": "failure", "truncated": "info", "opaque_content": "info"}
SUMMARY_SEGMENT = {"auth_failure": "e1-input", "input_rejected": "e1-input"}


def new_stream_id() -> int:
    return int.from_bytes(os.urandom(8), "big") or 1


def _key(v: Any) -> Optional[str]:
    """A host or source as a summary key (the aggregator may send anything)."""
    return None if v is None else str(v)[:256]
```

(b) `Sender.__init__`: add three keyword parameters at the end of the signature,
`stream_id: Optional[int] = None, audit: Optional[auditlog.AuditLog] = None,
config_sha256: Optional[str] = None`. Replace
`self.stream_id = int.from_bytes(os.urandom(8), "big") or 1` with
`self.stream_id = stream_id or new_stream_id()`. Just before `self.state_path = state_path` add:

```python
        self.audit = audit
        self.summary = auditlog.Summarizer()
        self.config_sha256 = config_sha256
```

(c) Replace `_start_state` and `_save_state` with:

```python
    def _audit(self, event: str, outcome: str = "info", **fields: Any) -> None:
        if self.audit is not None:
            self.audit.write(event, outcome, **fields)

    def _start_state(self) -> None:
        """Read the previous run's record, then claim the next boot number for this run."""
        prev: Dict[str, Any] = {}
        try:
            with open(self.state_path, "rb") as f:  # type: ignore[arg-type]
                body = f.read()
            prev = json.loads(body)
            if not isinstance(prev, dict):
                raise ValueError("not a JSON object")
        except FileNotFoundError:
            self._audit("state_reset", "info", path=self.state_path, reason="missing")
        except (OSError, ValueError) as e:
            # Starting over at boot 1 is visible on the receiver as sender_boot_reset.
            log.error("sender state %s unreadable (%s): restart count starts over", self.state_path, e)
            prev = {}
            self._audit("state_reset", "failure", path=self.state_path, reason="unreadable: %s" % e)
        else:
            self._audit("state_loaded", "success", path=self.state_path,
                        file_sha256=hashlib.sha256(body).hexdigest(), boot=prev.get("boot"),
                        prev_stream=prev.get("stream"), prev_last_seq=prev.get("last_seq"))
        old_cfg = prev.get("config_sha256")
        if self.config_sha256 and isinstance(old_cfg, str) and old_cfg != self.config_sha256:
            self._audit("config_changed", "info", old_config_sha256=old_cfg,
                        config_sha256=self.config_sha256)
        boot = prev.get("boot")
        self.link = {"boot": boot + 1 if isinstance(boot, int) and boot >= 1 else 1}
        stream = prev.get("stream")
        last_seq = prev.get("last_seq")
        if isinstance(stream, str) and isinstance(last_seq, int):
            try:
                self.link.update(prev_stream=int(stream, 16), prev_last_seq=last_seq)
            except ValueError:
                pass
        self._save_state()
        log.info("boot %d%s", self.link["boot"],
                 " after stream %016x (last seq %d)" % (self.link["prev_stream"], self.link["prev_last_seq"])
                 if "prev_stream" in self.link else "")

    def _save_state(self) -> None:
        """Record this run's stream and progress. Called with the lock held (or at start)."""
        if not self.state_path:
            return
        st: Dict[str, Any] = {"boot": self.link["boot"], "stream": "%016x" % self.stream_id,
                              "last_seq": self.seq}
        if self.config_sha256:
            st["config_sha256"] = self.config_sha256
        body = json.dumps(st)
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.state_path)
        except OSError as e:
            self._log_error(e.errno or -1, "sender state write failed: %s" % e)
```

(d) Replace `_transmit` with:

```python
    def _transmit(self, datagram: bytes) -> bool:
        self._pace()
        code = errno.ENOBUFS
        for _ in range(100):
            try:
                self.sock.sendto(datagram, self.dst)
                self.counters["datagrams_sent"] += 1
                return True
            except OSError as e:
                code = e.errno or -1
                if e.errno not in (errno.ENOBUFS, errno.EAGAIN, errno.EWOULDBLOCK):
                    self.counters["send_errors"] += 1
                    self._log_error(e.errno or -1, "send failed: %s" % e)
                    break
                time.sleep(0.001)
        self.counters["sender_drops"] += 1
        self.summary.note("send_failure", {"error": errno.errorcode.get(code, str(code))})
        return False
```

(e) In `_fit`, right after `self.counters["truncated"] += 1`, add:

```python
        self.summary.note("truncated", {"host": _key(event.get("host")),
                                        "source": _key(event.get("source"))},
                          max_original_bytes=len(raw_bytes))
```

(f) In `send_event`, replace

```python
                if found.get(OPAQUE_FIELD):
                    self.counters["opaque_events"] += 1
```

with

```python
                if found.get(OPAQUE_FIELD):
                    self.counters["opaque_events"] += 1
                    self.summary.note("opaque_content", {"host": _key(event.get("host")),
                                                         "source": _key(event.get("source"))},
                                      kinds=found[OPAQUE_FIELD],
                                      max_blob_bytes=found[OPAQUE_BYTES_FIELD])
```

(g) Replace `count_bad_input` and add `flush_summaries` and `periodic` after `count_unread`:

```python
    def count_bad_input(self, reason: str = "bad_json") -> None:
        with self.lock:
            self.counters["bad_input"] += 1
        self.summary.note("input_rejected", {"reason": reason})

    def flush_summaries(self) -> None:
        """The last minute's frequent events, one audit record per kind and key."""
        if self.audit is None:
            return
        for event, fields in self.summary.drain():
            fields.setdefault("segment", SUMMARY_SEGMENT.get(event))
            self.audit.write(event, SUMMARY_OUTCOME.get(event, "info"),
                             stream="%016x" % self.stream_id, **fields)

    def periodic(self) -> None:
        """About once a minute, from the heartbeat thread: summaries, time quality, free space
        and the daily self-check of the audit chain."""
        if self.audit is None:
            return
        self.flush_summaries()
        self.audit.check_time()
        self.audit.check_space()
        self.audit.maybe_verify()
```

(h) `CriblHandler`: register nothing new yet, but route input messages to `log_input` and note
rejections. In `_run`, replace the gzip block and the over-long-line block:

```python
                if chunk[:2] == b"\x1f\x8b":
                    log_input.error("gzip data from %s: turn off compression on the log "
                                    "aggregator's output", self.client_address)
                    srv.sender.summary.note("input_rejected", {"reason": "gzip"},
                                            client=self.client_address[0])
                    return
```

```python
            if len(buf) > MAX_LINE:
                srv.sender.count_bad_input("line_too_long")
                log_input.warning("dropped input line over %d bytes", MAX_LINE)
```

and `log.warning("shutdown: %d bytes ...` → `log_input.warning(` (same text). In `_line`:

```python
        try:
            obj = json.loads(line)
        except ValueError:
            srv.sender.count_bad_input("bad_json")
            self.first_line = False
            return True
        if not isinstance(obj, dict):
            srv.sender.count_bad_input("not_object")
            self.first_line = False
            return True
        if self.first_line and _is_header(obj):
            self.first_line = False
            if srv.auth_token is not None and obj.get("authToken") != srv.auth_token:
                log_input.error("bad auth token from %s", self.client_address)
                srv.sender.summary.note("auth_failure", {"client": self.client_address[0],
                                                         "reason": "bad token"})
                return False
            if isinstance(obj.get("fields"), dict):
                self.defaults = obj["fields"]
            return True
        if self.first_line and srv.auth_token is not None:
            log_input.error("no auth header from %s", self.client_address)
            srv.sender.summary.note("auth_failure", {"client": self.client_address[0],
                                                     "reason": "no header"})
            return False
```

(i) `_heartbeat_loop`: give the per-minute line its stream tag (the text stays the same) and run
the housekeeping after it:

```python
            log.info("stream=%016x last_seq=%d %s", sender.stream_id, sender.seq, counters,
                     extra={"stream": "%016x" % sender.stream_id, "seq": sender.seq})
            sender.periodic()
```

(j) Replace `main` with `build_parser`, `config_settings` and a new `main`:

```python
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wd2l-sender", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # ... every existing p.add_argument(...) line from the old main(), unchanged, then:
    p.add_argument("--audit-dir", help="write hash-chained audit records here "
                                       "(deployed: /var/log/wd2l)")
    p.add_argument("--audit-min-free-mb", type=int, default=256,
                   help="free space below this raises audit_failure")
    p.add_argument("--chronyc", default="chronyc",
                   help="chronyc command for time quality (\"-c tracking\" is added)")
    p.add_argument("--log-format", choices=("text", "json"), default="text",
                   help="operational log lines: text, or one JSON object per line")
    return p


def config_settings(a: argparse.Namespace) -> Dict[str, Any]:
    """This run's settings for the config audit record. Token files appear as paths only."""
    return {k: v for k, v in sorted(vars(a).items())}


def main(argv: Optional[Sequence[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    logsetup.setup(a.log_format, a.verbose)
    settings = config_settings(a)
    cfg_sha = auditlog.sha256_hex(auditlog.canonical(settings))
    tq = hostinfo.TimeQuality(shlex.split(a.chronyc) + ["-c", "tracking"])
    audit = None
    if a.audit_dir:
        try:
            audit = auditlog.AuditLog(a.audit_dir, "sender", 1, time_quality=tq, forward=False,
                                      min_free_bytes=a.audit_min_free_mb * 1024 * 1024)
        except auditlog.AuditLocked as e:
            raise SystemExit(str(e))
    # Before any other thread exists, so only the watcher thread receives SIGUSR1.
    logsetup.SignalWatcher({signal.SIGUSR1: logsetup.debug_toggle_handler(audit)}).start()
    sid = new_stream_id()
    if audit:
        audit.write("start", "success", pid=os.getpid(), stream="%016x" % sid,
                    config_sha256=cfg_sha, code_sha256=hostinfo.code_sha256(),
                    python=platform.python_version())
        audit.write("config", "info", settings=settings, config_sha256=cfg_sha)
        audit.check_time()

    token = None
    if a.auth_token_file:
        with open(a.auth_token_file) as f:
            token = f.read().strip()
    bind_ip, bind_port = _bind_addr(a.bind)
    sender = Sender(_hostport(a.dst), bind_ip, a.max_datagram, a.max_event, a.rate_pps,
                    a.extra_field, state_path=a.state, source_seq=a.source_seq,
                    tx_time=a.tx_time, opaque_check=a.opaque_check, bind_port=bind_port,
                    stream_id=sid, audit=audit, config_sha256=cfg_sha)
    if audit:
        audit.start_verify()
    server = InputServer(_hostport(a.listen), sender, token, a.input_rcvbuf, a.drain_timeout)
    stop = threading.Event()
    hb = threading.Thread(target=_heartbeat_loop,
                          args=(sender, a.heartbeat, stop, a.stats_interval), daemon=True)
    hb.start()
    stopped_by: List[int] = []

    def _shutdown(signum, _frame):
        stopped_by.append(signum)
        log.info("signal %d, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    log.info("stream %016x: listening on %s, sending to %s", sender.stream_id, a.listen, a.dst)
    server.serve_forever()
    # Order matters: stop accepting, finish reading what is in flight, and only then send the
    # final heartbeat, so its sequence number really is the last one.
    server.drain()
    stop.set()
    hb.join()
    sender.send_heartbeat(final=True)
    log.info("final: last_seq=%d %s", sender.seq, json.dumps(sender.counters, sort_keys=True))
    if audit:
        sender.flush_summaries()
        audit.write("stop", "success", stream="%016x" % sender.stream_id, last_seq=sender.seq,
                    signal=signal.Signals(stopped_by[0]).name if stopped_by else None,
                    counters=dict(sender.counters))
        audit.close()
    return 0
```

Move every existing `p.add_argument(...)` call from the old `main()` into `build_parser()` where
the comment says, in the same order, unchanged, ending with `-v/--verbose`.

- [ ] **Step 4: Run the new and the existing sender tests**

Run: `T tests/test_sender_audit.py tests/test_sender.py tests/test_end_to_end.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/sender.py tests/test_sender_audit.py
git commit -m "Sender: audit catalog (start, config, state, input, truncation, opaque, send failures, debug, stop)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.7: Outputs carry audit records

**Files:**
- Modify: `wd2l/outputs.py`
- Modify: `tests/helpers.py` (`MemOutput.audit`)
- Modify: `tests/test_hec.py` (append)
- Create: `tests/test_outputs_audit.py`

**Interfaces:**
- Consumes: `audit.canonical`, `audit.ts_epoch`.
- Produces:
  - `Output.audit(rec: dict)` on every output (base raises `NotImplementedError`)
  - `FileOutput.audit` appends `canonical(rec)` lines to `<out_dir>/audit.jsonl` (opened lazily);
    `FileOutput._file(name)` opens extra files lazily
  - `HecOutput(..., audit_index="wd2l_audit", stat_prefix="")`; `HecOutput.audit(rec)` posts
    `sourcetype=wd2l:audit`, `source=wd2l-<component>`, `index=<audit_index>` (never
    `force_index`), `event` = the canonical JSON text; data events naming the audit index go to
    the default index (`hec_audit_index_refused`); a health or audit record lost because queue and
    spool are both full is counted (`hec_records_lost`); `stats()` keys get `stat_prefix`
  - `MemOutput.audits: list`

- [ ] **Step 1: Write the failing tests**

In `tests/helpers.py`, give `MemOutput` an audit list:

```python
class MemOutput(Output):
    def __init__(self):
        self.events = []
        self.records = []
        self.audits = []

    def event(self, evt, stream_id, seq):
        self.events.append((stream_id, seq, evt))

    def health(self, rec):
        self.records.append(rec)

    def audit(self, rec):
        self.audits.append(rec)
```

(keep `kinds` and `seqs` as they are).

Append to `tests/test_hec.py`:

```python
from wd2l import audit as auditlog


def test_audit_records_go_to_the_audit_index_as_canonical_text(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path, force_index="everything")
    rec = {"ts": "2026-10-05T14:03:22.500000Z", "event": "gap", "component": "receiver",
           "n": 1, "prev_hash": "0" * 64, "hash": "f" * 64}
    o.audit(rec)
    o.health({"type": "health", "time": 1})
    assert wait_for(lambda: len(splunk.records()) == 2)
    o.close()
    a, h = sorted(splunk.records(), key=lambda r: r["sourcetype"])
    assert (a["sourcetype"], a["index"], a["source"]) == ("wd2l:audit", "wd2l_audit", "wd2l-receiver")
    assert a["event"] == auditlog.canonical(rec).decode() and a["time"] == 1791209002.5
    assert h["index"] == "everything"


def test_data_event_cannot_land_in_the_audit_index(splunk, tmp_path):
    """Review focus 4: an imported event naming the audit index stays with the data."""
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path)
    o.event({"_raw": "x", "index": "wd2l_audit"}, 1, 1)
    assert wait_for(lambda: len(splunk.records()) == 1)
    o.close()
    assert splunk.records()[0]["index"] == "enclave1"
    assert o.stats()["hec_audit_index_refused"] == 1


def test_audit_output_with_its_own_token_and_prefixed_stats(splunk, tmp_path):
    o = HecOutput("http://127.0.0.1:%d" % splunk.port, "audit-tok", str(tmp_path / "sp"),
                  stat_prefix="audit_", retry_interval=0.2)
    o.audit({"ts": "2026-10-05T14:03:22.500000Z", "event": "start", "component": "receiver"})
    assert wait_for(lambda: len(splunk.records()) == 1)
    o.close()
    assert splunk.auth == ["Splunk audit-tok"]
    assert o.stats()["audit_hec_events_sent"] == 1 and "hec_events_sent" not in o.stats()
```

`tests/test_outputs_audit.py`:

```python
import json

from wd2l import audit as auditlog
from wd2l.outputs import FileOutput, MultiOutput

from helpers import MemOutput


def test_file_output_writes_audit_lines_canonically(tmp_path):
    o = FileOutput(str(tmp_path))
    assert not (tmp_path / "audit.jsonl").exists()        # opened only when needed
    rec = {"event": "start", "n": 1, "b": "é"}
    o.audit(rec)
    o.close()
    assert (tmp_path / "audit.jsonl").read_bytes() == auditlog.canonical(rec) + b"\n"


def test_multi_output_fans_audit_out():
    a, b = MemOutput(), MemOutput()
    MultiOutput([a, b]).audit({"event": "x"})
    assert a.audits == b.audits == [{"event": "x"}]
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_hec.py tests/test_outputs_audit.py -q`
Expected: failures on `audit` (`NotImplementedError` / `AttributeError`) and on
`hec_audit_index_refused`.

- [ ] **Step 3: Implement**

In `wd2l/outputs.py`:

Add `from .audit import canonical, ts_epoch` after the typing import.

In `Output`, after `health`, add:

```python
    def audit(self, rec: Dict[str, Any]) -> None:
        """One of this host's audit records. Never dropped, like health records."""
        raise NotImplementedError
```

In `FileOutput.__init__` add `self.dir = out_dir` and `self._extra: Dict[str, Any] = {}`, and add
these methods:

```python
    def _file(self, name: str):
        f = self._extra.get(name)
        if f is None:
            f = self._extra[name] = open(os.path.join(self.dir, name), "a", encoding="utf-8")
        return f

    def audit(self, rec):
        f = self._file("audit.jsonl")
        f.write(canonical(rec).decode("utf-8") + "\n")
        f.flush()
```

and in `FileOutput.close`, before `self.events.close()`:

```python
        for f in self._extra.values():
            f.flush()
            os.fsync(f.fileno())
            f.close()
```

In `MultiOutput` add:

```python
    def audit(self, rec):
        for o in self.outputs:
            o.audit(rec)
```

In `HecOutput.__init__`, add parameters `audit_index: str = "wd2l_audit", stat_prefix: str = ""`
after `force_index`, store them (`self.audit_index`, `self.stat_prefix`), and add
`"hec_audit_index_refused": 0, "hec_records_lost": 0` to `self.counters`.

In `HecOutput._put`, replace the `key is None` branch with:

```python
        if key is None:
            # Health and audit records are few and they are how loss gets reported: never drop
            # one quietly.
            if not self.spool.write(line + b"\n"):
                self.counters["hec_records_lost"] += 1
                log.error("health or audit record lost: queue and spool both full")
            return
```

In `HecOutput.event`, after the index lines, add:

```python
        if rec.get("index") == self.audit_index:
            # Only wd2l writes audit records: an imported event can't land among them.
            self.counters["hec_audit_index_refused"] += 1
            if self.default_index and self.default_index != self.audit_index:
                rec["index"] = self.default_index
            else:
                del rec["index"]
```

Replace `HecOutput.health` with `_record`, `health` and `audit`:

```python
    def _record(self, event: Any, sourcetype: str, source: str, index: Optional[str],
                t: Any) -> None:
        out: Dict[str, Any] = {"time": t, "host": self.hostname, "source": source,
                               "sourcetype": sourcetype, "event": event}
        if index:
            out["index"] = index
        self._put(out, None)

    def health(self, rec):
        self._record(rec, "wd2l:health", "wd2l-receiver", self.health_index,
                     rec.get("time", time.time()))

    def audit(self, rec):
        """The exact canonical text goes in, so a SIEM export can be checked against the chain.
        force_index never moves audit records."""
        ts = rec.get("ts")
        t = ts_epoch(ts) if isinstance(ts, str) else time.time()
        self._record(canonical(rec).decode("utf-8"), "wd2l:audit",
                     "wd2l-%s" % rec.get("component", "receiver"), self.audit_index, t)
```

Replace `HecOutput.stats` with:

```python
    def stats(self):
        s = dict(self.counters)
        s["hec_queue"] = self.q.qsize()
        s["hec_spool_files"] = len(self.spool.files())
        return {self.stat_prefix + k: v for k, v in s.items()}
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_hec.py tests/test_outputs_audit.py tests/test_receiver.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/outputs.py tests/helpers.py tests/test_hec.py tests/test_outputs_audit.py
git commit -m "Outputs carry audit records: own index and token, canonical text, audit index guarded" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.8: The receiver and the archive replay write the catalog

**Files:**
- Modify: `wd2l/receiver.py`
- Modify: `wd2l/packets.py` (`iter_pcap_paths(..., digests=None)`)
- Modify: `tests/helpers.py` (add `write_pcap`)
- Create: `tests/test_receiver_audit.py`

**Interfaces:**
- Consumes: Tasks 1.1–1.7.
- Produces:
  - `Receiver(..., audit=None, audit_output=None, config_sha256=None, audit_interval=60.0)`
  - `Receiver.outputs: List[Output]`, `Receiver.audit_out`, `Receiver.flush()`,
    `Receiver.audit_periodic()`, `Receiver.finish(now, on_end=None)`
  - `receiver.AUDITED_HEALTH`, `receiver.BOUNDARY_COUNTERS`, `receiver.OUTPUT_COUNTERS`
  - `receiver.build_parser()`, `receiver.build_outputs(a) -> (out, audit_out)` (replaces
    `build_output`); new flags `--audit-dir`, `--audit-min-free-mb`, `--hec-audit-token-file`,
    `--audit-index`, `--chronyc`, `--log-format`
  - `packets.iter_pcap_paths(paths, digests: Optional[list] = None)` appends
    `{"file", "sha256", "bytes"}` per file read
  - `helpers.write_pcap(path, datagrams, t0=1000.0)`
  - Receiver state file gains `config_sha256`; an unreadable state file now stops the receiver
    with a clear `SystemExit` message (was a traceback)

Events written: `start`, `config`, `time_quality`, `state_loaded` / `state_reset`,
`config_changed`, `gap`, `stream_start`, `stream_end`, `stream_lost`, `stream_missing`,
`sender_boot_reset`, `stream_evicted`, `gap_filled` (summarised), `boundary_anomaly` and
`output_failure` (per-minute counter deltas), `replay_run`, `debug_toggled`, `audit_failure`,
`audit_verify`, `stop`.

- [ ] **Step 1: Add the test helper**

Append to `tests/helpers.py`:

```python
def write_pcap(path, datagrams, t0=1000.0):
    with open(path, "wb") as f:
        w = packets.PcapWriter(f)
        for i, d in enumerate(datagrams):
            w.write(t0 + i * 0.0005, eth(d, i))
```

- [ ] **Step 2: Write the failing tests**

`tests/test_receiver_audit.py`:

```python
import hashlib
import json
import os

import pytest

from wd2l import audit as auditlog
from wd2l import packets, receiver, wire
from wd2l.receiver import Receiver
from wd2l.sender import Sender

from helpers import FakeSock, MemOutput, SlowOutput, eth, read_audit, write_pcap

SID = 0x1111


def ev(seq, sid=SID):
    return wire.encode_event(sid, seq, json.dumps({"_raw": "event %d" % seq}).encode())


def hb(last_seq, sid=SID, **info):
    return wire.encode_heartbeat(sid, last_seq, dict({"events_sent": last_seq}, **info))


def make(tmp_path, out=None, **kw):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="rx01", actor="me", build="b")
    out = out or MemOutput()
    kw.setdefault("health_interval", 1e9)
    r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, audit=a, **kw)
    return r, out, a


def feed(r, dgs, now):
    for d in dgs:
        r.handle_frame(eth(d), now)


def events(a, name):
    return [x for x in read_audit(a.dir) if x["event"] == name]


def test_gaps_are_audit_events_and_reach_the_audit_output(tmp_path):
    r, out, a = make(tmp_path, gap_window=1)
    feed(r, ev(1) + ev(4), 0)
    r.tick(5)
    [g] = events(a, "gap")
    assert (g["seq_first"], g["seq_last"], g["count"], g["reason"], g["outcome"]) == \
        (2, 3, 2, "not_received", "failure")
    assert g["stream"] == "%016x" % SID and g["segment"] == "e2-receiver"
    assert [x["event"] for x in out.audits if x["event"] == "gap"] == ["gap"]


def test_stream_start_and_clean_end_are_audited(tmp_path):
    r, out, a = make(tmp_path)
    feed(r, ev(1) + [hb(1, final=True)], 0)
    assert [x["outcome"] for x in events(a, "stream_start")] == ["info"]
    [e] = events(a, "stream_end")
    assert e["outcome"] == "success" and e["seq_last"] == 1


def test_state_reset_then_loaded_then_config_changed(tmp_path):
    state = str(tmp_path / "state.json")
    r, _, a = make(tmp_path, state_path=state, config_sha256="a" * 64)
    assert [x["reason"] for x in events(a, "state_reset")] == ["missing"]
    feed(r, ev(1), 0)
    r.save_state()
    a.close()
    with open(state, "rb") as f:
        body = f.read()
    _, _, a2 = make(tmp_path, state_path=state, config_sha256="b" * 64)
    [ld] = events(a2, "state_loaded")
    assert ld["file_sha256"] == hashlib.sha256(body).hexdigest() and ld["streams"] == 1
    [cc] = events(a2, "config_changed")
    assert (cc["old_config_sha256"], cc["config_sha256"]) == ("a" * 64, "b" * 64)


def test_unreadable_state_stops_the_receiver_and_is_audited(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("{oops")
    with pytest.raises(SystemExit, match="unreadable"):
        make(tmp_path, state_path=str(state))
    recs = read_audit(tmp_path / "audit")
    assert recs[-1]["event"] == "state_reset" and recs[-1]["outcome"] == "failure"


def test_boundary_anomalies_are_summarised_each_minute(tmp_path):
    r, out, a = make(tmp_path)
    r.handle_frame(b"\x00" * 60, 0)                     # not IPv4/UDP
    good = ev(1)[0]
    r.handle_frame(eth(good[:-1] + bytes([good[-1] ^ 0xFF])), 0)   # bad CRC
    r.audit_periodic()
    got = {x["reason"]: x for x in events(a, "boundary_anomaly")}
    assert got["other_packets"]["count"] == 1 and got["other_packets"]["segment"] == "boundary"
    assert got["bad_frames"]["reasons"] == {"bad crc": 1}
    r.audit_periodic()
    assert len(events(a, "boundary_anomaly")) == 2      # deltas: nothing new


def test_output_failures_are_audited_against_the_siem_segment(tmp_path):
    r, out, a = make(tmp_path, out=SlowOutput())
    feed(r, ev(1), 0)
    out.fail(SID, 1)
    r.tick(1)
    r.audit_periodic()
    [f] = events(a, "output_failure")
    assert (f["reason"], f["count"], f["segment"]) == ("output_dropped", 1, "e2-siem")


def test_late_fills_are_summarised_as_gap_filled(tmp_path):
    r, out, a = make(tmp_path, gap_window=1)
    feed(r, ev(1) + ev(5), 0)
    r.tick(5)
    feed(r, ev(3) + ev(2), 6)
    r.audit_periodic()
    [f] = events(a, "gap_filled")
    assert (f["count"], f["seq_first"], f["seq_last"], f["outcome"]) == (2, 2, 3, "success")


def replay_pcap(tmp_path):
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    for i in range(20):
        s.send_event({"_raw": "line %d" % i})
    s.send_heartbeat(final=True)
    path = str(tmp_path / "cap-1.pcap")
    write_pcap(path, sock.sent)
    return path


def test_replay_run_records_the_files_and_their_hashes(tmp_path):
    p = replay_pcap(tmp_path)
    adir, out = str(tmp_path / "audit"), str(tmp_path / "out")
    receiver.main(["--pcap", p, "--out-dir", out, "--audit-dir", adir, "--chronyc", "/bin/false"])
    recs = read_audit(adir)
    names = [x["event"] for x in recs]
    assert names[0] == "start" and recs[0]["component"] == "replay" and names[-1] == "stop"
    phases = [x["phase"] for x in recs if x["event"] == "replay_run"]
    assert phases == ["start", "finish"]
    fin = [x for x in recs if x["event"] == "replay_run"][-1]
    with open(p, "rb") as f:
        data = f.read()
    assert fin["files"] == [{"file": "cap-1.pcap", "sha256": hashlib.sha256(data).hexdigest(),
                             "bytes": len(data)}]
    assert auditlog.verify_dir(adir).ok
    with open(os.path.join(out, "audit.jsonl"), "rb") as f:
        forwarded = [json.loads(x) for x in f]
    assert forwarded == recs                            # the SIEM copy matches the official one


def test_replay_refuses_while_another_process_holds_the_audit_dir(tmp_path):
    """Review focus 2: a replay next to a live receiver must not interleave chains."""
    p = replay_pcap(tmp_path)
    held = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="h", actor="a", build="b")
    try:
        with pytest.raises(SystemExit, match="in use by another wd2l process"):
            receiver.main(["--pcap", p, "--out-dir", str(tmp_path / "out"),
                           "--audit-dir", str(tmp_path / "audit"), "--chronyc", "/bin/false"])
    finally:
        held.close()
```

- [ ] **Step 3: Run them to see them fail**

Run: `T tests/test_receiver_audit.py -q`
Expected: `TypeError: __init__() got an unexpected keyword argument 'audit'`.

- [ ] **Step 4: Implement `packets.iter_pcap_paths(..., digests=)`**

Replace `iter_pcap_paths` in `wd2l/packets.py` (add `import hashlib` and
`from typing import Any, Dict, List` to the imports):

```python
class _Hashing:
    """A file wrapper that hashes what is read through it."""

    def __init__(self, f: BinaryIO):
        self.f, self.h, self.n = f, hashlib.sha256(), 0

    def read(self, size: int = -1) -> bytes:
        b = self.f.read(size)
        self.h.update(b)
        self.n += len(b)
        return b


def iter_pcap_paths(paths, digests: Optional[List[Dict[str, Any]]] = None
                    ) -> Iterator[Tuple[float, bytes]]:
    """Frames from several pcap files, oldest file first (by mtime). With `digests`, each
    file's SHA-256 and size, computed while reading it, is appended once it has been read."""
    for p in sorted(paths, key=lambda p: (os.path.getmtime(p), p)):
        with open(p, "rb") as f:
            src = _Hashing(f) if digests is not None else f
            yield from read_pcap(src)  # type: ignore[arg-type]
            if digests is not None:
                digests.append({"file": os.path.basename(p), "sha256": src.h.hexdigest(),
                                "bytes": src.n})
```

- [ ] **Step 5: Implement the receiver changes**

All in `wd2l/receiver.py`.

(a) Imports: add `import platform`, `import shlex`, and
`from . import __version__, hostinfo, logsetup, packets, wire` /
`from . import audit as auditlog` / `from .audit import Summarizer` (keep the outputs import).
Remove `logging.basicConfig` use (step i).

(b) Constants, after `RX_TIME_FIELD`:

```python
# Health records that are also audit events (§6), with their outcome.
AUDITED_HEALTH = {"gap": "failure", "stream_start": "info", "stream_end": "success",
                  "stream_lost": "failure", "stream_missing": "failure",
                  "sender_boot_reset": "failure", "stream_evicted": "failure"}
# Counters whose growth is written once a minute as boundary_anomaly / output_failure.
BOUNDARY_COUNTERS = ("other_packets", "bad_frames", "bad_events", "digest_mismatch",
                     "event_too_big", "reasm_inconsistent")
OUTPUT_COUNTERS = ("output_dropped", "hec_rejected_events", "hec_queue_overflow_events",
                   "hec_spool_overflow_events", "hec_records_lost",
                   "audit_hec_rejected_events", "audit_hec_spool_overflow_events",
                   "audit_hec_records_lost")
```

(c) `Receiver.__init__`: add keyword parameters at the end:
`audit: Optional[auditlog.AuditLog] = None, audit_output: Optional[Output] = None,
config_sha256: Optional[str] = None, audit_interval: float = 60.0`. Replace the last two lines
(`if state_path and os.path.exists(state_path): self._load_state()`) with:

```python
        self.audit = audit
        self.audit_out = audit_output or output
        self.outputs: List[Output] = [output] if self.audit_out is output else [output, self.audit_out]
        self.config_sha256 = config_sha256
        self.summary = Summarizer()
        self.audit_interval = audit_interval
        self.last_audit: Optional[float] = None
        self._audit_prev: Dict[str, Any] = {}
        if state_path and os.path.exists(state_path):
            self._load_state()
        elif state_path and audit is not None:
            audit.write("state_reset", "info", path=state_path, reason="missing")
```

(d) Output helpers, after `_bump`:

```python
    def flush(self) -> None:
        for o in self.outputs:
            o.flush()

    def _pending(self) -> Dict[int, Set[int]]:
        out: Dict[int, Set[int]] = {}
        for o in self.outputs:
            for sid, seqs in o.pending().items():
                out.setdefault(sid, set()).update(seqs)
        return out

    def _take_failed(self) -> List[Tuple[int, int]]:
        return [k for o in self.outputs for k in o.take_failed()]

    def _stats(self) -> Dict[str, Any]:
        s: Dict[str, Any] = {}
        for o in self.outputs:
            s.update(o.stats())
        return s
```

and use them: in `_apply_failed` iterate `self._take_failed()`; in `emit_health` replace
`**self.out.stats()` with `**self._stats()`; in `save_state` replace
`self.out.flush(); pending = self.out.pending()` with `self.flush(); pending = self._pending()`,
and add `if self.config_sha256: state["config_sha256"] = self.config_sha256` before writing.

(e) `handle_datagram`: replace

```python
        if res == "late":
            self.counters["late_fills"] += 1
```

with

```python
        if res == "late":
            self.counters["late_fills"] += 1
            self.summary.note("gap_filled", {"stream": "%016x" % f.stream_id},
                              seq_first=f.seq, seq_last=f.seq)
```

(f) Replace `_health_record`:

```python
    def _health_record(self, kind: str, now: float, **kw: Any) -> None:
        rec = {"type": kind, "time": round(self._wall(now), 3)}
        rec.update(kw)
        self.out.health(rec)
        if self.audit is not None and kind in AUDITED_HEALTH:
            fields = dict(kw)
            if "first_seq" in fields:
                fields["seq_first"] = fields.pop("first_seq")
            if "last_seq" in fields:
                fields["seq_last"] = fields.pop("last_seq")
            self.audit.write(kind, AUDITED_HEALTH[kind], **fields)
```

(g) Audit housekeeping. At the end of `tick`, add:

```python
        if self.audit is not None:
            if self.last_audit is None:
                self.last_audit = now
            elif now - self.last_audit >= self.audit_interval:
                self.last_audit = now
                self.audit_periodic()
            self._drain_audit()
```

and add these methods after `emit_health`:

```python
    def _drain_audit(self) -> None:
        if self.audit is not None:
            for rec in self.audit.take_outbox():
                self.audit_out.audit(rec)

    def audit_periodic(self) -> None:
        """Once a minute: summaries, counter growth, time quality, free space, self-check."""
        if self.audit is None:
            return
        for event, fields in self.summary.drain():
            self.audit.write(event, "success" if event == "gap_filled" else "info", **fields)
        self._audit_deltas()
        self.audit.check_time()
        self.audit.check_space()
        self.audit.maybe_verify()
        self._drain_audit()

    def _audit_deltas(self) -> None:
        cur: Dict[str, Any] = dict(self.counters, **self.reasm.counters, **self._stats())
        reasons = {"other_packets": dict(self.other_reasons), "bad_frames": dict(self.bad_reasons)}
        prev = self._audit_prev
        for name in BOUNDARY_COUNTERS:
            d = cur.get(name, 0) - prev.get(name, 0)
            if d > 0:
                old = prev.get("reasons:" + name, {})
                why = {k: v - old.get(k, 0) for k, v in reasons.get(name, {}).items()
                       if v > old.get(k, 0)}
                self.audit.write("boundary_anomaly", "failure", segment="boundary", reason=name,
                                 count=d, reasons=why or None)
        for name in OUTPUT_COUNTERS:
            d = cur.get(name, 0) - prev.get(name, 0)
            if d > 0:
                self.audit.write("output_failure", "failure", segment="e2-siem", reason=name,
                                 count=d)
        cur.update(("reasons:" + k, v) for k, v in reasons.items())
        self._audit_prev = cur
```

(g2) Tag operational log lines that are about a stream (§4; the texts stay the same): in
`_report_gaps` pass `extra={"stream": "%016x" % t.stream_id, "seq": a}` to the `log.warning`
call, and in `_stream` pass `extra={"stream": "%016x" % sid}` to `log.info("new stream ...")`.

(h) `finish` and `close`:

```python
    def finish(self, now: float, on_end: Optional[Callable[[Dict[str, Any]], None]] = None
               ) -> Dict[str, Any]:
        """End of input (pcap replay): give up on partial events, declare every remaining hole
        a gap, then close the output and save state. `on_end` runs before the outputs close."""
        self._apply_failed(now)
        self.reasm.expire(now, force=True)
        for t in self.streams.values():
            self._report_gaps(t, t.declare(now, self.gap_window, force=True), now)
        rec = self.emit_health(now)
        if on_end is not None:
            on_end(rec)
        self.close(now, health=False)
        return rec

    def close(self, now: float, health: bool = True) -> None:
        """Clean stop: final health record, let the output settle, save state. Anything the
        output could not make durable is saved as uncommitted and reported on the next start."""
        if health:
            self.emit_health(now)
        self._drain_audit()
        for o in self.outputs:
            o.close()
        if self.state_path:
            self.save_state(extra_uncommitted=self._take_failed())
```

(i) `_load_state`: replace its first three lines (open / `json.load` / version check start) with:

```python
        with open(self.state_path, "rb") as f:  # type: ignore[arg-type]
            body = f.read()
        try:
            state = json.loads(body)
            if not isinstance(state, dict):
                raise ValueError("not a JSON object")
        except ValueError as e:
            if self.audit is not None:
                self.audit.write("state_reset", "failure", path=self.state_path,
                                 reason="unreadable: %s" % e)
            raise SystemExit("state file %s is unreadable (%s); move it aside to start over"
                             % (self.state_path, e))
        if state.get("version", 1) not in (1, STATE_VERSION):
            raise SystemExit("state file %s has unknown version %r"
                             % (self.state_path, state.get("version")))
        if self.audit is not None:
            self.audit.write("state_loaded", "success", path=self.state_path,
                             file_sha256=hashlib.sha256(body).hexdigest(),
                             streams=len(state.get("streams", {})),
                             retired=len(state.get("retired", [])))
            old = state.get("config_sha256")
            if self.config_sha256 and isinstance(old, str) and old != self.config_sha256:
                self.audit.write("config_changed", "info", old_config_sha256=old,
                                 config_sha256=self.config_sha256)
```

(the rest of `_load_state` stays).

(j) Replace `build_output` and `main`:

```python
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wd2l-receiver", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # ... every existing argument from the old main(), unchanged, in order, ending with
    # --no-rx-time; then:
    p.add_argument("--hec-audit-token-file",
                   help="token for audit records (their own token, so it can be limited to the "
                        "audit index)")
    p.add_argument("--audit-index", default="wd2l_audit", help="index for audit records")
    p.add_argument("--audit-dir", help="write hash-chained audit records here "
                                       "(deployed: /var/log/wd2l)")
    p.add_argument("--audit-min-free-mb", type=int, default=256,
                   help="free space below this raises audit_failure")
    p.add_argument("--chronyc", default="chronyc",
                   help="chronyc command for time quality (\"-c tracking\" is added)")
    p.add_argument("--log-format", choices=("text", "json"), default="text",
                   help="operational log lines: text, or one JSON object per line")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def _token(path: str) -> str:
    with open(path) as f:
        return f.read().strip()


def build_outputs(a: argparse.Namespace) -> Tuple[Output, Output]:
    """(output for events and health, output for audit records). They are the same object
    unless --hec-audit-token-file gives audit records their own token."""
    file_out = FileOutput(a.out_dir) if a.out_dir else None
    hec = audit_hec = None
    if a.hec_url:
        if not a.hec_token_file:
            raise SystemExit("--hec-url needs --hec-token-file")
        hec = HecOutput(a.hec_url, _token(a.hec_token_file), a.spool_dir, a.hec_ca,
                        a.hec_insecure, a.default_index, a.health_index, a.force_index,
                        queue_size=a.hec_queue, audit_index=a.audit_index)
        if a.hec_audit_token_file:
            audit_hec = HecOutput(a.hec_url, _token(a.hec_audit_token_file),
                                  os.path.join(a.spool_dir, "audit"), a.hec_ca, a.hec_insecure,
                                  audit_index=a.audit_index, stat_prefix="audit_",
                                  queue_size=10000)
    outs: List[Output] = [o for o in (file_out, hec) if o is not None]
    if not outs:
        raise SystemExit("need at least one output: --out-dir and/or --hec-url")
    out = outs[0] if len(outs) == 1 else MultiOutput(outs)
    if audit_hec is None:
        return out, out
    return out, (MultiOutput([file_out, audit_hec]) if file_out else audit_hec)


def _stop_counters(rx: "Receiver") -> Dict[str, int]:
    return {k: rx.counters[k] for k in ("events_delivered", "gap_events", "late_fills",
                                        "duplicates", "output_dropped")}


def main(argv: Optional[Sequence[str]] = None) -> int:
    a = build_parser().parse_args(argv)
    logsetup.setup(a.log_format, a.verbose)
    settings = {k: v for k, v in sorted(vars(a).items())}
    cfg_sha = auditlog.sha256_hex(auditlog.canonical(settings))
    tq = hostinfo.TimeQuality(shlex.split(a.chronyc) + ["-c", "tracking"])
    component = "replay" if a.pcap else "receiver"
    audit = None
    if a.audit_dir:
        try:
            audit = auditlog.AuditLog(a.audit_dir, component, 2, time_quality=tq,
                                      min_free_bytes=a.audit_min_free_mb * 1024 * 1024)
        except auditlog.AuditLocked as e:
            raise SystemExit(str(e))
    if not a.pcap:
        # Before the HEC thread starts, so only the watcher thread receives SIGUSR1.
        logsetup.SignalWatcher({signal.SIGUSR1: logsetup.debug_toggle_handler(audit)}).start()
    out, audit_out = build_outputs(a)
    if audit:
        audit.write("start", "success", pid=os.getpid(), config_sha256=cfg_sha,
                    code_sha256=hostinfo.code_sha256(), python=platform.python_version())
        audit.write("config", "info", settings=settings, config_sha256=cfg_sha)
        audit.check_time()
    kw = dict(dst_ip=a.dst_ip or None, dst_port=a.dst_port, src_ip=a.src_ip or None,
              state_path=a.state, max_event=a.max_event, max_buffer=a.max_buffer,
              reasm_timeout=a.reasm_timeout, gap_window=a.gap_window, hb_timeout=a.hb_timeout,
              health_interval=a.health_interval, stream_lost_after=a.stream_lost_after,
              stream_retention=a.stream_retention, rx_time=a.rx_time, src_port=a.src_port,
              audit=audit, audit_output=audit_out, config_sha256=cfg_sha)
    try:
        if a.pcap:
            if audit:
                audit.write("replay_run", "info", phase="start", files=[
                    os.path.basename(p) for p in sorted(a.pcap, key=lambda p: (os.path.getmtime(p), p))])
            rx = Receiver(out, **kw)
            digests: List[Dict[str, Any]] = []
            last = None
            for ts, frame in packets.iter_pcap_paths(a.pcap, digests=digests):
                rx.handle_frame(frame, ts)
                if last is None or ts - last >= 0.2:
                    rx.tick(ts)
                    last = ts

            def ended(summary: Dict[str, Any]) -> None:
                if audit is None:
                    return
                rx.audit_periodic()
                audit.write("replay_run", "success", phase="finish", files=digests,
                            events_filled=rx.counters["late_fills"],
                            duplicates_skipped=rx.counters["duplicates"],
                            open_gap_events=summary["open_gap_events"])
                audit.write("stop", "success", counters=_stop_counters(rx))

            summary = rx.finish((last or time.time()) + a.gap_window, on_end=ended)
            print(json.dumps(summary, sort_keys=True))
            return 0

        clock = steady_clock()
        rx = Receiver(out, record_clock=time.time, **kw)
        if audit:
            audit.start_verify()
        stopped_by: List[int] = []
        signal.signal(signal.SIGTERM, lambda s, _f: stopped_by.append(s))
        signal.signal(signal.SIGINT, lambda s, _f: stopped_by.append(s))
        cap = packets.LiveCapture(a.live)
        log.info("capturing on %s, dst %s:%d", a.live, a.dst_ip or "*", a.dst_port)
        last = 0.0
        while not stopped_by:
            frame = cap.recv()
            now = clock()
            if frame is not None:
                rx.handle_frame(frame, now)
            if now - last >= 0.2:
                _, drops = cap.kernel_stats()
                rx.counters["kernel_drops"] += drops
                rx.tick(now)
                rx.flush()
                last = now
        cap.close()
        if audit:
            rx.audit_periodic()
            audit.write("stop", "success", signal=signal.Signals(stopped_by[0]).name,
                        counters=_stop_counters(rx))
        rx.close(clock())
        return 0
    finally:
        for o in {id(x): x for x in (out, audit_out)}.values():
            o.close()
        if audit:
            audit.close()
```

Search the repo for other callers of `build_output` (`git grep -n build_output`) and switch them
to `build_outputs(a)[0]`.

- [ ] **Step 6: Run the receiver tests**

Run: `T tests/test_receiver_audit.py tests/test_receiver.py tests/test_end_to_end.py tests/test_hec.py tests/test_file_roundtrip.py -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add wd2l/receiver.py wd2l/packets.py tests/helpers.py tests/test_receiver_audit.py
git commit -m "Receiver and replay: audit catalog, replay file hashes, one writer per audit directory" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.9: Health records say who wrote them and where the audit chain stands

**Files:**
- Modify: `wd2l/receiver.py`
- Modify: `tests/test_receiver_audit.py` (append)

**Interfaces:**
- Consumes: `hostinfo.hostname()`, `hostinfo.TimeQuality`, `AuditLog.status()`.
- Produces: `Receiver(..., component="receiver", time_quality=None)`. Every health record gains
  `host`, `enclave` (2), `component`, `version`. Every `type=health` summary also gains
  `time_quality` (when given) and `audit_ok`, `audit_n`, `audit_hash` (when auditing). `main`
  passes `component` and `time_quality=tq`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_receiver_audit.py`:

```python
import wd2l


class FakeTQ:
    def read(self):
        return {"stratum": 3, "offset_ms": 0.1, "synced": True, "source": "gps"}

    def alarm(self, q=None):
        return None


def test_health_records_say_who_wrote_them_and_where_the_chain_stands(tmp_path):
    r, out, a = make(tmp_path, time_quality=FakeTQ())
    feed(r, ev(1), 0)
    rec = r.emit_health(0)
    assert (rec["enclave"], rec["component"], rec["version"]) == (2, "receiver", wd2l.__version__)
    assert rec["host"] and rec["time_quality"]["stratum"] == 3
    st = a.status()
    assert (rec["audit_ok"], rec["audit_n"], rec["audit_hash"], rec["audit_verify"]) == \
        (True, st["audit_n"], st["audit_hash"], None)
    start = out.kinds("stream_start")[0]
    assert start["enclave"] == 2 and start["component"] == "receiver"
```

- [ ] **Step 2: Run it to see it fail**

Run: `T tests/test_receiver_audit.py -q -k who_wrote`
Expected: `TypeError: ... unexpected keyword argument 'time_quality'`.

- [ ] **Step 3: Implement**

In `Receiver.__init__` add parameters `component: str = "receiver", time_quality: Any = None`
and store `self.component = component`, `self.tq = time_quality`,
`self.host = hostinfo.hostname()`. Add a helper and use it in `_health_record` and
`emit_health`:

```python
    def _identity(self) -> Dict[str, Any]:
        return {"host": self.host, "enclave": 2, "component": self.component,
                "version": __version__}
```

In `_health_record`: `rec = {"type": kind, "time": round(self._wall(now), 3)}` →
`rec = dict(self._identity(), type=kind, time=round(self._wall(now), 3))`.

In `emit_health`, after the `rec.update(type="health", ...)` call, add:

```python
        rec.update(self._identity())
        if self.tq is not None:
            rec["time_quality"] = self.tq.read()
        if self.audit is not None:
            rec.update(self.audit.status())
```

In `main`, add `component=component, time_quality=tq` to `kw`.

- [ ] **Step 4: Run all tests**

Run: `T -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/receiver.py tests/test_receiver_audit.py
git commit -m "Health records carry identity, time quality and the audit chain position" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1.10: The lab runs with audit on; version 0.2.0

**Files:**
- Create: `lab/fake_chronyc.py`
- Modify: `lab/run-lab.sh`, `lab/verify.py`
- Modify: `wd2l/__init__.py`, `pyproject.toml`

**Interfaces:**
- Produces: `lab/fake_chronyc.py [FLAG_FILE] -c tracking` (synced stratum 3, or "Not
  synchronised" while `FLAG_FILE` exists; Task 2.9 uses the flag); `verify.py --audit-dir DIR`
  (repeatable); `wd2l.__version__ == "0.2.0"`.

- [ ] **Step 1: Write the lab stand-in**

`lab/fake_chronyc.py`:

```python
#!/usr/bin/env python3
"""Stand-in for `chronyc -c tracking` in the lab: synchronised at stratum 3, as the hosts are
behind a GPS receiver and a stratum-2 switch, or "Not synchronised" while the flag file named
by the first argument exists (lab --fault clock)."""

import os
import sys

SYNCED = ("47505300,GPS,3,1791209000.000000000,0.000004000,0.000001000,0.000003000,-1.000,"
          "0.000,0.010,0.000100000,0.000050000,16.0,Normal")
UNSYNCED = ("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,"
            "1.000000000,1.000000000,0.0,Not synchronised")

flag = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
print(UNSYNCED if flag and os.path.exists(flag) else SYNCED)
```

- [ ] **Step 2: Turn audit on in every lab run**

In `lab/run-lab.sh`, after `MAINT=0` add:

```bash
CHRONYC="python3 $HERE/fake_chronyc.py"   # the clock-bad flag file is added once OUT is known
```

after `mkdir -p "$OUT/pcap" "$OUT/received"` add:

```bash
CHRONYC="$CHRONYC $OUT/clock-bad"
```

Extend `RX_ARGS` with `--audit-dir "$OUT/audit-e2" --chronyc "$CHRONYC"`; extend the sender's
command line in `start_sender` with `--audit-dir "$OUT/audit-e1" --chronyc "$CHRONYC"`; extend
the archive replay command with `--audit-dir "$OUT/audit-e2" --chronyc "$CHRONYC"`; and add
`--audit-dir "$OUT/audit-e1" --audit-dir "$OUT/audit-e2"` to `VERIFY_ARGS`.

- [ ] **Step 3: Check both chains in `lab/verify.py`**

Add the argument after `--sender-runs`:

```python
    p.add_argument("--audit-dir", action="append", default=[],
                   help="an audit directory whose hash chain must verify (repeatable)")
```

add `from wd2l import audit as auditlog  # noqa: E402` beside the other wd2l imports, and before
`print("sent: ...")`:

```python
    for d in a.audit_dir:
        res = auditlog.verify_dir(d)
        names = []
        for path in auditlog.audit_files(d):
            with open(path, "rb") as f:
                names += [json.loads(x)["event"] for x in auditlog.split_lines(f.read())
                          if x.endswith(b"\n")]
        if not res.ok:
            problems.append("audit chain in %s: %s" % (d, res.problems[:3]))
        if "start" not in names:
            problems.append("audit trail in %s has no start record" % d)
        print("audit %-28s %d records, chain %s%s" % (
            os.path.basename(d.rstrip("/")) + ":", res.records, "ok" if res.ok else "BROKEN",
            ", %d torn line(s)" % len(res.torn) if res.torn else ""))
```

- [ ] **Step 4: Version 0.2.0**

`wd2l/__init__.py`: `__version__ = "0.2.0"`. `pyproject.toml`: `version = "0.2.0"`.

- [ ] **Step 5: Verify**

Run: `T -q` and the byte-compile command from the plan README.
Expected: all pass. Then push the branch and check the CI `lab` job: every run prints two
`audit ... chain ok` lines and still ends in `PASS`. (Optionally try the privileged-container
lab command first.)

- [ ] **Step 6: Commit**

```bash
git add lab/fake_chronyc.py lab/run-lab.sh lab/verify.py wd2l/__init__.py pyproject.toml
git commit -m "Lab: audit on in every run, both chains verified; version 0.2.0" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Phase 1 checkpoint:** full suite green on 3.9 and 3.12, CI lab green. Stop for review.
