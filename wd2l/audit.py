"""Audit records: one JSON object per line, hash-chained, in append-only files.

Every record has the common fields of docs/audit-and-health.md section 3, plus `n` (1, 2,
3, ... in its directory's chain), `prev_hash` and `hash`. `hash` is the SHA-256 of the record as
canonical JSON (keys sorted, no spaces, UTF-8) without `hash`. The first record's `prev_hash` is
64 zeros. Editing, removing or reordering a record breaks the chain.

    python3 -m wd2l.audit verify DIR [--upto N --upto-hash H]     (the daily self-check)
"""

from __future__ import annotations

import argparse
import calendar
import errno
import fcntl
import glob
import hashlib
import json
import logging
import math
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__, hostinfo

log = logging.getLogger("wd2l.audit")

GENESIS = "0" * 64
FILE_GLOB = "audit-*.jsonl"

DEFAULT_MAX_BYTES = 64 * 1024 * 1024
DEFAULT_MIN_FREE = 256 * 1024 * 1024
TAIL_BYTES = 1024 * 1024
OUTCOMES = ("success", "failure", "info")
HOME_SEGMENT = {"sender": "e1-sender", "receiver": "e2-receiver", "replay": "e2-receiver"}
_UNSET = object()
MIN_FIELDS = {"seq_first"}
SUM_FIELDS = {"gaps"}
VERIFY_TIMEOUT = 6 * 3600.0     # a self-check still running after this is killed


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


class Summarizer:
    """Counts frequent events (bad input, truncation, send errors, gap fills...) so the owner
    writes one audit record per event and key a minute instead of one per occurrence (§4)."""

    def __init__(self, max_keys: int = 100):
        self.max_keys = max_keys
        self.lock = threading.Lock()
        self.items: Dict[Tuple[str, Tuple[Tuple[str, Any], ...]], Dict[str, Any]] = {}

    def note(self, event: str, key: Optional[Dict[str, Any]] = None, count: int = 1,
             **values: Any) -> None:
        """`key`: the fields that split the summary (host, source, reason...). `values`: numbers
        keep the maximum (the minimum for MIN_FIELDS, the sum for SUM_FIELDS); strings are
        collected."""
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
                    if name in SUM_FIELDS:
                        item["num"][name] = item["num"].get(name, 0) + v
                        continue
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


# ---- writing

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


def _jsonable(v: Any) -> Any:
    """A value canonical() can always serialize: non-finite floats become None, containers are
    converted recursively, and anything that is not plain JSON becomes its str()."""
    if v is None or isinstance(v, (str, bool, int)):
        return v
    if isinstance(v, float):
        return v if math.isfinite(v) else None
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (set, frozenset)):
        return [_jsonable(x) for x in sorted(v, key=repr)]
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return str(v)


class AuditLog:
    """This process's audit trail: <directory>/audit-<UTC start>.jsonl, hash-chained (§8).

    * One record is one write() and one fsync(). Files are only ever appended to. Past
      max_bytes the next record starts a new file and the chain carries on. Nothing is renamed
      or truncated, so no log rotation tool is involved.
    * A lock file keeps a second writer out, e.g. an archive replay while the live receiver runs.
    * If a write fails (disk full, I/O error) the transfer keeps going: the record is still
      queued for forwarding, with n/prev_hash/hash null; `ok` turns False (health shows
      audit_ok=false); the first record written afterwards is an audit_failure saying how many
      records the file missed. After a short write (a partial line on disk) writing resumes in a
      new file, so nothing is ever appended to a partial line.
    * While free space is below min_free_bytes (check_space), every write is such a failure, so
      the audit files never take the room the state file, spool and archive need. Writing
      resumes in a new file once there is space again.
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
        self.verify_files: List[Any] = []     # the child's stdout and stderr
        self.verify_timeout = VERIFY_TIMEOUT
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
            rec["time_quality"] = _jsonable(self.tq.read())
        return rec

    def write(self, event: str, outcome: str = "info", **fields: Any) -> Dict[str, Any]:
        """Write one record (the common fields plus `fields`; None values are left out), queue
        it for forwarding, and return it."""
        if outcome not in OUTCOMES:
            raise ValueError("outcome must be one of %s" % (OUTCOMES,))
        with self.lock:
            rec = self._base(event, outcome)
            rec.update((k, _jsonable(v)) for k, v in fields.items() if v is not None)
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
        if self.low_space:
            self._close_file()      # resume in a new file once there is space again
            return self._failed(rec, OSError(errno.ENOSPC, "free space below the audit floor "
                                             "(--audit-min-free-mb, %d bytes)" % self.min_free))
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
            if not self.low_space:      # below the floor, check_space's low_space record says why
                fail = self._base("audit_failure", "failure")
                fail.update(reason="write_failed", error=str(e), n=None, prev_hash=None,
                            hash=None)
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
        """Compare free space with the floor. Below it, every write fails (see _append) until
        a later call finds space again. The owners call this at start and about once a minute."""
        try:
            free = self._disk_usage(self.dir).free
        except OSError:
            return
        low = free < self.min_free
        if low != self.low_space:
            with self.lock:
                self.low_space = low
            if low:
                log.error("audit directory %s: %d bytes free, below %d", self.dir, free, self.min_free)
                self.write("audit_failure", "failure", reason="low_space", free_bytes=free,
                           min_free_bytes=self.min_free)
            else:
                self.write("audit_failure", "info", reason="space_ok", free_bytes=free)

    def start_verify(self) -> None:
        """Check the chain in a child process (`python3 -m wd2l.audit verify`), up to where it
        stands now. A child keeps the capture loop's interpreter free. Its output goes to
        temporary files, not pipes: a pipe read only once the child has exited fills up (one
        line per audit file) and the child never exits. A child that can't be started is a
        failed check, never an exception for the caller."""
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
        files: List[Any] = []
        try:
            files = [tempfile.TemporaryFile(), tempfile.TemporaryFile()]
            self.verify_proc = subprocess.Popen(
                [sys.executable, "-m", "wd2l.audit", "verify", self.dir, "--upto", str(n),
                 "--upto-hash", h], stdout=files[0], stderr=files[1], env=env)
        except (OSError, subprocess.SubprocessError) as e:
            for f in files:
                f.close()
            self._verify_failed("could not start", str(e))
            return
        self.verify_files = files

    def _end_verify(self) -> Tuple[bytes, bytes]:
        """Forget the child; return what it wrote to stdout and stderr."""
        self.verify_proc = None
        out = []
        for f in self.verify_files:
            try:
                f.seek(0)
                out.append(f.read())
            except OSError:
                out.append(b"")
            f.close()
        self.verify_files = []
        return (out[0], out[1]) if len(out) == 2 else (b"", b"")

    def _verify_failed(self, reason: str, error: str) -> Dict[str, Any]:
        log.error("audit chain self-check %s: %s", reason, error)
        self.verify_result = "failed"
        self.write("audit_verify", "failure", upto=self.verify_upto, reason=reason, error=error)
        return {"result": "failed", "files": [], "problems": ["self-check %s: %s" % (reason, error)]}

    def poll_verify(self, wait: bool = False) -> Optional[Dict[str, Any]]:
        """Collect a finished self-check and record it as audit_verify. A child still running
        after verify_timeout seconds is killed, and the check is recorded as failed."""
        p = self.verify_proc
        if p is None:
            return None
        if not wait and p.poll() is None:
            if self.last_verify is None or self.clock() - self.last_verify < self.verify_timeout:
                return None
            p.kill()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                pass
            self._end_verify()
            return self._verify_failed("timeout", "still running after %d s, killed"
                                       % self.verify_timeout)
        p.wait()
        out, err = self._end_verify()
        try:
            res = json.loads(out)
            if not isinstance(res, dict):
                raise ValueError("not a JSON object")
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
            for f in self.verify_files:
                f.close()
            self.verify_files = []
            self._close_file()
            if self._lockfd is not None:
                os.close(self._lockfd)
                self._lockfd = None


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
    if res.records == 0 and a.upto is None:
        # An empty or wiped directory proves nothing (same wording as wd2l-audit-report).
        res.problems.append("no audit records found")
    print(json.dumps(res.to_json(), sort_keys=True))
    return 0 if res.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
