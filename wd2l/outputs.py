"""Where rebuilt events go in Enclave 2: a SIEM's HTTP event collector and/or local JSONL files.

Delivery contract with the receiver:

* ``event()`` hands an event over. The output owns it from then on, but it is not safe yet.
* ``pending()`` lists events handed over that are not yet durable (accepted by the SIEM, written
  to the on-disk spool, or fsync'd to a file). The receiver saves these in its state file as
  "uncommitted", so a crash turns them into reported gaps that an archive replay can fill,
  instead of silently losing them.
* ``take_failed()`` returns events the output gave up on (queue full, spool full). The receiver
  reports them as gaps.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from .audit import canonical, ts_epoch

log = logging.getLogger("wd2l.outputs")

Key = Tuple[int, int]  # (stream_id, seq)


class Output:
    def event(self, evt: Dict[str, Any], stream_id: int, seq: int) -> None:
        raise NotImplementedError

    def health(self, rec: Dict[str, Any]) -> None:
        raise NotImplementedError

    def audit(self, rec: Dict[str, Any]) -> None:
        """One of this host's audit records. Never dropped, like health records."""
        raise NotImplementedError

    def flush(self) -> None:
        """Make everything handed over so far durable, where this output can do that itself."""

    def pending(self) -> Dict[int, Set[int]]:
        """stream_id -> sequence numbers handed over but not yet durable."""
        return {}

    def take_failed(self) -> List[Key]:
        """Events this output gave up on since the last call."""
        return []

    def stats(self) -> Dict[str, Any]:
        return {}

    def close(self) -> None:
        self.flush()


def _merge(into: Dict[int, Set[int]], more: Dict[int, Set[int]]) -> None:
    for sid, seqs in more.items():
        into.setdefault(sid, set()).update(seqs)


class FileOutput(Output):
    """events.jsonl (one rebuilt event per line, with wd2l_stream/wd2l_seq) + health.jsonl.

    An event counts as durable once flush() has fsync'd the file."""

    def __init__(self, out_dir: str):
        os.makedirs(out_dir, exist_ok=True)
        self.dir = out_dir
        self._extra: Dict[str, Any] = {}
        self.events = open(os.path.join(out_dir, "events.jsonl"), "a", encoding="utf-8")
        self.healthf = open(os.path.join(out_dir, "health.jsonl"), "a", encoding="utf-8")
        self._pending: Dict[int, Set[int]] = {}
        self.closed = False

    def event(self, evt, stream_id, seq):
        rec = dict(evt, wd2l_stream="%016x" % stream_id, wd2l_seq=seq)
        self.events.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
        self._pending.setdefault(stream_id, set()).add(seq)

    def health(self, rec):
        self.healthf.write(json.dumps(rec, sort_keys=True) + "\n")
        self.healthf.flush()

    def _file(self, name: str):
        f = self._extra.get(name)
        if f is None:
            f = self._extra[name] = open(os.path.join(self.dir, name), "a", encoding="utf-8")
        return f

    def audit(self, rec):
        f = self._file("audit.jsonl")
        f.write(canonical(rec).decode("utf-8") + "\n")
        f.flush()

    def flush(self):
        if self.closed:
            return
        self.events.flush()
        self.healthf.flush()
        if self._pending:
            os.fsync(self.events.fileno())
            self._pending = {}

    def pending(self):
        return {sid: set(s) for sid, s in self._pending.items()}

    def close(self):
        if self.closed:
            return
        self.flush()
        os.fsync(self.healthf.fileno())
        for f in self._extra.values():
            f.flush()
            os.fsync(f.fileno())
            f.close()
        self.events.close()
        self.healthf.close()
        self.closed = True


class MultiOutput(Output):
    def __init__(self, outputs: List[Output]):
        self.outputs = outputs

    def event(self, evt, stream_id, seq):
        for o in self.outputs:
            o.event(evt, stream_id, seq)

    def health(self, rec):
        for o in self.outputs:
            o.health(rec)

    def audit(self, rec):
        for o in self.outputs:
            o.audit(rec)

    def flush(self):
        for o in self.outputs:
            o.flush()

    def pending(self):
        out: Dict[int, Set[int]] = {}
        for o in self.outputs:
            _merge(out, o.pending())
        return out

    def take_failed(self):
        failed: List[Key] = []
        for o in self.outputs:
            failed.extend(o.take_failed())
        return failed

    def stats(self):
        out: Dict[str, Any] = {}
        for o in self.outputs:
            out.update(o.stats())
        return out

    def close(self):
        for o in self.outputs:
            o.close()


# ---------------------------------------------------------------- SIEM (HTTP event collector)

class Spool:
    """Directory of HEC request bodies that could not be delivered yet. Oldest first."""

    def __init__(self, path: str, max_bytes: int):
        self.path = path
        self.max_bytes = max_bytes
        self.lock = threading.Lock()
        self.counter = 0
        os.makedirs(path, exist_ok=True)
        self._size = sum(os.path.getsize(os.path.join(path, f)) for f in self.files())

    def files(self) -> List[str]:
        return sorted(f for f in os.listdir(self.path) if f.endswith(".ndjson"))

    def size(self) -> int:
        return self._size

    def write(self, body: bytes) -> bool:
        with self.lock:
            if self._size + len(body) > self.max_bytes:
                return False
            self.counter += 1
            name = "spool-%020d-%06d.ndjson" % (time.time_ns(), self.counter)
            tmp = os.path.join(self.path, name + ".tmp")
            try:
                with open(tmp, "wb") as f:
                    f.write(body)
                    f.flush()
                    os.fsync(f.fileno())
                os.rename(tmp, os.path.join(self.path, name))
            except OSError as e:
                log.error("spool write failed: %s", e)
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                return False
            self._size += len(body)
            return True

    def replace(self, name: str, body: bytes) -> None:
        """Rewrite a spool file with what is left of it (atomic)."""
        path = os.path.join(self.path, name)
        with self.lock:
            old = os.path.getsize(path)
            tmp = path + ".tmp"
            with open(tmp, "wb") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            self._size += len(body) - old

    def remove(self, name: str, to_dir: Optional[str] = None) -> None:
        path = os.path.join(self.path, name)
        with self.lock:
            size = os.path.getsize(path)
            if to_dir:
                os.rename(path, os.path.join(to_dir, name))
            else:
                os.unlink(path)
            self._size -= size


class HecOutput(Output):
    """Batch events to a SIEM's HTTP event collector (HEC format, as defined by Splunk) from a
    background thread.

    The capture loop only ever does a non-blocking queue put: no disk I/O, no network. If the
    queue is full the event is given up (take_failed) and the receiver reports it as a gap; the
    pcap archive still has it. If the SIEM is down, batches go to an on-disk spool and are
    retried oldest first.

    HTTP 400 (bad index, bad data) is not retried as a batch. The batch is re-posted one event
    at a time so only the events the SIEM refuses go to <spool>/rejected for a human to look at.
    An index that does not exist in Enclave 2 is the usual cause, so create matching indexes or
    use force_index. The SIEM may already have indexed some events of a refused batch, so the
    re-post can create duplicates (``| dedup wd2l_stream wd2l_seq``); that is preferred over loss.
    """

    def __init__(self, url: str, token: str, spool_dir: str, ca_file: Optional[str] = None,
                 insecure: bool = False, default_index: Optional[str] = None,
                 health_index: Optional[str] = None, force_index: Optional[str] = None,
                 audit_index: str = "wd2l_audit", stat_prefix: str = "",
                 batch_events: int = 500,
                 batch_bytes: int = 1024 * 1024, queue_size: int = 100000,
                 retry_interval: float = 10.0, max_spool_bytes: int = 10 * 1024 ** 3,
                 timeout: float = 10.0):
        self.url = url.rstrip("/") + "/services/collector/event"
        self.headers = {"Authorization": "Splunk " + token, "Content-Type": "application/json"}
        if url.startswith("https"):
            self.ctx: Optional[ssl.SSLContext] = ssl.create_default_context(cafile=ca_file)
            if insecure:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
        else:
            self.ctx = None
        self.default_index = default_index
        self.force_index = force_index
        self.audit_index = audit_index
        self.stat_prefix = stat_prefix
        self.health_index = health_index or force_index or default_index
        self.batch_events = batch_events
        self.batch_bytes = batch_bytes
        self.retry_interval = retry_interval
        self.timeout = timeout
        self.spool = Spool(spool_dir, max_spool_bytes)
        self.rejected_dir = os.path.join(spool_dir, "rejected")
        os.makedirs(self.rejected_dir, exist_ok=True)
        self.q: "queue.Queue[Tuple[bytes, Optional[Key]]]" = queue.Queue(maxsize=queue_size)
        self.hostname = socket.gethostname()
        self.counters = {"hec_events_sent": 0, "hec_posts_failed": 0, "hec_spooled_batches": 0,
                         "hec_rejected_batches": 0, "hec_rejected_events": 0,
                         "hec_spool_overflow_events": 0, "hec_queue_overflow_events": 0,
                         "hec_audit_index_refused": 0, "hec_records_lost": 0}
        self.retry_after = 0.0
        self._plock = threading.Lock()
        self._pending: Dict[int, Set[int]] = {}
        self._failed: List[Key] = []
        self.closed = False
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="hec", daemon=True)
        self.thread.start()

    # -- bookkeeping shared by both threads

    def _settle(self, keys: Iterable[Optional[Key]], failed: bool = False) -> None:
        with self._plock:
            for k in keys:
                if k is None:
                    continue
                s = self._pending.get(k[0])
                if s is not None:
                    s.discard(k[1])
                    if not s:
                        del self._pending[k[0]]
                if failed:
                    self._failed.append(k)

    def pending(self):
        with self._plock:
            return {sid: set(s) for sid, s in self._pending.items()}

    def take_failed(self):
        with self._plock:
            failed, self._failed = self._failed, []
        return failed

    # -- producer side (capture thread)

    def _put(self, rec: Dict[str, Any], key: Optional[Key]) -> None:
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if key is not None:
            with self._plock:
                self._pending.setdefault(key[0], set()).add(key[1])
        try:
            self.q.put_nowait((line, key))
            return
        except queue.Full:
            pass
        if key is None:
            # Health and audit records are few and they are how loss gets reported: never drop
            # one quietly.
            if not self.spool.write(line + b"\n"):
                self.counters["hec_records_lost"] += 1
                log.error("health or audit record lost: queue and spool both full")
            return
        self.counters["hec_queue_overflow_events"] += 1
        self._settle([key], failed=True)

    def event(self, evt, stream_id, seq):
        rec: Dict[str, Any] = {"event": evt["_raw"]}
        if "_time" in evt:
            rec["time"] = evt["_time"]
        for k in ("host", "source", "sourcetype", "index"):
            if k in evt:
                rec[k] = evt[k]
        if self.force_index:
            rec["index"] = self.force_index
        elif "index" not in rec and self.default_index:
            rec["index"] = self.default_index
        if rec.get("index") == self.audit_index:
            # Only wd2l writes audit records: an imported event can't land among them.
            self.counters["hec_audit_index_refused"] += 1
            if self.default_index and self.default_index != self.audit_index:
                rec["index"] = self.default_index
            else:
                del rec["index"]
        rec["fields"] = dict(evt.get("fields", {}), wd2l_stream="%016x" % stream_id, wd2l_seq=seq)
        self._put(rec, (stream_id, seq))

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

    def stats(self):
        s = dict(self.counters)
        s["hec_queue"] = self.q.qsize()
        s["hec_spool_files"] = len(self.spool.files())
        return {self.stat_prefix + k: v for k, v in s.items()}

    # -- consumer side (hec thread)

    def _post(self, body: bytes) -> str:
        """Returns "ok", "retry" or "reject"."""
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                r.read()
                return "ok"
        except urllib.error.HTTPError as e:
            detail = e.read()[:500]
            log.error("HEC HTTP %d: %r", e.code, detail)
            return "reject" if e.code == 400 else "retry"
        except (urllib.error.URLError, OSError) as e:
            log.error("HEC unreachable: %s", e)
            return "retry"

    def _reject(self, lines: List[bytes]) -> None:
        self.counters["hec_rejected_batches"] += 1
        self.counters["hec_rejected_events"] += len(lines)
        name = "rejected-%020d.ndjson" % time.time_ns()
        with open(os.path.join(self.rejected_dir, name), "wb") as f:
            f.write(b"".join(x + b"\n" for x in lines))
            f.flush()
            os.fsync(f.fileno())

    def _post_lines(self, lines: List[bytes]) -> Tuple[str, List[bytes]]:
        """Post a batch. On a 400, post the lines one by one and reject only the bad ones.

        Returns ("done", []) when every line was sent or rejected, or ("retry", unsent) if the
        SIEM stopped answering part way."""
        res = self._post(b"".join(x + b"\n" for x in lines))
        if res == "ok":
            self.counters["hec_events_sent"] += len(lines)
            return "done", []
        self.counters["hec_posts_failed"] += 1
        if res == "retry":
            self.retry_after = time.monotonic() + self.retry_interval
            return "retry", lines
        if len(lines) == 1:
            self._reject(lines)
            return "done", []
        bad: List[bytes] = []
        for i, line in enumerate(lines):
            one = self._post(line + b"\n")
            if one == "ok":
                self.counters["hec_events_sent"] += 1
            elif one == "reject":
                bad.append(line)
            else:
                self.counters["hec_posts_failed"] += 1
                self.retry_after = time.monotonic() + self.retry_interval
                if bad:
                    self._reject(bad)
                return "retry", lines[i:]
        if bad:
            self._reject(bad)
        return "done", []

    def _deliver(self, items: List[Tuple[bytes, Optional[Key]]]) -> None:
        lines = [x[0] for x in items]
        keys = [x[1] for x in items]
        unsent = lines
        if time.monotonic() >= self.retry_after:
            res, unsent = self._post_lines(lines)
            if res == "done":
                self._settle(keys)
                return
        n = len(unsent)
        sent_keys, unsent_keys = keys[:len(keys) - n], keys[len(keys) - n:]
        self._settle(sent_keys)
        if self.spool.write(b"".join(x + b"\n" for x in unsent)):
            self.counters["hec_spooled_batches"] += 1
            self._settle(unsent_keys)
        else:
            self.counters["hec_spool_overflow_events"] += n
            self._settle(unsent_keys, failed=True)

    def _drain_spool(self) -> None:
        for name in self.spool.files():
            if time.monotonic() < self.retry_after:
                return
            with open(os.path.join(self.spool.path, name), "rb") as f:
                lines = [x for x in f.read().split(b"\n") if x]
            if not lines:
                self.spool.remove(name)
                continue
            res, unsent = self._post_lines(lines)
            if res == "retry":
                if len(unsent) < len(lines):
                    self.spool.replace(name, b"".join(x + b"\n" for x in unsent))
                return
            self.spool.remove(name)

    def _run(self) -> None:
        while True:
            batch: List[Tuple[bytes, Optional[Key]]] = []
            size = 0
            deadline = time.monotonic() + 1.0
            while len(batch) < self.batch_events and size < self.batch_bytes:
                try:
                    item = self.q.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    break
                batch.append(item)
                size += len(item[0]) + 1
            if batch:
                self._deliver(batch)
            elif self.stop.is_set():
                return
            if time.monotonic() >= self.retry_after and not self.stop.is_set():
                self._drain_spool()

    def flush(self) -> None:
        pass  # the background thread sends continuously

    def close(self, wait: float = 15.0) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        self.thread.join(wait)
        if self.thread.is_alive():
            # Still stuck on a post. Leave its batch pending: the receiver records it as
            # uncommitted, so a crash here costs duplicates at worst, never silent loss.
            log.warning("HEC thread still busy after %.0fs; its batch stays uncommitted", wait)
        # Anything still queued goes to the spool for the next start.
        items: List[Tuple[bytes, Optional[Key]]] = []
        while True:
            try:
                items.append(self.q.get_nowait())
            except queue.Empty:
                break
        if items:
            keys = [k for _, k in items]
            if self.spool.write(b"".join(x + b"\n" for x, _ in items)):
                self._settle(keys)
            else:
                self.counters["hec_spool_overflow_events"] += sum(k is not None for k in keys)
                self._settle(keys, failed=True)
