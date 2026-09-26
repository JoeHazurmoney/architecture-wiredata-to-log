"""Where rebuilt events go in Enclave 2: a SIEM's HTTP event collector and/or local JSONL files."""

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
from typing import Any, Dict, List, Optional

log = logging.getLogger("wd2l.outputs")


class Output:
    def event(self, evt: Dict[str, Any], stream_id: int, seq: int) -> None:
        raise NotImplementedError

    def health(self, rec: Dict[str, Any]) -> None:
        raise NotImplementedError

    def flush(self) -> None:
        pass

    def stats(self) -> Dict[str, Any]:
        return {}

    def close(self) -> None:
        self.flush()


class FileOutput(Output):
    """events.jsonl (one rebuilt event per line, with wd2l_stream/wd2l_seq) + health.jsonl."""

    def __init__(self, out_dir: str):
        os.makedirs(out_dir, exist_ok=True)
        self.events = open(os.path.join(out_dir, "events.jsonl"), "a", encoding="utf-8")
        self.healthf = open(os.path.join(out_dir, "health.jsonl"), "a", encoding="utf-8")

    def event(self, evt, stream_id, seq):
        rec = dict(evt, wd2l_stream="%016x" % stream_id, wd2l_seq=seq)
        self.events.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")

    def health(self, rec):
        self.healthf.write(json.dumps(rec, sort_keys=True) + "\n")
        self.healthf.flush()

    def flush(self):
        self.events.flush()
        self.healthf.flush()

    def close(self):
        self.flush()
        self.events.close()
        self.healthf.close()


class MultiOutput(Output):
    def __init__(self, outputs: List[Output]):
        self.outputs = outputs

    def event(self, evt, stream_id, seq):
        for o in self.outputs:
            o.event(evt, stream_id, seq)

    def health(self, rec):
        for o in self.outputs:
            o.health(rec)

    def flush(self):
        for o in self.outputs:
            o.flush()

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

    def files(self) -> List[str]:
        return sorted(f for f in os.listdir(self.path) if f.endswith(".ndjson"))

    def size(self) -> int:
        return sum(os.path.getsize(os.path.join(self.path, f)) for f in self.files())

    def write(self, body: bytes) -> bool:
        with self.lock:
            if self.size() + len(body) > self.max_bytes:
                return False
            self.counter += 1
            name = "spool-%020d-%06d.ndjson" % (time.time_ns(), self.counter)
            tmp = os.path.join(self.path, name + ".tmp")
            with open(tmp, "wb") as f:
                f.write(body)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp, os.path.join(self.path, name))
            return True


class HecOutput(Output):
    """Batch events to a SIEM's HTTP event collector (HEC format, as defined by Splunk) from a
    background thread.

    The capture loop only ever does a non-blocking queue put. If the SIEM is down, batches go
    to an on-disk spool and are retried oldest first. HTTP 400 (bad index, bad data) is not
    retried; the batch is moved to <spool>/rejected for a human to look at. An index that does
    not exist in Enclave 2 causes exactly that, so create matching indexes or use
    force_index.
    """

    def __init__(self, url: str, token: str, spool_dir: str, ca_file: Optional[str] = None,
                 insecure: bool = False, default_index: Optional[str] = None,
                 health_index: Optional[str] = None, force_index: Optional[str] = None,
                 batch_events: int = 500,
                 batch_bytes: int = 1024 * 1024, queue_size: int = 50000,
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
        self.health_index = health_index or force_index or default_index
        self.batch_events = batch_events
        self.batch_bytes = batch_bytes
        self.retry_interval = retry_interval
        self.timeout = timeout
        self.spool = Spool(spool_dir, max_spool_bytes)
        self.rejected_dir = os.path.join(spool_dir, "rejected")
        os.makedirs(self.rejected_dir, exist_ok=True)
        self.q: "queue.Queue[bytes]" = queue.Queue(maxsize=queue_size)
        self.hostname = socket.gethostname()
        self.counters = {"hec_events_sent": 0, "hec_posts_failed": 0, "hec_spooled_batches": 0,
                         "hec_rejected_batches": 0, "hec_spool_overflow_events": 0}
        self.retry_after = 0.0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, name="hec", daemon=True)
        self.thread.start()

    # -- producer side (capture thread)

    def _put(self, rec: Dict[str, Any]) -> None:
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        try:
            self.q.put_nowait(line)
        except queue.Full:
            if not self.spool.write(line + b"\n"):
                self.counters["hec_spool_overflow_events"] += 1

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
        rec["fields"] = dict(evt.get("fields", {}), wd2l_stream="%016x" % stream_id, wd2l_seq=seq)
        self._put(rec)

    def health(self, rec):
        out: Dict[str, Any] = {"time": rec.get("time", time.time()), "host": self.hostname,
                               "source": "wd2l-receiver", "sourcetype": "wd2l:health",
                               "event": rec}
        if self.health_index:
            out["index"] = self.health_index
        self._put(out)

    def stats(self):
        s = dict(self.counters)
        s["hec_queue"] = self.q.qsize()
        s["hec_spool_files"] = len(self.spool.files())
        return s

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

    def _deliver(self, body: bytes, nlines: int) -> None:
        if time.monotonic() >= self.retry_after:
            res = self._post(body)
            if res == "ok":
                self.counters["hec_events_sent"] += nlines
                return
            self.counters["hec_posts_failed"] += 1
            if res == "reject":
                self.counters["hec_rejected_batches"] += 1
                name = "rejected-%020d.ndjson" % time.time_ns()
                with open(os.path.join(self.rejected_dir, name), "wb") as f:
                    f.write(body)
                return
            self.retry_after = time.monotonic() + self.retry_interval
        if self.spool.write(body):
            self.counters["hec_spooled_batches"] += 1
        else:
            self.counters["hec_spool_overflow_events"] += nlines

    def _drain_spool(self) -> None:
        for name in self.spool.files():
            if time.monotonic() < self.retry_after:
                return
            path = os.path.join(self.spool.path, name)
            with open(path, "rb") as f:
                body = f.read()
            res = self._post(body)
            if res == "retry":
                self.counters["hec_posts_failed"] += 1
                self.retry_after = time.monotonic() + self.retry_interval
                return
            if res == "ok":
                self.counters["hec_events_sent"] += body.count(b"\n") + (not body.endswith(b"\n"))
            else:
                self.counters["hec_rejected_batches"] += 1
                os.rename(path, os.path.join(self.rejected_dir, name))
                continue
            os.unlink(path)

    def _run(self) -> None:
        while True:
            batch: List[bytes] = []
            size = 0
            deadline = time.monotonic() + 1.0
            while len(batch) < self.batch_events and size < self.batch_bytes:
                try:
                    item = self.q.get(timeout=max(0.0, deadline - time.monotonic()))
                except queue.Empty:
                    break
                batch.append(item)
                size += len(item) + 1
            if batch:
                self._deliver(b"\n".join(batch) + b"\n", len(batch))
            elif self.stop.is_set():
                return
            if time.monotonic() >= self.retry_after:
                self._drain_spool()

    def flush(self) -> None:
        pass  # the background thread sends continuously

    def close(self, wait: float = 15.0) -> None:
        self.stop.set()
        self.thread.join(wait)
        # Anything still queued goes to the spool for the next start.
        lines = []
        while True:
            try:
                lines.append(self.q.get_nowait())
            except queue.Empty:
                break
        if lines:
            self.spool.write(b"\n".join(lines) + b"\n")
