"""Enclave 1 sidecar: take events from the log aggregator (JSON lines over TCP), send them one way as WD2L UDP frames.

    log aggregator --JSON lines (127.0.0.1:10070)--> wd2l-sender --UDP--> black-hole IP

Every event gets the next sequence number. A heartbeat goes out every second with the last
sequence number and counters, so the receiver can tell "quiet" from "broken".

With --state, the sender also counts its own restarts and tells the receiver which stream came
before this one and how far it got, so the receiver can spot a lost tail or a whole missed run.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import logging
import os
import platform
import select
import signal
import socket
import socketserver
import struct
import termios
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Sequence, Set, Tuple

from . import __version__
from . import audit as auditlog
from . import hostinfo, logsetup, opaque, wire
from .reconcile import SetHash

log = logging.getLogger("wd2l.sender")
log_input = logging.getLogger("wd2l.sender.input")

IP_MTU_DISCOVER = getattr(socket, "IP_MTU_DISCOVER", 10)
IP_PMTUDISC_DO = getattr(socket, "IP_PMTUDISC_DO", 2)
SRC_SEQ_FIELD = "wd2l_src_seq"
TX_TIME_FIELD = "wd2l_tx_time"
OPAQUE_FIELD = "wd2l_opaque"
OPAQUE_BYTES_FIELD = "wd2l_opaque_bytes"
MAX_LINE = 16 * 1024 * 1024
ERROR_LOG_EVERY = 10.0
# Sender.periodic(): the per-minute health record, audit summaries and checks the docs promise.
PERIODIC_EVERY = 60.0
MAX_UDP_PAYLOAD = 65507     # 65,535 less the IPv4 and UDP headers
# The final heartbeat ends a run, and nothing acknowledges it: lost, Enclave 2 sees stream_lost
# instead of stream_end and has no reconcile record until its hourly pass. So it goes out this
# many times, identical, this far apart; the receiver acts on the first (ICD §8).
FINAL_COPIES = 3
FINAL_SPACING_S = 0.05
# Frequent events become one audit record per kind and key a minute (§4).
SUMMARY_OUTCOME = {"auth_failure": "failure", "input_rejected": "failure",
                   "send_failure": "failure", "truncated": "info", "opaque_content": "info"}
SUMMARY_SEGMENT = {"auth_failure": "e1-input", "input_rejected": "e1-input"}


def new_stream_id() -> int:
    return int.from_bytes(os.urandom(8), "big") or 1


def _key(v: Any) -> Optional[str]:
    """A host or source as a summary key (the aggregator may send anything)."""
    return None if v is None else str(v)[:256]


def check_limits(max_datagram: int, max_event: int) -> None:
    """Refuse at start what the wire format can't carry (ICD), rather than at the first event,
    after it already has its sequence number (#137)."""
    if max_event < 1024:
        raise ValueError("max_event must be at least 1024")
    if not wire.OVERHEAD + 1 <= max_datagram <= MAX_UDP_PAYLOAD:
        raise ValueError("max_datagram must be %d to %d" % (wire.OVERHEAD + 1, MAX_UDP_PAYLOAD))
    if -(-max_event // (max_datagram - wire.OVERHEAD)) > wire.MAX_CHUNKS:
        raise ValueError("max_datagram %d is too small for max_event %d: an event would need "
                         "more than %d chunks" % (max_datagram, max_event, wire.MAX_CHUNKS))


class Sender:
    def __init__(self, dst: Tuple[str, int], bind_ip: Optional[str] = None,
                 max_datagram: int = wire.DEFAULT_MAX_DATAGRAM,
                 max_event: int = wire.DEFAULT_MAX_EVENT,
                 rate_pps: float = 20000.0, extra_fields: Sequence[str] = (),
                 sock: Optional[socket.socket] = None, state_path: Optional[str] = None,
                 source_seq: bool = False, tx_time: bool = True, opaque_check: bool = True,
                 bind_port: int = 0, stream_id: Optional[int] = None,
                 audit: Optional[auditlog.AuditLog] = None,
                 config_sha256: Optional[str] = None, time_quality: Any = None,
                 egress_iface: Optional[str] = None):
        check_limits(max_datagram, max_event)
        self.dst = dst
        self.max_datagram = max_datagram
        self.max_event = max_event
        self.extra_fields = tuple(extra_fields)
        # Optional per-file line counter (indexed field wd2l_src_seq): numbers events 1, 2, 3...
        # separately for each (host, source), so Enclave 2 can rebuild several interleaved files
        # and name the exact lines a gap took from each one.
        self.source_seq = source_seq
        self.src_counters: Dict[Tuple[Any, Any], int] = {}
        if source_seq and SRC_SEQ_FIELD not in self.extra_fields:
            self.extra_fields += (SRC_SEQ_FIELD,)
        # Send time (indexed field wd2l_tx_time, epoch seconds): with the receiver's
        # wd2l_rx_time it splits the delay into Enclave 1, the link, and the SIEM.
        self.tx_time = tx_time
        if tx_time and TX_TIME_FIELD not in self.extra_fields:
            self.extra_fields += (TX_TIME_FIELD,)
        # Flag long encrypted, compressed or random-looking blobs in _raw (wd2l/opaque.py).
        # Flagged events still cross unchanged; the flag is what Enclave 2 alerts on.
        self.opaque_check = opaque_check
        if opaque_check:
            self.extra_fields += tuple(f for f in (OPAQUE_FIELD, OPAQUE_BYTES_FIELD)
                                       if f not in self.extra_fields)
        self.stream_id = stream_id or new_stream_id()
        self.seq = 0
        self.events_hash = SetHash()   # §7: this run's set hash over (seq, event SHA-256)
        self.next_reconcile = time.monotonic() + 3600
        self.started = time.time()
        self.counters = {"events_sent": 0, "datagrams_sent": 0, "sender_drops": 0,
                         "truncated": 0, "bad_input": 0, "send_errors": 0,
                         "shutdown_unread_bytes": 0, "opaque_events": 0,
                         "events_in": 0, "heartbeat_trimmed": 0}
        self.lock = threading.Lock()
        self.closed = False
        self.rate = float(rate_pps)
        self.tokens = max(1.0, self.rate / 10)
        self.last_refill = time.monotonic()
        self._err_log: Dict[int, List[float]] = {}  # errno -> [last logged, suppressed since]
        self.audit = audit
        self.summary = auditlog.Summarizer()
        self.config_sha256 = config_sha256
        self.tq = time_quality
        self.hostname = audit.host if audit is not None else hostinfo.hostname()
        self.last_snapshot: Dict[str, Any] = {}
        self.egress_iface = egress_iface
        self.sysfs = "/sys/class/net"
        self.input_server: Optional["InputServer"] = None
        self.proc = hostinfo.ProcStats()
        self.stall_s = 0.0    # time spent waiting on pacing or a full send buffer
        # The records stream (§5): this sender's own audit and health records, in-band, as a
        # second stream with its own id, numbers and heartbeat, marked by flags bit 0.
        self.records = audit is not None and audit.forward
        self.rec_stream_id = new_stream_id()
        while self.rec_stream_id == self.stream_id:
            self.rec_stream_id = new_stream_id()
        self.rec_seq = 0
        self.rec_counters = {"events_sent": 0, "records_too_big": 0}
        self.rec_closed = False
        self.health_outbox: Deque[Dict[str, Any]] = deque(maxlen=100)
        self.state_path = state_path
        self.link: Dict[str, int] = {}
        if state_path:
            self._start_state()
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
            # A fixed source port (the unit uses 5514) keeps the flow the same across restarts
            # for the firewall, the tap filter and the ICD. 0 lets the kernel pick one.
            if bind_ip or bind_port:
                sock.bind((bind_ip or "", bind_port))
        self.sock = sock

    # -- restart chain

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

    # -- sending

    def _pace(self) -> None:
        if self.rate <= 0:
            return
        now = time.monotonic()
        self.tokens = min(max(1.0, self.rate / 10), self.tokens + (now - self.last_refill) * self.rate)
        self.last_refill = now
        if self.tokens < 1:
            wait = (1 - self.tokens) / self.rate
            time.sleep(wait)
            self.stall_s += wait
            self.tokens = 1.0
            self.last_refill = time.monotonic()
        self.tokens -= 1

    def _log_error(self, code: int, msg: str) -> None:
        """Log an error at most once per ERROR_LOG_EVERY seconds per errno (sends can fail
        thousands of times a second when the egress link is down)."""
        now = time.monotonic()
        last, suppressed = self._err_log.get(code, [-1e9, 0])
        if now - last >= ERROR_LOG_EVERY:
            log.error("%s%s", msg, " (%d more like this since the last message)" % suppressed
                      if suppressed else "")
            self._err_log[code] = [now, 0]
        else:
            self._err_log[code] = [last, suppressed + 1]

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
                self.stall_s += 0.001
        self.counters["sender_drops"] += 1
        self.summary.note("send_failure", {"error": errno.errorcode.get(code, str(code))})
        return False

    def _fit(self, event: Dict[str, Any]) -> bytes:
        """Serialize; if too big, cut _raw down to fit and flag it (like a SIEM's line-length limit)."""
        data = wire.serialize_event(event, self.extra_fields)
        if len(data) <= self.max_event:
            return data
        raw = event.get("_raw")
        if not isinstance(raw, str):
            raw = json.loads(data)["_raw"]
        raw_bytes = raw.encode("utf-8")
        trimmed = dict(event, _raw=raw)
        fields = self.extra_fields + ("wd2l_truncated",)
        trimmed["wd2l_truncated"] = len(raw_bytes)
        keep = len(raw_bytes)
        while len(data) > self.max_event:
            if keep <= 0:
                # Metadata alone is too big: keep only time and the truncation marker. Time only
                # if it is a number: a string could be any size (#137).
                trimmed = {"_raw": "", "wd2l_truncated": len(raw_bytes)}
                t = event.get("_time")
                if isinstance(t, (int, float)) and not isinstance(t, bool):
                    trimmed["_time"] = t
                data = wire.serialize_event(trimmed, ("wd2l_truncated",))
                break
            keep -= max(1, len(data) - self.max_event)
            trimmed["_raw"] = raw_bytes[:max(0, keep)].decode("utf-8", "ignore")
            data = wire.serialize_event(trimmed, fields)
        self.counters["truncated"] += 1
        self.summary.note("truncated", {"host": _key(event.get("host")),
                                        "source": _key(event.get("source"))},
                          max_original_bytes=len(raw_bytes))
        log.warning("truncated event host=%s source=%s from %d bytes",
                    event.get("host"), event.get("source"), len(raw_bytes))
        return data

    def opaque_fields(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """The opaque-content fields for this event. Both keys are always set when the check is
        on (None when nothing is found, which drops them), so an upstream value can't stand."""
        if not self.opaque_check:
            return {}
        raw = event.get("_raw")
        found = opaque.inspect(raw) if isinstance(raw, str) else None
        return {OPAQUE_FIELD: found.kind if found else None,
                OPAQUE_BYTES_FIELD: found.nbytes if found else None}

    def send_event(self, event: Dict[str, Any]) -> int:
        """Send one event. Returns its sequence number (0 if the sender has already closed)."""
        found = self.opaque_fields(event)   # depends only on the event: outside the lock
        stamped = self.source_seq or self.tx_time or self.opaque_check
        if not stamped:
            data = self._fit(event)
            digest = wire.event_digest(data)
        with self.lock:
            if self.closed:
                return 0
            self.counters["events_in"] += 1
            if stamped:
                # Stamped under the lock, together with seq, so all orders agree.
                stamps: Dict[str, Any] = dict(found)
                if found.get(OPAQUE_FIELD):
                    self.counters["opaque_events"] += 1
                    self.summary.note("opaque_content", {"host": _key(event.get("host")),
                                                         "source": _key(event.get("source"))},
                                      kinds=found[OPAQUE_FIELD],
                                      max_blob_bytes=found[OPAQUE_BYTES_FIELD])
                if self.source_seq:
                    key = (event.get("host"), event.get("source"))
                    n = self.src_counters.get(key, 0) + 1
                    self.src_counters[key] = n
                    stamps[SRC_SEQ_FIELD] = n
                if self.tx_time:
                    stamps[TX_TIME_FIELD] = round(time.time(), 3)
                data = self._fit(dict(event, **stamps))
                digest = wire.event_digest(data)
            self.seq += 1
            self.events_hash.add(self.seq, digest)
            for dg in wire.encode_event(self.stream_id, self.seq, data, self.max_datagram,
                                        digest=digest):
                self._transmit(dg)
            self.counters["events_sent"] += 1
            return self.seq

    def snapshot(self) -> Dict[str, Any]:
        """Enclave 1's state for every heartbeat (§5): input, the sender process, the egress NIC,
        time and the audit trail. Read outside the lock; values that can't be read are left out."""
        snap: Dict[str, Any] = {"stall_s": round(self.stall_s, 3)}
        srv = self.input_server
        if srv is not None:
            snap.update(clients=srv.client_count(), input_backlog_bytes=srv.backlog_bytes())
        snap.update(self.proc.read())
        if self.egress_iface:
            nic = hostinfo.nic_stats(self.egress_iface, self.sysfs)
            snap.update(nic_carrier=nic["carrier"], nic_tx_packets=nic["tx_packets"],
                        nic_tx_errors=nic["tx_errors"], nic_tx_dropped=nic["tx_dropped"])
        if self.tq is not None:
            q = self.tq.read()
            snap.update(time_stratum=q.get("stratum"), time_offset_ms=q.get("offset_ms"),
                        time_synced=q.get("synced"))
            if q.get("synced") is None:
                # chrony can't be read: the None values are left out below, so say so
                # explicitly, or Enclave 2 would see no time keys and no alarm.
                snap["time_unavailable"] = True
        if self.audit is not None:
            st = self.audit.status()
            snap.update(audit_ok=st["audit_ok"], audit_n=st["audit_n"])
        return {k: v for k, v in snap.items() if v is not None}

    def heartbeat_info(self, final: bool = False,
                       snap: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        info = dict(self.counters, sender_time=round(time.time(), 3),
                    uptime=round(time.time() - self.started, 1),
                    events_hash=self.events_hash.hex(), **self.link)
        if snap:
            info.update(snap)
        if final:
            info["final"] = True
        return info

    def _heartbeat_frame(self, final: bool, snap: Dict[str, Any]) -> bytes:
        """One packet, always: if the snapshot would make it too big, it is left out."""
        frame = wire.encode_heartbeat(self.stream_id, self.seq, self.heartbeat_info(final, snap))
        if len(frame) > self.max_datagram and snap:
            self.counters["heartbeat_trimmed"] += 1
            frame = wire.encode_heartbeat(self.stream_id, self.seq, self.heartbeat_info(final))
        return frame

    def send_heartbeat(self, final: bool = False) -> None:
        snap = self.snapshot()
        with self.lock:
            if self.closed:
                return
            self.last_snapshot = snap
            frame = self._heartbeat_frame(final, snap)
            self._transmit(frame)
            self._save_state()
            if final:
                self.closed = True
        if final:
            self._repeat_final(frame)

    def _repeat_final(self, frame: bytes) -> None:
        """The rest of a final heartbeat's copies (FINAL_COPIES), spaced so that one burst of
        loss doesn't take them all."""
        for _ in range(FINAL_COPIES - 1):
            time.sleep(FINAL_SPACING_S)
            with self.lock:
                self._transmit(frame)

    def count_bad_input(self, reason: str = "bad_json") -> None:
        with self.lock:
            self.counters["bad_input"] += 1
            self.counters["events_in"] += 1
        self.summary.note("input_rejected", {"reason": reason})

    def count_unread(self, nbytes: int) -> None:
        with self.lock:
            self.counters["shutdown_unread_bytes"] += nbytes

    def flush_summaries(self) -> None:
        """The last minute's frequent events, one audit record per kind and key."""
        if self.audit is None:
            return
        for event, fields in self.summary.drain():
            fields.setdefault("segment", SUMMARY_SEGMENT.get(event))
            self.audit.write(event, SUMMARY_OUTCOME.get(event, "info"),
                             stream="%016x" % self.stream_id, **fields)

    def reconcile_record(self) -> None:
        """§7: this side's numbers at the current cut, for the reconcile report."""
        if self.audit is None:
            return
        with self.lock:
            fields = dict(stream="%016x" % self.stream_id, cut=self.seq, last_seq=self.seq,
                          events_in=self.counters["events_in"],
                          events_sent=self.counters["events_sent"],
                          sender_hash=self.events_hash.hex())
        self.audit.write("reconcile", "info", **fields)

    def periodic(self) -> None:
        """About once a minute, from the heartbeat thread: summaries, time quality, free space
        and the daily self-check of the audit chain."""
        if self.audit is None:
            return
        self.flush_summaries()
        if time.monotonic() >= self.next_reconcile:
            self.next_reconcile += 3600
            self.reconcile_record()
        self.audit.check_time()
        self.audit.check_space()
        self.audit.maybe_verify()
        if self.records:
            self.health_outbox.append(self.health_record())

    def health_record(self) -> Dict[str, Any]:
        """The sender's per-minute health summary (§2): counters, the latest snapshot, where the
        audit chain stands, and time quality."""
        with self.lock:
            rec: Dict[str, Any] = dict(self.counters, stream="%016x" % self.stream_id,
                                       last_seq=self.seq)
        rec.update(type="health", time=round(time.time(), 3), host=self.hostname, enclave=1,
                   component="sender", segment="e1-sender", version=__version__)
        rec.update(self.last_snapshot)
        if self.audit is not None:
            rec.update(self.audit.status())
        if self.tq is not None:
            rec["time_quality"] = self.tq.read()
        return rec

    def _record_body(self, kind: str, rec: Dict[str, Any]) -> bytes:
        t = rec.get("time")
        if not isinstance(t, (int, float)):
            t = auditlog.ts_epoch(rec["ts"]) if isinstance(rec.get("ts"), str) else time.time()
        return wire.serialize_event({"_time": t, "host": self.hostname, "source": "wd2l-sender",
                                     "sourcetype": "wd2l:sender:" + kind,
                                     "_raw": auditlog.canonical(rec).decode("utf-8")})

    def flush_records(self, final: bool = False) -> None:
        """Every heartbeat: send queued audit and health records on the records stream, then
        its heartbeat. The local audit files stay the official copy; these are for Enclave 2."""
        if not self.records:
            return
        items = [("audit", r) for r in self.audit.take_outbox()]  # type: ignore[union-attr]
        while self.health_outbox:
            items.append(("health", self.health_outbox.popleft()))
        bodies = []
        for kind, rec in items:
            body = self._record_body(kind, rec)
            if len(body) > self.max_event:
                self.rec_counters["records_too_big"] += 1
                log.warning("%s record %s too big to send in-band (%d bytes); it is in the "
                            "local audit file", kind, rec.get("event", rec.get("type")), len(body))
                continue
            bodies.append(body)
        with self.lock:
            if self.rec_closed:
                return
            for body in bodies:
                self.rec_seq += 1
                for dg in wire.encode_event(self.rec_stream_id, self.rec_seq, body,
                                            self.max_datagram, flags=wire.FLAG_RECORDS):
                    self._transmit(dg)
                self.rec_counters["events_sent"] += 1
            info: Dict[str, Any] = dict(self.rec_counters, sender_time=round(time.time(), 3),
                                        uptime=round(time.time() - self.started, 1),
                                        outbox_dropped=self.audit.outbox_dropped)  # type: ignore[union-attr]
            if final:
                info["final"] = True
                self.rec_closed = True
            frame = wire.encode_heartbeat(self.rec_stream_id, self.rec_seq, info,
                                          flags=wire.FLAG_RECORDS)
            self._transmit(frame)
        if final:
            self._repeat_final(frame)


# ---------------------------------------------------------------- log aggregator input (JSON lines over TCP)

def _is_header(obj: Dict[str, Any]) -> bool:
    """The optional first line: {"authToken": ..., "fields": {...}}. A line without authToken
    only counts as a header if "fields" is its only key, so a real event is never swallowed."""
    return "authToken" in obj or set(obj) == {"fields"}


def _unread_bytes(sock: socket.socket) -> int:
    """Bytes the kernel has received (and acknowledged) that nobody has read yet."""
    try:
        buf = fcntl.ioctl(sock.fileno(), termios.FIONREAD, b"\0\0\0\0")
        return struct.unpack("i", buf)[0]
    except OSError:
        return 0


class CriblHandler(socketserver.BaseRequestHandler):
    """One log aggregator connection (e.g. Cribl Stream's TCP JSON destination): optional
    header line, then one JSON event per line.

    Reads with select() rather than a blocking readline so it can react to shutdown: once the
    server is stopping it keeps reading whatever is already arriving (the aggregator thinks
    those bytes are delivered), and stops when the connection goes quiet or the drain time runs
    out. Whatever is left unread then is counted in shutdown_unread_bytes."""

    def handle(self) -> None:
        srv: "InputServer" = self.server  # type: ignore[assignment]
        with srv.handlers_lock:
            srv.conns.add(self.request)
        try:
            self._run(srv, self.request)
        finally:
            with srv.handlers_lock:
                srv.handlers.discard(threading.current_thread())
                srv.conns.discard(self.request)

    def _run(self, srv: "InputServer", sock: socket.socket) -> None:
        self.defaults: Dict[str, Any] = {}
        self.first_line = True
        buf = b""
        skipping = False
        started = False
        deadline: Optional[float] = None
        while True:
            if srv.stopping.is_set() and deadline is None:
                deadline = time.monotonic() + srv.drain_timeout
            if deadline is not None and time.monotonic() > deadline:
                break
            ready, _, _ = select.select([sock], [], [], 0.2)
            if not ready:
                if deadline is not None:
                    break  # quiet while stopping: everything sent to us has been read
                continue
            try:
                chunk = sock.recv(65536)
            except OSError:
                return
            if not chunk:
                if buf and not skipping:
                    self._line(srv, buf)
                return
            if not started:
                started = True
                if chunk[:2] == b"\x1f\x8b":
                    log_input.error("gzip data from %s: turn off compression on the log "
                                    "aggregator's output", self.client_address)
                    srv.sender.summary.note("input_rejected", {"reason": "gzip"},
                                            client=self.client_address[0])
                    return
            parts = (buf + chunk).split(b"\n")
            buf = parts.pop()
            if skipping and parts:
                parts.pop(0)  # the end of a line that was too long
                skipping = False
            for line in parts:
                if not self._line(srv, line):
                    return
            if len(buf) > MAX_LINE:
                srv.sender.count_bad_input("line_too_long")
                log_input.warning("dropped input line over %d bytes", MAX_LINE)
                buf = b""
                skipping = True
                self.first_line = False
        # Stopping: what is left was acknowledged to the aggregator but will not be sent.
        unread = len(buf) + _unread_bytes(sock)
        if unread:
            srv.sender.count_unread(unread)
            log_input.warning("shutdown: %d bytes from %s left unread", unread, self.client_address)

    def _line(self, srv: "InputServer", line: bytes) -> bool:
        """Handle one input line. Returns False to close the connection."""
        line = line.strip()
        if not line:
            return True
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
        self.first_line = False
        for k, v in self.defaults.items():
            obj.setdefault(k, v)
        srv.sender.send_event(obj)
        return True


class InputServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr: Tuple[str, int], sender: Sender, auth_token: Optional[str] = None,
                 rcvbuf: int = 256 * 1024, drain_timeout: float = 2.0):
        self.sender = sender
        self.auth_token = auth_token
        self.rcvbuf = rcvbuf
        self.drain_timeout = drain_timeout
        self.stopping = threading.Event()
        self.handlers: Set[threading.Thread] = set()
        self.conns: Set[socket.socket] = set()
        self.handlers_lock = threading.Lock()
        super().__init__(addr, CriblHandler)

    def client_count(self) -> int:
        with self.handlers_lock:
            return len(self.conns)

    def backlog_bytes(self) -> int:
        """Bytes the aggregator has handed over that the sender hasn't read yet."""
        with self.handlers_lock:
            socks = list(self.conns)
        return sum(_unread_bytes(s) for s in socks)

    def server_bind(self) -> None:
        # A small receive buffer (inherited by accepted connections) bounds how much data the
        # kernel acknowledges to the aggregator ahead of the sender actually reading it.
        if self.rcvbuf:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        super().server_bind()

    def process_request(self, request, client_address) -> None:
        t = threading.Thread(target=self.process_request_thread,
                             args=(request, client_address), daemon=True)
        with self.handlers_lock:
            self.handlers.add(t)
        t.start()

    def drain(self) -> None:
        """Call after serve_forever() returns. Stops input without dropping data the kernel has
        already acknowledged: connections still waiting in the accept queue are taken on too,
        the listener is closed, and every connection gets to finish what is already arriving."""
        self.stopping.set()
        self.socket.setblocking(False)
        while True:
            try:
                request, addr = self.socket.accept()
            except OSError:
                break
            request.setblocking(True)
            self.process_request(request, addr)
        self.server_close()
        with self.handlers_lock:
            threads = list(self.handlers)
        for t in threads:
            t.join(self.drain_timeout + 1.0)


def _heartbeat_loop(sender: Sender, interval: float, stop: threading.Event,
                    stats_every: float, periodic_every: float = PERIODIC_EVERY) -> None:
    """Heartbeats; the stats log line every stats_every (--stats-interval); and the per-minute
    work on its own timer, so quieting the journal can't slow the health records and the audit
    checks (#135)."""
    next_stats = time.monotonic() + stats_every
    next_periodic = time.monotonic() + periodic_every
    last_error: Optional[float] = None
    while not stop.wait(interval):
        try:
            sender.send_heartbeat()
            now = time.monotonic()
            if now >= next_stats:
                next_stats += stats_every
                with sender.lock:
                    counters = json.dumps(sender.counters, sort_keys=True)
                log.info("stream=%016x last_seq=%d %s", sender.stream_id, sender.seq, counters,
                         extra={"stream": "%016x" % sender.stream_id, "seq": sender.seq})
            if now >= next_periodic:
                next_periodic += periodic_every
                sender.periodic()
            sender.flush_records()
        except Exception as e:
            # Ended, this thread would stop heartbeats, the records stream and state saves
            # while data kept flowing. Log it (traceback at most once a minute) and go on.
            now = time.monotonic()
            if last_error is None or now - last_error >= 60:
                last_error = now
                log.error("heartbeat loop error, heartbeats go on: %s", e, exc_info=True)


def _hostport(s: str) -> Tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


def _bind_addr(s: Optional[str]) -> Tuple[Optional[str], int]:
    """--bind value: "IP" (kernel picks the source port) or "IP:PORT"."""
    if not s:
        return None, 0
    return _hostport(s) if ":" in s else (s, 0)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wd2l-sender", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--listen", default="127.0.0.1:10070", help="TCP JSON listen address")
    p.add_argument("--dst", default="10.255.255.2:5514", help="black-hole IP:port")
    p.add_argument("--bind", metavar="IP[:PORT]",
                   help="source address: the egress NIC's IP, and optionally a fixed UDP "
                        "source port (the unit uses 10.255.255.1:5514)")
    p.add_argument("--max-datagram", type=int, default=wire.DEFAULT_MAX_DATAGRAM,
                   help="UDP payload bytes per packet (1472 for 1500 MTU, 8972 for 9000)")
    p.add_argument("--max-event", type=int, default=wire.DEFAULT_MAX_EVENT,
                   help="events bigger than this are truncated and flagged")
    p.add_argument("--rate-pps", type=float, default=20000, help="packet rate cap, 0 = none")
    p.add_argument("--heartbeat", type=float, default=1.0, help="seconds between heartbeats")
    p.add_argument("--stats-interval", type=float, default=60, help="seconds between stats logs")
    p.add_argument("--auth-token-file", help="file holding the token the log aggregator sends in its header")
    p.add_argument("--extra-field", action="append", default=[],
                   help="extra event field to carry as an indexed field in the SIEM (repeatable)")
    p.add_argument("--source-seq", action="store_true",
                   help="number events per (host, source) in indexed field wd2l_src_seq, so "
                        "Enclave 2 can rebuild interleaved files and locate lost lines")
    p.add_argument("--no-tx-time", dest="tx_time", action="store_false",
                   help="don't stamp each event's send time in indexed field wd2l_tx_time")
    p.add_argument("--no-opaque-check", dest="opaque_check", action="store_false",
                   help="don't flag long encrypted, compressed or random-looking blobs "
                        "(indexed fields wd2l_opaque, wd2l_opaque_bytes)")
    p.add_argument("--state", help="state file for the restart count and previous stream "
                                   "(lets the receiver link runs together)")
    p.add_argument("--drain-timeout", type=float, default=2.0,
                   help="seconds to keep reading already-arriving input on shutdown")
    p.add_argument("--input-rcvbuf", type=int, default=256 * 1024,
                   help="TCP receive buffer for aggregator connections (0 = system default)")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--audit-dir", help="write hash-chained audit records here "
                                       "(deployed: /var/log/wd2l)")
    p.add_argument("--audit-min-free-mb", type=int, default=256,
                   help="free space below this raises audit_failure")
    p.add_argument("--egress-iface", help="egress NIC whose carrier and transmit counters go in "
                                          "every heartbeat (deployed: ens224)")
    p.add_argument("--chronyc", default="chronyc",
                   help="chronyc command for time quality (\"-c tracking\" is added)")
    p.add_argument("--chrony-addr", type=hostinfo.chrony_address, metavar="HOST[:PORT]",
                   help="ask chronyd over UDP (its command port, 323) for time quality instead "
                        "of running --chronyc; the container units use 127.0.0.1:323")
    p.add_argument("--max-stratum", type=hostinfo.stratum, default=3, metavar="N",
                   help="time alarm when chrony's stratum is above N (1 is a server with its own "
                        "reference clock, e.g. GPS)")
    p.add_argument("--log-format", choices=("text", "json"), default="text",
                   help="operational log lines: text, or one JSON object per line")
    return p


def config_settings(a: argparse.Namespace) -> Dict[str, Any]:
    """This run's settings for the config audit record. Token files appear as paths only."""
    return {k: v for k, v in sorted(vars(a).items())}


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = build_parser()
    a = p.parse_args(argv)
    try:
        check_limits(a.max_datagram, a.max_event)
    except ValueError as e:
        p.error(str(e))
    logsetup.setup(a.log_format, a.verbose)
    settings = config_settings(a)
    cfg_sha = auditlog.sha256_hex(auditlog.canonical(settings))
    tq = hostinfo.time_quality(a.chronyc, a.chrony_addr, max_stratum=a.max_stratum)
    audit = None
    if a.audit_dir:
        try:
            audit = auditlog.AuditLog(a.audit_dir, "sender", 1, time_quality=tq, forward=True,
                                      min_free_bytes=a.audit_min_free_mb * 1024 * 1024)
        except auditlog.AuditLocked as e:
            raise SystemExit(str(e))
        audit.check_space()     # the floor holds from the first record
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
                    stream_id=sid, audit=audit, config_sha256=cfg_sha, time_quality=tq,
                    egress_iface=a.egress_iface)
    if audit:
        audit.start_verify()
    server = InputServer(_hostport(a.listen), sender, token, a.input_rcvbuf, a.drain_timeout)
    sender.input_server = server
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
        sender.reconcile_record()
        audit.write("stop", "success", stream="%016x" % sender.stream_id, last_seq=sender.seq,
                    signal=signal.Signals(stopped_by[0]).name if stopped_by else None,
                    counters=dict(sender.counters))
        sender.flush_records(final=True)
        audit.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
