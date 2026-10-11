"""Enclave 2 receiver: rebuild logs from captured packets.

    capture NIC (RX-only fiber from the network tap's monitor port)
        -> wd2l-receiver --live cap0      (or --pcap files from the capture archive)
        -> SIEM (HTTP event collector) and/or JSONL files, plus wd2l:health records (gaps, heartbeats, counters)

Everything arriving on the wire is treated as untrusted: sizes are capped, reassembly
memory is capped, anything malformed is counted and dropped.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import logging
import os
import platform
import re
import signal
import time
from collections import OrderedDict, deque
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import __version__, fault, hostinfo, logsetup, packets, wire
from . import audit as auditlog
from .audit import Summarizer
from .outputs import FileOutput, HecOutput, MultiOutput, Output
from .reconcile import StreamReconciler

log = logging.getLogger("wd2l.receiver")

MAX_GAP_RANGES = 100000
MAX_STREAMS = 1000
MAX_RETIRED = 10000
MAX_REASONS = 32
STATE_VERSION = 2
RX_TIME_FIELD = "wd2l_rx_time"
HEX64 = re.compile(r"[0-9a-f]{64}")

# Health records that are also audit events (§4), with their outcome. `gap` is audited too, but
# summarised once a minute per stream and reason (SUMMARY_OUTCOME): chronic loss would otherwise
# write one audit record per gap.
AUDITED_HEALTH = {"stream_start": "info", "stream_end": "success",
                  "stream_lost": "failure", "stream_missing": "failure",
                  "sender_boot_reset": "failure", "stream_evicted": "failure"}
SUMMARY_OUTCOME = {"gap": "failure", "gap_filled": "success"}
# Counters whose growth is written once a minute as boundary_anomaly / output_failure.
BOUNDARY_COUNTERS = ("other_packets", "bad_frames", "bad_events", "digest_mismatch",
                     "event_too_big", "reasm_inconsistent", "records_bad")
OUTPUT_COUNTERS = ("output_dropped", "hec_rejected_events", "hec_queue_overflow_events",
                   "hec_spool_overflow_events", "hec_records_lost",
                   "audit_hec_rejected_events", "audit_hec_spool_overflow_events",
                   "audit_hec_records_lost")


def to_ranges(seqs: Iterable[int]) -> List[List[int]]:
    """[1, 2, 3, 7, 9, 10] -> [[1, 3], [7, 7], [9, 10]]"""
    out: List[List[int]] = []
    for s in sorted(seqs):
        if out and s == out[-1][1] + 1:
            out[-1][1] = s
        else:
            out.append([s, s])
    return out


def from_ranges(ranges: Iterable[Sequence[int]]) -> List[int]:
    return [s for a, b in ranges for s in range(int(a), int(b) + 1)]


# ---------------------------------------------------------------- range bookkeeping

class RangeSet:
    """Sorted, non-overlapping inclusive [start, end] ranges of sequence numbers."""

    def __init__(self, ranges: Optional[List[List[int]]] = None):
        self.r: List[List[int]] = [list(x) for x in (ranges or [])]
        self.forgotten = 0

    def add(self, a: int, b: int) -> None:
        self.r.append([a, b])
        self.r.sort()
        merged: List[List[int]] = []
        for x in self.r:
            if merged and x[0] <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], x[1])
            else:
                merged.append(x)
        self.r = merged
        while len(self.r) > MAX_GAP_RANGES:
            a0, b0 = self.r.pop(0)
            self.forgotten += b0 - a0 + 1

    def _find(self, s: int) -> int:
        """Index of the range holding s, or -1."""
        i = bisect.bisect_right(self.r, [s, float("inf")]) - 1
        return i if i >= 0 and self.r[i][0] <= s <= self.r[i][1] else -1

    def remove(self, s: int) -> bool:
        i = self._find(s)
        if i < 0:
            return False
        a, b = self.r[i]
        self.r[i:i + 1] = ([[a, s - 1]] if a < s else []) + ([[s + 1, b]] if s < b else [])
        return True

    def __contains__(self, s: int) -> bool:
        return self._find(s) >= 0

    def count(self) -> int:
        return sum(b - a + 1 for a, b in self.r)


class StreamTracker:
    """Per-stream accounting: what was delivered, what is late, what is declared lost.

    lo      lowest sequence number not yet resolved (everything below is delivered or a gap)
    above   sequence numbers >= lo already delivered out of order
    known   highest sequence number we know exists (from data or heartbeats)

    A missing sequence number is "overtaken" once a higher one arrives or a heartbeat says it
    was sent. It becomes a gap when it has been overtaken for longer than the gap window.
    marks holds (known, time) each time known grew, so the moment any missing number was
    first overtaken is the time of the first mark whose known >= it.
    """

    def __init__(self, stream_id: int, first_seen: float):
        self.stream_id = stream_id
        self.lo = 1
        self.above: set = set()
        self.known = 0
        self.marks: Deque[Tuple[int, float]] = deque()
        self.gaps = RangeSet()
        self.first_seen = first_seen
        self.last_seen = first_seen
        self.last_hb: Optional[float] = None   # when its latest heartbeat arrived
        self.final = False
        self.lost_reported = False
        self.hb: Dict[str, Any] = {}
        self.delivered = 0
        self.boot: Optional[int] = None   # sender restart count, if the sender reports one
        self.linked = False               # its link to the previous stream has been checked
        self.records = False   # the sender's records stream (flags bit 0)
        self.clock_offset: Optional[float] = None   # receiver minus sender clock, last heartbeat
        self.rc = StreamReconciler()

    def needed(self, seq: int) -> bool:
        if seq < self.lo:
            return seq in self.gaps
        return seq not in self.above

    def _advance(self) -> None:
        while self.lo in self.above:
            self.above.discard(self.lo)
            self.lo += 1
        while self.marks and self.marks[0][0] < self.lo:
            self.marks.popleft()

    def _raise_known(self, seq: int, now: float) -> None:
        if seq > self.known:
            self.known = seq
            if seq >= self.lo:
                self.marks.append((seq, now))

    def on_event(self, seq: int, now: float) -> str:
        """Record a completed event. Returns "new", "late" (filled a declared gap) or "dup"."""
        self.last_seen = now
        if seq < self.lo:
            if not self.gaps.remove(seq):
                return "dup"
            self.delivered += 1
            return "late"
        if seq in self.above:
            return "dup"
        self.above.add(seq)
        self._raise_known(seq, now)
        self._advance()
        self.delivered += 1
        return "new"

    def on_heartbeat(self, last_seq: int, info: Dict[str, Any], now: float) -> None:
        self.last_seen = self.last_hb = now
        self.hb = info
        self._raise_known(last_seq, now)
        self._advance()
        if info.get("final") is True:
            self.final = True

    def reopen(self, seqs: Iterable[int]) -> List[Tuple[int, int]]:
        """Events counted as delivered that the output never made durable: make them needed again.

        Those below lo become gaps right away (returned, so they can be reported). Those at or
        above lo become ordinary holes again and are declared by the usual gap window."""
        lost: List[int] = []
        for s in seqs:
            if s < self.lo:
                if s not in self.gaps:
                    lost.append(s)
            else:
                self.above.discard(s)
        ranges = [(a, b) for a, b in to_ranges(lost)]
        for a, b in ranges:
            self.gaps.add(a, b)
        return ranges

    def declare(self, now: float, window: float, force: bool = False) -> List[Tuple[int, int]]:
        """Turn holes overtaken more than `window` ago (or all holes, if force) into gaps."""
        if force:
            end = self.known
        else:
            end = self.lo - 1
            for seq, t in self.marks:
                if now - t < window:
                    break
                end = seq
        if end < self.lo:
            return []
        declared: List[Tuple[int, int]] = []
        cur = self.lo
        for s in sorted(x for x in self.above if x <= end):
            if s > cur:
                declared.append((cur, s - 1))
            cur = s + 1
        if cur <= end:
            declared.append((cur, end))
        self.above = {x for x in self.above if x > end}
        self.lo = end + 1
        self._advance()
        for a, b in declared:
            self.gaps.add(a, b)
        return declared

    def to_json(self) -> Dict[str, Any]:
        return {"lo": self.lo, "above": sorted(self.above), "known": self.known,
                "marks": list(self.marks), "gaps": self.gaps.r, "first_seen": self.first_seen,
                "last_seen": self.last_seen, "last_hb": self.last_hb, "final": self.final,
                "lost_reported": self.lost_reported, "hb": self.hb,
                "delivered": self.delivered, "boot": self.boot, "linked": self.linked,
                "records": self.records, "rc": self.rc.to_json()}

    @classmethod
    def from_json(cls, sid: int, d: Dict[str, Any]) -> "StreamTracker":
        t = cls(sid, float(d.get("first_seen", 0)))
        t.lo = int(d["lo"])
        t.above = {int(x) for x in d.get("above", [])}
        t.known = int(d.get("known", 0))
        # Marks from before a restart have been overtaken for longer than any gap window, and
        # their times came from another run's clock. Time 0 makes them due right away.
        t.marks = deque((int(a), 0.0) for a, _ in d.get("marks", []))
        t.gaps = RangeSet(d.get("gaps", []))
        t.last_seen = float(d.get("last_seen", 0))
        t.final = bool(d.get("final", False))
        t.lost_reported = bool(d.get("lost_reported", False))
        t.hb = d.get("hb", {}) if isinstance(d.get("hb"), dict) else {}
        lh = d.get("last_hb")
        if isinstance(lh, (int, float)) and not isinstance(lh, bool):
            t.last_hb = float(lh)
        elif t.hb:
            t.last_hb = t.last_seen     # a state file from before last_hb was kept
        t.delivered = int(d.get("delivered", 0))
        boot = d.get("boot")
        t.boot = int(boot) if isinstance(boot, int) else None
        t.linked = bool(d.get("linked", False))
        t.records = bool(d.get("records", False))
        t.rc = StreamReconciler.from_json(d.get("rc"))
        return t


# ---------------------------------------------------------------- chunk reassembly

class _Partial:
    __slots__ = ("count", "event_len", "digest", "chunks", "size", "first")

    def __init__(self, f: wire.Frame, now: float):
        self.count = f.chunk_count
        self.event_len = f.event_len
        self.digest = f.digest
        self.chunks: Dict[int, bytes] = {}
        self.size = 0
        self.first = now


class Reassembler:
    def __init__(self, max_event: int, max_buffer: int, timeout: float):
        self.max_event = max_event
        self.max_buffer = max_buffer
        self.timeout = timeout
        self.partials: Dict[Tuple[int, int], _Partial] = {}
        self.buffered = 0
        self.counters = {"reasm_expired": 0, "reasm_evicted": 0, "reasm_inconsistent": 0,
                         "digest_mismatch": 0, "event_too_big": 0}

    def add(self, f: wire.Frame, now: float) -> Optional[bytes]:
        """Add a DATA chunk. Returns the whole event once every chunk is in and verified."""
        if f.event_len > self.max_event:
            self.counters["event_too_big"] += 1
            return None
        if f.chunk_count == 1:
            return self._verify(f.payload, f.event_len, f.digest)
        key = (f.stream_id, f.seq)
        p = self.partials.get(key)
        if p is None:
            p = self.partials[key] = _Partial(f, now)
        elif (p.count, p.event_len, p.digest) != (f.chunk_count, f.event_len, f.digest):
            self.counters["reasm_inconsistent"] += 1
            self._drop(key)
            return None
        if f.chunk_idx in p.chunks:
            return None
        if p.size + len(f.payload) > p.event_len:
            self.counters["reasm_inconsistent"] += 1
            self._drop(key)
            return None
        while self.buffered + len(f.payload) > self.max_buffer and self.partials:
            oldest = min(self.partials, key=lambda k: self.partials[k].first)
            self.counters["reasm_evicted"] += 1
            self._drop(oldest)
            if oldest == key:
                return None
        p.chunks[f.chunk_idx] = f.payload
        p.size += len(f.payload)
        self.buffered += len(f.payload)
        if len(p.chunks) < p.count:
            return None
        self._drop(key)
        data = b"".join(p.chunks[i] for i in range(p.count))
        return self._verify(data, p.event_len, p.digest)

    def _verify(self, data: bytes, event_len: int, digest: bytes) -> Optional[bytes]:
        if len(data) != event_len or hashlib.sha256(data).digest() != digest:
            self.counters["digest_mismatch"] += 1
            return None
        return data

    def _drop(self, key: Tuple[int, int]) -> None:
        p = self.partials.pop(key, None)
        if p is not None:
            self.buffered -= p.size

    def expire(self, now: float, force: bool = False) -> None:
        for key in [k for k, p in self.partials.items() if force or now - p.first > self.timeout]:
            self.counters["reasm_expired"] += 1
            self._drop(key)


# ---------------------------------------------------------------- receiver

class Receiver:
    def __init__(self, output: Output, dst_ip: Optional[str] = None, dst_port: int = 5514,
                 src_ip: Optional[str] = None, state_path: Optional[str] = None,
                 max_event: int = wire.DEFAULT_MAX_EVENT, max_buffer: int = 64 * 1024 * 1024,
                 reasm_timeout: float = 5.0, gap_window: float = 2.0, hb_timeout: float = 5.0,
                 health_interval: float = 60.0, stream_lost_after: float = 60.0,
                 stream_retention: float = 7 * 86400.0,
                 record_clock: Optional[Callable[[], float]] = None, rx_time: bool = True,
                 src_port: int = 0, audit: Optional[auditlog.AuditLog] = None,
                 audit_output: Optional[Output] = None, config_sha256: Optional[str] = None,
                 audit_interval: float = 60.0,
                 component: str = "receiver", time_quality: Any = None,
                 nic_probe: Optional[Callable[[], Dict[str, Any]]] = None,
                 archive_probe: Optional[Callable[[], Dict[str, Any]]] = None,
                 sample_interval: float = 5.0,
                 fault_interval: float = 0.0, fault_window: float = 60.0,
                 input_flat_after: float = 300.0, backlog_alarm_bytes: int = 1 << 20,
                 archive_stale_after: float = 15.0, max_skew_s: float = 0.05):
        """`now` passed to handle_frame/tick drives every timer. Live capture passes a steady
        clock (immune to clock steps); pcap replay passes packet timestamps. `record_clock`,
        if given, supplies the wall-clock `time` written into health records, each event's
        arrival time (indexed field wd2l_rx_time, unless rx_time is off) and the clock offset.
        Without it (replay) those use the packet's capture time."""
        self.out = output
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.src_port = src_port  # 0 = any
        self.state_path = state_path
        self.reasm = Reassembler(max_event, max_buffer, reasm_timeout)
        self.gap_window = gap_window
        self.hb_timeout = hb_timeout
        self.health_interval = health_interval
        self.stream_lost_after = stream_lost_after
        self.stream_retention = stream_retention
        self.record_clock = record_clock
        self.rx_time = rx_time
        self.last_clock_offset: Optional[float] = None
        self.streams: Dict[int, StreamTracker] = {}
        # Streams no longer tracked in full: stream_id -> [known seq, final]. Enough to drop
        # replayed duplicates and to follow a sender's restart chain.
        self.retired: "OrderedDict[int, List[Any]]" = OrderedDict()
        self.last_boot: Optional[int] = None
        self.had_history = False
        self.counters = {"frames": 0, "other_packets": 0, "bad_frames": 0, "bad_events": 0,
                         "events_delivered": 0, "duplicates": 0, "late_fills": 0,
                         "gap_events": 0, "heartbeats": 0, "kernel_drops": 0,
                         "uncommitted_at_start": 0, "output_dropped": 0,
                         "records_delivered": 0, "records_bad": 0}
        self.other_reasons: Dict[str, int] = {}
        self.bad_reasons: Dict[str, int] = {}
        self.last_hb: Optional[float] = None
        self.hb_stale = False
        self.started: Optional[float] = None
        self.last_health: Optional[float] = None
        self.last_save = 0.0
        self.dirty = False
        self.saved_with_pending = False
        self.audit = audit
        self.component = component
        self.tq = time_quality
        self.host = hostinfo.hostname()
        self.audit_out = audit_output or output
        self.outputs: List[Output] = [output] if self.audit_out is output else [output, self.audit_out]
        self.config_sha256 = config_sha256
        self.loaded_config_sha256: Optional[str] = None
        self.summary = Summarizer()
        self.audit_interval = audit_interval
        self.last_audit: Optional[float] = None
        self._audit_prev: Dict[str, Any] = {}
        self.nic_probe = nic_probe
        self.archive_probe = archive_probe
        self.sample_interval = sample_interval
        self.fault_interval = fault_interval
        self.input_flat_after = input_flat_after
        self.backlog_alarm_bytes = backlog_alarm_bytes
        self.archive_stale_after = archive_stale_after
        self.max_skew_s = max_skew_s
        self.faults = fault.FaultTracker(fault_window)
        self.last_fault: Optional[float] = None
        self.last_rc: Optional[float] = None
        self.last_rc_hourly: Optional[float] = None
        self.gap_by_reason: Dict[str, int] = {}
        self.proc = hostinfo.ProcStats()
        self.sample: Dict[str, Any] = {}
        self.last_sample: Optional[float] = None
        self.last_packet: Optional[float] = None   # any frame on the capture NIC
        self.last_wd2l: Optional[float] = None     # a valid wd2l frame
        if state_path and os.path.exists(state_path):
            self._load_state()
        elif state_path and audit is not None:
            audit.write("state_reset", "info", path=state_path, reason="missing")

    # -- input

    @staticmethod
    def _bump(d: Dict[str, int], reason: str) -> None:
        if reason in d or len(d) < MAX_REASONS:
            d[reason] = d.get(reason, 0) + 1
        else:
            d["other"] = d.get("other", 0) + 1

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

    def handle_frame(self, frame: bytes, now: float) -> None:
        self.last_packet = now
        self.counters["frames"] += 1
        try:
            udp = packets.parse_udp(frame)
        except packets.NotUdp as e:
            self.counters["other_packets"] += 1
            self._bump(self.other_reasons, str(e))
            return
        if (udp.dst_port != self.dst_port or (self.dst_ip and udp.dst_ip != self.dst_ip)
                or (self.src_ip and udp.src_ip != self.src_ip)):
            self.counters["other_packets"] += 1
            self._bump(self.other_reasons, "udp %s:%d" % (udp.dst_ip, udp.dst_port))
            return
        if self.src_port and udp.src_port != self.src_port:
            self.counters["other_packets"] += 1
            self._bump(self.other_reasons, "udp from %s:%d" % (udp.src_ip, udp.src_port))
            return
        self.handle_datagram(udp.payload, now)

    def handle_datagram(self, datagram: bytes, now: float) -> None:
        if self.started is None:
            self.started = now
        try:
            f = wire.decode(datagram)
        except wire.FrameError as e:
            self.counters["bad_frames"] += 1
            self._bump(self.bad_reasons, str(e))
            return
        self.last_wd2l = now
        t = self._stream(f.stream_id, now, bool(f.flags & wire.FLAG_RECORDS))
        if f.type == wire.TYPE_HEARTBEAT:
            self._heartbeat(t, f, now)
            return
        if not t.needed(f.seq):
            self.counters["duplicates"] += f.chunk_idx == 0
            return
        data = self.reasm.add(f, now)
        if data is None:
            return
        try:
            evt = wire.parse_event(data)
        except wire.FrameError as e:
            self.counters["bad_events"] += 1
            self._bump(self.bad_reasons, str(e))
            return
        res = t.on_event(f.seq, now)
        if res == "dup":
            self.counters["duplicates"] += 1
            return
        if res == "late":
            t.rc.filled += 1
            self.counters["late_fills"] += 1
            self.summary.note("gap_filled", {"stream": "%016x" % f.stream_id},
                              seq_first=f.seq, seq_last=f.seq)
        if t.records:
            self._deliver_record(evt, f.stream_id, f.seq)
            self.dirty = True
            return
        t.rc.delivered(f.seq, f.digest)
        if self.rx_time:
            evt["fields"] = dict(evt.get("fields", {}), **{RX_TIME_FIELD: round(self._wall(now), 3)})
        self.out.event(evt, f.stream_id, f.seq)
        self.counters["events_delivered"] += 1
        self.dirty = True

    # -- stream bookkeeping

    @staticmethod
    def _flag(t: StreamTracker) -> Dict[str, Any]:
        return {"records": True} if t.records else {}

    def _deliver_record(self, evt: Dict[str, Any], sid: int, seq: int) -> None:
        """A record from the sender's records stream: re-serialized canonically (so a line can't
        be smuggled into a file) and sent to the audit or health index. Only records that say
        they are the Enclave 1 sender's are passed on: Enclave 1 can't speak for Enclave 2."""
        try:
            rec = json.loads(evt["_raw"])
            if not isinstance(rec, dict):
                raise ValueError("not a JSON object")
            enclave = rec.get("enclave")
            if (not isinstance(enclave, int) or isinstance(enclave, bool) or enclave != 1
                    or rec.get("component") != "sender"):
                raise ValueError("not a record of the Enclave 1 sender")
            raw = auditlog.canonical(rec).decode("utf-8")
        except (ValueError, RecursionError):
            self.counters["records_bad"] += 1
            return
        kind = "audit" if evt.get("sourcetype") == "wd2l:sender:audit" else "health"
        (self.audit_out if kind == "audit" else self.out).forwarded(dict(evt, _raw=raw), sid, seq, kind)
        self.counters["records_delivered"] += 1

    def _stream(self, sid: int, now: float, records: bool = False) -> StreamTracker:
        t = self.streams.get(sid)
        if t is not None:
            return t
        if sid in self.retired:
            t = self._restore(sid, now)
            t.records = records
            return t
        # Only data streams are history: a records stream must not make a new receiver report
        # the runs before it as missing.
        if not records and (any(not s.records for s in self.streams.values()) or self.retired):
            self.had_history = True
        t = StreamTracker(sid, now)
        t.records = records
        t.rc.enabled = not records
        self._add(t, now)
        log.info("new %sstream %016x", "records " if records else "", sid,
                 extra={"stream": "%016x" % sid})
        self._health_record("stream_start", now, stream="%016x" % sid, **self._flag(t))
        return t

    def _add(self, t: StreamTracker, now: float) -> None:
        if len(self.streams) >= MAX_STREAMS:
            self._evict(now)
        self.streams[t.stream_id] = t
        self.dirty = True

    def _restore(self, sid: int, now: float) -> StreamTracker:
        """Bring a retired stream back (e.g. an old archive is replayed): everything it had is
        treated as delivered, so replayed copies are dropped as duplicates."""
        known, final = self.retired.pop(sid)
        t = StreamTracker(sid, now)
        t.rc = StreamReconciler(enabled=False)
        t.lo, t.known, t.final = int(known) + 1, int(known), bool(final)
        t.lost_reported = t.linked = True
        self._add(t, now)
        return t

    def _retire(self, t: StreamTracker) -> None:
        self.retired[t.stream_id] = [t.known, t.final]
        self.retired.move_to_end(t.stream_id)
        while len(self.retired) > MAX_RETIRED:
            self.retired.popitem(last=False)
        del self.streams[t.stream_id]
        self.dirty = True

    def _evict(self, now: float) -> None:
        """Too many streams: drop the quietest one, preferring one with nothing left open."""
        clean = [t for t in self.streams.values() if not t.gaps.r]
        victim = min(clean or list(self.streams.values()), key=lambda s: s.last_seen)
        if victim.gaps.r:
            log.warning("evicting stream %016x with %d open gap events",
                        victim.stream_id, victim.gaps.count())
            self._health_record("stream_evicted", now, stream="%016x" % victim.stream_id,
                                open_gap_events=victim.gaps.count(), gaps=victim.gaps.r[:100],
                                **self._flag(victim))
        self._retire(victim)

    def _prune(self, now: float) -> None:
        """Retire streams that are over, fully resolved and older than the archive retention."""
        for t in list(self.streams.values()):
            if ((t.final or t.lost_reported) and not t.gaps.r and t.lo > t.known
                    and now - t.last_seen > self.stream_retention):
                self._retire(t)

    def _heartbeat(self, t: StreamTracker, f: wire.Frame, now: float) -> None:
        try:
            info = json.loads(f.payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):  # Recursion: too deeply nested
            info = None
        if not isinstance(info, dict):
            self.counters["bad_frames"] += 1
            self._bump(self.bad_reasons, "bad heartbeat json")
            return
        eh = info.get("events_hash")
        info = {k: v for k, v in info.items()
                if isinstance(k, str) and isinstance(v, (int, float, bool))}
        if isinstance(eh, str) and HEX64.fullmatch(eh) and not t.records:
            info["events_hash"] = eh
            t.rc.cut(f.seq, eh)
        # A 64-bit id is kept out of the stored counters: SIEMs read JSON numbers as floats.
        prev = info.pop("prev_stream", None)
        self.counters["heartbeats"] += 1
        sent = info.get("sender_time")
        if isinstance(sent, (int, float)) and not isinstance(sent, bool):
            # Clock offset plus the one-way delay, which is well under 1 ms on a direct fiber.
            t.clock_offset = self.last_clock_offset = round(self._wall(now) - sent, 3)
        if not t.linked and not t.records:
            self._link(t, info, prev, now)
        was_final = t.final
        t.on_heartbeat(f.seq, info, now)
        if t.final and not was_final:
            self._health_record("stream_end", now, stream="%016x" % t.stream_id,
                                last_seq=f.seq, sender=info, **self._flag(t))
        self.last_hb = now
        if self.hb_stale:
            self.hb_stale = False
            self._health_record("heartbeat_restored", now)
        self.dirty = True

    def _link(self, t: StreamTracker, info: Dict[str, Any], prev: Any, now: float) -> None:
        """Check a new stream against the one before it (sender --state).

        The sender reports its restart count (`boot`) and the previous run's stream id and last
        sequence number. That reveals events lost at the end of the previous run, and whole
        runs the receiver never saw (e.g. a sender restart during a link outage)."""
        t.linked = True
        boot = info.get("boot")
        if not isinstance(boot, int) or isinstance(boot, bool) or boot < 1:
            return
        t.boot = boot
        prev_last = info.get("prev_last_seq")
        prev_known = False
        if (isinstance(prev, int) and not isinstance(prev, bool) and 0 < prev != t.stream_id
                and isinstance(prev_last, int) and prev_last >= 0):
            p = self.streams.get(prev)
            if p is None and prev in self.retired:
                p = self._restore(prev, now)
            if p is not None:
                prev_known = True
                p._raise_known(prev_last, now)  # a tail gap, if any, is declared as usual
                if not p.final and not p.lost_reported:
                    p.lost_reported = True
                    self._health_record("stream_lost", now, stream="%016x" % p.stream_id,
                                        last_seq=p.known, idle_s=round(now - p.last_seen, 1),
                                        replaced_by="%016x" % t.stream_id)
            elif self.had_history:
                prev_known = True
                p = StreamTracker(prev, now)
                p.rc = StreamReconciler(enabled=False)
                p.boot, p.lost_reported, p.linked = boot - 1, True, True
                p._raise_known(prev_last, now)  # all of it becomes a gap after the window
                self._add(p, now)
                log.warning("stream %016x (sender boot %d) was never seen: %d events",
                            prev, boot - 1, prev_last)
                self._health_record("stream_missing", now, stream="%016x" % prev,
                                    boot=boot - 1, last_seq=prev_last)
        if self.last_boot is not None:
            if boot <= self.last_boot:
                self._health_record("sender_boot_reset", now, stream="%016x" % t.stream_id,
                                    boot=boot, previous_boot=self.last_boot)
            else:
                first, last = self.last_boot + 1, boot - 1 - prev_known
                if last >= first:
                    self._health_record("stream_missing", now, first_boot=first, last_boot=last,
                                        runs=last - first + 1, note="stream ids and event counts unknown")
        self.last_boot = boot
        self.dirty = True

    # -- time-driven work

    def tick(self, now: float) -> None:
        if self.started is None:
            self.started = now
        self._apply_failed(now)
        self.reasm.expire(now)
        for t in list(self.streams.values()):
            self._report_gaps(t, t.declare(now, self.gap_window), now)
            if (not t.final and not t.lost_reported
                    and now - t.last_seen > self.stream_lost_after):
                t.lost_reported = True
                self._health_record("stream_lost", now, stream="%016x" % t.stream_id,
                                    last_seq=t.known, idle_s=round(now - t.last_seen, 1),
                                    **self._flag(t))
        self._prune(now)
        if self.sample_interval and (self.last_sample is None
                                     or now - self.last_sample >= self.sample_interval):
            self.last_sample = now
            self._take_sample()
        ref = self.last_hb if self.last_hb is not None else self.started
        if not self.hb_stale and now - ref > self.hb_timeout:
            self.hb_stale = True
            log.warning("no heartbeat for %.1fs", now - ref)
            self._health_record("heartbeat_stale", now, age_s=round(now - ref, 1))
        if self.last_health is None:
            self.last_health = now
        elif now - self.last_health >= self.health_interval:
            self.last_health = now
            self.emit_health(now)
        if (self.state_path and (self.dirty or self.saved_with_pending)
                and time.monotonic() - self.last_save >= 1.0):
            self.save_state(now=now)
        if self.last_rc is None or now - self.last_rc >= 1.0:
            self.last_rc = now
            self._reconcile(now)
        if self.fault_interval and (self.last_fault is None
                                    or now - self.last_fault >= self.fault_interval):
            self.last_fault = now
            self._evaluate_faults(now)
        if self.audit is not None:
            if self.last_audit is None:
                self.last_audit = now
            elif now - self.last_audit >= self.audit_interval:
                self.last_audit = now
                self.audit_periodic()
            self._drain_audit()

    def _reconcile(self, now: float) -> None:
        """Settle what the outputs made durable, compare at ready cuts, write reconcile records:
        for ended streams whenever (cut, balanced) changes, and hourly for the rest."""
        pending = self._pending()
        self._apply_failed(now)   # snapshot first, then failures, then settle
        hourly = self.last_rc_hourly is not None and now - self.last_rc_hourly >= 3600
        if self.last_rc_hourly is None or hourly:
            self.last_rc_hourly = now
        for t in list(self.streams.values()):
            if t.records or not t.rc.enabled:
                continue
            t.rc.settle(pending.get(t.stream_id, set()))
            t.rc.check(t.lo, t.gaps)
            last = t.rc.last
            if last is None:
                continue
            ended = t.final and t.lo > t.known and last["cut"] == t.known
            key = (last["cut"], last["balanced"])
            if (ended and key != t.rc.written) or (
                    hourly and (now - t.last_seen < 3600 or not last["balanced"])):
                self._reconcile_record(t, last, now)

    def _reconcile_record(self, t: StreamTracker, res: Dict[str, Any], now: float) -> None:
        """A health record for the dashboard and, when auditing, the full audit record."""
        sid = "%016x" % t.stream_id
        self._health_record("reconcile", now, stream=sid, cut=res["cut"],
                            balanced=res["balanced"], gaps_open=t.gaps.count(),
                            events_delivered=t.delivered)
        if self.audit is not None:
            self.audit.write(
                "reconcile", "success" if res["balanced"] else "failure",
                stream=sid, cut=res["cut"], events_in=t.hb.get("events_in"),
                events_sent=t.hb.get("events_sent"), events_delivered=t.delivered,
                gaps_open=t.gaps.count(), gaps_filled=t.rc.filled, last_seq=t.known,
                sender_hash=res["sender_hash"], receiver_hash=res["receiver_hash"],
                balanced=res["balanced"])
        t.rc.written = (res["cut"], res["balanced"])
        self.dirty = True       # saved, so a crash while idle doesn't write the record again

    def _newest_run(self) -> Optional[StreamTracker]:
        """The sender run the fault rules read: the data stream whose latest heartbeat is the
        newest. A placeholder for a run never seen, or a retired stream brought back, has no
        heartbeat and is skipped, however recently it was created. Without any heartbeat yet,
        the stream first seen last."""
        data = [t for t in self.streams.values() if not t.records]
        heard = [t for t in data if t.hb and t.last_hb is not None]
        if heard:
            return max(heard, key=lambda t: (t.last_hb, t.first_seen))
        return max(data, key=lambda t: t.first_seen) if data else None

    def _evaluate_faults(self, now: float) -> None:
        newest = self._newest_run()
        hb = newest.hb if newest is not None else {}
        stats = self._stats()
        ft = self.faults
        ft.add(now, {
            "gaps_not_received": self.gap_by_reason.get("not_received", 0),
            "gaps_output_dropped": self.gap_by_reason.get("output_dropped", 0),
            "nic_errors": sum(self.sample.get("nic_" + k) or 0 for k in (
                "rx_errors", "rx_crc_errors", "rx_frame_errors", "rx_missed_errors")),
            "kernel_drops": self.counters["kernel_drops"],
            "output_dropped": self.counters["output_dropped"],
            "hec_errors": sum(stats.get(p + k, 0) for p in ("", "audit_")
                              for k in ("hec_posts_failed", "hec_rejected_events")),
            "spool_files": stats.get("hec_spool_files", 0) + stats.get("audit_hec_spool_files", 0),
            "sender_drops": hb.get("sender_drops", 0), "send_errors": hb.get("send_errors", 0),
            "input_backlog_bytes": hb.get("input_backlog_bytes", 0)})
        ref = self.started if self.started is not None else now
        packet_age = now - (self.last_packet if self.last_packet is not None else ref)
        frame_age = now - (self.last_wd2l if self.last_wd2l is not None else ref)
        live_run = newest is not None and not newest.final
        flat = ft.input_flat(now, newest.stream_id if newest else None,
                             hb.get("events_in", hb.get("events_sent")))
        archive_age = self.sample.get("archive_age_s")
        sig = fault.Signals(
            hb_timeout=self.hb_timeout, carrier=self.sample.get("nic_carrier"),
            packet_age=packet_age, frame_age=frame_age,
            clean_end=newest is not None and newest.final,
            input_flat_s=flat if live_run else 0.0, input_flat_after=self.input_flat_after,
            sender_drops=ft.delta("sender_drops"), send_errors=ft.delta("send_errors"),
            backlog_growing=(ft.delta("input_backlog_bytes") > 0
                             and (hb.get("input_backlog_bytes") or 0) > self.backlog_alarm_bytes),
            gaps_not_received=ft.delta("gaps_not_received"),
            gaps_output_dropped=ft.delta("gaps_output_dropped"),
            nic_errors=ft.delta("nic_errors"), kernel_drops=ft.delta("kernel_drops"),
            output_dropped=ft.delta("output_dropped"), spool_growing=ft.delta("spool_files") > 0,
            hec_errors=ft.delta("hec_errors"),
            archive_stale=(None if archive_age is None else
                           packet_age < self.hb_timeout and archive_age > self.archive_stale_after))
        f = fault.evaluate(sig)
        prev, ft.current = ft.current, f
        if f.key() != prev.key():
            (log.info if f.status == "ok" else log.warning)(
                "fault status %s%s", f.status,
                " in %s (rule %d): %s" % (f.segment, f.rule, f.detail) if f.rule else "")
            self._health_record("fault", now, fault_status=f.status, fault_segment=f.segment,
                                fault_rule=f.rule, fault_detail=f.detail, segments=f.segments,
                                previous_status=prev.status, previous_segment=prev.segment,
                                previous_rule=prev.rule)
        ts = fault.time_status(self.tq.read() if self.tq is not None else None, hb,
                               self.last_clock_offset, max_skew_s=self.max_skew_s)
        if ts != ft.time:
            ft.time = ts
            self._health_record("time_status", now, time_status=ts[0], time_reason=ts[1])

    def _take_sample(self) -> None:
        s: Dict[str, Any] = dict(self.proc.read())
        if self.nic_probe is not None:
            s.update(("nic_" + k, v) for k, v in self.nic_probe().items())
        if self.archive_probe is not None:
            s.update(self.archive_probe())
        self.sample = s

    def _apply_failed(self, now: float) -> None:
        by: Dict[int, List[int]] = {}
        for sid, seq in self._take_failed():
            by.setdefault(sid, []).append(seq)
        for sid, seqs in by.items():
            self.counters["output_dropped"] += len(seqs)
            log.error("output gave up on %d events of stream %016x", len(seqs), sid)
            t = self.streams.get(sid)
            if t is not None:
                for s in seqs:
                    t.rc.dropped(s)
                self._report_gaps(t, t.reopen(seqs), now, reason="output_dropped")

    def _report_gaps(self, t: StreamTracker, declared: List[Tuple[int, int]], now: float,
                     reason: str = "not_received") -> None:
        for a, b in declared:
            n = b - a + 1
            self.gap_by_reason[reason] = self.gap_by_reason.get(reason, 0) + n
            self.counters["gap_events"] += n
            log.warning("GAP stream %016x seq %d-%d (%d events, %s)", t.stream_id, a, b, n, reason,
                        extra={"stream": "%016x" % t.stream_id, "seq": a})
            self._health_record("gap", now, stream="%016x" % t.stream_id,
                                first_seq=a, last_seq=b, count=n, reason=reason,
                                **self._flag(t))
            if self.audit is not None:
                self.summary.note("gap", dict({"stream": "%016x" % t.stream_id,
                                               "reason": reason}, **self._flag(t)),
                                  count=n, seq_first=a, seq_last=b, gaps=1)
            self.dirty = True

    def _wall(self, now: float) -> float:
        """Wall-clock time for records: the live clock, or the packet time during replay."""
        return self.record_clock() if self.record_clock else now

    def _identity(self) -> Dict[str, Any]:
        return {"host": self.host, "enclave": 2, "component": self.component,
                "version": __version__}

    def _health_record(self, kind: str, now: float, **kw: Any) -> None:
        rec = dict(self._identity(), type=kind, time=round(self._wall(now), 3))
        rec.update(kw)
        self.out.health(rec)
        if self.audit is not None and kind in AUDITED_HEALTH:
            fields = dict(kw)
            if "first_seq" in fields:
                fields["seq_first"] = fields.pop("first_seq")
            if "last_seq" in fields:
                fields["seq_last"] = fields.pop("last_seq")
            self.audit.write(kind, AUDITED_HEALTH[kind], **fields)

    def emit_health(self, now: float) -> Dict[str, Any]:
        streams = {}
        for t in self.streams.values():
            if t.final and not t.gaps.r and now - t.last_seen > 3600:
                continue
            streams["%016x" % t.stream_id] = {
                "next_seq": t.lo, "known_seq": t.known, "open_gap_events": t.gaps.count(),
                "final": t.final, "idle_s": round(now - t.last_seen, 1), "boot": t.boot,
                "clock_offset_s": t.clock_offset, "sender": t.hb,
                "reconcile": ({"cut": t.rc.last["cut"], "balanced": t.rc.last["balanced"]}
                              if t.rc.last else None), **self._flag(t)}
        ref = self.last_hb if self.last_hb is not None else self.started
        rec = dict(self.counters, **self.reasm.counters, **self._stats())
        # Flat totals so SIEM alerts don't have to dig into the per-stream map.
        live = [t for t in self.streams.values()
                if "%016x" % t.stream_id in streams and not t.records]
        rec.update(open_gap_events=sum(t.gaps.count() for t in self.streams.values()),
                   sender_drops=sum(int(t.hb.get("sender_drops", 0)) for t in live),
                   sender_truncated=sum(int(t.hb.get("truncated", 0)) for t in live),
                   sender_opaque_events=sum(int(t.hb.get("opaque_events", 0)) for t in live),
                   sender_bad_input=sum(int(t.hb.get("bad_input", 0)) for t in live),
                   sender_unread_bytes=sum(int(t.hb.get("shutdown_unread_bytes", 0)) for t in live),
                   sender_events_in=sum(int(t.hb.get("events_in", 0)) for t in live),
                   reconcile_unbalanced=sum(1 for t in self.streams.values()
                                            if t.rc.last and not t.rc.last["balanced"]))
        rec.update(type="health", time=round(self._wall(now), 3),
                   streams=streams, retired_streams=len(self.retired),
                   clock_offset_s=self.last_clock_offset,
                   heartbeat_age_s=round(now - ref, 1) if ref is not None else None,
                   heartbeat_stale=self.hb_stale, other_reasons=self.other_reasons,
                   bad_reasons=self.bad_reasons, reasm_buffered=self.reasm.buffered)
        rec.update(self.sample)
        rec.update(packet_age_s=round(now - self.last_packet, 1) if self.last_packet is not None else None,
                   frame_age_s=round(now - self.last_wd2l, 1) if self.last_wd2l is not None else None)
        if self.fault_interval:
            f = self.faults.current
            rec.update(fault_status=f.status, fault_segment=f.segment, fault_rule=f.rule,
                       fault_detail=f.detail or None, time_status=self.faults.time[0],
                       time_reason=self.faults.time[1])
            rec.update(("seg_" + k.replace("-", "_"), v) for k, v in f.segments.items())
        rec.update(self._identity())
        if self.tq is not None:
            rec["time_quality"] = self.tq.read()
        if self.audit is not None:
            rec.update(self.audit.status())
        self.out.health(rec)
        return rec

    def _drain_audit(self) -> None:
        if self.audit is not None:
            for rec in self.audit.take_outbox():
                self.audit_out.audit(rec)

    def audit_periodic(self) -> None:
        """Once a minute: summaries, counter growth, time quality, free space, self-check."""
        if self.audit is None:
            return
        self._write_summaries()
        self._audit_deltas()
        self.audit.check_time()
        self.audit.check_space()
        self.audit.maybe_verify()
        self._drain_audit()

    def _write_summaries(self) -> None:
        """The summarised audit events (gap, gap_filled) noted since the last call."""
        if self.audit is not None:
            for event, fields in self.summary.drain():
                self.audit.write(event, SUMMARY_OUTCOME.get(event, "info"), **fields)

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

    def finish(self, now: float, on_end: Optional[Callable[[Dict[str, Any]], None]] = None
               ) -> Dict[str, Any]:
        """End of input (pcap replay): give up on partial events, declare every remaining hole
        a gap, then close the output and save state. `on_end` runs before the outputs close."""
        self._apply_failed(now)
        self.reasm.expire(now, force=True)
        for t in self.streams.values():
            self._report_gaps(t, t.declare(now, self.gap_window, force=True), now)
        self.flush()
        self._reconcile(now)
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
        self.flush()
        self._reconcile(now)
        self._write_summaries()     # e.g. gaps of events the output gave up on just now
        self._drain_audit()
        for o in self.outputs:
            o.close()
        if self.state_path:
            self.save_state(extra_uncommitted=self._take_failed())

    # -- state

    def save_state(self, extra_uncommitted: Sequence[Tuple[int, int]] = (),
                   now: Optional[float] = None) -> None:
        self.flush()
        pending = self._pending()
        for sid, seq in extra_uncommitted:
            pending.setdefault(sid, set()).add(seq)
        if now is not None:
            self._apply_failed(now)
        for sid, t in self.streams.items():
            t.rc.settle(pending.get(sid, set()))
        streams = {}
        for sid, t in self.streams.items():
            d = t.to_json()
            if pending.get(sid):
                d["uncommitted"] = to_ranges(pending[sid])
            streams["%016x" % sid] = d
        state = {"version": STATE_VERSION, "last_boot": self.last_boot, "streams": streams,
                 "retired": [["%016x" % sid, k, f] for sid, (k, f) in self.retired.items()]}
        saved_hash = self.config_sha256 or self.loaded_config_sha256
        if saved_hash:
            state["config_sha256"] = saved_hash
        tmp = self.state_path + ".tmp"  # type: ignore[operator]
        with open(tmp, "w") as f:
            json.dump(state, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)  # type: ignore[arg-type]
        self.last_save = time.monotonic()
        self.dirty = False
        self.saved_with_pending = any(pending.values())

    def _load_state(self) -> None:
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
        old_hash = state.get("config_sha256")
        self.loaded_config_sha256 = old_hash if isinstance(old_hash, str) else None
        if self.audit is not None:
            self.audit.write("state_loaded", "success", path=self.state_path,
                             file_sha256=hashlib.sha256(body).hexdigest(),
                             streams=len(state.get("streams", {})),
                             retired=len(state.get("retired", [])))
            old = self.loaded_config_sha256
            if self.config_sha256 and isinstance(old, str) and old != self.config_sha256:
                self.audit.write("config_changed", "info", old_config_sha256=old,
                                 config_sha256=self.config_sha256)
        # Everything left unresolved by the last run is reported now, before any new input:
        # events it handed to the output that were never confirmed, and holes still open.
        # Both can be filled by replaying the archive.
        now = self.record_clock() if self.record_clock else time.time()
        reopened_total = 0
        for sid_hex, d in state.get("streams", {}).items():
            sid = int(sid_hex, 16)
            t = self.streams[sid] = StreamTracker.from_json(sid, d)
            unc = from_ranges(d.get("uncommitted", []))
            reopened_total += len(unc)
            lost = t.reopen(unc) + t.declare(now, self.gap_window, force=True)
            self._report_gaps(t, sorted(lost), now, reason="receiver_restart")
        for sid_hex, known, final in state.get("retired", []):
            self.retired[int(sid_hex, 16)] = [int(known), bool(final)]
        lb = state.get("last_boot")
        self.last_boot = lb if isinstance(lb, int) else None
        self.had_history = bool(self.streams or self.retired)
        if reopened_total:
            self.counters["uncommitted_at_start"] = reopened_total
            self.dirty = True
            log.warning("%d events were handed to the output but not confirmed before the last "
                        "stop; they are reported as gaps (reason=receiver_restart). Replay the "
                        "archive to fill them.", reopened_total)
        log.info("loaded state for %d streams (%d retired)", len(self.streams), len(self.retired))


# ---------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="wd2l-receiver", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--live", metavar="IFACE", help="capture from this interface")
    src.add_argument("--pcap", nargs="+", metavar="FILE",
                     help="read pcap files (archive replay: stop the live receiver first "
                          "and point at the same --state)")
    p.add_argument("--dst-ip", default="10.255.255.2", help="black-hole IP ('' = any)")
    p.add_argument("--dst-port", type=int, default=5514)
    p.add_argument("--src-ip", default="", help="only accept this sender IP ('' = any)")
    p.add_argument("--src-port", type=int, default=0,
                   help="only accept this sender UDP source port (0 = any; the unit uses 5514)")
    p.add_argument("--state", help="state file (gap tracking survives restarts)")
    p.add_argument("--out-dir", help="write events.jsonl / health.jsonl here")
    p.add_argument("--hec-url", help="SIEM HTTP event collector base URL (HEC format), e.g. https://siem:8088")
    p.add_argument("--hec-token-file")
    p.add_argument("--hec-ca", help="CA bundle for the HEC certificate")
    p.add_argument("--hec-insecure", action="store_true", help="skip TLS verification (lab only)")
    p.add_argument("--hec-queue", type=int, default=100000,
                   help="events held in memory for the SIEM; overflow is reported as gaps")
    p.add_argument("--spool-dir", default="/var/lib/wd2l/spool")
    p.add_argument("--default-index", help="index for events that arrive without one")
    p.add_argument("--force-index", help="send every event to this index, ignoring the one set in Enclave 1")
    p.add_argument("--health-index", help="index for wd2l:health records")
    p.add_argument("--max-event", type=int, default=wire.DEFAULT_MAX_EVENT)
    p.add_argument("--max-buffer", type=int, default=64 * 1024 * 1024,
                   help="max bytes held for partly received events")
    p.add_argument("--reasm-timeout", type=float, default=5.0)
    p.add_argument("--gap-window", type=float, default=2.0,
                   help="seconds a missing event may be late before it is declared a gap")
    p.add_argument("--hb-timeout", type=float, default=5.0)
    p.add_argument("--health-interval", type=float, default=60.0)
    p.add_argument("--fault-interval", type=float, default=5.0,
                   help="seconds between fault-location checks (live capture only)")
    p.add_argument("--fault-window", type=float, default=60.0,
                   help="seconds over which counter growth counts as 'new'")
    p.add_argument("--input-flat-after", type=float, default=300.0,
                   help="seconds without new events from the aggregator before rule 5 fires")
    p.add_argument("--time-check-interval", type=float, default=60.0,
                   help="seconds between chrony reads")
    p.add_argument("--stream-lost-after", type=float, default=60.0)
    p.add_argument("--stream-retention", type=float, default=7 * 86400.0,
                   help="seconds to keep full records of finished streams with nothing open; "
                        "keep it at least as long as the pcap archive")
    p.add_argument("--no-rx-time", dest="rx_time", action="store_false",
                   help="don't stamp each event's arrival time in indexed field wd2l_rx_time")
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
    p.add_argument("--chrony-addr", type=hostinfo.chrony_address, metavar="HOST[:PORT]",
                   help="ask chronyd over UDP (its command port, 323) for time quality instead "
                        "of running --chronyc; the container units use 127.0.0.1:323")
    p.add_argument("--capture-iface", help="NIC whose carrier and receive counters are reported "
                                           "(default: the --live interface)")
    p.add_argument("--pcap-dir", help="capture archive directory, to check tcpdump is writing it "
                                      "(deployed: /var/lib/wd2l/pcap)")
    p.add_argument("--capture-rcvbuf", type=int, default=64 * 1024 * 1024,
                   help="receive buffer of the capture socket, bytes")
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


def rcvbuf_warning(got: int, wanted: int) -> Optional[str]:
    """A warning when the kernel gave the capture socket less than --capture-rcvbuf. It
    reports double what it set, so anything under 2 x wanted is less."""
    if got >= 2 * wanted:
        return None
    return ("capture receive buffer is %d KiB, not the %d KiB asked for (--capture-rcvbuf): "
            "bursts can be dropped by the kernel. Raise net.core.rmem_max to at least %d "
            "(deploy/receiver/90-wd2l.conf)" % (got // 2048, wanted // 1024, wanted))


def steady_clock() -> Callable[[], float]:
    """Wall-clock time at start plus monotonic time since: it reads like wall time but a clock
    step (NTP correction, operator change) can't make timers fire early or stall."""
    wall0, mono0 = time.time(), time.monotonic()
    return lambda: wall0 + (time.monotonic() - mono0)


def _stop_counters(rx: "Receiver") -> Dict[str, int]:
    return {k: rx.counters[k] for k in ("events_delivered", "gap_events", "late_fills",
                                        "duplicates", "output_dropped")}


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = build_parser()
    a = p.parse_args(argv)
    if a.audit_dir and a.hec_url and not a.hec_audit_token_file:
        # On the data token, whose index list leaves the audit index out, the SIEM would refuse
        # every audit record.
        p.error("--audit-dir with --hec-url needs --hec-audit-token-file (a token that can write "
                "the audit index). If the site uses one token for both, name the same file as "
                "--hec-token-file")
    logsetup.setup(a.log_format, a.verbose)
    settings = {k: v for k, v in sorted(vars(a).items())}
    cfg_sha = auditlog.sha256_hex(auditlog.canonical(settings))
    tq = hostinfo.time_quality(a.chronyc, a.chrony_addr, every=a.time_check_interval)
    component = "replay" if a.pcap else "receiver"
    audit = None
    if a.audit_dir:
        try:
            audit = auditlog.AuditLog(a.audit_dir, component, 2, time_quality=tq,
                                      min_free_bytes=a.audit_min_free_mb * 1024 * 1024)
        except auditlog.AuditLocked as e:
            raise SystemExit(str(e))
        audit.check_space()     # the floor holds from the first record
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
              audit=audit, audit_output=audit_out,
              config_sha256=None if a.pcap else cfg_sha,
              fault_window=a.fault_window, input_flat_after=a.input_flat_after,
              component=component, time_quality=tq)
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
        rx = Receiver(out, record_clock=time.time, fault_interval=a.fault_interval,
                      nic_probe=(lambda: hostinfo.nic_stats(a.capture_iface or a.live)),
                      archive_probe=(lambda: hostinfo.archive_status(a.pcap_dir))
                      if a.pcap_dir else None, **kw)
        if audit:
            audit.start_verify()
        stopped_by: List[int] = []
        signal.signal(signal.SIGTERM, lambda s, _f: stopped_by.append(s))
        signal.signal(signal.SIGINT, lambda s, _f: stopped_by.append(s))
        cap = packets.LiveCapture(a.live, rcvbuf=a.capture_rcvbuf)
        warning = rcvbuf_warning(cap.rcvbuf, a.capture_rcvbuf)
        if warning:
            log.warning(warning)
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


if __name__ == "__main__":
    raise SystemExit(main())
