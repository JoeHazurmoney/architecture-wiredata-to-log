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
import signal
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from . import packets, wire
from .outputs import FileOutput, HecOutput, MultiOutput, Output

log = logging.getLogger("wd2l.receiver")

MAX_GAP_RANGES = 100000
MAX_STREAMS = 1000
MAX_REASONS = 32


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
        self.final = False
        self.lost_reported = False
        self.hb: Dict[str, Any] = {}
        self.delivered = 0

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
        self.last_seen = now
        self.hb = info
        self._raise_known(last_seq, now)
        self._advance()
        if info.get("final") is True:
            self.final = True

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
                "last_seen": self.last_seen, "final": self.final,
                "lost_reported": self.lost_reported, "hb": self.hb,
                "delivered": self.delivered}

    @classmethod
    def from_json(cls, sid: int, d: Dict[str, Any]) -> "StreamTracker":
        t = cls(sid, float(d.get("first_seen", 0)))
        t.lo = int(d["lo"])
        t.above = {int(x) for x in d.get("above", [])}
        t.known = int(d.get("known", 0))
        t.marks = deque((int(a), float(b)) for a, b in d.get("marks", []))
        t.gaps = RangeSet(d.get("gaps", []))
        t.last_seen = float(d.get("last_seen", 0))
        t.final = bool(d.get("final", False))
        t.lost_reported = bool(d.get("lost_reported", False))
        t.hb = d.get("hb", {}) if isinstance(d.get("hb"), dict) else {}
        t.delivered = int(d.get("delivered", 0))
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
                 health_interval: float = 60.0, stream_lost_after: float = 60.0):
        self.out = output
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.src_ip = src_ip
        self.state_path = state_path
        self.reasm = Reassembler(max_event, max_buffer, reasm_timeout)
        self.gap_window = gap_window
        self.hb_timeout = hb_timeout
        self.health_interval = health_interval
        self.stream_lost_after = stream_lost_after
        self.streams: Dict[int, StreamTracker] = {}
        self.counters = {"frames": 0, "other_packets": 0, "bad_frames": 0, "bad_events": 0,
                         "events_delivered": 0, "duplicates": 0, "late_fills": 0,
                         "gap_events": 0, "heartbeats": 0, "kernel_drops": 0}
        self.other_reasons: Dict[str, int] = {}
        self.bad_reasons: Dict[str, int] = {}
        self.last_hb: Optional[float] = None
        self.hb_stale = False
        self.started: Optional[float] = None
        self.last_health: Optional[float] = None
        self.last_save = 0.0
        self.dirty = False
        if state_path and os.path.exists(state_path):
            self._load_state()

    # -- input

    @staticmethod
    def _bump(d: Dict[str, int], reason: str) -> None:
        if reason in d or len(d) < MAX_REASONS:
            d[reason] = d.get(reason, 0) + 1
        else:
            d["other"] = d.get("other", 0) + 1

    def handle_frame(self, frame: bytes, now: float) -> None:
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
        t = self._stream(f.stream_id, now)
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
            self.counters["late_fills"] += 1
        self.out.event(evt, f.stream_id, f.seq)
        self.counters["events_delivered"] += 1
        self.dirty = True

    def _stream(self, sid: int, now: float) -> StreamTracker:
        t = self.streams.get(sid)
        if t is None:
            if len(self.streams) >= MAX_STREAMS:
                oldest = min(self.streams.values(), key=lambda s: s.last_seen)
                del self.streams[oldest.stream_id]
            t = self.streams[sid] = StreamTracker(sid, now)
            log.info("new stream %016x", sid)
            self._health_record("stream_start", now, stream="%016x" % sid)
            self.dirty = True
        return t

    def _heartbeat(self, t: StreamTracker, f: wire.Frame, now: float) -> None:
        try:
            info = json.loads(f.payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            info = None
        if not isinstance(info, dict):
            self.counters["bad_frames"] += 1
            self._bump(self.bad_reasons, "bad heartbeat json")
            return
        info = {k: v for k, v in info.items()
                if isinstance(k, str) and isinstance(v, (int, float, bool))}
        self.counters["heartbeats"] += 1
        was_final = t.final
        t.on_heartbeat(f.seq, info, now)
        if t.final and not was_final:
            self._health_record("stream_end", now, stream="%016x" % t.stream_id,
                                last_seq=f.seq, sender=info)
        self.last_hb = now
        if self.hb_stale:
            self.hb_stale = False
            self._health_record("heartbeat_restored", now)
        self.dirty = True

    # -- time-driven work

    def tick(self, now: float) -> None:
        if self.started is None:
            self.started = now
        self.reasm.expire(now)
        for t in list(self.streams.values()):
            self._report_gaps(t, t.declare(now, self.gap_window), now)
            if (not t.final and not t.lost_reported
                    and now - t.last_seen > self.stream_lost_after):
                t.lost_reported = True
                self._health_record("stream_lost", now, stream="%016x" % t.stream_id,
                                    last_seq=t.known, idle_s=round(now - t.last_seen, 1))
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
        if self.state_path and self.dirty and time.monotonic() - self.last_save >= 1.0:
            self.save_state()

    def _report_gaps(self, t: StreamTracker, declared: List[Tuple[int, int]], now: float) -> None:
        for a, b in declared:
            n = b - a + 1
            self.counters["gap_events"] += n
            log.warning("GAP stream %016x seq %d-%d (%d events)", t.stream_id, a, b, n)
            self._health_record("gap", now, stream="%016x" % t.stream_id,
                                first_seq=a, last_seq=b, count=n)
            self.dirty = True

    def _health_record(self, kind: str, now: float, **kw: Any) -> None:
        rec = {"type": kind, "time": round(now, 3)}
        rec.update(kw)
        self.out.health(rec)

    def emit_health(self, now: float) -> Dict[str, Any]:
        streams = {}
        for t in self.streams.values():
            if t.final and not t.gaps.r and now - t.last_seen > 3600:
                continue
            streams["%016x" % t.stream_id] = {
                "next_seq": t.lo, "known_seq": t.known, "open_gap_events": t.gaps.count(),
                "final": t.final, "idle_s": round(now - t.last_seen, 1), "sender": t.hb}
        ref = self.last_hb if self.last_hb is not None else self.started
        rec = dict(self.counters, **self.reasm.counters, **self.out.stats())
        # Flat totals so SIEM alerts don't have to dig into the per-stream map.
        live = [t for t in self.streams.values() if "%016x" % t.stream_id in streams]
        rec.update(open_gap_events=sum(t.gaps.count() for t in self.streams.values()),
                   sender_drops=sum(int(t.hb.get("sender_drops", 0)) for t in live),
                   sender_truncated=sum(int(t.hb.get("truncated", 0)) for t in live),
                   sender_bad_input=sum(int(t.hb.get("bad_input", 0)) for t in live))
        rec.update(type="health", time=round(now, 3), streams=streams,
                   heartbeat_age_s=round(now - ref, 1) if ref is not None else None,
                   heartbeat_stale=self.hb_stale, other_reasons=self.other_reasons,
                   bad_reasons=self.bad_reasons, reasm_buffered=self.reasm.buffered)
        self.out.health(rec)
        return rec

    def finish(self, now: float) -> Dict[str, Any]:
        """End of input: give up on partial events, declare every remaining hole a gap."""
        self.reasm.expire(now, force=True)
        for t in self.streams.values():
            self._report_gaps(t, t.declare(now, self.gap_window, force=True), now)
        rec = self.emit_health(now)
        self.out.flush()
        if self.state_path:
            self.save_state()
        return rec

    # -- state

    def save_state(self) -> None:
        state = {"version": 1, "streams": {"%016x" % s: t.to_json() for s, t in self.streams.items()}}
        tmp = self.state_path + ".tmp"  # type: ignore[operator]
        with open(tmp, "w") as f:
            json.dump(state, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)  # type: ignore[arg-type]
        self.last_save = time.monotonic()
        self.dirty = False

    def _load_state(self) -> None:
        with open(self.state_path) as f:  # type: ignore[arg-type]
            state = json.load(f)
        for sid, d in state.get("streams", {}).items():
            self.streams[int(sid, 16)] = StreamTracker.from_json(int(sid, 16), d)
        log.info("loaded state for %d streams", len(self.streams))


# ---------------------------------------------------------------- main

def build_output(a: argparse.Namespace) -> Output:
    outs: List[Output] = []
    if a.out_dir:
        outs.append(FileOutput(a.out_dir))
    if a.hec_url:
        if not a.hec_token_file:
            raise SystemExit("--hec-url needs --hec-token-file")
        with open(a.hec_token_file) as f:
            token = f.read().strip()
        outs.append(HecOutput(a.hec_url, token, a.spool_dir, a.hec_ca, a.hec_insecure,
                              a.default_index, a.health_index, a.force_index))
    if not outs:
        raise SystemExit("need at least one output: --out-dir and/or --hec-url")
    return outs[0] if len(outs) == 1 else MultiOutput(outs)


def main(argv: Optional[Sequence[str]] = None) -> int:
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
    p.add_argument("--state", help="state file (gap tracking survives restarts)")
    p.add_argument("--out-dir", help="write events.jsonl / health.jsonl here")
    p.add_argument("--hec-url", help="SIEM HTTP event collector base URL (HEC format), e.g. https://siem:8088")
    p.add_argument("--hec-token-file")
    p.add_argument("--hec-ca", help="CA bundle for the HEC certificate")
    p.add_argument("--hec-insecure", action="store_true", help="skip TLS verification (lab only)")
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
    p.add_argument("--stream-lost-after", type=float, default=60.0)
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")

    out = build_output(a)
    rx = Receiver(out, a.dst_ip or None, a.dst_port, a.src_ip or None, a.state, a.max_event,
                  a.max_buffer, a.reasm_timeout, a.gap_window, a.hb_timeout,
                  a.health_interval, a.stream_lost_after)
    try:
        if a.pcap:
            last = None
            for ts, frame in packets.iter_pcap_paths(a.pcap):
                rx.handle_frame(frame, ts)
                if last is None or ts - last >= 0.2:
                    rx.tick(ts)
                    last = ts
            summary = rx.finish((last or time.time()) + a.gap_window)
            print(json.dumps(summary, sort_keys=True))
            return 0

        stop = []
        signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
        signal.signal(signal.SIGINT, lambda *_: stop.append(1))
        cap = packets.LiveCapture(a.live)
        log.info("capturing on %s, dst %s:%d", a.live, a.dst_ip or "*", a.dst_port)
        last = 0.0
        while not stop:
            frame = cap.recv()
            now = time.time()
            if frame is not None:
                rx.handle_frame(frame, now)
            if now - last >= 0.2:
                _, drops = cap.kernel_stats()
                rx.counters["kernel_drops"] += drops
                rx.tick(now)
                rx.out.flush()
                last = now
        cap.close()
        rx.emit_health(time.time())
        if a.state:
            rx.save_state()
        return 0
    finally:
        out.close()


if __name__ == "__main__":
    raise SystemExit(main())
