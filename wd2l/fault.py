"""Where is the fault? The receiver's decision rules (docs/audit-and-health.md §10).

evaluate() takes one snapshot of signals and returns the first rule that matches: a status
(ok, amber, red), the suspected segment, the rule number and a sentence for the operator. Every
matching rule also colors its own segments, for the pipeline picture on the dashboard; segments
the receiver can't see while nothing arrives are "unknown". The receiver keeps the answer and
writes a type=fault record only when it changes (FaultTracker)."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .hostinfo import time_alarm

SEGMENTS = ("e1-input", "e1-sender", "boundary", "e2-capture", "e2-receiver", "e2-siem")
RANK = {"ok": 0, "unknown": 1, "amber": 2, "red": 3}


@dataclass
class Signals:
    hb_timeout: float = 5.0
    carrier: Optional[bool] = None          # capture NIC carrier (None: not known)
    packet_age: Optional[float] = None      # s since any frame on the capture NIC (None: never)
    frame_age: Optional[float] = None       # s since a valid wd2l frame (None: never)
    clean_end: bool = False                 # the newest sender run ended with a final heartbeat
    input_flat_s: float = 0.0               # s the sender's events_in hasn't grown
    input_flat_after: float = 300.0
    sender_drops: int = 0                   # growth over the window, from here down
    send_errors: int = 0
    backlog_growing: bool = False
    gaps_not_received: int = 0
    gaps_output_dropped: int = 0
    nic_errors: int = 0                     # capture NIC receive errors (CRC, frame, ...)
    kernel_drops: int = 0
    output_dropped: int = 0
    spool_growing: bool = False
    hec_errors: int = 0                     # failed or rejected posts to the SIEM
    archive_stale: Optional[bool] = None    # packets arrive but the archive isn't written


@dataclass
class Fault:
    status: str
    segment: Optional[str]
    rule: int
    detail: str
    segments: Dict[str, str] = field(default_factory=lambda: dict.fromkeys(SEGMENTS, "ok"))

    def key(self) -> Tuple[str, Optional[str], int]:
        return (self.status, self.segment, self.rule)


OK = Fault("ok", None, 0, "")


def evaluate(s: Signals) -> Fault:
    seg = dict.fromkeys(SEGMENTS, "ok")
    hits: List[Tuple[int, str, str, str]] = []

    def hit(rule: int, status: str, label: str, segs: Tuple[str, ...], detail: str) -> None:
        hits.append((rule, status, label, detail))
        for x in segs:
            if RANK[status] > RANK[seg[x]]:
                seg[x] = status

    def unknown(*segs: str) -> None:
        for x in segs:
            if seg[x] == "ok":
                seg[x] = "unknown"

    silent = s.packet_age is None or s.packet_age > s.hb_timeout
    no_frames = s.frame_age is None or s.frame_age > s.hb_timeout
    if s.carrier is False:
        hit(1, "red", "boundary", ("boundary",), "capture NIC has no carrier: tap, fiber or optic")
    if silent:
        if s.clean_end:
            hit(2, "amber", "e1-sender", ("e1-sender",),
                "the sender stopped cleanly (planned downtime?) and nothing has arrived since")
        else:
            hit(3, "red", "e1-sender/boundary", ("e1-sender", "boundary"),
                "nothing arriving: the sender, its egress NIC, or the tap; after recovery, an "
                "unchanged boot means the sender stayed up and the link was the problem")
        unknown("e1-input")
    elif no_frames:
        hit(4, "red", "boundary", ("boundary",),
            "packets arrive but none are valid wd2l frames: tap filter or wiring")
        unknown("e1-input", "e1-sender")
    else:
        if s.input_flat_s >= s.input_flat_after:
            hit(5, "amber", "e1-input", ("e1-input",),
                "no events from the log aggregator for %d s" % s.input_flat_s)
        trouble = [name for name, v in (("drops", s.sender_drops), ("send errors", s.send_errors))
                   if v] + (["input backlog growing"] if s.backlog_growing else [])
        if trouble:
            hit(6, "amber", "e1-sender", ("e1-sender",), "sender: " + ", ".join(trouble))
        if s.gaps_not_received:
            n = s.gaps_not_received
            if s.nic_errors:
                hit(7, "red", "boundary", ("boundary",),
                    "%d events lost with capture NIC receive errors: fiber or optic" % n)
            elif s.kernel_drops:
                hit(8, "red", "e2-capture", ("e2-capture", "e2-receiver"),
                    "%d events lost with kernel drops: receiver host capacity" % n)
            else:
                # Also what the receiver's own downtime looks like, capture still running: the
                # gaps are real until a replay fills them, so the rule still fires (#133).
                hit(9, "amber", "boundary", ("boundary",),
                    "%d events lost, no NIC errors or kernel drops: loss on the path, or the "
                    "receiver was down" % n)
    dropped = s.output_dropped or s.gaps_output_dropped
    if dropped or s.spool_growing or s.hec_errors:
        hit(10, "red" if dropped else "amber", "e2-siem", ("e2-siem",),
            "SIEM delivery: " + ", ".join(
                x for x, on in (("events dropped", dropped), ("spool growing", s.spool_growing),
                                ("posts failing or rejected", s.hec_errors)) if on))
    if s.archive_stale:
        hit(11, "amber", "e2-capture", ("e2-capture",),
            "the capture archive isn't being written: a replay would have nothing")
    if not hits:
        return Fault("ok", None, 0, "", seg)
    rule, status, label, detail = min(hits)
    return Fault(status, label, rule, detail, seg)


def time_status(own: Optional[Dict[str, Any]], sender_hb: Dict[str, Any],
                clock_offset_s: Optional[float], max_stratum: int = 3,
                max_offset_ms: float = 100.0, max_skew_s: float = 0.05
                ) -> Tuple[str, Optional[str]]:
    """Time quality on both sides and the skew between them (§9). Shown apart from the transfer
    fault: bad time doesn't lose events, but it makes their timestamps wrong."""
    reasons = []
    if own is not None:
        why = time_alarm(own, max_stratum, max_offset_ms)
        if why:
            reasons.append("receiver: " + why)
    if "time_synced" in sender_hb:
        why = time_alarm({"synced": sender_hb.get("time_synced"),
                          "stratum": sender_hb.get("time_stratum", 0),
                          "offset_ms": sender_hb.get("time_offset_ms", 0.0)},
                         max_stratum, max_offset_ms)
        if why:
            reasons.append("sender: " + why)
    if sender_hb.get("time_unavailable") is True:
        reasons.append("sender: unavailable")
    if clock_offset_s is not None and abs(clock_offset_s) > max_skew_s:
        reasons.append("clock skew %.3f s > %g s" % (clock_offset_s, max_skew_s))
    return ("alarm", "; ".join(reasons)) if reasons else ("ok", None)


class FaultTracker:
    """Turns cumulative counters into growth over a window, and remembers the last answers."""

    def __init__(self, window: float = 60.0):
        self.window = window
        self.samples: Deque[Tuple[float, Dict[str, float]]] = deque()
        self.current: Fault = OK
        self.time: Tuple[str, Optional[str]] = ("ok", None)
        self._input: Tuple[Any, Any] = (None, None)
        self._input_since: Optional[float] = None

    def add(self, now: float, counters: Dict[str, float]) -> None:
        self.samples.append((now, dict(counters)))
        while len(self.samples) > 2 and now - self.samples[1][0] >= self.window:
            self.samples.popleft()

    def delta(self, name: str) -> float:
        """Growth over the window. A counter that went down (a new sender run) counts from 0."""
        if len(self.samples) < 2:
            return 0
        new = self.samples[-1][1].get(name) or 0
        old = self.samples[0][1].get(name) or 0
        return new - old if new >= old else new

    def input_flat(self, now: float, stream: Any, value: Any) -> float:
        """Seconds that `value` (the newest run's events_in) has stayed the same."""
        if (stream, value) != self._input or self._input_since is None:
            self._input, self._input_since = (stream, value), now
        return now - self._input_since
