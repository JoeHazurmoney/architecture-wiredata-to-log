"""End-to-end reconciliation (docs/audit-and-health.md §7).

Each side keeps a set hash per data stream: the sum, modulo 2^256, of
SHA-256(seq as 8 bytes big-endian || event SHA-256) over every event. A sum doesn't depend on
order, so an event that arrives out of order, or fills a gap days later from an archive replay,
just adds its term. Equal values at a cut prove the receiver delivered exactly the events the
sender numbered up to it, unchanged and under the right numbers. This detects accidental loss,
duplication, change or misnumbering; it doesn't defend against someone who controls the sender."""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Any, Deque, Dict, Optional, Set, Tuple

MOD = 1 << 256


def term(seq: int, digest: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seq.to_bytes(8, "big") + digest).digest(), "big")


class SetHash:
    __slots__ = ("value",)

    def __init__(self, value: int = 0):
        self.value = value % MOD

    def add(self, seq: int, digest: bytes) -> None:
        self.value = (self.value + term(seq, digest)) % MOD

    def hex(self) -> str:
        return "%064x" % self.value

    @classmethod
    def from_hex(cls, h: str) -> "SetHash":
        return cls(int(h, 16))


class StreamReconciler:
    """The receiver's side of one data stream.

    unsettled  events handed to the output, not durable yet (seq -> digest)
    base       set hash of durable events with seq <= checked (the last compared cut)
    above      durable events with seq > checked, kept apart until a cut covers them
    cuts       the sender's (seq, events_hash) from heartbeats, waiting to be compared
    "Delivered" is what ADR-0003 defines: the SIEM answered 200, or the event is in the spool.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.base = SetHash()
        self.above: Dict[int, bytes] = {}
        self.checked = 0
        self.unsettled: Dict[int, bytes] = {}
        self.cuts: Deque[Tuple[int, str]] = deque(maxlen=64)
        self.last_cut: Optional[Tuple[int, str]] = None
        self.dirty = False
        self.last: Optional[Dict[str, Any]] = None
        self.filled = 0
        self.written: Optional[Tuple[int, bool]] = None   # (cut, balanced) last recorded

    def delivered(self, seq: int, digest: bytes) -> None:
        if self.enabled:
            self.unsettled[seq] = digest

    def dropped(self, seq: int) -> None:
        self.unsettled.pop(seq, None)

    def cut(self, seq: int, sender_hash: str) -> None:
        newest = max([c[0] for c in self.cuts] + ([self.last_cut[0]] if self.last_cut else []),
                     default=-1)
        if self.enabled and seq > newest:
            self.cuts.append((seq, sender_hash))

    def settle(self, pending: Set[int]) -> None:
        """Move events the output no longer holds as pending (now durable) into the hash."""
        for seq in [s for s in self.unsettled if s not in pending]:
            digest = self.unsettled.pop(seq)
            if seq <= self.checked:
                self.base.add(seq, digest)
                self.dirty = True
            else:
                self.above[seq] = digest

    def check(self, lo: int, gaps: Any) -> Optional[Dict[str, Any]]:
        """Compare at the highest cut whose events are all resolved (below `lo`) and durable.
        With no new cut, compare again at the last one if late events were added below it."""
        if not self.enabled:
            return None
        low = min(self.unsettled) if self.unsettled else None
        ready = [c for c in self.cuts if c[0] < lo and (low is None or c[0] < low)]
        if ready:
            cut = ready[-1]
            while self.cuts and self.cuts[0][0] <= cut[0]:
                self.cuts.popleft()
        elif self.dirty and self.last_cut is not None and (low is None or self.last_cut[0] < low):
            cut = self.last_cut
        else:
            return None
        seq, sender_hash = cut
        for s in [s for s in self.above if s <= seq]:
            self.base.add(s, self.above.pop(s))
        self.checked = max(self.checked, seq)
        self.last_cut, self.dirty = cut, False
        open_below = bool(gaps.r) and gaps.r[0][0] <= seq
        rh = self.base.hex()
        self.last = {"cut": seq, "sender_hash": sender_hash, "receiver_hash": rh,
                     "balanced": rh == sender_hash and not open_below}
        return self.last

    def to_json(self) -> Dict[str, Any]:
        """Durable events only: unsettled ones are the state file's "uncommitted" and come back
        as gaps after a restart."""
        return {"enabled": self.enabled, "base": self.base.hex(), "checked": self.checked,
                "above": [[s, dg.hex()] for s, dg in sorted(self.above.items())],
                "cuts": [list(c) for c in self.cuts],
                "last_cut": list(self.last_cut) if self.last_cut else None,
                "last": self.last, "filled": self.filled,
                "written": list(self.written) if self.written else None}

    @classmethod
    def from_json(cls, d: Optional[Dict[str, Any]]) -> "StreamReconciler":
        if not d:
            return cls(enabled=False)   # saved before reconciliation existed: history unknown
        r = cls(enabled=bool(d.get("enabled", True)))
        r.base = SetHash.from_hex(d["base"])
        r.checked = int(d.get("checked", 0))
        r.above = {int(s): bytes.fromhex(h) for s, h in d.get("above", [])}
        r.cuts.extend((int(s), str(h)) for s, h in d.get("cuts", []))
        lc = d.get("last_cut")
        r.last_cut = (int(lc[0]), str(lc[1])) if lc else None
        r.last = d.get("last")
        r.filled = int(d.get("filled", 0))
        w = d.get("written")
        r.written = (int(w[0]), bool(w[1])) if w else None
        r.dirty = r.last_cut is not None   # compare again: a replay may add events
        return r
