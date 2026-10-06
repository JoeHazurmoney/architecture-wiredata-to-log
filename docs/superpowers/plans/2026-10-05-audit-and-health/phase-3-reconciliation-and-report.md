# Phase 3: reconciliation and the audit report

Part of the [audit and health implementation plan](README.md). Read its **Global constraints**
first. Spec: [docs/audit-and-health-plan.md](../../../audit-and-health-plan.md) §9 and §10
(`wd2l-audit-report verify`).

**Delivers:** both sides keep a set hash per data stream; every heartbeat carries the sender's
value at its `seq`; the receiver compares at each cut once everything up to it is resolved and
durable, survives restarts and replays, and writes `reconcile` records (hourly, at stream end,
and when an ended stream's balance changes). `wd2l-audit-report` verifies chains (files or a SIEM
export), reports reconciliation per day and stream, and filters records. The lab checks the
balance on every run.

Run tests with `T` from the plan README.

---

### Task 3.1: The set hash

**Files:**
- Create: `wd2l/reconcile.py`
- Create: `tests/test_reconcile.py`

**Interfaces:**
- Produces:
  - `reconcile.MOD = 2**256`, `reconcile.term(seq: int, digest: bytes) -> int`
  - `reconcile.SetHash(value=0)` with `.add(seq, digest)`, `.hex() -> str` (64 hex digits),
    `SetHash.from_hex(h)`
  - `reconcile.StreamReconciler(enabled=True)` with `.delivered(seq, digest)`, `.dropped(seq)`,
    `.cut(seq, sender_hash)`, `.settle(pending: Set[int])`, `.check(lo: int, gaps) ->
    Optional[dict]` (`gaps` has `.r`, sorted `[a, b]` ranges, like `receiver.RangeSet`),
    `.to_json()`, `StreamReconciler.from_json(d)`; attributes `enabled, last, last_cut, filled,
    written, unsettled`

- [ ] **Step 1: Write the failing tests**

`tests/test_reconcile.py`:

```python
import hashlib
import random

from wd2l import reconcile
from wd2l.receiver import RangeSet
from wd2l.reconcile import SetHash, StreamReconciler


def d(i):
    return hashlib.sha256(b"event %d" % i).digest()


def sender_hash(seqs):
    h = SetHash()
    for s in seqs:
        h.add(s, d(s))
    return h.hex()


def test_term_is_sha256_of_seq_and_digest():
    want = int.from_bytes(hashlib.sha256((7).to_bytes(8, "big") + d(7)).digest(), "big")
    assert reconcile.term(7, d(7)) == want


def test_set_hash_ignores_order_and_wraps():
    seqs = list(range(1, 200))
    shuffled = seqs[:]
    random.Random(3).shuffle(shuffled)
    assert sender_hash(seqs) == sender_hash(shuffled)
    assert len(SetHash().hex()) == 64 and SetHash().hex() == "0" * 64
    big = SetHash(reconcile.MOD - 1)
    big.add(1, d(1))
    assert big.value == reconcile.term(1, d(1)) - 1
    assert SetHash.from_hex(sender_hash(seqs)).hex() == sender_hash(seqs)


def ready(rc, seqs, lo, gaps=None, pending=()):
    for s in seqs:
        rc.delivered(s, d(s))
    rc.settle(set(pending))
    return rc.check(lo, gaps or RangeSet())


def test_everything_delivered_balances():
    rc = StreamReconciler()
    rc.cut(10, sender_hash(range(1, 11)))
    res = ready(rc, range(1, 11), lo=11)
    assert res == {"cut": 10, "sender_hash": sender_hash(range(1, 11)),
                   "receiver_hash": sender_hash(range(1, 11)), "balanced": True}


def test_no_comparison_until_the_cut_is_resolved_and_durable():
    rc = StreamReconciler()
    rc.cut(10, sender_hash(range(1, 11)))
    assert ready(rc, range(1, 10), lo=10) is None                 # 10 not resolved yet
    assert ready(rc, [10], lo=11, pending={10}) is None           # 10 not durable yet
    rc.settle(set())
    assert rc.check(11, RangeSet())["balanced"] is True


def test_an_open_gap_unbalances_and_a_late_fill_rebalances():
    rc = StreamReconciler()
    rc.cut(5, sender_hash(range(1, 6)))
    gaps = RangeSet([[3, 3]])
    res = ready(rc, [1, 2, 4, 5], lo=6, gaps=gaps)
    assert res["balanced"] is False and res["receiver_hash"] != res["sender_hash"]
    gaps.remove(3)
    rc.filled += 1
    res = ready(rc, [3], lo=6, gaps=gaps)                         # same cut, compared again
    assert res["balanced"] is True and res["cut"] == 5


def test_events_past_the_cut_wait_for_the_next_cut():
    rc = StreamReconciler()
    rc.cut(3, sender_hash(range(1, 4)))
    assert ready(rc, range(1, 6), lo=6)["balanced"] is True       # 4 and 5 kept apart
    rc.cut(5, sender_hash(range(1, 6)))
    assert rc.check(6, RangeSet())["balanced"] is True


def test_dropped_before_durable_is_not_counted():
    rc = StreamReconciler()
    rc.cut(2, sender_hash([1, 2]))
    rc.delivered(1, d(1))
    rc.delivered(2, d(2))
    rc.dropped(2)
    rc.settle(set())
    assert rc.check(3, RangeSet([[2, 2]]))["balanced"] is False


def test_state_round_trip_and_old_state_is_disabled():
    rc = StreamReconciler()
    rc.cut(3, sender_hash(range(1, 4)))
    ready(rc, range(1, 6), lo=6)
    rc.cut(9, "f" * 64)
    back = StreamReconciler.from_json(rc.to_json())
    assert back.to_json()["base"] == rc.to_json()["base"] and back.last == rc.last
    assert sorted(back.above) == [4, 5] and list(back.cuts) == [(9, "f" * 64)]
    assert StreamReconciler.from_json(None).enabled is False
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_reconcile.py -q`
Expected: `ModuleNotFoundError: No module named 'wd2l.reconcile'`.

- [ ] **Step 3: Write the implementation**

`wd2l/reconcile.py`:

```python
"""End-to-end reconciliation (docs/audit-and-health-plan.md §9).

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
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_reconcile.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/reconcile.py tests/test_reconcile.py
git commit -m "Set hash and per-stream reconciler" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.2: The sender's set hash in every heartbeat

**Files:**
- Modify: `wd2l/sender.py`
- Modify: `tests/test_sender_health.py` (append)
- Modify: `docs/interface-description.md`, `docs/wire-format.md` (same commit)

**Interfaces:**
- Consumes: `reconcile.SetHash`, `wire.event_digest`, `wire.encode_event(..., digest=)`.
- Produces: `Sender.events_hash: SetHash`; heartbeat key `events_hash` (always present, never
  trimmed; 64 hex digits, covering events 1 … the heartbeat's `seq`);
  `Sender.reconcile_record()` writes `reconcile` (`stream`, `cut`, `last_seq`, `events_in`,
  `events_sent`, `sender_hash`); `Sender.next_reconcile` (monotonic time; hourly from
  `periodic()`); `main` writes one more `reconcile` just before `stop`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_sender_health.py`:

```python
from wd2l.reconcile import SetHash
from helpers import read_audit


def test_heartbeat_events_hash_covers_events_up_to_its_seq():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=500)
    s.send_heartbeat()
    assert last_info(sock)["events_hash"] == "0" * 64
    for i in range(5):
        s.send_event({"_raw": "line %d " % i * 100})    # several pieces each
    s.send_heartbeat()
    h = SetHash()
    for f in [wire.decode(x) for x in sock.sent]:
        if f.type == wire.TYPE_DATA and f.chunk_idx == 0:
            h.add(f.seq, f.digest)
    assert last_info(sock)["events_hash"] == h.hex() and wire.decode(sock.sent[-1]).seq == 5


def test_worst_case_heartbeat_fits_one_packet():
    """Review focus 3: every key at its largest still fits one packet at MTU 1500."""
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    s.link = {"boot": 2 ** 63, "prev_stream": 2 ** 64 - 1, "prev_last_seq": 2 ** 63}
    s.counters = {k: 2 ** 63 for k in s.counters}
    s.events_hash = SetHash(2 ** 256 - 1)
    snap = {"stall_s": 123456789.123, "cpu_pct": 9999.9, "rss_mb": 1048576.5, "clients": 99999,
            "input_backlog_bytes": 2 ** 63, "nic_carrier": False, "nic_tx_packets": 2 ** 63,
            "nic_tx_errors": 2 ** 63, "nic_tx_dropped": 2 ** 63, "time_stratum": 16,
            "time_offset_ms": -123456789.123, "time_synced": False, "audit_ok": False,
            "audit_n": 2 ** 63}
    frame = s._heartbeat_frame(True, snap)
    info = json.loads(wire.decode(frame).payload)
    assert "nic_tx_dropped" in info and info["events_hash"] == "f" * 64
    assert len(frame) <= wire.DEFAULT_MAX_DATAGRAM, len(frame)


def test_reconcile_records(tmp_path):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="h", actor="me", build="b")
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, audit=a)
    for i in range(3):
        s.send_event({"_raw": "x%d" % i})
    s.reconcile_record()
    [r] = [x for x in read_audit(a.dir) if x["event"] == "reconcile"]
    assert (r["cut"], r["last_seq"], r["events_sent"], r["sender_hash"]) == \
        (3, 3, 3, s.events_hash.hex())
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_sender_health.py -q`
Expected: `KeyError: 'events_hash'` / `AttributeError: ... 'events_hash'`.

- [ ] **Step 3: Implement**

In `wd2l/sender.py`:

(a) `from .reconcile import SetHash`. In `Sender.__init__`, after `self.seq = 0`:

```python
        self.events_hash = SetHash()   # §9: this run's set hash over (seq, event SHA-256)
        self.next_reconcile = time.monotonic() + 3600
```

(b) In `send_event`, compute the digest once and use it for the frame and the hash:

```python
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
                # ... the existing stamping block, unchanged, ending with:
                data = self._fit(dict(event, **stamps))
                digest = wire.event_digest(data)
            self.seq += 1
            self.events_hash.add(self.seq, digest)
            for dg in wire.encode_event(self.stream_id, self.seq, data, self.max_datagram,
                                        digest=digest):
                self._transmit(dg)
            self.counters["events_sent"] += 1
            return self.seq
```

(c) `heartbeat_info`: add `events_hash=self.events_hash.hex()` to the base dict (it is never
trimmed).

(d) Add `reconcile_record` and call it hourly:

```python
    def reconcile_record(self) -> None:
        """§9: this side's numbers at the current cut, for the reconcile report."""
        if self.audit is None:
            return
        with self.lock:
            fields = dict(stream="%016x" % self.stream_id, cut=self.seq, last_seq=self.seq,
                          events_in=self.counters["events_in"],
                          events_sent=self.counters["events_sent"],
                          sender_hash=self.events_hash.hex())
        self.audit.write("reconcile", "info", **fields)
```

In `periodic`, after `self.flush_summaries()`:

```python
        if time.monotonic() >= self.next_reconcile:
            self.next_reconcile += 3600
            self.reconcile_record()
```

In `main`, inside `if audit:` at shutdown, call `sender.reconcile_record()` before the `stop`
record.

- [ ] **Step 4: Update the interface pages (same commit)**

`docs/interface-description.md` §8: add the row `events_hash` | string, 64 hex digits | | always
(wd2l ≥ 0.2.0) | "Set hash of this run's events 1 … `seq` (the heartbeat's `seq` is the cut):
the sum modulo 2²⁵⁶ of SHA-256(`seq` as 8 bytes big-endian ‖ the event's SHA-256 `digest`).
Enclave 2 compares it with its own value to prove it delivered exactly these events
([audit plan §9](audit-and-health-plan.md#9-reconciliation-completeness-and-accuracy)). Never
dropped from a trimmed heartbeat." §9: add a bullet "Each heartbeat's `events_hash` lets
Enclave 2 reconcile the data stream end to end; the records stream doesn't carry one."

`docs/wire-format.md`: add `events_hash` to the heartbeat example and one paragraph defining it
as above.

- [ ] **Step 5: Run the tests**

Run: `T tests/test_sender_health.py tests/test_sender.py tests/test_end_to_end.py -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add wd2l/sender.py tests/test_sender_health.py docs/interface-description.md docs/wire-format.md
git commit -m "Sender: set hash of every event, in each heartbeat and in hourly reconcile records" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.3: The receiver reconciles at each cut

**Files:**
- Modify: `wd2l/receiver.py`
- Create: `tests/test_receiver_reconcile.py`

**Interfaces:**
- Consumes: `reconcile.StreamReconciler`, heartbeat `events_hash`, frame `digest`.
- Produces:
  - `StreamTracker.rc: StreamReconciler` (persisted as `rc`; disabled for records streams,
    restored retired streams, never-seen runs, and streams loaded from a state file without `rc`)
  - `Receiver._reconcile(now)` (each second from `tick`, and from `finish`/`close`); `reconcile`
    audit records: hourly for streams seen in the last hour or not balanced, and for ended
    streams whenever `(cut, balanced)` changes. Fields: `stream`, `cut`, `events_in`,
    `events_sent`, `events_delivered`, `gaps_open`, `gaps_filled`, `last_seq`, `sender_hash`,
    `receiver_hash`, `balanced`; outcome `success` if balanced, else `failure`
  - at the same moments, with or without auditing, a `type=reconcile` health record (`stream`,
    `cut`, `balanced`, `gaps_open`, `events_delivered`), so operators, who can't read the audit
    index, see the balance on the dashboard
  - health summaries: per stream `reconcile: {"cut", "balanced"}`, flat `reconcile_unbalanced`
  - the heartbeat filter keeps `events_hash` when it is 64 lowercase hex digits

- [ ] **Step 1: Write the failing tests**

`tests/test_receiver_reconcile.py`:

```python
import json

from wd2l import audit as auditlog
from wd2l import wire
from wd2l.receiver import Receiver
from wd2l.sender import Sender

from helpers import FakeSock, MemOutput, SlowOutput, eth, read_audit


def run(n=20):
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    for i in range(n):
        s.send_event({"_raw": "event %d" % i})
    s.send_heartbeat(final=True)
    return s, sock.sent[:-1], sock.sent[-1:]


def rx(out=None, **kw):
    out = out or MemOutput()
    kw.setdefault("health_interval", 1e9)
    kw.setdefault("gap_window", 1)
    return Receiver(out, dst_ip="10.255.255.2", dst_port=5514, **kw), out


def feed(r, dgs, now):
    for d in dgs:
        r.handle_frame(eth(d), now)


def last(r, s):
    return r.streams[s.stream_id].rc.last


def test_a_clean_stream_balances():
    s, data, hb = run()
    r, out = rx()
    feed(r, data + hb, 0)
    r.tick(1)
    assert last(r, s) == {"cut": 20, "sender_hash": s.events_hash.hex(),
                          "receiver_hash": s.events_hash.hex(), "balanced": True}
    rec = r.emit_health(1)
    assert rec["reconcile_unbalanced"] == 0
    assert rec["streams"]["%016x" % s.stream_id]["reconcile"] == {"cut": 20, "balanced": True}


def test_loss_unbalances_until_the_gap_is_filled():
    s, data, hb = run()
    r, out = rx()
    feed(r, data[:4] + data[5:] + hb, 0)
    r.tick(3)
    assert last(r, s)["balanced"] is False
    assert r.emit_health(3)["reconcile_unbalanced"] == 1
    feed(r, data[4:5], 4)          # archive replay fills seq 5
    r.tick(5)
    assert last(r, s)["balanced"] is True


def test_a_changed_event_with_a_valid_frame_is_caught():
    s, data, hb = run()
    forged = wire.encode_event(s.stream_id, 5, json.dumps({"_raw": "forged"}).encode())
    r, out = rx()
    feed(r, data[:4] + forged + data[5:] + hb, 0)
    r.tick(1)
    res = last(r, s)
    assert res["balanced"] is False and r.streams[s.stream_id].gaps.r == []


def test_duplicates_count_once():
    s, data, hb = run()
    r, out = rx()
    feed(r, data + data + hb + data, 0)
    r.tick(1)
    assert last(r, s)["balanced"] is True


def test_events_not_yet_durable_are_not_compared():
    s, data, hb = run()
    out = SlowOutput()
    r, _ = rx(out)
    feed(r, data + hb, 0)
    r.tick(1)
    assert last(r, s) is None
    out.commit()
    r.tick(2)
    assert last(r, s)["balanced"] is True


def test_events_the_output_dropped_unbalance_until_replayed():
    s, data, hb = run()
    out = SlowOutput()
    r, _ = rx(out)
    feed(r, data + hb, 0)
    out.fail(s.stream_id, 7)
    out.commit()
    r.tick(1)
    assert last(r, s)["balanced"] is False
    feed(r, data[6:7], 2)
    out.commit()
    r.tick(3)
    assert last(r, s)["balanced"] is True


def test_crash_replay_restores_the_balance(tmp_path):
    """Review focus 5: the hash survives a crash; the replay fills the gap; each event counts once."""
    s, data, hb = run()
    state = str(tmp_path / "state.json")
    out1 = SlowOutput()
    r1, _ = rx(out1, state_path=state)
    feed(r1, data[:10], 0)
    out1.commit()
    feed(r1, data[10:] + hb, 1)
    r1.tick(2)
    assert last(r1, s) is None              # 11..20 aren't durable yet
    r1.save_state()                         # ... and then the receiver crashes
    r2, out2 = rx(state_path=state)
    assert [(g["first_seq"], g["last_seq"], g["reason"]) for g in out2.kinds("gap")] == \
        [(11, 20, "receiver_restart")]
    feed(r2, data + hb, 10)                 # archive replay of the whole capture
    r2.tick(11)
    assert [e[1] for e in out2.events] == list(range(11, 21))
    assert last(r2, s) == {"cut": 20, "sender_hash": s.events_hash.hex(),
                           "receiver_hash": s.events_hash.hex(), "balanced": True}


def test_a_bad_events_hash_is_ignored():
    r, out = rx()
    feed(r, [wire.encode_heartbeat(0x33, 0, {"events_hash": "zz"})], 0)
    r.tick(1)
    assert r.streams[0x33].rc.last is None and "events_hash" not in r.streams[0x33].hb


def test_reconcile_records_at_stream_end_and_when_the_balance_changes(tmp_path):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="rx", actor="me", build="b")
    s, data, hb = run()
    r, out = rx(audit=a)
    feed(r, data[:4] + data[5:] + hb, 0)
    r.tick(3)
    r.tick(4)
    feed(r, data[4:5], 5)
    r.tick(6)
    recs = [x for x in read_audit(a.dir) if x["event"] == "reconcile"]
    assert [(x["balanced"], x["outcome"], x["gaps_open"]) for x in recs] == \
        [(False, "failure", 1), (True, "success", 0)]
    assert recs[-1]["receiver_hash"] == recs[-1]["sender_hash"] == s.events_hash.hex()
    assert recs[-1]["events_delivered"] == 20 and recs[-1]["gaps_filled"] == 1
    assert [(h["balanced"], h["gaps_open"]) for h in out.kinds("reconcile")] == [(False, 1), (True, 0)]


def test_hourly_reconcile_record_for_a_live_stream(tmp_path):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="rx", actor="me", build="b")
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    s.send_event({"_raw": "x"})
    s.send_heartbeat()
    r, out = rx(audit=a)
    feed(r, sock.sent, 0)
    r.tick(1)
    feed(r, [sock.sent[-1]], 3600)
    r.tick(3601)
    assert [x["cut"] for x in read_audit(a.dir) if x["event"] == "reconcile"] == [1]
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_receiver_reconcile.py -q`
Expected: `AttributeError: 'StreamTracker' object has no attribute 'rc'`.

- [ ] **Step 3: Implement**

In `wd2l/receiver.py`:

(a) `import re`; `from .reconcile import StreamReconciler`; constant
`HEX64 = re.compile(r"[0-9a-f]{64}")`.

(b) `StreamTracker.__init__`: `self.rc = StreamReconciler()`. `to_json`: `"rc": self.rc.to_json()`.
`from_json`: `t.rc = StreamReconciler.from_json(d.get("rc"))`.

(c) Disable it where the history is unknown: in `_stream`, after `t.records = records`, add
`t.rc.enabled = not records`; in `_restore`, after creating `t`, add
`t.rc = StreamReconciler(enabled=False)`; in `_link`'s never-seen branch, after creating `p`, add
`p.rc = StreamReconciler(enabled=False)`.

(d) `handle_datagram`: in the `if res == "late":` block add `t.rc.filled += 1`; after the
`if t.records: ... return` block add `t.rc.delivered(f.seq, f.digest)`.

(e) `_apply_failed`: after `t = self.streams.get(sid)` / `if t is not None:` add
`for s in seqs: t.rc.dropped(s)` before reporting.

(f) `_heartbeat`: keep the hash before the numeric filter:

```python
        eh = info.get("events_hash")
        info = {k: v for k, v in info.items()
                if isinstance(k, str) and isinstance(v, (int, float, bool))}
        if isinstance(eh, str) and HEX64.fullmatch(eh) and not t.records:
            info["events_hash"] = eh
            t.rc.cut(f.seq, eh)
```

(g) `Receiver.__init__`: `self.last_rc: Optional[float] = None`,
`self.last_rc_hourly: Optional[float] = None`.

(h) Add:

```python
    def _reconcile(self, now: float) -> None:
        """Settle what the outputs made durable, compare at ready cuts, write reconcile records:
        for ended streams whenever (cut, balanced) changes, and hourly for the rest."""
        pending = self._pending()
        hourly = self.last_rc_hourly is not None and now - self.last_rc_hourly >= 3600
        if self.last_rc_hourly is None or hourly:
            self.last_rc_hourly = now
        for t in list(self.streams.values()):
            if t.records or not t.rc.enabled:
                continue
            t.rc.settle(pending.get(t.stream_id, set()))
            res = t.rc.check(t.lo, t.gaps)
            last = t.rc.last
            if last is None:
                continue
            ended = t.final and t.lo > t.known and last["cut"] == t.known
            key = (last["cut"], last["balanced"])
            if (ended and res is not None and key != t.rc.written) or (
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
```

(i) Call it: in `tick`, before the fault block,

```python
        if self.last_rc is None or now - self.last_rc >= 1.0:
            self.last_rc = now
            self._reconcile(now)
```

In `finish`, before `rec = self.emit_health(now)`: `self.flush()` and `self._reconcile(now)`.
In `close`, before `self._drain_audit()` and before the outputs are closed: `self.flush()` and
`self._reconcile(now)`. Never call it after the outputs are closed: it writes health records.
(With the SIEM output, events still in flight aren't settled yet at that point; the saved state
settles them, and the next start compares again and writes the record.)

(j) `save_state`: right after `pending = self._pending()` (and the uncommitted merge), settle so
the saved hash holds every durable event:

```python
        for sid, t in self.streams.items():
            t.rc.settle(pending.get(sid, set()))
```

(k) `emit_health`: in the per-stream dict add
`"reconcile": ({"cut": t.rc.last["cut"], "balanced": t.rc.last["balanced"]} if t.rc.last else None)`,
and to the flat totals
`reconcile_unbalanced=sum(1 for t in self.streams.values() if t.rc.last and not t.rc.last["balanced"])`.

- [ ] **Step 4: Run all tests**

Run: `T -q`
Expected: all pass. (`test_hourly_reconcile_record_for_a_live_stream` relies on the first
`_reconcile` call setting the hourly clock, so the record comes exactly one hour later.)

- [ ] **Step 5: Commit**

```bash
git add wd2l/receiver.py tests/test_receiver_reconcile.py
git commit -m "Receiver: reconcile each data stream at heartbeat cuts; reconcile records; survives restarts" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.4: `wd2l-audit-report`

**Files:**
- Create: `wd2l/audit_report.py`
- Create: `tests/test_audit_report.py`
- Modify: `pyproject.toml` (`[project.scripts]`)

**Interfaces:**
- Consumes: `audit.audit_files`, `audit.split_lines`, `audit.verify_dir`, `audit.record_hash`,
  `audit.GENESIS`.
- Produces:
  - `audit_report.load(dirs, exports) -> List[dict]`, `audit_report.unwrap(obj) -> Optional[dict]`
  - `audit_report.verify_export(records) -> Dict[str, dict]` (one result per `host/enclaveN`
    chain: `result`, `records`, `first_n`, `last_n`, `last_hash`, `missing` ranges,
    `unchained`, `problems`)
  - `audit_report.reconcile_rows(records) -> List[dict]` (one row per UTC day and stream)
  - `audit_report.filter_events(records, since, until, streams, events, segments, components, hosts)`
  - `audit_report.main(argv) -> int` (exit 0 ok, 1 problems found, 2 usage)
  - console script `wd2l-audit-report`

```
wd2l-audit-report verify    (--dir DIR | --export FILE...) [--upto N --upto-hash H] [--complete] [--format json|csv]
wd2l-audit-report reconcile (--dir DIR... | --export FILE...) [--since T] [--until T] [--format json|csv]
wd2l-audit-report events    (--dir DIR... | --export FILE...) [--since T] [--until T] [--stream S]
                            [--event E]... [--segment S]... [--component C]... [--host H]... [--format json|csv]
```

- [ ] **Step 1: Write the failing tests**

`tests/test_audit_report.py`:

```python
import csv
import io
import json

from wd2l import audit as auditlog
from wd2l import audit_report

from helpers import read_audit


def trail(tmp_path, name, component, enclave, t0):
    t = [t0]

    def clock():
        t[0] += 60
        return t[0]
    a = auditlog.AuditLog(str(tmp_path / name), component, enclave, host=name, actor="me",
                          build="b", clock=clock)
    return a


def make(tmp_path):
    day1 = 1791158400.0                      # 2026-10-05T00:00:00Z
    snd = trail(tmp_path, "logsrv01", "sender", 1, day1)
    rcv = trail(tmp_path, "rx01", "receiver", 2, day1)
    snd.write("start", "success")
    snd.write("reconcile", "info", stream="ab", cut=10, events_in=10, events_sent=10,
              sender_hash="1" * 64)
    rcv.write("start", "success")
    rcv.write("gap", "failure", stream="ab", seq_first=3, seq_last=3, segment="e2-receiver")
    rcv.write("reconcile", "failure", stream="ab", cut=10, events_delivered=9, gaps_open=1,
              gaps_filled=0, sender_hash="1" * 64, receiver_hash="2" * 64, balanced=False)
    rcv.write("config_changed", "info", old_config_sha256="a" * 64, config_sha256="b" * 64)
    snd.close()
    rcv.close()
    return str(tmp_path / "logsrv01"), str(tmp_path / "rx01")


def run(capsys, argv):
    code = audit_report.main(argv)
    return code, capsys.readouterr().out


def splunk_export(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps({"preview": False, "result": {
                "_raw": auditlog.canonical(r).decode(), "sourcetype": "wd2l:audit"}}) + "\n")


def test_verify_dir(tmp_path, capsys):
    e1, _ = make(tmp_path)
    code, out = run(capsys, ["verify", "--dir", e1])
    assert code == 0 and json.loads(out)["result"] == "ok"


def test_verify_dir_finds_tampering(tmp_path, capsys):
    e1, _ = make(tmp_path)
    [path] = auditlog.audit_files(e1)
    with open(path, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:
        f.write(data.replace(b'"cut":10', b'"cut":11'))
    code, out = run(capsys, ["verify", "--dir", e1])
    assert code == 1 and json.loads(out)["problems"]


def test_verify_a_siem_export_per_chain(tmp_path, capsys):
    e1, e2 = make(tmp_path)
    recs = read_audit(e1) + read_audit(e2)
    exp = tmp_path / "export.json"
    splunk_export(exp, list(reversed(recs)) + recs[:1])     # any order, one duplicate
    code, out = run(capsys, ["verify", "--export", str(exp)])
    res = json.loads(out)
    assert code == 0 and set(res) == {"logsrv01/enclave1", "rx01/enclave2"}
    assert res["rx01/enclave2"]["records"] == 4 and res["rx01/enclave2"]["missing"] == []


def test_export_with_a_record_missing_lists_it_and_complete_fails(tmp_path, capsys):
    _, e2 = make(tmp_path)
    recs = read_audit(e2)
    exp = tmp_path / "export.json"
    splunk_export(exp, recs[:1] + recs[2:])
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 0 and json.loads(out)["rx01/enclave2"]["missing"] == [[2, 2]]
    code, _ = run(capsys, ["verify", "--export", str(exp), "--complete"])
    assert code == 1


def test_export_with_two_different_records_for_one_n_fails(tmp_path, capsys):
    _, e2 = make(tmp_path)
    recs = read_audit(e2)
    other = dict(recs[1], event="forged")
    exp = tmp_path / "export.json"
    splunk_export(exp, recs + [other])
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 1 and any("two different records" in p
                             for p in json.loads(out)["rx01/enclave2"]["problems"])


def test_reconcile_report_joins_both_sides(tmp_path, capsys):
    e1, e2 = make(tmp_path)
    code, out = run(capsys, ["reconcile", "--dir", e1, "--dir", e2])
    [row] = json.loads(out)
    assert (row["day"], row["stream"], row["sender_cut"], row["receiver_cut"]) == \
        ("2026-10-05", "ab", 10, 10)
    assert (row["events_sent"], row["events_delivered"], row["gaps_open"], row["balanced"]) == \
        (10, 9, 1, False)
    code, out = run(capsys, ["reconcile", "--dir", e1, "--dir", e2, "--format", "csv"])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert rows[0]["balanced"] == "False"


def test_events_filters(tmp_path, capsys):
    e1, e2 = make(tmp_path)
    code, out = run(capsys, ["events", "--dir", e1, "--dir", e2, "--event", "gap",
                             "--event", "config_changed"])
    assert [r["event"] for r in json.loads(out)] == ["gap", "config_changed"]
    code, out = run(capsys, ["events", "--dir", e2, "--segment", "e2-receiver",
                             "--since", "2026-10-05T00:02", "--until", "2026-10-05T00:04"])
    assert [r["event"] for r in json.loads(out)] == ["gap"]
    code, out = run(capsys, ["events", "--dir", e1, "--format", "csv"])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["event"] for r in rows] == ["start", "reconcile"] and "details" in rows[0]


def test_needs_a_source(capsys):
    assert audit_report.main(["events"]) == 2
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_audit_report.py -q`
Expected: `ImportError: cannot import name 'audit_report'`.

- [ ] **Step 3: Write the implementation**

`wd2l/audit_report.py`:

```python
"""wd2l-audit-report: reports from wd2l audit records, for assessors and audit reviews
(docs/audit-and-health-plan.md §9).

    wd2l-audit-report verify    --dir DIR | --export FILE...    check the hash chain
    wd2l-audit-report reconcile --dir DIR... | --export FILE...  reconciliation per day and stream
    wd2l-audit-report events    --dir DIR... | --export FILE...  the records, filtered

--dir reads audit files (the official copy). --export reads a SIEM export: JSON lines that are
records, or objects holding the record as text in "_raw" (also inside "result", as Splunk's
export API writes them). Times are UTC, ISO 8601, compared as text: --since is inclusive,
--until exclusive. Output is JSON (default) or CSV."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .audit import GENESIS, audit_files, record_hash, split_lines, verify_dir

RECONCILE_COLUMNS = ("day", "stream", "sender_cut", "events_in", "events_sent", "sender_hash",
                     "receiver_cut", "events_delivered", "gaps_open", "gaps_filled",
                     "receiver_hash", "balanced")
EVENT_COLUMNS = ("ts", "host", "enclave", "component", "segment", "event", "outcome", "actor",
                 "stream", "seq_first", "seq_last", "n")


def unwrap(obj: Any) -> Optional[Dict[str, Any]]:
    if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
        obj = obj["result"]
    if isinstance(obj, dict) and isinstance(obj.get("_raw"), str):
        try:
            obj = json.loads(obj["_raw"])
        except ValueError:
            return None
    return obj if isinstance(obj, dict) and "event" in obj else None


def load(dirs: Sequence[str], exports: Sequence[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for d in dirs:
        for path in audit_files(d):
            with open(path, "rb") as f:
                out += [json.loads(x) for x in split_lines(f.read()) if x.endswith(b"\n")]
    for path in exports:
        with open(path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    rec = unwrap(json.loads(line))
                    if rec is not None:
                        out.append(rec)
    return out


def verify_export(records: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """A SIEM copy can come in any order, with duplicates (re-sent) and holes (records-stream
    loss, or a search window): sort by n, accept identical copies, list the holes. Links are
    checked between neighbouring numbers only."""
    chains: Dict[str, List[Dict[str, Any]]] = {}
    for r in records:
        chains.setdefault("%s/enclave%s" % (r.get("host"), r.get("enclave")), []).append(r)
    out: Dict[str, Dict[str, Any]] = {}
    for name, recs in sorted(chains.items()):
        problems: List[str] = []
        by_n: Dict[int, Dict[str, Any]] = {}
        unchained = 0
        for r in recs:
            n = r.get("n")
            if n is None:
                unchained += 1
                continue
            if n in by_n and by_n[n] != r:
                problems.append("n=%d: two different records" % n)
            by_n[n] = r
        missing: List[List[int]] = []
        prev = None
        for n in sorted(by_n):
            r = by_n[n]
            if record_hash(r) != r.get("hash"):
                problems.append("n=%d content does not match its hash (edited)" % n)
            if prev is None:
                if n == 1 and r.get("prev_hash") != GENESIS:
                    problems.append("n=1 does not start from the genesis hash")
            elif n == prev[0] + 1:
                if r.get("prev_hash") != prev[1]:
                    problems.append("n=%d does not link to n=%d" % (n, prev[0]))
            else:
                missing.append([prev[0] + 1, n - 1])
            prev = (n, r.get("hash"))
        ns = sorted(by_n)
        out[name] = {"result": "failed" if problems else "ok", "records": len(by_n),
                     "first_n": ns[0] if ns else None, "last_n": ns[-1] if ns else None,
                     "last_hash": by_n[ns[-1]].get("hash") if ns else None, "missing": missing,
                     "unchained": unchained, "problems": problems[:100]}
    return out


def reconcile_rows(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The day's last reconcile record from each side, per UTC day and stream."""
    rows: Dict[tuple, Dict[str, Any]] = {}
    for r in records:
        if r.get("event") != "reconcile":
            continue
        ts = str(r.get("ts", ""))
        key = (ts[:10], r.get("stream"))
        row = rows.setdefault(key, {"day": key[0], "stream": key[1]})
        side = "sender" if r.get("component") == "sender" else "receiver"
        if ts < row.get("_" + side, ""):
            continue
        row["_" + side] = ts
        if side == "sender":
            row.update(sender_cut=r.get("cut"), events_in=r.get("events_in"),
                       events_sent=r.get("events_sent"), sender_hash=r.get("sender_hash"))
        else:
            row.update(receiver_cut=r.get("cut"), events_delivered=r.get("events_delivered"),
                       gaps_open=r.get("gaps_open"), gaps_filled=r.get("gaps_filled"),
                       receiver_hash=r.get("receiver_hash"), balanced=r.get("balanced"))
            row.setdefault("sender_hash", r.get("sender_hash"))
    return [{c: rows[k].get(c) for c in RECONCILE_COLUMNS} for k in sorted(rows, key=str)]


def filter_events(records: Iterable[Dict[str, Any]], since: Optional[str] = None,
                  until: Optional[str] = None, streams: Sequence[str] = (),
                  events: Sequence[str] = (), segments: Sequence[str] = (),
                  components: Sequence[str] = (), hosts: Sequence[str] = ()
                  ) -> List[Dict[str, Any]]:
    out = []
    for r in records:
        ts = str(r.get("ts", ""))
        if (since and ts < since) or (until and ts >= until):
            continue
        for want, field in ((streams, "stream"), (events, "event"), (segments, "segment"),
                            (components, "component"), (hosts, "host")):
            if want and r.get(field) not in want:
                break
        else:
            out.append(r)
    return sorted(out, key=lambda r: (str(r.get("ts", "")), str(r.get("host")), r.get("n") or 0))


def _csv(rows: List[Dict[str, Any]], columns: Sequence[str]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=list(columns), extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue()


def _event_row(r: Dict[str, Any]) -> Dict[str, Any]:
    row = {c: r.get(c) for c in EVENT_COLUMNS}
    row["details"] = json.dumps({k: v for k, v in r.items()
                                 if k not in EVENT_COLUMNS and k not in ("prev_hash", "hash")},
                                sort_keys=True)
    return row


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="wd2l-audit-report", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")
    cmds = {name: sub.add_parser(name) for name in ("verify", "reconcile", "events")}
    for sp in cmds.values():
        sp.add_argument("--dir", action="append", default=[], help="audit directory (repeatable)")
        sp.add_argument("--export", nargs="+", default=[], help="SIEM export files (JSON lines)")
        sp.add_argument("--format", choices=("json", "csv"), default="json")
    cmds["verify"].add_argument("--upto", type=int, help="with --dir: the chain must reach this n")
    cmds["verify"].add_argument("--upto-hash", help="... and record --upto must have this hash")
    cmds["verify"].add_argument("--complete", action="store_true",
                                help="with --export: records missing from the export fail")
    for name in ("reconcile", "events"):
        cmds[name].add_argument("--since", help="UTC, e.g. 2026-10-05 or 2026-10-05T14:00")
        cmds[name].add_argument("--until")
    ev = cmds["events"]
    for flag in ("--stream", "--event", "--segment", "--component", "--host"):
        ev.add_argument(flag, action="append", default=[])
    try:
        a = p.parse_args(argv)
    except SystemExit:
        return 2
    if not a.cmd or not (a.dir or a.export):
        p.print_usage(sys.stderr)
        print("need a subcommand and --dir or --export", file=sys.stderr)
        return 2

    if a.cmd == "verify":
        if a.dir:
            if len(a.dir) != 1 or a.export:
                print("verify takes one --dir (one chain) or --export", file=sys.stderr)
                return 2
            res = verify_dir(a.dir[0], a.upto, a.upto_hash).to_json()
            print(json.dumps(res, sort_keys=True) if a.format == "json" else
                  _csv([dict(res, problems="; ".join(res["problems"]))], sorted(res)), end="\n")
            return 0 if res["result"] == "ok" else 1
        chains = verify_export(load([], a.export))
        bad = any(c["problems"] or (a.complete and c["missing"]) for c in chains.values())
        if a.format == "json":
            print(json.dumps(chains, sort_keys=True))
        else:
            rows = [dict(c, chain=k, missing=json.dumps(c["missing"]), problems="; ".join(c["problems"]))
                    for k, c in chains.items()]
            print(_csv(rows, ["chain", "result", "records", "first_n", "last_n", "missing",
                              "unchained", "problems"]), end="")
        return 1 if bad else 0

    recs = load(a.dir, a.export)
    if a.cmd == "reconcile":
        rows = reconcile_rows(filter_events(recs, a.since, a.until, events=["reconcile"]))
        print(json.dumps(rows) if a.format == "json" else _csv(rows, RECONCILE_COLUMNS), end="\n")
        return 0
    rows = filter_events(recs, a.since, a.until, a.stream, a.event, a.segment, a.component, a.host)
    if a.format == "json":
        print(json.dumps(rows))
    else:
        print(_csv([_event_row(r) for r in rows], EVENT_COLUMNS + ("details",)), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

In `pyproject.toml`, under `[project.scripts]`, add
`wd2l-audit-report = "wd2l.audit_report:main"`.

- [ ] **Step 4: Run the tests**

Run: `T tests/test_audit_report.py -q`
Expected: all pass. (In `test_events_filters` the second query relies on the fake clock, which
moves 60 s on every read. Creating the first file reads it once too, so the receiver's records
are at 00:01 (start), 00:03 (gap), 00:04 (reconcile) and 00:05 (config_changed), and the window
`[00:02, 00:04)` holds only the gap. If the count differs, print the records' `ts` and adjust
the window, not the code.)

- [ ] **Step 5: Commit**

```bash
git add wd2l/audit_report.py tests/test_audit_report.py pyproject.toml
git commit -m "wd2l-audit-report: verify chains (files or SIEM export), reconcile per day, filter events" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3.5: The lab checks the balance

**Files:**
- Modify: `lab/verify.py`, `lab/run-lab.sh`

**Interfaces:**
- Produces: `verify.py --reconcile-dir DIR`: every data stream's last receiver-side `reconcile`
  record in DIR must be balanced; with `--expect-gaps`, at least one must not be.

- [ ] **Step 1: Add the check**

In `lab/verify.py`, add
`p.add_argument("--reconcile-dir", help="Enclave 2's audit directory: each data stream's last reconcile record must be balanced (with --expect-gaps: at least one must not be)")`
and before the summary prints:

```python
    if a.reconcile_dir:
        last_rc = {}
        for path in auditlog.audit_files(a.reconcile_dir):
            with open(path, "rb") as f:
                for line in auditlog.split_lines(f.read()):
                    if line.endswith(b"\n"):
                        r = json.loads(line)
                        if r["event"] == "reconcile" and r["component"] in ("receiver", "replay"):
                            last_rc[r["stream"]] = r
        for s in sorted(set(runs) | streams):
            r = last_rc.get(s)
            if r is None:
                problems.append("no reconcile record for stream %s" % s)
            elif not r["balanced"] and not a.expect_gaps:
                problems.append("stream %s not balanced at cut %s (%s open gap events)"
                                % (s, r["cut"], r["gaps_open"]))
        if a.expect_gaps and last_rc and all(r["balanced"] for r in last_rc.values()):
            problems.append("events were lost but every reconcile record says balanced")
        print("reconcile:       %s" % "; ".join(
            "%s cut %s %s" % (s, r["cut"], "balanced" if r["balanced"] else "NOT balanced")
            for s, r in sorted(last_rc.items())))
```

In the `--sender-runs` / single-run code above it, `streams` and `runs` already hold the data
streams (Task 2.3). In `lab/run-lab.sh` add `--reconcile-dir "$OUT/audit-e2"` to `VERIFY_ARGS`.

- [ ] **Step 2: Verify**

Run: `T -q`. Push; the CI `lab` job must pass every run, each printing a `reconcile:` line:
`balanced` for clean, outage, crash, maintenance and file runs, and at least one `NOT balanced`
for `--loss 1`, `--fault tap-down`, `--fault wire-loss` and `--fault receiver-slow`.

- [ ] **Step 3: Commit**

```bash
git add lab/verify.py lab/run-lab.sh
git commit -m "Lab: every run checks end-to-end reconciliation" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Phase 3 checkpoint:** full suite green, CI lab green with reconciliation in every run. Stop for
review.
