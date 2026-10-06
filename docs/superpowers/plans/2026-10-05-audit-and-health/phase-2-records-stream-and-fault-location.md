# Phase 2: Enclave 1 records in-band, health signals, fault location

Part of the [audit and health implementation plan](README.md). Read its **Global constraints**
first. Spec: [docs/audit-and-health-plan.md](../../../audit-and-health-plan.md) §7, §8, §11, §12,
§16 (lab table).

**Delivers:** the sender's audit and health records cross in-band on a second, flagged stream
and land in their own index; every heartbeat carries a snapshot of Enclave 1's state; the
receiver samples its capture NIC, archive, CPU and memory; it decides where a fault is (rules
1–11), writes `type=fault` and `type=time_status` records when the answer changes, and colors six
segments; the lab injects each fault and checks the answer. The ICD and wire-format pages change
in the same commits as the wire.

Run tests with `T` from the plan README.

---

### Task 2.1: A frame flag for the records stream

**Files:**
- Modify: `wd2l/wire.py`
- Modify: `tests/test_wire.py` (append)

**Interfaces:**
- Produces: `wire.FLAG_RECORDS = 0x0001`; `wire.event_digest(event: bytes) -> bytes`;
  `wire.encode_event(stream_id, seq, event, max_datagram=..., flags=0, digest=None)`;
  `wire.encode_heartbeat(stream_id, last_seq, info, flags=0)`. `decode` is unchanged (it already
  returns `flags`).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_wire.py` (add `import hashlib` if missing):

```python
def test_flags_round_trip_and_default_to_zero():
    body = b'{"_raw":"x"}'
    assert wire.decode(wire.encode_event(5, 1, body)[0]).flags == 0
    assert wire.decode(wire.encode_event(5, 1, body, flags=wire.FLAG_RECORDS)[0]).flags == 1
    assert wire.decode(wire.encode_heartbeat(5, 1, {"a": 1}, flags=wire.FLAG_RECORDS)).flags == 1


def test_a_precomputed_digest_is_used():
    body = b'{"_raw":"x"}'
    d = wire.event_digest(body)
    assert d == hashlib.sha256(body).digest()
    assert wire.decode(wire.encode_event(5, 1, body, digest=d)[0]).digest == d
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_wire.py -q`
Expected: `AttributeError: module 'wd2l.wire' has no attribute 'FLAG_RECORDS'`.

- [ ] **Step 3: Implement**

In `wd2l/wire.py`: in the module docstring change the `flags` line to
`6      2    flags        bit 0: records stream (the sender's own records); others 0`. After
`TYPE_HEARTBEAT = 2` add:

```python
# flags bit 0: the frame belongs to the sender's records stream, which carries its own audit and
# health records (docs/audit-and-health-plan.md section 7). The other bits are reserved (0).
FLAG_RECORDS = 0x0001
```

Replace `_pack`, `encode_event` and `encode_heartbeat`:

```python
def _pack(ftype: int, stream_id: int, seq: int, idx: int, count: int,
          event_len: int, digest: bytes, payload: bytes, flags: int = 0) -> bytes:
    head = HEADER.pack(MAGIC, VERSION, ftype, flags, stream_id, seq, idx, count, event_len, digest)
    body = head + payload
    return body + CRC.pack(zlib.crc32(body) & 0xFFFFFFFF)


def event_digest(event: bytes) -> bytes:
    """SHA-256 of a serialized event: the frame's digest, and the sender's reconciliation term."""
    return hashlib.sha256(event).digest()


def encode_event(stream_id: int, seq: int, event: bytes,
                 max_datagram: int = DEFAULT_MAX_DATAGRAM, flags: int = 0,
                 digest: Optional[bytes] = None) -> List[bytes]:
    """Split one serialized event into DATA frames that each fit in max_datagram bytes."""
    chunk_size = max_datagram - OVERHEAD
    if chunk_size < 1:
        raise ValueError("max_datagram too small")
    count = max(1, -(-len(event) // chunk_size))
    if count > MAX_CHUNKS:
        raise ValueError("event needs more than %d chunks" % MAX_CHUNKS)
    if digest is None:
        digest = event_digest(event)
    return [
        _pack(TYPE_DATA, stream_id, seq, i, count, len(event), digest,
              event[i * chunk_size:(i + 1) * chunk_size], flags)
        for i in range(count)
    ]


def encode_heartbeat(stream_id: int, last_seq: int, info: Dict[str, Any], flags: int = 0) -> bytes:
    payload = json.dumps(info, separators=(",", ":"), sort_keys=True).encode()
    return _pack(TYPE_HEARTBEAT, stream_id, last_seq, 0, 1, len(payload),
                 hashlib.sha256(payload).digest(), payload, flags)
```

Add `Optional` to the `typing` import.

- [ ] **Step 4: Run the tests**

Run: `T tests/test_wire.py tests/test_packets.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/wire.py tests/test_wire.py
git commit -m "Wire: flags bit 0 marks the records stream; encoders take flags and a digest" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.2: The sender sends its records in-band

**Files:**
- Modify: `wd2l/sender.py`
- Create: `tests/test_records_stream.py`
- Modify: `docs/interface-description.md`, `docs/wire-format.md` (interface change, same commit)

**Interfaces:**
- Consumes: `wire.FLAG_RECORDS`, `AuditLog.take_outbox()/status()/outbox_dropped/forward`,
  `hostinfo.hostname()`.
- Produces:
  - `Sender(..., time_quality=None)`; attributes `records: bool` (true when an audit log that
    forwards is given), `rec_stream_id`, `rec_seq`, `rec_counters` (`events_sent`,
    `records_too_big`), `health_outbox` (deque, max 100), `last_snapshot: dict` (filled in Task 2.5)
  - `Sender.health_record() -> dict` (`type=health`, `time`, identity, counters, `stream`,
    `last_seq`, snapshot, audit status, `time_quality`)
  - `Sender.flush_records(final=False)`: queued audit records and health records go out as DATA
    frames with `FLAG_RECORDS` on `rec_stream_id`, then that stream's heartbeat
  - Records-stream event body: `{"_time", "host": <log server>, "source": "wd2l-sender",
    "sourcetype": "wd2l:sender:audit" | "wd2l:sender:health", "_raw": <canonical JSON of the record>}`
  - `periodic()` also queues `health_record()`; `_heartbeat_loop` calls `flush_records()` every
    heartbeat; `main` opens the audit log with `forward=True` and ends with
    `flush_records(final=True)` after the `stop` record

- [ ] **Step 1: Write the failing tests**

`tests/test_records_stream.py`:

```python
import json

from wd2l import audit as auditlog
from wd2l import wire
from wd2l.sender import Sender

from helpers import FakeSock


def make(tmp_path, **kw):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="logsrv01", actor="me",
                          build="b")
    sock = FakeSock()
    kw.setdefault("rate_pps", 0)
    return Sender(("10.255.255.2", 5514), sock=sock, audit=a, **kw), a, sock


def frames(sock):
    return [wire.decode(d) for d in sock.sent]


def record_bodies(sock):
    return [wire.parse_event(f.payload) for f in frames(sock)
            if f.flags & wire.FLAG_RECORDS and f.type == wire.TYPE_DATA]


def test_records_go_in_band_on_their_own_flagged_stream(tmp_path):
    s, a, sock = make(tmp_path)
    s.send_event({"_raw": "data"})
    rec = a.write("start", "success")
    s.flush_records()
    fs = frames(sock)
    data = [f for f in fs if f.flags == 0]
    recs = [f for f in fs if f.flags & wire.FLAG_RECORDS]
    assert {f.stream_id for f in data} == {s.stream_id}
    assert {f.stream_id for f in recs} == {s.rec_stream_id} and s.rec_stream_id != s.stream_id
    [body] = record_bodies(sock)
    assert (body["sourcetype"], body["host"], body["source"]) == \
        ("wd2l:sender:audit", "logsrv01", "wd2l-sender")
    assert body["_raw"] == auditlog.canonical(rec).decode() and "index" not in body
    assert recs[0].seq == 1 and recs[-1].type == wire.TYPE_HEARTBEAT and recs[-1].seq == 1


def test_the_senders_health_record_goes_in_band(tmp_path):
    s, a, sock = make(tmp_path)
    s.health_outbox.append(s.health_record())
    s.flush_records()
    [body] = record_bodies(sock)
    h = json.loads(body["_raw"])
    assert body["sourcetype"] == "wd2l:sender:health"
    assert (h["type"], h["component"], h["enclave"], h["segment"]) == ("health", "sender", 1, "e1-sender")
    assert h["audit_n"] == a.n and h["stream"] == "%016x" % s.stream_id and "time" in h


def test_final_records_heartbeat_comes_after_the_data_streams(tmp_path):
    s, a, sock = make(tmp_path)
    s.send_event({"_raw": "x"})
    s.send_heartbeat(final=True)
    a.write("stop", "success")
    s.flush_records(final=True)
    fs = frames(sock)
    last_data = max(i for i, f in enumerate(fs) if f.flags == 0)
    assert json.loads(fs[last_data].payload)["final"] is True
    assert fs[-1].flags & wire.FLAG_RECORDS and json.loads(fs[-1].payload)["final"] is True
    n = len(sock.sent)
    s.flush_records()
    assert len(sock.sent) == n


def test_a_record_too_big_for_one_event_is_counted_not_sent(tmp_path):
    s, a, sock = make(tmp_path, max_event=1024)
    a.write("config", settings={"x": "y" * 5000})
    s.flush_records()
    hbs = [f for f in frames(sock) if f.flags and f.type == wire.TYPE_HEARTBEAT]
    assert json.loads(hbs[-1].payload)["records_too_big"] == 1
    assert record_bodies(sock) == []


def test_no_records_stream_without_a_forwarding_audit_log(tmp_path):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="h", actor="me", build="b",
                          forward=False)
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, audit=a)
    a.write("start", "success")
    s.flush_records(final=True)
    assert sock.sent == []
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_records_stream.py -q`
Expected: `AttributeError: 'Sender' object has no attribute 'flush_records'`.

- [ ] **Step 3: Implement**

In `wd2l/sender.py`:

(a) Imports: add `from collections import deque` and `Deque` to the typing import, and
`from . import __version__`.

(b) `Sender.__init__`: add `time_quality: Any = None` after `config_sha256`. After
`self.config_sha256 = config_sha256` add:

```python
        self.tq = time_quality
        self.hostname = hostinfo.hostname()
        self.last_snapshot: Dict[str, Any] = {}
        # The records stream (§7): this sender's own audit and health records, in-band, as a
        # second stream with its own id, numbers and heartbeat, marked by flags bit 0.
        self.records = audit is not None and audit.forward
        self.rec_stream_id = new_stream_id()
        while self.rec_stream_id == self.stream_id:
            self.rec_stream_id = new_stream_id()
        self.rec_seq = 0
        self.rec_counters = {"events_sent": 0, "records_too_big": 0}
        self.rec_closed = False
        self.health_outbox: Deque[Dict[str, Any]] = deque(maxlen=100)
```

(c) Add after `periodic`:

```python
    def health_record(self) -> Dict[str, Any]:
        """The sender's per-minute health summary (§4): counters, the latest snapshot, where the
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
            self._transmit(wire.encode_heartbeat(self.rec_stream_id, self.rec_seq, info,
                                                 flags=wire.FLAG_RECORDS))
```

(d) In `periodic`, append at the end: `if self.records: self.health_outbox.append(self.health_record())`.

(e) `_heartbeat_loop`: as the last line inside the `while` body, add `sender.flush_records()`.

(f) `main`: open the audit log with `forward=True`; pass `time_quality=tq` to `Sender(...)`;
replace the shutdown tail with:

```python
    sender.send_heartbeat(final=True)
    log.info("final: last_seq=%d %s", sender.seq, json.dumps(sender.counters, sort_keys=True))
    if audit:
        sender.flush_summaries()
        audit.write("stop", "success", stream="%016x" % sender.stream_id, last_seq=sender.seq,
                    signal=signal.Signals(stopped_by[0]).name if stopped_by else None,
                    counters=dict(sender.counters))
        sender.flush_records(final=True)
        audit.close()
    return 0
```

(g) In `tests/test_sender_audit.py`, `test_a_sender_run_leaves_a_verifiable_trail` still passes:
the UDP socket now also receives records-stream frames, and `got_data` waits for a DATA frame
with `flags == 0`, so it isn't fooled by them. In `_stream` (Task 2.3) keep the `extra=` stream
tag from Task 1.8 on the log line.

- [ ] **Step 4: Update the interface pages (same commit)**

`docs/interface-description.md`:

* §1 table, **Messages** row: append "With `--audit-dir` (deployed: yes), each sender run has a
  second stream, the **records stream**, carrying the sender's own audit and health records
  ([§9](#9-streams-and-sequence-numbers))."
* §6 table, `flags` row: value `0` (data stream) or `1` (records stream); notes "Bit 0 marks the
  records stream. The other bits are reserved: sent as 0, ignored by the receiver."
* §8: add, after the heartbeat table, a subsection **Records stream heartbeat**: same frame,
  `flags` bit 0 set, every second and once more at shutdown; keys `events_sent` (records sent),
  `records_too_big` (records kept out of the stream because they don't fit one event; they are
  still in the local audit file), `outbox_dropped` (records not queued for sending because more
  than 10,000 were waiting), `sender_time`, `uptime`, `final`. No `boot` or `prev_*`: records
  streams aren't linked across runs.
* §9: add a bullet list **Records stream**: its own random `stream_id`, its own `seq` from 1, its
  own heartbeat; DATA bodies are records, not logs: `host` = the log server, `source` =
  `wd2l-sender`, `sourcetype` = `wd2l:sender:audit` or `wd2l:sender:health`, `_raw` = the record
  as canonical JSON (the same bytes as the line in the local audit file), no `index` (Enclave 2
  chooses it); the receiver routes by the flag, never by `sourcetype`; volume is bounded
  (summaries, about one record a minute plus events); loss shows up as a gap marked
  `records: true`. Receivers older than wd2l 0.2.0 ignore `flags` and would treat the records
  stream as one more data stream: **update the receiver first**.
* §14: add "Records-stream events go to the audit index (`wd2l_audit`, its own token) or the
  health index, never to the data index."
* §16 table: add row `--audit-dir` (sender) | "Adds the records stream (flags bit 0)".
* §17: change "`flags` is reserved for future use and is sent as 0." to "`flags` bit 0 marks the
  records stream; the other bits are reserved and sent as 0."

`docs/wire-format.md`: change the `flags` row to "bit 0 = records stream (below); other bits 0",
and add a section **Records stream** (before "Why the sequence number never resets") that says
the same as the §9 bullets above in two short paragraphs, plus the receiver rule "Frames with
`flags` bit 0 set are tracked as their own stream, delivered to the audit or health index, and
never linked to the run chain."

- [ ] **Step 5: Run the tests**

Run: `T tests/test_records_stream.py tests/test_sender.py tests/test_sender_audit.py -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add wd2l/sender.py tests/test_records_stream.py docs/interface-description.md docs/wire-format.md
git commit -m "Sender: its own audit and health records cross in-band on a flagged records stream" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.3: The receiver routes the records stream

**Files:**
- Modify: `wd2l/receiver.py`, `wd2l/outputs.py`
- Modify: `tests/helpers.py` (`MemOutput.forwarded`)
- Modify: `tests/test_records_stream.py`, `tests/test_hec.py` (append)
- Modify: `lab/verify.py`, `lab/run-lab.sh`

**Interfaces:**
- Consumes: Task 2.2 frames; `audit.canonical`.
- Produces:
  - `Output.forwarded(evt, stream_id, seq, kind)` (`kind` = `"audit"` or `"health"`), tracked
    for durability like `event()`. `FileOutput`: audit → `audit.jsonl`, health →
    `e1-health.jsonl`. `HecOutput`: `sourcetype=wd2l:sender:<kind>`, index = `audit_index` or
    `health_index` (never `force_index`), `fields` `wd2l_stream`/`wd2l_seq`.
    `MemOutput.forwarded_records: list` of `(kind, stream_id, seq, evt)`.
  - `StreamTracker.records: bool` (persisted). Records-stream `stream_start`, `stream_end`,
    `stream_lost`, `stream_evicted` and `gap` records carry `records: true`. New counters
    `records_delivered`, `records_bad`. Records streams are excluded from the `sender_*` totals and
    from run linking; `had_history` counts data streams only.
  - `lab/verify.py --e1-audit-dir DIR`: Enclave 2's in-band copy must match Enclave 1's files.

- [ ] **Step 1: Write the failing tests**

In `tests/helpers.py`, add to `MemOutput.__init__` `self.forwarded_records = []` and the method:

```python
    def forwarded(self, evt, stream_id, seq, kind):
        self.forwarded_records.append((kind, stream_id, seq, evt))
```

Append to `tests/test_records_stream.py`:

```python
import os

from wd2l import receiver
from wd2l.outputs import FileOutput
from wd2l.receiver import Receiver

from helpers import MemOutput, eth, read_audit, write_pcap

DATA, RECS = 0x1111, 0x2222


def rx(**kw):
    out, aout = MemOutput(), MemOutput()
    kw.setdefault("health_interval", 1e9)
    return Receiver(out, dst_ip="10.255.255.2", dst_port=5514, audit_output=aout, **kw), out, aout


def rec_frames(seq, rec, kind="audit", sid=RECS):
    body = json.dumps({"_raw": json.dumps(rec), "host": "logsrv01",
                       "sourcetype": "wd2l:sender:" + kind}).encode()
    return wire.encode_event(sid, seq, body, flags=wire.FLAG_RECORDS)


def feed(r, dgs, now=0):
    for d in dgs:
        r.handle_frame(eth(d), now)


def test_records_stream_is_routed_by_the_flag(tmp_path):
    s, a, sock = make(tmp_path)
    s.send_event({"_raw": "data"})
    a.write("start", "success")
    s.health_outbox.append(s.health_record())
    s.flush_records()
    r, out, aout = rx()
    feed(r, sock.sent)
    assert [e[2]["_raw"] for e in out.events] == ["data"]
    assert [k for k, *_ in aout.forwarded_records] == ["audit"]
    assert [k for k, *_ in out.forwarded_records] == ["health"]
    assert r.counters["events_delivered"] == 1 and r.counters["records_delivered"] == 2
    audit_evt = aout.forwarded_records[0][3]
    assert json.loads(audit_evt["_raw"])["event"] == "start"


def test_aggregator_event_claiming_audit_sourcetype_stays_data():
    """Review focus 4: routing is by the flag, never by sourcetype."""
    r, out, aout = rx()
    body = json.dumps({"_raw": '{"event":"start"}', "sourcetype": "wd2l:sender:audit",
                       "index": "wd2l_audit"}).encode()
    feed(r, wire.encode_event(DATA, 1, body))
    assert len(out.events) == 1 and out.forwarded_records == aout.forwarded_records == []


def test_lost_records_frames_are_a_gap_marked_records():
    r, out, _ = rx(gap_window=1)
    feed(r, rec_frames(1, {"event": "a"}) + rec_frames(3, {"event": "c"}))
    r.tick(5)
    [g] = out.kinds("gap")
    assert g["records"] is True and (g["first_seq"], g["last_seq"]) == (2, 2)
    assert out.kinds("stream_start")[0]["records"] is True


def test_records_streams_stay_out_of_the_sender_totals():
    r, out, _ = rx()
    feed(r, [wire.encode_heartbeat(DATA, 0, {"sender_drops": 2})])
    feed(r, [wire.encode_heartbeat(RECS, 0, {"sender_drops": 5}, flags=wire.FLAG_RECORDS)])
    assert r.emit_health(0)["sender_drops"] == 2


def test_a_records_stream_is_not_history_for_a_new_receiver():
    r, out, _ = rx()
    feed(r, rec_frames(1, {"event": "start"}))
    feed(r, [wire.encode_heartbeat(DATA, 0, {"boot": 5, "prev_stream": 99, "prev_last_seq": 10})])
    assert out.kinds("stream_missing") == []


def test_bad_record_json_is_counted_and_not_forwarded():
    r, out, aout = rx()
    body = json.dumps({"_raw": "not json", "sourcetype": "wd2l:sender:audit"}).encode()
    feed(r, wire.encode_event(RECS, 1, body, flags=wire.FLAG_RECORDS))
    assert r.counters["records_bad"] == 1 and aout.forwarded_records == []


def test_file_output_writes_forwarded_records_durably(tmp_path):
    o = FileOutput(str(tmp_path))
    o.forwarded({"_raw": '{"event":"start"}'}, RECS, 1, "audit")
    o.forwarded({"_raw": '{"type":"health"}'}, RECS, 2, "health")
    assert o.pending() == {RECS: {1, 2}}
    o.flush()
    assert o.pending() == {}
    o.close()
    assert (tmp_path / "audit.jsonl").read_text() == '{"event":"start"}\n'
    assert (tmp_path / "e1-health.jsonl").read_text() == '{"type":"health"}\n'


def test_the_senders_trail_arrives_whole_in_enclave_2(tmp_path):
    s, a, sock = make(tmp_path)
    a.write("start", "success")
    for i in range(30):
        s.send_event({"_raw": "line %d" % i})
        if i % 10 == 9:
            a.write("gap_check", "info", i=i)
            s.flush_records()
    s.send_heartbeat(final=True)
    a.write("stop", "success")
    s.flush_records(final=True)
    write_pcap(str(tmp_path / "a.pcap"), sock.sent)
    out = tmp_path / "out"
    receiver.main(["--pcap", str(tmp_path / "a.pcap"), "--out-dir", str(out)])
    with open(out / "audit.jsonl") as f:
        inband = [json.loads(x) for x in f]
    assert inband == read_audit(a.dir)
```

Append to `tests/test_hec.py`:

```python
def test_forwarded_records_keep_their_index_whatever_force_index_says(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path, force_index="everything",
            health_index="wd2l")
    o.forwarded({"_raw": '{"event":"start"}', "_time": 5, "host": "logsrv01",
                 "source": "wd2l-sender"}, 0x22, 1, "audit")
    o.forwarded({"_raw": '{"type":"health"}', "_time": 6, "host": "logsrv01"}, 0x22, 2, "health")
    assert wait_for(lambda: len(splunk.records()) == 2)
    assert wait_for(lambda: o.pending() == {})
    o.close()
    a, h = sorted(splunk.records(), key=lambda x: x["time"])
    assert (a["index"], a["sourcetype"], a["host"], a["event"]) == \
        ("wd2l_audit", "wd2l:sender:audit", "logsrv01", '{"event":"start"}')
    assert (h["index"], h["sourcetype"]) == ("wd2l", "wd2l:sender:health")
    assert a["fields"] == {"wd2l_stream": "0000000000000022", "wd2l_seq": 1}
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_records_stream.py tests/test_hec.py -q`
Expected: the new tests fail (`NotImplementedError` / `AttributeError: forwarded`, missing
`records_delivered`).

- [ ] **Step 3: Implement the outputs**

In `wd2l/outputs.py`:

`Output`, after `audit`:

```python
    def forwarded(self, evt: Dict[str, Any], stream_id: int, seq: int, kind: str) -> None:
        """An Enclave 1 record from the sender's records stream (kind "audit" or "health").
        Tracked for durability like event()."""
        raise NotImplementedError
```

`FileOutput`:

```python
    def forwarded(self, evt, stream_id, seq, kind):
        f = self._file("audit.jsonl" if kind == "audit" else "e1-health.jsonl")
        f.write(evt["_raw"] + "\n")
        self._pending.setdefault(stream_id, set()).add(seq)
```

and replace `FileOutput.flush` with:

```python
    def flush(self):
        if self.closed:
            return
        self.events.flush()
        self.healthf.flush()
        for f in self._extra.values():
            f.flush()
        if self._pending:
            os.fsync(self.events.fileno())
            for f in self._extra.values():
                os.fsync(f.fileno())
            self._pending = {}
```

`MultiOutput`:

```python
    def forwarded(self, evt, stream_id, seq, kind):
        for o in self.outputs:
            o.forwarded(evt, stream_id, seq, kind)
```

`HecOutput`:

```python
    def forwarded(self, evt, stream_id, seq, kind):
        rec: Dict[str, Any] = {"time": evt.get("_time", time.time()),
                               "host": evt.get("host", self.hostname),
                               "source": evt.get("source", "wd2l-sender"),
                               "sourcetype": "wd2l:sender:" + kind, "event": evt["_raw"],
                               "fields": {"wd2l_stream": "%016x" % stream_id, "wd2l_seq": seq}}
        index = self.audit_index if kind == "audit" else self.health_index
        if index:
            rec["index"] = index
        self._put(rec, (stream_id, seq))
```

- [ ] **Step 4: Implement the receiver routing**

In `wd2l/receiver.py`:

(a) `StreamTracker.__init__`: add `self.records = False   # the sender's records stream (flags bit 0)`.
`to_json`: add `"records": self.records`. `from_json`: add `t.records = bool(d.get("records", False))`.

(b) `Receiver.__init__`: add `"records_delivered": 0, "records_bad": 0` to `self.counters`.

(c) Add a helper:

```python
    @staticmethod
    def _flag(t: StreamTracker) -> Dict[str, Any]:
        return {"records": True} if t.records else {}
```

(d) Replace `_stream`:

```python
    def _stream(self, sid: int, now: float, records: bool = False) -> StreamTracker:
        t = self.streams.get(sid)
        if t is not None:
            return t
        if sid in self.retired:
            return self._restore(sid, now)
        # Only data streams are history: a records stream must not make a new receiver report
        # the runs before it as missing.
        if not records and (any(not s.records for s in self.streams.values()) or self.retired):
            self.had_history = True
        t = StreamTracker(sid, now)
        t.records = records
        self._add(t, now)
        log.info("new %sstream %016x", "records " if records else "", sid,
                 extra={"stream": "%016x" % sid})
        self._health_record("stream_start", now, stream="%016x" % sid, **self._flag(t))
        return t
```

(e) `handle_datagram`: `t = self._stream(f.stream_id, now)` →
`t = self._stream(f.stream_id, now, bool(f.flags & wire.FLAG_RECORDS))`. After the
`if res == "late": ...` block, before the `if self.rx_time:` line, add:

```python
        if t.records:
            self._deliver_record(evt, f.stream_id, f.seq)
            self.dirty = True
            return
```

and add the method:

```python
    def _deliver_record(self, evt: Dict[str, Any], sid: int, seq: int) -> None:
        """A record from the sender's records stream: re-serialized canonically (so a line can't
        be smuggled into a file) and sent to the audit or health index."""
        try:
            rec = json.loads(evt["_raw"])
            if not isinstance(rec, dict):
                raise ValueError("not a JSON object")
            raw = auditlog.canonical(rec).decode("utf-8")
        except ValueError:
            self.counters["records_bad"] += 1
            return
        kind = "audit" if evt.get("sourcetype") == "wd2l:sender:audit" else "health"
        (self.audit_out if kind == "audit" else self.out).forwarded(dict(evt, _raw=raw), sid, seq, kind)
        self.counters["records_delivered"] += 1
```

(f) `_heartbeat`: `if not t.linked:` → `if not t.linked and not t.records:`. The `stream_end`
record: add `**self._flag(t)`.

(g) `tick` (`stream_lost`), `_evict` (`stream_evicted`) and `_report_gaps` (`gap`): add
`**self._flag(t)` (`victim` in `_evict`) to each `_health_record(...)` call.

(h) `emit_health`: change `live = [...]` to
`live = [t for t in self.streams.values() if "%016x" % t.stream_id in streams and not t.records]`,
and in the `streams[...] = {...}` dict add `**self._flag(t)`.

- [ ] **Step 5: Check the in-band copy in the lab**

In `lab/verify.py`:

* add `p.add_argument("--e1-audit-dir", help="Enclave 1's audit directory: the in-band copy in "
  "<received>/audit.jsonl must match it")`;
* data-stream records only: `runs = list(dict.fromkeys(h["stream"] for h in health if
  h["type"] == "stream_start" and not h.get("records")))`, `ends = {... if h["type"] ==
  "stream_end" and not h.get("records")}`, the `kind in ("stream_lost", ...)` count skips
  `h.get("records")`, the gap loop skips `h.get("records")`, and in the `--state` branch skip
  `s.get("records")` streams;
* before the summary prints:

```python
    if a.e1_audit_dir:
        official = {}
        for path in auditlog.audit_files(a.e1_audit_dir):
            with open(path, "rb") as f:
                for line in auditlog.split_lines(f.read()):
                    if line.endswith(b"\n"):
                        r = json.loads(line)
                        official[r["n"]] = r["hash"]
        inband = [r for r in load(os.path.join(a.received_dir, "audit.jsonl"))
                  if r.get("component") == "sender" and r.get("n") is not None]
        wrong = [r["n"] for r in inband if official.get(r["n"]) != r["hash"]]
        missing = set(official) - {r["n"] for r in inband}
        if wrong:
            problems.append("%d in-band sender audit records differ from Enclave 1's files: %s"
                            % (len(wrong), wrong[:10]))
        if missing and not a.expect_gaps:
            problems.append("%d sender audit records never reached Enclave 2: %s"
                            % (len(missing), sorted(missing)[:10]))
        print("sender audit:    %d of %d records arrived in-band" % (len(official) - len(missing),
                                                                     len(official)))
```

In `lab/run-lab.sh` add `--e1-audit-dir "$OUT/audit-e1"` to `VERIFY_ARGS`.

- [ ] **Step 6: Run the tests**

Run: `T -q`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add wd2l/receiver.py wd2l/outputs.py tests/helpers.py tests/test_records_stream.py tests/test_hec.py lab/verify.py lab/run-lab.sh
git commit -m "Receiver: route the records stream by its flag to the audit and health indexes" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.4: Probes for NIC counters and the capture archive

**Files:**
- Modify: `wd2l/hostinfo.py`
- Modify: `tests/test_hostinfo.py` (append)

**Interfaces:**
- Produces:
  - `hostinfo.NIC_COUNTERS` (`rx_packets, rx_bytes, rx_errors, rx_dropped, rx_crc_errors,
    rx_frame_errors, rx_missed_errors, tx_packets, tx_errors, tx_dropped`)
  - `hostinfo.nic_stats(iface, sysfs="/sys/class/net") -> {"carrier": bool|None,
    "carrier_changes": int|None, <counter>: int|None ...}` (carrier `False` when the interface
    exists but is down, `None` when it doesn't exist)
  - `hostinfo.archive_status(pcap_dir, now=None, pattern="cap-*.pcap") -> {"archive_file",
    "archive_age_s", "archive_bytes"}` (all `None` when there's no file)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_hostinfo.py`:

```python
import os


def fake_nic(root, name, carrier="1", **counters):
    d = root / name
    (d / "statistics").mkdir(parents=True)
    if carrier is not None:
        (d / "carrier").write_text(carrier + "\n")
    (d / "carrier_changes").write_text("3\n")
    for k, v in counters.items():
        (d / "statistics" / k).write_text("%d\n" % v)


def test_nic_stats_reads_carrier_and_counters(tmp_path):
    fake_nic(tmp_path, "cap0", rx_packets=10, rx_crc_errors=2)
    s = hostinfo.nic_stats("cap0", str(tmp_path))
    assert (s["carrier"], s["carrier_changes"], s["rx_packets"], s["rx_crc_errors"]) == (True, 3, 10, 2)
    assert s["tx_errors"] is None


def test_nic_down_or_missing(tmp_path):
    fake_nic(tmp_path, "cap0", carrier=None)     # reading carrier fails while the link is down
    assert hostinfo.nic_stats("cap0", str(tmp_path))["carrier"] is False
    assert hostinfo.nic_stats("nope", str(tmp_path))["carrier"] is None


def test_archive_status_reports_the_newest_file(tmp_path):
    assert hostinfo.archive_status(str(tmp_path)) == {
        "archive_file": None, "archive_age_s": None, "archive_bytes": None}
    old, new = tmp_path / "cap-1.pcap", tmp_path / "cap-2.pcap"
    old.write_bytes(b"x" * 10)
    new.write_bytes(b"y" * 20)
    os.utime(old, (1000, 1000))
    os.utime(new, (2000, 2000))
    assert hostinfo.archive_status(str(tmp_path), now=2030.0) == {
        "archive_file": "cap-2.pcap", "archive_age_s": 30.0, "archive_bytes": 20}
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_hostinfo.py -q`
Expected: `AttributeError: module 'wd2l.hostinfo' has no attribute 'nic_stats'`.

- [ ] **Step 3: Implement**

Append to `wd2l/hostinfo.py` (add `import glob`):

```python
# ---------------------------------------------------------------- NICs and the capture archive

NIC_COUNTERS = ("rx_packets", "rx_bytes", "rx_errors", "rx_dropped", "rx_crc_errors",
                "rx_frame_errors", "rx_missed_errors", "tx_packets", "tx_errors", "tx_dropped")


def _int(v: Optional[str]) -> Optional[int]:
    try:
        return int(v) if v is not None else None
    except ValueError:
        return None


def nic_stats(iface: str, sysfs: str = "/sys/class/net") -> Dict[str, Any]:
    """Carrier and counters from sysfs. Reading `carrier` fails while the interface is down,
    which counts as no carrier. Driver-specific counters need `ethtool -S` by hand."""
    base = os.path.join(sysfs, iface)
    carrier = _read(os.path.join(base, "carrier"))
    out: Dict[str, Any] = {
        "carrier": (carrier == "1") if carrier in ("0", "1") else (False if os.path.isdir(base) else None),
        "carrier_changes": _int(_read(os.path.join(base, "carrier_changes")))}
    for c in NIC_COUNTERS:
        out[c] = _int(_read(os.path.join(base, "statistics", c)))
    return out


def archive_status(pcap_dir: str, now: Optional[float] = None,
                   pattern: str = "cap-*.pcap") -> Dict[str, Any]:
    """The newest capture file: name, seconds since it was last written, size. tcpdump -U
    writes every packet as it arrives, so with packets arriving the age stays near 0."""
    files = glob.glob(os.path.join(pcap_dir, pattern))
    if not files:
        return {"archive_file": None, "archive_age_s": None, "archive_bytes": None}
    newest = max(files, key=os.path.getmtime)
    st = os.stat(newest)
    now = time.time() if now is None else now
    return {"archive_file": os.path.basename(newest), "archive_age_s": round(now - st.st_mtime, 1),
            "archive_bytes": st.st_size}
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_hostinfo.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/hostinfo.py tests/test_hostinfo.py
git commit -m "Probes: NIC carrier and counters from sysfs, capture archive age" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.5: Every heartbeat carries a snapshot of Enclave 1

**Files:**
- Modify: `wd2l/sender.py`
- Create: `tests/test_sender_health.py`
- Modify: `docs/interface-description.md`, `docs/wire-format.md` (same commit)

**Interfaces:**
- Consumes: `hostinfo.ProcStats`, `hostinfo.nic_stats`, `TimeQuality.read()`, `AuditLog.status()`.
- Produces:
  - `Sender(..., egress_iface=None)`; `Sender.sysfs = "/sys/class/net"`;
    `Sender.input_server` (set by `main`); `Sender.stall_s: float`
  - new counters `events_in` (input lines that were events or were rejected) and
    `heartbeat_trimmed`
  - `Sender.snapshot() -> dict` with `stall_s`, `cpu_pct`, `rss_mb`, and when available
    `clients`, `input_backlog_bytes`, `nic_carrier`, `nic_tx_packets`, `nic_tx_errors`,
    `nic_tx_dropped`, `time_stratum`, `time_offset_ms`, `time_synced`, `audit_ok`, `audit_n`
  - `Sender.heartbeat_info(final=False, snap=None)`; `Sender._heartbeat_frame(final, snap) -> bytes`
    (falls back to no snapshot if the frame wouldn't fit `max_datagram`)
  - `InputServer.conns`, `InputServer.client_count()`, `InputServer.backlog_bytes()`
  - sender flag `--egress-iface`

- [ ] **Step 1: Write the failing tests**

`tests/test_sender_health.py`:

```python
import json
import socket
import threading
import time

from wd2l import audit as auditlog
from wd2l import wire
from wd2l.sender import InputServer, Sender

from helpers import FakeSock


class FakeTQ:
    def read(self):
        return {"stratum": 3, "offset_ms": 0.25, "synced": True, "source": "gps"}

    def alarm(self, q=None):
        return None


def fake_nic(root, name):
    d = root / name
    (d / "statistics").mkdir(parents=True)
    (d / "carrier").write_text("1\n")
    for k, v in (("tx_packets", 10), ("tx_errors", 0), ("tx_dropped", 1)):
        (d / "statistics" / k).write_text("%d\n" % v)


def last_info(sock):
    return json.loads(wire.decode(sock.sent[-1]).payload)


def test_heartbeat_carries_the_snapshot(tmp_path):
    fake_nic(tmp_path, "ens224")
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="h", actor="me", build="b")
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, audit=a, time_quality=FakeTQ(),
               egress_iface="ens224")
    s.sysfs = str(tmp_path)
    s.send_event({"_raw": "x"})
    s.count_bad_input()
    s.send_heartbeat()
    info = last_info(sock)
    assert info["events_in"] == 2 and info["events_sent"] == 1
    assert (info["nic_carrier"], info["nic_tx_packets"], info["nic_tx_dropped"]) == (True, 10, 1)
    assert (info["time_stratum"], info["time_offset_ms"], info["time_synced"]) == (3, 0.25, True)
    assert info["audit_ok"] is True and info["audit_n"] == a.n
    assert info["cpu_pct"] >= 0 and info["rss_mb"] > 0 and info["stall_s"] >= 0
    assert s.health_record()["nic_tx_packets"] == 10


def test_pacing_time_is_counted_as_stall():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=500)
    for _ in range(150):
        s.send_event({"_raw": "x"})
    assert s.stall_s >= 0.1


def test_heartbeat_falls_back_if_the_snapshot_would_not_fit():
    """Review focus 3: a heartbeat that can't be sent would break liveness."""
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=600)
    s.snapshot = lambda: {"pad_%02d" % i: 10 ** 18 for i in range(20)}
    s.send_heartbeat()
    info = last_info(sock)
    assert "pad_00" not in info and info["heartbeat_trimmed"] == 1
    assert len(sock.sent[-1]) <= 600


def test_clients_come_from_the_input_server():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    srv = InputServer(("127.0.0.1", 0), s)
    s.input_server = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = socket.create_connection(srv.server_address)
    try:
        end = time.time() + 3
        while srv.client_count() != 1 and time.time() < end:
            time.sleep(0.01)
        snap = s.snapshot()
        assert snap["clients"] == 1 and snap["input_backlog_bytes"] >= 0
    finally:
        c.close()
        srv.shutdown()
        srv.server_close()
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_sender_health.py -q`
Expected: `TypeError: ... unexpected keyword argument 'egress_iface'`.

- [ ] **Step 3: Implement**

In `wd2l/sender.py`:

(a) `Sender.__init__`: add parameter `egress_iface: Optional[str] = None`; add
`"events_in": 0, "heartbeat_trimmed": 0` to `self.counters`; and after
`self.last_snapshot = {}` add:

```python
        self.egress_iface = egress_iface
        self.sysfs = "/sys/class/net"
        self.input_server: Optional["InputServer"] = None
        self.proc = hostinfo.ProcStats()
        self.stall_s = 0.0    # time spent waiting on pacing or a full send buffer
```

(b) `_pace`: replace `time.sleep((1 - self.tokens) / self.rate)` with

```python
            wait = (1 - self.tokens) / self.rate
            time.sleep(wait)
            self.stall_s += wait
```

and in `_transmit` replace `time.sleep(0.001)` with `time.sleep(0.001)` followed by
`self.stall_s += 0.001`.

(c) `send_event`: right after the `if self.closed: return 0` line add
`self.counters["events_in"] += 1`. `count_bad_input`: inside the lock add
`self.counters["events_in"] += 1`.

(d) Replace `heartbeat_info` and `send_heartbeat`, and add `snapshot` and `_heartbeat_frame`:

```python
    def snapshot(self) -> Dict[str, Any]:
        """Enclave 1's state for every heartbeat (§7): input, the sender process, the egress NIC,
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
        if self.audit is not None:
            st = self.audit.status()
            snap.update(audit_ok=st["audit_ok"], audit_n=st["audit_n"])
        return {k: v for k, v in snap.items() if v is not None}

    def heartbeat_info(self, final: bool = False,
                       snap: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        info = dict(self.counters, sender_time=round(time.time(), 3),
                    uptime=round(time.time() - self.started, 1), **self.link)
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
            self._transmit(self._heartbeat_frame(final, snap))
            self._save_state()
            if final:
                self.closed = True
```

(e) `InputServer.__init__`: add `self.conns: Set[socket.socket] = set()` and methods:

```python
    def client_count(self) -> int:
        with self.handlers_lock:
            return len(self.conns)

    def backlog_bytes(self) -> int:
        """Bytes the aggregator has handed over that the sender hasn't read yet."""
        with self.handlers_lock:
            socks = list(self.conns)
        return sum(_unread_bytes(s) for s in socks)
```

In `CriblHandler.handle`, register the connection:

```python
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
```

(f) `build_parser`: add
`p.add_argument("--egress-iface", help="egress NIC whose carrier and transmit counters go in "
"every heartbeat (deployed: ens224)")`. `main`: pass `egress_iface=a.egress_iface` to `Sender`
and set `sender.input_server = server` right after creating the server.

- [ ] **Step 4: Update the interface pages (same commit)**

`docs/interface-description.md` §8: add rows to the heartbeat table (keep it sorted by name):
`audit_n` (integer, with `--audit-dir`: records in the sender's audit chain),
`audit_ok` (boolean, with `--audit-dir`: the audit file is being written and has free space),
`clients` (integer: aggregator connections), `cpu_pct` (number, %: sender process CPU over the
last heartbeat interval), `events_in` (integer, lines: input lines that were events or were
rejected), `heartbeat_trimmed` (integer: heartbeats sent without the snapshot because it
wouldn't fit), `input_backlog_bytes` (integer, bytes: handed over by the aggregator, not yet
read), `nic_carrier`, `nic_tx_packets`, `nic_tx_errors`, `nic_tx_dropped` (with
`--egress-iface`: the egress NIC), `rss_mb` (number, MiB: sender memory), `stall_s` (number, s:
cumulative time waiting on pacing or a full send buffer), `time_offset_ms`, `time_stratum`,
`time_synced` (chrony on the log server). Change "about 200–300 bytes, so the datagram is about
270–370 bytes" to "about 600–800 bytes with the deployed unit, so the datagram is about 670–870
bytes. It is always one packet: if the snapshot keys would not fit `--max-datagram`, they are
left out of that heartbeat and `heartbeat_trimmed` counts it." §10, HEARTBEAT and Expected load:
two heartbeats per second per run (data and records streams), about 8 kbit/s. §16: add
`--egress-iface` (sender) | "Adds `nic_*` keys to the heartbeat". Update the worked example in
§13 only if you re-capture it; otherwise add one sentence under it: "Captured before wd2l 0.2.0;
current heartbeats carry more keys (§8)."

`docs/wire-format.md`: replace the HEARTBEAT example body with one that includes the new keys
(take a real one from a lab run's capture: `tcpdump -r lab/out/pcap/*.pcap -A -c 3 'udp[13] = 2'`)
and add one sentence: "Since wd2l 0.2.0 the heartbeat also carries a snapshot of Enclave 1
(input, sender process, egress NIC, time, audit); see the ICD §8 for every key."

- [ ] **Step 5: Run the tests**

Run: `T tests/test_sender_health.py tests/test_sender.py tests/test_records_stream.py -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add wd2l/sender.py tests/test_sender_health.py docs/interface-description.md docs/wire-format.md
git commit -m "Sender: every heartbeat carries input, process, egress NIC, time and audit state" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.6: The receiver samples its own signals

**Files:**
- Modify: `wd2l/receiver.py`
- Create: `tests/test_receiver_signals.py`

**Interfaces:**
- Consumes: `hostinfo.ProcStats`, `hostinfo.nic_stats`, `hostinfo.archive_status`.
- Produces:
  - `Receiver(..., nic_probe=None, archive_probe=None, sample_interval=5.0)` (probes are
    zero-argument callables returning dicts)
  - `Receiver.last_packet`, `Receiver.last_wd2l` (times of the last frame of any kind and the last
    valid wd2l frame), `Receiver.sample: dict` (latest `cpu_pct`, `rss_mb`, `nic_*`, `archive_*`)
  - `type=health` summaries gain the sample plus `packet_age_s`, `frame_age_s`,
    `sender_events_in`
  - receiver flags `--capture-iface` (default: the `--live` interface), `--pcap-dir`,
    `--capture-rcvbuf` (bytes, default 64 MiB)

- [ ] **Step 1: Write the failing test**

`tests/test_receiver_signals.py`:

```python
import json

from wd2l import wire
from wd2l.receiver import Receiver

from helpers import MemOutput, eth

SID = 0x1111


def test_health_summary_carries_the_receivers_signals():
    nic = {"carrier": True, "carrier_changes": 1, "rx_packets": 50, "rx_crc_errors": 0}
    arch = {"archive_file": "cap-1.pcap", "archive_age_s": 0.4, "archive_bytes": 1000}
    out = MemOutput()
    r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, health_interval=1e9,
                 nic_probe=lambda: dict(nic), archive_probe=lambda: dict(arch), sample_interval=1)
    r.handle_frame(eth(wire.encode_event(SID, 1, json.dumps({"_raw": "x"}).encode())[0]), 0)
    r.handle_frame(eth(wire.encode_heartbeat(SID, 1, {"events_in": 7})), 0.5)
    r.tick(1)
    rec = r.emit_health(3)
    assert (rec["nic_carrier"], rec["nic_rx_packets"], rec["archive_age_s"]) == (True, 50, 0.4)
    assert rec["cpu_pct"] >= 0 and rec["rss_mb"] > 0
    assert (rec["packet_age_s"], rec["frame_age_s"], rec["sender_events_in"]) == (2.5, 2.5, 7)
```

- [ ] **Step 2: Run it to see it fail**

Run: `T tests/test_receiver_signals.py -q`
Expected: `TypeError: ... unexpected keyword argument 'nic_probe'`.

- [ ] **Step 3: Implement**

In `wd2l/receiver.py`:

(a) `Receiver.__init__`: add parameters
`nic_probe: Optional[Callable[[], Dict[str, Any]]] = None,
archive_probe: Optional[Callable[[], Dict[str, Any]]] = None, sample_interval: float = 5.0`
and store them, plus:

```python
        self.proc = hostinfo.ProcStats()
        self.sample: Dict[str, Any] = {}
        self.last_sample: Optional[float] = None
        self.last_packet: Optional[float] = None   # any frame on the capture NIC
        self.last_wd2l: Optional[float] = None     # a valid wd2l frame
```

(b) `handle_frame`: first line `self.last_packet = now`. `handle_datagram`: right after the
successful `f = wire.decode(datagram)` (after the `except` block) add `self.last_wd2l = now`.

(c) Add:

```python
    def _take_sample(self) -> None:
        s: Dict[str, Any] = dict(self.proc.read())
        if self.nic_probe is not None:
            s.update(("nic_" + k, v) for k, v in self.nic_probe().items())
        if self.archive_probe is not None:
            s.update(self.archive_probe())
        self.sample = s
```

and in `tick`, after `self._prune(now)`:

```python
        if self.sample_interval and (self.last_sample is None
                                     or now - self.last_sample >= self.sample_interval):
            self.last_sample = now
            self._take_sample()
```

(d) `emit_health`: add to the `rec.update(open_gap_events=..., ...)` call
`sender_events_in=sum(int(t.hb.get("events_in", 0)) for t in live)`, and after the
`rec.update(type="health", ...)` call:

```python
        rec.update(self.sample)
        rec.update(packet_age_s=round(now - self.last_packet, 1) if self.last_packet is not None else None,
                   frame_age_s=round(now - self.last_wd2l, 1) if self.last_wd2l is not None else None)
```

(e) `build_parser`: add

```python
    p.add_argument("--capture-iface", help="NIC whose carrier and receive counters are reported "
                                           "(default: the --live interface)")
    p.add_argument("--pcap-dir", help="capture archive directory, to check tcpdump is writing it "
                                      "(deployed: /var/lib/wd2l/pcap)")
    p.add_argument("--capture-rcvbuf", type=int, default=64 * 1024 * 1024,
                   help="receive buffer of the capture socket, bytes")
```

`main`, live branch: build `rx` with
`nic_probe=(lambda: hostinfo.nic_stats(a.capture_iface or a.live))` and
`archive_probe=(lambda: hostinfo.archive_status(a.pcap_dir)) if a.pcap_dir else None`, and open
`packets.LiveCapture(a.live, rcvbuf=a.capture_rcvbuf)`.

- [ ] **Step 4: Run the tests**

Run: `T tests/test_receiver_signals.py tests/test_receiver.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/receiver.py tests/test_receiver_signals.py
git commit -m "Receiver: capture NIC, archive, CPU/memory and packet ages in every health summary" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.7: The fault rules

**Files:**
- Create: `wd2l/fault.py`
- Create: `tests/test_fault.py`

**Interfaces:**
- Produces:
  - `fault.SEGMENTS = ("e1-input", "e1-sender", "boundary", "e2-capture", "e2-receiver", "e2-siem")`
  - `fault.Signals` (dataclass; fields and defaults below)
  - `fault.Fault(status, segment, rule, detail, segments)` with `.key()`; `fault.OK`
  - `fault.evaluate(s: Signals) -> Fault` (statuses `ok`, `amber`, `red`; segment colors also
    `unknown`)
  - `fault.time_status(own, sender_hb, clock_offset_s, max_stratum=3, max_offset_ms=100.0,
    max_skew_s=0.05) -> Tuple[str, Optional[str]]` (`("ok", None)` or `("alarm", reasons)`)

Rules (first match wins; every match colors its segments):

| # | When | `segment` | status |
|---|---|---|---|
| 1 | `carrier is False` | `boundary` | red |
| 2 | silent (no frame for > `hb_timeout`) and `clean_end` | `e1-sender` | amber |
| 3 | silent | `e1-sender/boundary` | red |
| 4 | packets arriving, no valid wd2l frame for > `hb_timeout` | `boundary` | red |
| 5 | heartbeats arriving, `input_flat_s >= input_flat_after` | `e1-input` | amber |
| 6 | `sender_drops` or `send_errors` grew, or `backlog_growing` | `e1-sender` | amber |
| 7 | `gaps_not_received` and `nic_errors` grew | `boundary` | red |
| 8 | `gaps_not_received` and `kernel_drops` grew | `e2-capture` | red |
| 9 | `gaps_not_received` grew | `boundary` | amber |
| 10 | `output_dropped`, `gaps_output_dropped`, `spool_growing` or `hec_errors` | `e2-siem` | red if anything was dropped, else amber |
| 11 | `archive_stale` | `e2-capture` | amber |

While silent (rules 2–3) `e1-input` is `unknown`; while no wd2l frames arrive (rule 4) both
Enclave 1 segments are `unknown`.

- [ ] **Step 1: Write the failing tests**

`tests/test_fault.py`:

```python
import pytest

from wd2l import fault
from wd2l.fault import Signals

LIVE = dict(packet_age=0.5, frame_age=0.5, carrier=True)


def ev(**kw):
    return fault.evaluate(Signals(**dict(LIVE, **kw)))


def test_all_quiet_is_ok():
    f = ev()
    assert (f.status, f.segment, f.rule) == ("ok", None, 0)
    assert set(f.segments.values()) == {"ok"} and list(f.segments) == list(fault.SEGMENTS)


@pytest.mark.parametrize("kw, want", [
    (dict(carrier=False, packet_age=30, frame_age=30), ("red", "boundary", 1)),
    (dict(packet_age=30, frame_age=30, clean_end=True), ("amber", "e1-sender", 2)),
    (dict(packet_age=30, frame_age=30), ("red", "e1-sender/boundary", 3)),
    (dict(frame_age=30), ("red", "boundary", 4)),
    (dict(input_flat_s=400), ("amber", "e1-input", 5)),
    (dict(sender_drops=3), ("amber", "e1-sender", 6)),
    (dict(send_errors=1), ("amber", "e1-sender", 6)),
    (dict(backlog_growing=True), ("amber", "e1-sender", 6)),
    (dict(gaps_not_received=5, nic_errors=2), ("red", "boundary", 7)),
    (dict(gaps_not_received=5, kernel_drops=9), ("red", "e2-capture", 8)),
    (dict(gaps_not_received=5), ("amber", "boundary", 9)),
    (dict(spool_growing=True), ("amber", "e2-siem", 10)),
    (dict(hec_errors=4), ("amber", "e2-siem", 10)),
    (dict(output_dropped=2), ("red", "e2-siem", 10)),
    (dict(gaps_output_dropped=2), ("red", "e2-siem", 10)),
    (dict(archive_stale=True), ("amber", "e2-capture", 11)),
])
def test_each_rule(kw, want):
    f = ev(**kw)
    assert (f.status, f.segment, f.rule) == want and f.detail


def test_first_match_wins_but_every_match_colors_its_segment():
    f = ev(carrier=False, packet_age=30, frame_age=30, output_dropped=1)
    assert f.rule == 1
    assert (f.segments["boundary"], f.segments["e1-sender"], f.segments["e2-siem"]) == \
        ("red", "red", "red")


def test_what_the_receiver_cannot_see_is_unknown():
    silent = ev(packet_age=30, frame_age=30)
    assert silent.segments["e1-input"] == "unknown" and silent.segments["e2-capture"] == "ok"
    foreign = ev(frame_age=30)
    assert foreign.segments["e1-input"] == foreign.segments["e1-sender"] == "unknown"


def test_never_seen_anything_counts_as_silent():
    f = fault.evaluate(Signals(packet_age=None, frame_age=None))
    assert f.rule == 3


def test_input_flat_is_ignored_while_silent():
    assert ev(packet_age=30, frame_age=30, input_flat_s=400).rule == 3


def test_fault_key():
    assert ev().key() == fault.OK.key() == ("ok", None, 0)


def test_time_status():
    good = {"stratum": 3, "offset_ms": 0.1, "synced": True}
    assert fault.time_status(good, {}, 0.001) == ("ok", None)
    assert fault.time_status({"synced": False, "stratum": 0, "offset_ms": 0.0}, {}, None) == \
        ("alarm", "receiver: unsynced")
    assert fault.time_status(good, {"time_synced": False}, None) == ("alarm", "sender: unsynced")
    assert fault.time_status(good, {"time_synced": True, "time_stratum": 5,
                                    "time_offset_ms": 0.0}, None) == ("alarm", "sender: stratum 5 > 3")
    assert fault.time_status(good, {}, -0.2) == ("alarm", "clock skew -0.200 s > 0.05 s")
    assert fault.time_status(None, {}, None) == ("ok", None)
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_fault.py -q`
Expected: `ModuleNotFoundError: No module named 'wd2l.fault'`.

- [ ] **Step 3: Write the implementation**

`wd2l/fault.py`:

```python
"""Where is the fault? The receiver's decision rules (docs/audit-and-health-plan.md §12).

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
                hit(9, "amber", "boundary", ("boundary",),
                    "%d events lost, no NIC errors or kernel drops: loss on the path" % n)
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
    """Time quality on both sides and the skew between them (§11). Shown apart from the transfer
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
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_fault.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/fault.py tests/test_fault.py
git commit -m "Fault location rules 1-11, segment colors and time status" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.8: The receiver decides where the fault is

**Files:**
- Modify: `wd2l/receiver.py`
- Modify: `tests/test_fault.py` (append)

**Interfaces:**
- Consumes: `fault.Signals`, `fault.evaluate`, `fault.time_status`, `fault.FaultTracker`, Task 2.6
  sample and packet times.
- Produces:
  - `Receiver(..., fault_interval=0.0, fault_window=60.0, input_flat_after=300.0,
    backlog_alarm_bytes=1 << 20, archive_stale_after=15.0, max_skew_s=0.05)`; `fault_interval`
    0 turns fault evaluation off (archive replay)
  - `Receiver.faults: FaultTracker`, `Receiver.gap_by_reason: Dict[str, int]`
  - `type=fault` health records on every change: `fault_status`, `fault_segment`, `fault_rule`,
    `fault_detail`, `segments`, `previous_status`, `previous_segment`, `previous_rule`
  - `type=time_status` health records on every change: `time_status`, `time_reason`
  - `type=health` summaries (when evaluating) gain `fault_status`, `fault_segment`, `fault_rule`,
    `fault_detail`, `time_status`, `time_reason`, `seg_e1_input`, `seg_e1_sender`,
    `seg_boundary`, `seg_e2_capture`, `seg_e2_receiver`, `seg_e2_siem`
  - receiver flags `--fault-interval` (default 5; ignored for `--pcap`), `--fault-window`
    (default 60), `--input-flat-after` (default 300), `--time-check-interval` (default 60, how
    often chrony is read)

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_fault.py`:

```python
import json

from wd2l import packets, wire
from wd2l.receiver import Receiver

from helpers import MemOutput, SlowOutput, eth

SID = 0x1111


def rxf(out=None, **kw):
    out = out or MemOutput()
    kw.setdefault("health_interval", 1e9)
    kw.setdefault("fault_interval", 1)
    kw.setdefault("fault_window", 10)
    kw.setdefault("gap_window", 1)
    return Receiver(out, dst_ip="10.255.255.2", dst_port=5514, **kw), out


def evt(seq):
    return wire.encode_event(SID, seq, json.dumps({"_raw": "e%d" % seq}).encode())


def hbf(seq, **info):
    return [wire.encode_heartbeat(SID, seq, dict({"events_sent": seq, "events_in": seq}, **info))]


def feed(r, dgs, now):
    for d in dgs:
        r.handle_frame(eth(d), now)


def faults(out):
    return [(f["fault_status"], f["fault_segment"], f["fault_rule"]) for f in out.kinds("fault")]


def test_carrier_down_then_back():
    nic = {"carrier": False}
    r, out = rxf(nic_probe=lambda: dict(nic), sample_interval=1)
    r.tick(0)
    nic["carrier"] = True
    feed(r, evt(1) + hbf(1), 2)
    r.tick(2)
    assert faults(out) == [("red", "boundary", 1), ("ok", None, 0)]
    assert out.kinds("fault")[1]["previous_status"] == "red"


def test_planned_stop_is_amber_and_a_hang_is_red():
    r, out = rxf()
    feed(r, evt(1) + hbf(1, final=True), 0)
    r.tick(0)
    r.tick(7)
    assert faults(out) == [("amber", "e1-sender", 2)]
    r2, out2 = rxf()
    feed(r2, evt(1) + hbf(1), 0)
    r2.tick(0)
    r2.tick(7)
    assert faults(out2) == [("red", "e1-sender/boundary", 3)]


def test_foreign_packets_only():
    r, out = rxf()
    feed(r, evt(1) + hbf(1), 0)
    r.tick(0)
    r.handle_frame(packets.build_udp_frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                                           "10.255.255.1", "10.255.255.2", 5514, 9999, b"x"), 7)
    r.tick(7)
    assert faults(out) == [("red", "boundary", 4)]


def lossy(r, now):
    feed(r, evt(1) + hbf(1), now)
    r.tick(now)
    feed(r, evt(3) + hbf(3), now + 1)
    r.tick(now + 3)


def test_loss_with_nothing_else_is_the_path():
    r, out = rxf()
    lossy(r, 0)
    assert faults(out) == [("amber", "boundary", 9)]


def test_loss_with_crc_errors_is_the_fiber():
    nic = {"carrier": True, "rx_crc_errors": 0}
    r, out = rxf(nic_probe=lambda: dict(nic), sample_interval=1)
    feed(r, evt(1) + hbf(1), 0)
    r.tick(0)
    nic["rx_crc_errors"] = 4
    feed(r, evt(3) + hbf(3), 1)
    r.tick(3)
    assert faults(out)[-1] == ("red", "boundary", 7)


def test_loss_with_kernel_drops_is_the_receiver_host():
    r, out = rxf()
    feed(r, evt(1) + hbf(1), 0)
    r.tick(0)
    r.counters["kernel_drops"] += 5
    feed(r, evt(3) + hbf(3), 1)
    r.tick(3)
    assert faults(out)[-1] == ("red", "e2-capture", 8)


def test_dropped_output_is_the_siem_and_red():
    r, out = rxf(out=SlowOutput())
    feed(r, evt(1) + hbf(1), 0)
    r.tick(0)
    out.fail(SID, 1)
    feed(r, hbf(1), 1)
    r.tick(1)
    assert faults(out)[-1] == ("red", "e2-siem", 10)


def test_stale_archive():
    r, out = rxf(archive_probe=lambda: {"archive_age_s": 60.0}, sample_interval=1)
    feed(r, evt(1) + hbf(1), 0)
    r.tick(0)
    assert faults(out) == [("amber", "e2-capture", 11)]


def test_flat_input_is_the_aggregator():
    r, out = rxf(input_flat_after=5)
    for t in range(8):
        feed(r, hbf(0), t)
        r.tick(t)
    assert faults(out) == [("amber", "e1-input", 5)]


def test_sender_drops():
    r, out = rxf()
    feed(r, hbf(0, sender_drops=0), 0)
    r.tick(0)
    feed(r, hbf(0, sender_drops=3), 1)
    r.tick(1)
    assert faults(out) == [("amber", "e1-sender", 6)]


class BadTQ:
    def read(self):
        return {"stratum": 0, "offset_ms": 0.0, "synced": False, "source": ""}

    def alarm(self, q=None):
        return "unsynced"


def test_time_status_changes_are_recorded():
    r, out = rxf(time_quality=BadTQ())
    feed(r, hbf(0), 0)
    r.tick(0)
    [t] = out.kinds("time_status")
    assert t["time_status"] == "alarm" and "receiver: unsynced" in t["time_reason"]


def test_skew_raises_the_time_alarm():
    r, out = rxf(record_clock=lambda: 1000.5)
    feed(r, hbf(0, sender_time=1000.0), 0)
    r.tick(0)
    assert "clock skew" in out.kinds("time_status")[0]["time_reason"]


def test_summary_carries_the_answer_and_the_segment_colors():
    r, out = rxf()
    feed(r, evt(1) + hbf(1), 0)
    r.tick(0)
    rec = r.emit_health(0)
    assert (rec["fault_status"], rec["time_status"], rec["seg_boundary"]) == ("ok", "ok", "ok")


def test_replay_does_not_evaluate_faults():
    r, out = rxf(fault_interval=0)
    r.tick(100)
    assert out.kinds("fault") == [] and "fault_status" not in r.emit_health(100)
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_fault.py -q`
Expected: the new tests fail with `TypeError: ... unexpected keyword argument 'fault_interval'`.

- [ ] **Step 3: Implement**

In `wd2l/receiver.py`:

(a) Import `from . import fault`.

(b) `Receiver.__init__`: add parameters
`fault_interval: float = 0.0, fault_window: float = 60.0, input_flat_after: float = 300.0,
backlog_alarm_bytes: int = 1 << 20, archive_stale_after: float = 15.0, max_skew_s: float = 0.05`
and store them; add `self.faults = fault.FaultTracker(fault_window)`,
`self.last_fault: Optional[float] = None`, `self.gap_by_reason: Dict[str, int] = {}`.

(c) `_report_gaps`: inside the loop, after `n = b - a + 1`, add
`self.gap_by_reason[reason] = self.gap_by_reason.get(reason, 0) + n`.

(d) At the end of `tick`, before the audit block:

```python
        if self.fault_interval and (self.last_fault is None
                                    or now - self.last_fault >= self.fault_interval):
            self.last_fault = now
            self._evaluate_faults(now)
```

(e) Add:

```python
    def _evaluate_faults(self, now: float) -> None:
        data = [t for t in self.streams.values() if not t.records]
        newest = max(data, key=lambda t: t.first_seen) if data else None
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
```

(f) `emit_health`, after `rec.update(self.sample)` and the ages:

```python
        if self.fault_interval:
            f = self.faults.current
            rec.update(fault_status=f.status, fault_segment=f.segment, fault_rule=f.rule,
                       fault_detail=f.detail or None, time_status=self.faults.time[0],
                       time_reason=self.faults.time[1])
            rec.update(("seg_" + k.replace("-", "_"), v) for k, v in f.segments.items())
```

(g) `build_parser`: add

```python
    p.add_argument("--fault-interval", type=float, default=5.0,
                   help="seconds between fault-location checks (live capture only)")
    p.add_argument("--fault-window", type=float, default=60.0,
                   help="seconds over which counter growth counts as 'new'")
    p.add_argument("--input-flat-after", type=float, default=300.0,
                   help="seconds without new events from the aggregator before rule 5 fires")
    p.add_argument("--time-check-interval", type=float, default=60.0,
                   help="seconds between chrony reads")
```

`main`: build `tq` with `every=a.time_check_interval`; add to `kw`
`fault_window=a.fault_window, input_flat_after=a.input_flat_after`; pass
`fault_interval=a.fault_interval` only in the live branch (the replay keeps the default 0).

- [ ] **Step 4: Run all tests**

Run: `T -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add wd2l/receiver.py tests/test_fault.py
git commit -m "Receiver: evaluate fault location every few seconds; fault and time_status records" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2.9: Lab fault injection

**Files:**
- Create: `lab/fake_siem.py`, `lab/check_fault.py`
- Modify: `lab/run-lab.sh`, `lab/fake_cribl.py`, `lab/verify.py`
- Modify: `.github/workflows/tests.yml`
- Modify: `docs/running-the-lab.md`

**Interfaces:**
- Produces:
  - `sudo lab/run-lab.sh --fault NAME` for `aggregator-stop sender-stop sender-hang tap-down
    foreign-only wire-loss receiver-slow siem-down clock`
  - `lab/check_fault.py HEALTH_JSONL (--segment S --status ST --rule N | --time-alarm)`: passes
    if a matching record was written and a later one returned to `ok`
  - `lab/fake_cribl.py --pause-after N --pause-s S`
  - `lab/fake_siem.py --port P [--out FILE]`: an HTTP event collector stand-in that answers 200
  - `lab/verify.py --allow-other-packets`

Expected results (from §16 of the spec):

| `--fault` | Injection | `check_fault.py` | `verify.py` extra flags |
|---|---|---|---|
| `aggregator-stop` | aggregator pauses 12 s mid-run | `--segment e1-input --status amber --rule 5` | — |
| `sender-stop` | first half, clean stop, 10 s, start, second half | `--segment e1-sender --status amber --rule 2` | `--sender-runs 2` |
| `sender-hang` | `kill -STOP` the sender 10 s | `--segment e1-sender/boundary --status red --rule 3` | — |
| `tap-down` | `tap0` down 10 s | `--segment boundary --status red --rule 1` | `--expect-gaps` |
| `foreign-only` | sender stopped, other UDP on the cable 10 s | `--segment boundary --status red --rule 4` | `--allow-other-packets` |
| `wire-loss` | 20% loss on the cable 10 s | `--segment boundary --status amber --rule 9` | `--expect-gaps` |
| `receiver-slow` | small capture buffer, receiver stopped 4 s at 5,000 events/s | `--segment e2-capture --status red --rule 8` | `--expect-gaps` |
| `siem-down` | the SIEM stand-in is down 12 s | `--segment e2-siem --status amber --rule 10` | — |
| `clock` | chrony "not synchronised" 10 s | `--time-alarm` | — |

- [ ] **Step 1: Write the stand-ins and the check**

`lab/fake_siem.py`:

```python
#!/usr/bin/env python3
"""Stand-in SIEM HTTP event collector for the lab (--fault siem-down): answers 200 to every
post to /services/collector/event and appends the bodies to --out."""

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=8088)
    p.add_argument("--out", help="append received bodies here")
    a = p.parse_args()

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if a.out:
                with open(a.out, "ab") as f:
                    f.write(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"text":"Success","code":0}')

        def log_message(self, *args):
            pass

    HTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
```

`lab/check_fault.py`:

```python
#!/usr/bin/env python3
"""Check that the receiver placed an injected fault where expected (lab --fault runs): a
type=fault record (or, with --time-alarm, a type=time_status alarm) matching the expectation,
and a later record saying things are ok again."""

import argparse
import json
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("health", help="health.jsonl from the receiver's --out-dir")
    p.add_argument("--segment")
    p.add_argument("--status")
    p.add_argument("--rule", type=int)
    p.add_argument("--time-alarm", action="store_true")
    a = p.parse_args()
    with open(a.health) as f:
        recs = [json.loads(x) for x in f if x.strip()]
    if a.time_alarm:
        seq = [(r["time_status"], r.get("time_reason")) for r in recs if r["type"] == "time_status"]
        hit = next((i for i, (s, _) in enumerate(seq) if s == "alarm"), None)
        cleared = hit is not None and any(s == "ok" for s, _ in seq[hit + 1:])
        print("time_status records: %s" % seq)
    else:
        seq = [(r["fault_status"], r["fault_segment"], r["fault_rule"])
               for r in recs if r["type"] == "fault"]
        want = (a.status, a.segment, a.rule)
        hit = next((i for i, x in enumerate(seq) if x == want), None)
        cleared = hit is not None and any(s == "ok" for s, _, _ in seq[hit + 1:])
        print("fault records: %s" % seq)
        print("expected:      %s" % (want,))
    if hit is None:
        print("FAIL: the expected fault was never reported")
        return 1
    if not cleared:
        print("FAIL: the fault was reported but never cleared")
        return 1
    print("PASS: fault reported where expected, then cleared")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Let the aggregator pause; let verify tolerate foreign packets**

`lab/fake_cribl.py`: add arguments

```python
    p.add_argument("--pause-after", type=int, default=0,
                   help="after this many events, stop sending (connection stays open)")
    p.add_argument("--pause-s", type=float, default=0, help="for this many seconds")
```

and in the send loop, after `n += 1`:

```python
            if a.pause_after and n == a.pause_after:
                time.sleep(a.pause_s)
                start += a.pause_s
```

`lab/verify.py`: add `p.add_argument("--allow-other-packets", action="store_true")` and skip
`other_packets` in the "last health record" check when it is set.

- [ ] **Step 3: Add `--fault` to `lab/run-lab.sh`**

* Usage comment: add
  `#   --fault NAME        inject one fault and check the receiver names its segment (aggregator-stop,`
  `#                       sender-stop, sender-hang, tap-down, foreign-only, wire-loss, receiver-slow,`
  `#                       siem-down, clock); see docs/running-the-lab.md`
* Defaults: `FAULT=""`; option parsing: `--fault) FAULT="$2"; shift 2 ;;`; then refuse
  combinations: `if [ -n "$FAULT" ] && { [ "$OUTAGE" = 1 ] || [ "$MAINT" = 1 ] || [ -n "$LOSS" ] || [ ${#FILES[@]} -gt 0 ]; }; then echo "--fault runs on its own (with --events / --eps)" >&2; exit 2; fi`
* Receiver arguments for every run: add `--pcap-dir "$OUT/pcap" --fault-interval 1`. For fault
  runs also add `--fault-window 10 --input-flat-after 5 --time-check-interval 1`; for
  `receiver-slow` also `--capture-rcvbuf 65536`; for `siem-down` also
  `--hec-url http://127.0.0.1:8088 --hec-token-file "$OUT/hec.token" --spool-dir "$OUT/spool"`
  (write any token to `$OUT/hec.token` first). Sender arguments for every run: add
  `--egress-iface enc1nic`.
* For fault runs default `EVENTS=20000` (unless `--events` was given) and `EPS=5000` for
  `receiver-slow`, so the run outlasts the injection.
* Replace the single aggregator start with a `case "$FAULT"` block after the receiver and sender
  have started:

```bash
FAULT_S=10
if [ -n "$FAULT" ]; then
  echo "== fault run: $FAULT"
  case "$FAULT" in
    aggregator-stop)
      $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" --pause-after 3000 --pause-s 12 \
        "$OUT/sent.jsonl" & AGG_PID=$! ;;
    sender-stop)
      HALF=$(( $(wc -l < "$OUT/sent.jsonl") / 2 ))
      head -n "$HALF" "$OUT/sent.jsonl" > "$OUT/sent-part1.jsonl"
      tail -n +"$((HALF + 1))" "$OUT/sent.jsonl" > "$OUT/sent-part2.jsonl"
      $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent-part1.jsonl"
      sleep 1; kill -TERM "$TX_PID"; wait "$TX_PID" 2>/dev/null || true
      sleep "$FAULT_S"; start_sender; sleep 1
      $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent-part2.jsonl" & AGG_PID=$! ;;
    *)
      $ENC1 python3 "$HERE/fake_cribl.py" --eps "$EPS" "$OUT/sent.jsonl" & AGG_PID=$!
      sleep 3
      case "$FAULT" in
        sender-hang)   kill -STOP "$TX_PID"; sleep "$FAULT_S"; kill -CONT "$TX_PID" ;;
        tap-down)      $BH ip link set tap0 down; sleep "$FAULT_S"; $BH ip link set tap0 up ;;
        foreign-only)  kill -STOP "$TX_PID"
                       $ENC1 python3 -c "import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range($FAULT_S*10): s.sendto(b'x'*100,('10.255.255.2',9999)); time.sleep(0.1)"
                       kill -CONT "$TX_PID" ;;
        wire-loss)     $ENC1 nft -f - <<'EOF'
table netdev faultloss {
  chain out { type filter hook egress device "enc1nic" priority 0; policy accept; numgen random mod 10 < 2 drop; }
}
EOF
                       sleep "$FAULT_S"; $ENC1 nft delete table netdev faultloss ;;
        receiver-slow) kill -STOP "$RX_PID"; sleep 4; kill -CONT "$RX_PID" ;;
        siem-down)     kill "$SIEM_PID"; wait "$SIEM_PID" 2>/dev/null || true; sleep 12
                       $ENC2 python3 "$HERE/fake_siem.py" --port 8088 --out "$OUT/siem.ndjson" &
                       SIEM_PID=$!; PIDS+=($SIEM_PID) ;;
        clock)         touch "$OUT/clock-bad"; sleep "$FAULT_S"; rm -f "$OUT/clock-bad" ;;
        *) echo "unknown fault $FAULT" >&2; exit 2 ;;
      esac ;;
  esac
  sleep 13   # longer than --fault-window, so the "ok again" record is written
elif [ "$MAINT" = 1 ]; then
```

  (the existing `--maintenance` branch and the plain aggregator start follow as `elif`/`else`).
  For `siem-down`, start the stand-in SIEM with the capture, before the receiver:
  `$ENC2 python3 "$HERE/fake_siem.py" --port 8088 --out "$OUT/siem.ndjson" & SIEM_PID=$!; PIDS+=($SIEM_PID)`.
* After the existing `verify.py` call, for fault runs:

```bash
if [ -n "$FAULT" ]; then
  echo "== checking where the receiver placed the fault"
  case "$FAULT" in
    aggregator-stop) EXPECT=(--segment e1-input --status amber --rule 5) ;;
    sender-stop)     EXPECT=(--segment e1-sender --status amber --rule 2) ;;
    sender-hang)     EXPECT=(--segment e1-sender/boundary --status red --rule 3) ;;
    tap-down)        EXPECT=(--segment boundary --status red --rule 1) ;;
    foreign-only)    EXPECT=(--segment boundary --status red --rule 4) ;;
    wire-loss)       EXPECT=(--segment boundary --status amber --rule 9) ;;
    receiver-slow)   EXPECT=(--segment e2-capture --status red --rule 8) ;;
    siem-down)       EXPECT=(--segment e2-siem --status amber --rule 10) ;;
    clock)           EXPECT=(--time-alarm) ;;
  esac
  python3 "$HERE/check_fault.py" "$OUT/received/health.jsonl" "${EXPECT[@]}" || RC=1
fi
```

  and add the per-fault `verify.py` flags from the table to `VERIFY_ARGS` before verify runs
  (`sender-stop` → `--sender-runs 2`; `tap-down`, `wire-loss`, `receiver-slow` →
  `--expect-gaps`; `foreign-only` → `--allow-other-packets`).

- [ ] **Step 4: CI and docs**

`.github/workflows/tests.yml`, `lab` job: add one step per fault,
`- run: sudo lab/run-lab.sh --fault aggregator-stop` … through `--fault clock`.

`docs/running-the-lab.md`: add a section **9. Inject faults and see where the receiver places
them** after section 8: one paragraph (the receiver decides which segment is at fault; each run
injects one fault, checks the answer, then checks it clears), the expected-results table from
this task (columns: fault, what the lab does, what the receiver should say), the command
`sudo lab/run-lab.sh --fault tap-down`, and where to look (`lab/out/received/health.jsonl`,
`grep '"type": "fault"'`). Link to [state-of-health.md](../../../state-of-health.md) for how the
answer appears on the dashboard (that page arrives in Task 4.3; until then, link to §12 of the
audit plan).

- [ ] **Step 5: Verify**

Run: `T -q` (nothing in pytest changes, but run it). Push and check the CI `lab` job: all nine
fault runs print `PASS: fault reported where expected, then cleared` and verify still prints
`PASS`. If a run is flaky, widen its timing (`FAULT_S`, the final `sleep`) rather than loosening
the check, and note it in the As-built log.

- [ ] **Step 6: Commit**

```bash
git add lab/ .github/workflows/tests.yml docs/running-the-lab.md
git commit -m "Lab: --fault injects one fault per segment and checks the receiver names it" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Phase 2 checkpoint:** full suite green, CI lab green including nine fault runs. Stop for
review.
