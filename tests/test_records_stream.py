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


def test_a_record_claiming_to_be_from_enclave_2_is_refused():
    """Final review I6: the low side must not plant records about the high side."""
    r, out, aout = rx()
    forged = {"event": "replay_run", "enclave": 2, "component": "receiver", "host": "rx01",
              "actor": "uid=0(root) auid=1001(admin)"}
    feed(r, rec_frames(1, forged))
    feed(r, rec_frames(2, dict(forged, type="health", audit_ok=True), kind="health"))
    for i, claim in enumerate(({"enclave": 1, "component": "receiver"},
                               {"enclave": 2, "component": "sender"},
                               {"enclave": True, "component": "sender"},
                               {"component": "sender"}), 3):
        feed(r, rec_frames(i, dict({"event": "start"}, **claim)))
    assert r.counters["records_bad"] == 6 and r.counters["records_delivered"] == 0
    assert aout.forwarded_records == out.forwarded_records == []
    feed(r, rec_frames(9, {"event": "start", "enclave": 1, "component": "sender"}))
    assert r.counters["records_delivered"] == 1 and len(aout.forwarded_records) == 1


def test_a_deeply_nested_record_is_counted_not_a_crash():
    r, out, aout = rx()
    body = json.dumps({"_raw": "[" * 10000 + "]" * 10000, "sourcetype": "wd2l:sender:audit"})
    feed(r, wire.encode_event(RECS, 1, body.encode(), flags=wire.FLAG_RECORDS))
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
