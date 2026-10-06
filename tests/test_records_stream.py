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
