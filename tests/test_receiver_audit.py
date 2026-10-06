import hashlib
import json
import os

import pytest

from wd2l import audit as auditlog
from wd2l import packets, receiver, wire
from wd2l.receiver import Receiver
from wd2l.sender import Sender

from helpers import FakeSock, MemOutput, SlowOutput, eth, read_audit, write_pcap

SID = 0x1111


def ev(seq, sid=SID):
    return wire.encode_event(sid, seq, json.dumps({"_raw": "event %d" % seq}).encode())


def hb(last_seq, sid=SID, **info):
    return wire.encode_heartbeat(sid, last_seq, dict({"events_sent": last_seq}, **info))


def make(tmp_path, out=None, **kw):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="rx01", actor="me", build="b")
    out = out or MemOutput()
    kw.setdefault("health_interval", 1e9)
    r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, audit=a, **kw)
    return r, out, a


def feed(r, dgs, now):
    for d in dgs:
        r.handle_frame(eth(d), now)


def events(a, name):
    return [x for x in read_audit(a.dir) if x["event"] == name]


def test_gaps_are_audit_events_and_reach_the_audit_output(tmp_path):
    r, out, a = make(tmp_path, gap_window=1)
    feed(r, ev(1) + ev(4), 0)
    r.tick(5)
    [g] = events(a, "gap")
    assert (g["seq_first"], g["seq_last"], g["count"], g["reason"], g["outcome"]) == \
        (2, 3, 2, "not_received", "failure")
    assert g["stream"] == "%016x" % SID and g["segment"] == "e2-receiver"
    assert [x["event"] for x in out.audits if x["event"] == "gap"] == ["gap"]


def test_stream_start_and_clean_end_are_audited(tmp_path):
    r, out, a = make(tmp_path)
    feed(r, ev(1) + [hb(1, final=True)], 0)
    assert [x["outcome"] for x in events(a, "stream_start")] == ["info"]
    [e] = events(a, "stream_end")
    assert e["outcome"] == "success" and e["seq_last"] == 1


def test_state_reset_then_loaded_then_config_changed(tmp_path):
    state = str(tmp_path / "state.json")
    r, _, a = make(tmp_path, state_path=state, config_sha256="a" * 64)
    assert [x["reason"] for x in events(a, "state_reset")] == ["missing"]
    feed(r, ev(1), 0)
    r.save_state()
    a.close()
    with open(state, "rb") as f:
        body = f.read()
    _, _, a2 = make(tmp_path, state_path=state, config_sha256="b" * 64)
    [ld] = events(a2, "state_loaded")
    assert ld["file_sha256"] == hashlib.sha256(body).hexdigest() and ld["streams"] == 1
    [cc] = events(a2, "config_changed")
    assert (cc["old_config_sha256"], cc["config_sha256"]) == ("a" * 64, "b" * 64)


def test_unreadable_state_stops_the_receiver_and_is_audited(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("{oops")
    with pytest.raises(SystemExit, match="unreadable"):
        make(tmp_path, state_path=str(state))
    recs = read_audit(tmp_path / "audit")
    assert recs[-1]["event"] == "state_reset" and recs[-1]["outcome"] == "failure"


def test_boundary_anomalies_are_summarised_each_minute(tmp_path):
    r, out, a = make(tmp_path)
    r.handle_frame(b"\x00" * 60, 0)                     # not IPv4/UDP
    good = ev(1)[0]
    r.handle_frame(eth(good[:-1] + bytes([good[-1] ^ 0xFF])), 0)   # bad CRC
    r.audit_periodic()
    got = {x["reason"]: x for x in events(a, "boundary_anomaly")}
    assert got["other_packets"]["count"] == 1 and got["other_packets"]["segment"] == "boundary"
    assert got["bad_frames"]["reasons"] == {"bad crc": 1}
    r.audit_periodic()
    assert len(events(a, "boundary_anomaly")) == 2      # deltas: nothing new


def test_output_failures_are_audited_against_the_siem_segment(tmp_path):
    r, out, a = make(tmp_path, out=SlowOutput())
    feed(r, ev(1), 0)
    out.fail(SID, 1)
    r.tick(1)
    r.audit_periodic()
    [f] = events(a, "output_failure")
    assert (f["reason"], f["count"], f["segment"]) == ("output_dropped", 1, "e2-siem")


def test_late_fills_are_summarised_as_gap_filled(tmp_path):
    r, out, a = make(tmp_path, gap_window=1)
    feed(r, ev(1) + ev(5), 0)
    r.tick(5)
    feed(r, ev(3) + ev(2), 6)
    r.audit_periodic()
    [f] = events(a, "gap_filled")
    assert (f["count"], f["seq_first"], f["seq_last"], f["outcome"]) == (2, 2, 3, "success")


def replay_pcap(tmp_path):
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    for i in range(20):
        s.send_event({"_raw": "line %d" % i})
    s.send_heartbeat(final=True)
    path = str(tmp_path / "cap-1.pcap")
    write_pcap(path, sock.sent)
    return path


def test_replay_run_records_the_files_and_their_hashes(tmp_path):
    p = replay_pcap(tmp_path)
    adir, out = str(tmp_path / "audit"), str(tmp_path / "out")
    receiver.main(["--pcap", p, "--out-dir", out, "--audit-dir", adir, "--chronyc", "/bin/false"])
    recs = read_audit(adir)
    names = [x["event"] for x in recs]
    assert names[0] == "start" and recs[0]["component"] == "replay" and names[-1] == "stop"
    phases = [x["phase"] for x in recs if x["event"] == "replay_run"]
    assert phases == ["start", "finish"]
    fin = [x for x in recs if x["event"] == "replay_run"][-1]
    with open(p, "rb") as f:
        data = f.read()
    assert fin["files"] == [{"file": "cap-1.pcap", "sha256": hashlib.sha256(data).hexdigest(),
                             "bytes": len(data)}]
    assert auditlog.verify_dir(adir).ok
    with open(os.path.join(out, "audit.jsonl"), "rb") as f:
        forwarded = [json.loads(x) for x in f]
    assert forwarded == recs                            # the SIEM copy matches the official one


def test_replay_refuses_while_another_process_holds_the_audit_dir(tmp_path):
    """Review focus 2: a replay next to a live receiver must not interleave chains."""
    p = replay_pcap(tmp_path)
    held = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="h", actor="a", build="b")
    try:
        with pytest.raises(SystemExit, match="in use by another wd2l process"):
            receiver.main(["--pcap", p, "--out-dir", str(tmp_path / "out"),
                           "--audit-dir", str(tmp_path / "audit"), "--chronyc", "/bin/false"])
    finally:
        held.close()


def test_replay_leaves_the_saved_config_hash_alone(tmp_path):
    state = str(tmp_path / "state.json")
    r, _, a = make(tmp_path, state_path=state, config_sha256="a" * 64)
    feed(r, ev(1), 0)
    r.save_state()
    a.close()
    # A replay (no config hash) shares the state file and saves it again.
    r2, _, a2 = make(tmp_path, state_path=state)
    r2.save_state()
    a2.close()
    with open(state) as f:
        assert json.load(f)["config_sha256"] == "a" * 64
    assert events(a2, "config_changed") == []
    # The live receiver, restarted with the same config, sees no change.
    _, _, a3 = make(tmp_path, state_path=state, config_sha256="a" * 64)
    assert events(a3, "config_changed") == []


def test_replay_main_does_not_touch_config_hash_in_state(tmp_path):
    p = replay_pcap(tmp_path)
    state = str(tmp_path / "state.json")
    r, _, a = make(tmp_path, state_path=state, config_sha256="a" * 64)
    r.save_state()
    a.close()
    adir = str(tmp_path / "audit2")
    receiver.main(["--pcap", p, "--out-dir", str(tmp_path / "out"), "--state", state,
                   "--audit-dir", adir, "--chronyc", "/bin/false"])
    with open(state) as f:
        assert json.load(f)["config_sha256"] == "a" * 64
    assert [x for x in read_audit(adir) if x["event"] == "config_changed"] == []
