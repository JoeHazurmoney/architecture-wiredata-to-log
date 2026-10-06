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
