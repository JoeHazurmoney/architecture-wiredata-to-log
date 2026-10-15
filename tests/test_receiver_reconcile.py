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


def test_an_event_delivered_again_after_the_output_gave_up_counts_once():
    """#129: the replay operations.md prescribes after output_dropped delivers seq 7 a second
    time. The stream's events_delivered (reconcile) still says 20, so "in_siem should equal
    events_delivered" holds. The global counter stays a count of events handed to the output."""
    s, data, hb = run()
    out = SlowOutput()
    r, _ = rx(out)
    feed(r, data + hb, 0)
    out.fail(s.stream_id, 7)
    out.commit()
    r.tick(1)
    assert r.streams[s.stream_id].delivered == 19
    feed(r, data[6:7], 2)
    out.commit()
    r.tick(3)
    assert r.streams[s.stream_id].delivered == 20 and last(r, s)["balanced"] is True
    assert out.kinds("reconcile")[-1]["events_delivered"] == 20
    assert r.counters["events_delivered"] == 21


def test_reconcile_records_count_the_gap_events_past_the_cap(tmp_path, monkeypatch):
    """#129: an unbalanced stream whose oldest gaps were dropped past the cap says so, so the
    reconciliation alert doesn't take it for one with nothing to explain it."""
    from wd2l import receiver
    monkeypatch.setattr(receiver, "MAX_GAP_RANGES", 1)
    a = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="rx", actor="me", build="b")
    s, data, hb = run()
    r, out = rx(audit=a)
    feed(r, data[:2] + data[3:4] + data[5:] + hb, 0)     # seq 3 and 5 lost: two ranges, cap 1
    r.tick(3)
    h = out.kinds("reconcile")[-1]
    assert (h["balanced"], h["gaps_open"], h["gaps_forgotten"]) == (False, 1, 1)
    rec = [x for x in read_audit(a.dir) if x["event"] == "reconcile"][-1]
    assert (rec["gaps_open"], rec["gaps_forgotten"]) == (1, 1)


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
    assert r2.streams[s.stream_id].delivered == 20      # 11..20 once, not twice (#129)


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


def test_the_stream_end_record_is_saved_so_a_crash_does_not_repeat_it(tmp_path):
    """Final review Minor 19: writing the record changes the state; it must be saved."""
    state = str(tmp_path / "state.json")
    s, data, hb = run()
    r, out = rx(state_path=state)
    feed(r, data + hb, 0)
    r.tick(1)                            # saves the events, then writes the stream-end record
    assert len(out.kinds("reconcile")) == 1 and r.dirty
    r.last_save -= 10                    # past the once-a-second save limit
    r.tick(2)                            # then the receiver crashes while idle
    r2, out2 = rx(state_path=state)
    r2.tick(3)
    assert out2.kinds("reconcile") == []


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


def test_a_restored_retired_stream_is_not_reconciled():
    s, data, hb = run()
    r, out = rx(stream_retention=10)
    feed(r, data + hb, 0)
    r.tick(1)
    r.tick(100)
    assert s.stream_id in r.retired
    feed(r, hb + data[:3], 101)
    r.tick(102)
    t = r.streams[s.stream_id]
    assert t.rc.enabled is False and t.rc.last is None
    assert len(out.kinds("reconcile")) == 1     # the one from before it was retired
    assert r.emit_health(102)["reconcile_unbalanced"] == 0


def _failed_after_snapshot(r, out, s, data, hb):
    feed(r, data + hb, 0)
    out.fail(s.stream_id, 7)
    out.commit()


def test_a_failure_the_output_reports_late_is_not_settled_as_durable():
    s, data, hb = run()
    out = SlowOutput()
    r, _ = rx(out)
    _failed_after_snapshot(r, out, s, data, hb)
    r._reconcile(1)                 # the HEC-thread race: no tick has applied the failure yet
    r.tick(2)
    feed(r, data[6:7], 3)
    out.commit()
    r.tick(4)
    assert last(r, s)["balanced"] is True


def test_save_state_does_not_settle_a_failed_event(tmp_path):
    s, data, hb = run()
    state = str(tmp_path / "state.json")
    out = SlowOutput()
    r, _ = rx(out, state_path=state)
    _failed_after_snapshot(r, out, s, data, hb)
    r.save_state(now=1)
    r2, out2 = rx(state_path=state)
    feed(r2, data + hb, 10)
    r2.tick(11)
    assert last(r2, s)["balanced"] is True


def test_stream_end_record_is_written_when_the_final_cut_was_compared_before_the_end(tmp_path):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "receiver", 2, host="rx", actor="me", build="b")
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    for i in range(20):
        s.send_event({"_raw": "event %d" % i})
    s.send_heartbeat()                 # regular heartbeat already carries seq 20
    n_regular = len(sock.sent)
    s.send_heartbeat(final=True)       # final heartbeat: same seq, no new cut
    r, out = rx(audit=a)
    feed(r, sock.sent[:n_regular], 0)
    r.tick(1)                          # the cut is compared; the stream is not final yet
    assert last(r, s)["balanced"] is True
    feed(r, sock.sent[n_regular:], 2)
    r.tick(3)
    r.tick(4)
    recs = [x for x in read_audit(a.dir) if x["event"] == "reconcile"]
    assert [(x["balanced"], x["cut"]) for x in recs] == [(True, 20)]
    assert [(h["balanced"], h["cut"]) for h in out.kinds("reconcile")] == [(True, 20)]


def finals_of(sent):
    return [i for i, d in enumerate(sent) if wire.decode(d).type == wire.TYPE_HEARTBEAT
            and json.loads(wire.decode(d).payload).get("final") is True]


def test_a_lost_final_heartbeat_still_ends_the_stream_with_its_reconcile_record():
    """#74: under --loss 1 the only final heartbeat was sometimes dropped, and the run ended
    with no stream_end and no reconcile record."""
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    for i in range(20):
        s.send_event({"_raw": "event %d" % i})
    s.send_heartbeat(final=True)
    first = finals_of(sock.sent)[0]
    r, out = rx()
    feed(r, sock.sent[:first] + sock.sent[first + 1:], 0)     # the first copy is lost
    r.tick(1)
    assert len(out.kinds("stream_end")) == 1
    [rec] = out.kinds("reconcile")
    assert (rec["cut"], rec["balanced"]) == (20, True)


def test_every_final_copy_arriving_gives_one_end_and_one_reconcile_record():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    for i in range(5):
        s.send_event({"_raw": "event %d" % i})
    s.send_heartbeat(final=True)
    assert len(finals_of(sock.sent)) == 3
    r, out = rx()
    feed(r, sock.sent, 0)
    r.tick(1)
    r.tick(2)
    assert len(out.kinds("stream_end")) == 1 and len(out.kinds("reconcile")) == 1
