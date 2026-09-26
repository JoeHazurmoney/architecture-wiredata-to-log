import json

from wd2l import wire
from wd2l.receiver import RangeSet, Receiver

from helpers import MemOutput, eth

SID = 0x1111


def ev(seq, raw=None, sid=SID, max_dg=wire.DEFAULT_MAX_DATAGRAM):
    data = json.dumps({"_raw": raw or "event %d" % seq, "host": "h"}).encode()
    return wire.encode_event(sid, seq, data, max_dg)


def hb(last_seq, sid=SID, **info):
    return wire.encode_heartbeat(sid, last_seq, dict({"events_sent": last_seq}, **info))


def rx(**kw):
    out = MemOutput()
    kw.setdefault("health_interval", 1e9)
    return Receiver(out, dst_ip="10.255.255.2", dst_port=5514, **kw), out


def feed(r, dgs, now):
    for d in dgs:
        r.handle_frame(eth(d), now)


def gaps(out):
    return [(g["first_seq"], g["last_seq"]) for g in out.kinds("gap")]


def test_in_order_no_gaps():
    r, out = rx()
    for s in range(1, 11):
        feed(r, ev(s), 0)
    feed(r, [hb(10)], 0)
    r.tick(100)
    assert out.seqs() == list(range(1, 11)) and gaps(out) == []


def test_reorder_inside_window_is_not_a_gap():
    r, out = rx(gap_window=2)
    feed(r, ev(1) + ev(3), 0)
    r.tick(1)
    feed(r, ev(2), 1.5)
    r.tick(10)
    assert sorted(out.seqs()) == [1, 2, 3] and gaps(out) == []


def test_gap_declared_after_window_then_late_fill():
    r, out = rx(gap_window=2)
    feed(r, ev(1) + ev(2) + ev(5) + ev(7), 0)
    r.tick(1)
    assert gaps(out) == []
    r.tick(2.5)
    assert gaps(out) == [(3, 4), (6, 6)]
    t = r.streams[SID]
    assert t.gaps.r == [[3, 4], [6, 6]]
    feed(r, ev(4), 3)  # arrives late (e.g. archive replay)
    assert out.seqs()[-1] == 4 and t.gaps.r == [[3, 3], [6, 6]]
    assert r.counters["late_fills"] == 1


def test_duplicates_dropped():
    r, out = rx()
    feed(r, ev(1) + ev(1) + ev(2) + ev(1), 0)
    assert out.seqs() == [1, 2] and r.counters["duplicates"] == 2


def test_heartbeat_reveals_tail_gap():
    r, out = rx(gap_window=2)
    feed(r, ev(1) + ev(2), 0)
    feed(r, [hb(5)], 0.5)
    r.tick(1)
    r.tick(3)
    assert gaps(out) == [(3, 5)]


def test_late_joiner_reports_what_it_missed():
    r, out = rx(gap_window=1)
    feed(r, ev(100), 0)
    r.tick(0)
    r.tick(2)
    assert gaps(out) == [(1, 99)]


def test_new_stream_after_restart_has_no_false_gap():
    r, out = rx(gap_window=1)
    feed(r, ev(1) + ev(2) + [hb(2, final=True)], 0)
    feed(r, ev(1, sid=0x2222) + ev(2, sid=0x2222), 1)
    r.tick(5)
    assert gaps(out) == []
    assert len(out.kinds("stream_start")) == 2 and len(out.kinds("stream_end")) == 1


def test_stream_lost_without_final_heartbeat():
    r, out = rx(stream_lost_after=10, hb_timeout=1e9)
    feed(r, ev(1) + [hb(1)], 0)
    r.tick(5)
    assert out.kinds("stream_lost") == []
    r.tick(11)
    r.tick(12)
    assert len(out.kinds("stream_lost")) == 1


def test_heartbeat_stale_and_restored():
    r, out = rx(hb_timeout=5)
    feed(r, [hb(0)], 0)
    r.tick(3)
    assert out.kinds("heartbeat_stale") == []
    r.tick(6)
    r.tick(7)
    assert len(out.kinds("heartbeat_stale")) == 1
    feed(r, [hb(0)], 8)
    assert len(out.kinds("heartbeat_restored")) == 1


def test_multichunk_out_of_order_and_duplicate_chunks():
    r, out = rx()
    raw = "x" * 5000
    dgs = ev(1, raw, max_dg=600)
    assert len(dgs) > 5
    feed(r, list(reversed(dgs)) + dgs[:2], 0)
    assert len(out.events) == 1 and out.events[0][2]["_raw"] == raw
    assert r.reasm.buffered == 0


def test_missing_chunk_expires_and_becomes_gap():
    r, out = rx(reasm_timeout=1, gap_window=2)
    dgs = ev(2, "y" * 3000, max_dg=600)
    feed(r, ev(1) + dgs[:-1] + ev(3), 0)
    r.tick(1.5)
    assert r.reasm.counters["reasm_expired"] == 1 and r.reasm.buffered == 0
    r.tick(3)
    assert gaps(out) == [(2, 2)]


def test_inconsistent_chunks_dropped():
    r, out = rx()
    a = ev(1, "a" * 3000, max_dg=600)
    b = ev(1, "b" * 3000, max_dg=600)
    feed(r, a[:2] + b[2:], 0)
    assert out.events == [] and r.reasm.counters["reasm_inconsistent"] == 1


def test_memory_cap_evicts_oldest():
    r, out = rx(max_buffer=4000)
    for s in range(1, 5):
        feed(r, ev(s, "z" * 5000, max_dg=1000)[:3], s)
    assert r.reasm.buffered <= 4000 and r.reasm.counters["reasm_evicted"] > 0


def test_oversize_event_len_refused():
    r, out = rx(max_event=2000)
    feed(r, ev(1, "q" * 5000, max_dg=600), 0)
    assert out.events == [] and r.reasm.counters["event_too_big"] > 0


def test_garbage_is_counted_not_fatal():
    r, out = rx()
    r.handle_frame(b"\x00" * 60, 0)
    r.handle_frame(eth(b"not a frame at all, just junk bytes here........................."), 0)
    good = ev(1)[0]
    r.handle_frame(eth(good)[:-3], 0)
    assert r.counters["other_packets"] == 2 and r.counters["bad_frames"] == 1
    bad_json = wire.encode_event(SID, 2, b"{not json")
    feed(r, bad_json, 0)
    assert r.counters["bad_events"] == 1 and out.events == []


def test_other_traffic_is_counted():
    from wd2l import packets
    r, out = rx()
    r.handle_frame(packets.build_udp_frame("02:00:00:00:00:01", "ff:ff:ff:ff:ff:ff",
                                           "10.255.255.1", "10.255.255.3", 68, 67, b"dhcp"), 0)
    assert r.counters["other_packets"] == 1 and "udp 10.255.255.3:67" in r.other_reasons


def test_state_survives_restart(tmp_path):
    state = str(tmp_path / "state.json")
    r, out = rx(state_path=state, gap_window=1)
    feed(r, ev(1) + ev(2) + ev(4), 0)
    r.tick(0)
    r.tick(2)
    r.save_state()
    assert gaps(out) == [(3, 3)]

    r2, out2 = rx(state_path=state, gap_window=1)
    feed(r2, ev(1) + ev(2) + ev(4), 3)  # replayed copies: ignored
    feed(r2, ev(3), 3)                    # the missing one: delivered
    feed(r2, ev(5), 3)
    r2.tick(10)
    assert out2.seqs() == [3, 5] and gaps(out2) == []
    assert r2.streams[SID].gaps.r == []


def test_finish_declares_all_holes():
    r, out = rx(gap_window=100)
    feed(r, ev(1) + ev(3) + [hb(5)], 0)
    r.finish(1)
    assert gaps(out) == [(2, 2), (4, 5)]


def test_health_record_contents():
    r, out = rx(health_interval=10)
    feed(r, ev(1) + [hb(1)], 0)
    r.tick(0)
    r.tick(11)
    [h] = out.kinds("health")
    assert h["events_delivered"] == 1 and h["heartbeats"] == 1
    assert h["streams"]["%016x" % SID]["next_seq"] == 2


def test_rangeset():
    rs = RangeSet()
    rs.add(5, 7)
    rs.add(1, 2)
    rs.add(3, 4)
    assert rs.r == [[1, 7]] and rs.count() == 7
    assert rs.remove(4) and rs.r == [[1, 3], [5, 7]]
    assert not rs.remove(4) and 5 in rs and 4 not in rs
    assert rs.remove(1) and rs.remove(7) and rs.r == [[2, 3], [5, 6]]
