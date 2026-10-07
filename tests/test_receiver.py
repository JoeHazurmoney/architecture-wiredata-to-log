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


def test_source_port_filter():
    from wd2l import packets
    r, out = rx(src_port=5514)
    feed(r, ev(1), 0)  # helpers.eth sends from port 40000
    assert r.counters["other_packets"] == 1 and "udp from 10.255.255.1:40000" in r.other_reasons
    assert out.events == []
    for dg in ev(2):
        r.handle_frame(packets.build_udp_frame("02:00:00:00:00:01", "02:00:00:00:00:02",
                                               "10.255.255.1", "10.255.255.2", 5514, 5514, dg), 0)
    assert [s for _, s, _ in out.events] == [2]


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


def test_time_of_the_last_heartbeat_survives_restart(tmp_path):
    state = str(tmp_path / "state.json")
    r, _ = rx(state_path=state)
    feed(r, ev(1), 5)
    feed(r, [hb(1)], 7)
    feed(r, ev(2), 9)
    assert (r.streams[SID].last_hb, r.streams[SID].last_seen) == (7, 9)
    r.save_state()
    r2, _ = rx(state_path=state)
    assert r2.streams[SID].last_hb == 7
    with open(state) as f:
        st = json.load(f)
    del st["streams"]["%016x" % SID]["last_hb"]      # a state file from before the key
    with open(state, "w") as f:
        json.dump(st, f)
    r3, _ = rx(state_path=state)
    assert r3.streams[SID].last_hb == 9


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


# ---------------------------------------------------------------- durability across crashes


def srx(state, **kw):
    from helpers import SlowOutput
    out = SlowOutput()
    kw.setdefault("health_interval", 1e9)
    return Receiver(out, dst_ip="10.255.255.2", dst_port=5514, state_path=state, **kw), out


def test_crash_with_unconfirmed_events_reports_them_and_replay_fills(tmp_path):
    state = str(tmp_path / "state.json")
    r, out = srx(state)
    feed(r, sum((ev(s) for s in range(1, 6)), []), 0)
    out.commit()                                   # 1-5 reached the SIEM
    feed(r, sum((ev(s) for s in range(6, 11)), []), 1)
    r.save_state()                                 # 6-10 still in the output's queue
    # crash: no close(), the output's queue is gone

    r2, out2 = srx(state)
    assert gaps(out2) == [(6, 10)]
    assert out2.kinds("gap")[0]["reason"] == "receiver_restart"
    assert r2.counters["uncommitted_at_start"] == 5
    feed(r2, sum((ev(s) for s in range(1, 11)), []), 5)   # archive replay
    assert out2.seqs() == [6, 7, 8, 9, 10]
    assert r2.counters["late_fills"] == 5 and r2.streams[SID].gaps.r == []


def test_crash_with_unconfirmed_out_of_order_events(tmp_path):
    state = str(tmp_path / "state.json")
    r, out = srx(state, gap_window=100)
    feed(r, ev(1) + ev(2), 0)
    out.commit()
    feed(r, ev(4), 1)                               # 3 still missing, 4 unconfirmed
    r.save_state()

    r2, out2 = srx(state, gap_window=100)
    assert gaps(out2) == [(3, 4)]                   # both unresolved at the crash
    feed(r2, ev(3) + ev(4), 2)
    assert out2.seqs() == [3, 4] and r2.streams[SID].gaps.r == []


def test_state_is_resaved_once_output_catches_up(tmp_path):
    state = str(tmp_path / "state.json")
    r, out = srx(state)
    feed(r, ev(1), 0)
    r.tick(0)
    r.save_state()
    assert r.saved_with_pending
    out.commit()
    r.last_save = -10
    r.tick(1)
    assert not r.saved_with_pending
    r2, out2 = srx(state)
    assert gaps(out2) == []


def test_output_dropped_events_become_gaps():
    from helpers import SlowOutput
    out = SlowOutput()
    r = Receiver(out, dst_ip="10.255.255.2", health_interval=1e9, gap_window=1)
    feed(r, ev(1) + ev(2) + ev(3), 0)
    out.fail(SID, 2)
    r.tick(0.5)
    assert gaps(out) == [(2, 2)] and out.kinds("gap")[0]["reason"] == "output_dropped"
    feed(r, ev(2), 1)                               # replay fills it
    assert r.counters["late_fills"] == 1


def test_clean_close_saves_failed_as_uncommitted(tmp_path):
    from helpers import SlowOutput

    class Closing(SlowOutput):
        def close(self):  # like HecOutput.close when the spool is full
            for k in list(self.waiting):
                self.fail(*k)

    state = str(tmp_path / "state.json")
    out = Closing()
    r = Receiver(out, dst_ip="10.255.255.2", state_path=state, health_interval=1e9)
    feed(r, ev(1) + ev(2), 0)
    r.close(1)
    r2, out2 = srx(state)
    assert gaps(out2) == [(1, 2)]


def test_file_output_is_durable_after_flush(tmp_path):
    from wd2l.outputs import FileOutput
    o = FileOutput(str(tmp_path / "o"))
    o.event({"_raw": "x"}, 1, 1)
    assert o.pending() == {1: {1}}
    o.flush()
    assert o.pending() == {}
    o.close()
    o.close()


# ---------------------------------------------------------------- stream linking and retention


def lhb(last_seq, sid, boot, prev=None, prev_last=None, **info):
    link = {"boot": boot}
    if prev is not None:
        link.update(prev_stream=prev, prev_last_seq=prev_last)
    return wire.encode_heartbeat(sid, last_seq, dict({"events_sent": last_seq}, **link, **info))


def test_link_reveals_tail_lost_before_crash():
    r, out = rx(gap_window=1, stream_lost_after=1e9)
    feed(r, ev(1) + ev(2) + [lhb(2, SID, boot=1)], 0)
    # sender crashed after sending 3-4 (lost on the wire); new run says the old one got to 4
    feed(r, [lhb(0, 0x2222, boot=2, prev=SID, prev_last=4)], 1)
    r.tick(1)
    r.tick(3)
    assert gaps(out) == [(3, 4)]
    [lost] = out.kinds("stream_lost")
    assert lost["replaced_by"] == "0000000000002222"
    assert "prev_stream" not in r.streams[0x2222].hb


def test_link_reports_a_run_never_seen():
    r, out = rx(gap_window=1)
    feed(r, ev(1) + [lhb(1, SID, boot=1, final=True)], 0)
    # boot 2 ran entirely during an outage; boot 3 names it as its predecessor
    feed(r, [lhb(0, 0x3333, boot=3, prev=0x2222, prev_last=50)], 10)
    [missing] = out.kinds("stream_missing")
    assert missing["stream"] == "0000000000002222" and missing["last_seq"] == 50
    r.tick(10)
    r.tick(12)
    assert gaps(out) == [(1, 50)]


def test_link_reports_boots_skipped_entirely():
    r, out = rx()
    feed(r, [lhb(0, SID, boot=1)], 0)
    feed(r, [lhb(0, 0x5555, boot=5, prev=0x4444, prev_last=0)], 1)
    recs = out.kinds("stream_missing")
    assert {"first_boot": 2, "last_boot": 3, "runs": 2}.items() <= recs[-1].items()


def test_first_stream_on_a_new_receiver_does_not_flag_history():
    r, out = rx()
    feed(r, [lhb(0, 0x9999, boot=7, prev=0x8888, prev_last=1000)], 0)
    r.tick(0)
    r.tick(10)
    assert out.kinds("stream_missing") == [] and gaps(out) == []


def test_sender_boot_reset_is_reported():
    r, out = rx()
    feed(r, [lhb(0, SID, boot=4)], 0)
    feed(r, [lhb(0, 0x2222, boot=1)], 1)
    assert len(out.kinds("sender_boot_reset")) == 1


def test_finished_streams_retire_but_replays_stay_duplicates(tmp_path):
    state = str(tmp_path / "state.json")
    r, out = rx(state_path=state, stream_retention=100)
    feed(r, ev(1) + ev(2) + [hb(2, final=True)], 0)
    r.tick(50)
    assert SID in r.streams
    r.tick(200)
    assert SID not in r.streams and SID in r.retired
    r.save_state()
    r2, out2 = rx(state_path=state)
    feed(r2, ev(1) + ev(2), 300)                    # an old archive replayed
    assert out2.seqs() == [] and r2.counters["duplicates"] == 2
    assert out2.kinds("stream_start") == []


def test_streams_with_open_gaps_are_kept_past_retention():
    r, out = rx(stream_retention=10, gap_window=1)
    feed(r, ev(1) + ev(3) + [hb(3, final=True)], 0)
    r.tick(2)
    r.tick(100)
    assert SID in r.streams


def test_eviction_prefers_clean_streams_and_reports_open_gaps(monkeypatch):
    import wd2l.receiver as recv
    monkeypatch.setattr(recv, "MAX_STREAMS", 2)
    r, out = rx(gap_window=1)
    feed(r, ev(1, sid=1) + ev(3, sid=1), 0)         # stream 1 will have a gap
    r.tick(0)
    r.tick(2)
    feed(r, ev(1, sid=2), 3)                        # clean
    feed(r, ev(1, sid=3), 4)                        # evicts the clean one, not the gappy one
    assert 1 in r.streams and 2 not in r.streams and out.kinds("stream_evicted") == []
    feed(r, ev(3, sid=3), 5)                        # now stream 3 has a gap too
    r.tick(5)
    r.tick(7)
    feed(r, ev(1, sid=4), 8)                        # no clean stream left: oldest goes, reported
    [ev_rec] = out.kinds("stream_evicted")
    assert ev_rec["stream"] == "%016x" % 1 and ev_rec["open_gap_events"] == 1
    assert 1 in r.retired


def test_steady_clock_ignores_wall_clock_steps(monkeypatch):
    import wd2l.receiver as recv
    wall = [1000.0]
    mono = [50.0]
    monkeypatch.setattr(recv.time, "time", lambda: wall[0])
    monkeypatch.setattr(recv.time, "monotonic", lambda: mono[0])
    clock = recv.steady_clock()
    mono[0] += 5
    wall[0] -= 3600                                  # clock stepped back an hour
    assert clock() == 1005.0


# ---------------------------------------------------------------- arrival time and clock offset


def test_events_carry_their_arrival_time_from_the_wall_clock():
    r, out = rx(record_clock=lambda: 1790000000.1234)
    feed(r, ev(1), 5.0)
    assert out.events[0][2]["fields"]["wd2l_rx_time"] == 1790000000.123


def test_replay_stamps_the_capture_time():
    r, out = rx()                      # no record_clock: archive replay, packet times drive it
    feed(r, ev(1), 1790000123.4567)
    assert out.events[0][2]["fields"]["wd2l_rx_time"] == 1790000123.457


def test_arrival_time_replaces_one_from_the_wire():
    r, out = rx()
    data = json.dumps({"_raw": "x", "fields": {"wd2l_rx_time": 1.0, "site": "a"}}).encode()
    feed(r, wire.encode_event(SID, 1, data), 50.0)
    assert out.events[0][2]["fields"] == {"wd2l_rx_time": 50.0, "site": "a"}


def test_arrival_time_can_be_turned_off():
    r, out = rx(rx_time=False)
    feed(r, ev(1), 5.0)
    assert "fields" not in out.events[0][2]


def test_heartbeat_gives_the_clock_offset():
    r, out = rx(record_clock=lambda: 1000.25)
    feed(r, [hb(0, sender_time=1000.0)], 0)
    rec = r.emit_health(0)
    assert rec["clock_offset_s"] == 0.25
    assert rec["streams"]["%016x" % SID]["clock_offset_s"] == 0.25


def test_health_totals_the_senders_opaque_events():
    r, out = rx()
    feed(r, [hb(0, opaque_events=2)], 0)
    feed(r, [hb(0, sid=0x2222, opaque_events=3)], 0)
    assert r.emit_health(0)["sender_opaque_events"] == 5
