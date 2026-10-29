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


def test_rule_9_names_the_receivers_own_downtime_too():
    """#133: events sent while the receiver was down (capture still running) are not_received
    gaps after its restart, and a replay fills them. The rule still fires: a gap is real until
    then."""
    f = ev(gaps_not_received=5)
    assert f.detail == ("5 events lost, no NIC errors or kernel drops: loss on the path, "
                        "or the receiver was down")


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


def test_sender_that_cannot_read_chrony_is_a_time_alarm():
    """Final review I1: the sender's "unavailable" alarms like the receiver's own."""
    good = {"stratum": 3, "offset_ms": 0.1, "synced": True}
    assert fault.time_status(good, {"time_unavailable": True}, None) == \
        ("alarm", "sender: unavailable")
    assert fault.time_status(good, {"time_unavailable": False}, None) == ("ok", None)


import json

from wd2l import wire
from wd2l.receiver import Receiver

from helpers import MemOutput, SlowOutput, build_udp_frame, eth

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
    r.handle_frame(build_udp_frame("02:00:00:00:00:01", "02:00:00:00:00:02",
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


def test_a_start_after_downtime_is_not_a_stale_archive():
    # #187: nothing was sent while it was down, so the newest capture file is old. Before the
    # first packet, packet_age counted from the start, and rule 11 fired until rule 2 outranked it.
    r, out = rxf(archive_probe=lambda: {"archive_age_s": 60.0}, sample_interval=1)
    r.tick(0)
    r.tick(3)
    assert ("amber", "e2-capture", 11) not in faults(out)
    feed(r, evt(1) + hbf(1), 4)                     # packets now, and still no archive written
    r.tick(4)
    assert faults(out)[-1] == ("amber", "e2-capture", 11)


def _sender_back_after_downtime():
    # The archive was last written at 0; the sender is down until 101, between two samples.
    arch = {"archive_age_s": 0.0}
    r, out = rxf(archive_probe=lambda: dict(arch), sample_interval=5)
    feed(r, evt(1) + hbf(1), 0)
    for t in range(0, 101, 5):
        arch["archive_age_s"] = float(t)
        r.tick(t)
    feed(r, evt(2) + hbf(2), 101)
    r.tick(101)
    return r, out, arch


def test_the_first_packet_after_downtime_is_not_judged_by_an_older_sample():
    # The sample at 100 was taken before the packet at 101 was written, so it says nothing.
    r, out, arch = _sender_back_after_downtime()
    arch["archive_age_s"] = 0.2                     # tcpdump wrote it
    r.tick(105)
    assert ("amber", "e2-capture", 11) not in faults(out)


def test_packets_after_downtime_with_no_archive_written_are_a_stale_archive():
    r, out, arch = _sender_back_after_downtime()
    arch["archive_age_s"] = 105.0
    r.tick(105)
    assert faults(out)[-1] == ("amber", "e2-capture", 11)


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


RUN_A, RUN_B, RUN_C = 0xA1, 0xB2, 0xC3


def run_evt(sid, seq):
    return wire.encode_event(sid, seq, json.dumps({"_raw": "e%d" % seq}).encode())


def run_hb(sid, seq, **info):
    return wire.encode_heartbeat(sid, seq, dict({"events_sent": seq, "events_in": seq}, **info))


def test_a_never_seen_run_does_not_hide_the_live_one():
    """Final review I2: run A ends cleanly, run B is never seen, run C sends DATA before its
    first heartbeat. B's placeholder (no heartbeat info) must not be read as the newest run:
    events flow, so there is no rule 5."""
    r, out = rxf()
    feed(r, run_evt(RUN_A, 1) + [run_hb(RUN_A, 1, boot=1, final=True)], 0)
    r.tick(0)
    for t in range(1, 411):
        if t >= 10:
            seq = t - 9
            dgs = run_evt(RUN_C, seq)
            if t >= 11:
                dgs.append(run_hb(RUN_C, seq, boot=3, prev_stream=RUN_B, prev_last_seq=50))
            feed(r, dgs, t)
        r.tick(t)
    assert out.kinds("stream_missing")[0]["stream"] == "%016x" % RUN_B
    assert ("amber", "e1-input", 5) not in faults(out), faults(out)
    assert faults(out)[-1] == ("ok", None, 0)


def test_a_restored_run_does_not_make_a_crash_look_planned():
    """Final review I2, restore variant: run A ended cleanly and was retired; run B's first
    heartbeat brings A back. When B then goes quiet without a final heartbeat, that is rule 3
    (red), not rule 2 (planned stop)."""
    r, out = rxf(stream_retention=20)
    feed(r, run_evt(RUN_A, 1) + [run_hb(RUN_A, 1, boot=1, final=True)], 0)
    for t in range(0, 30):
        r.tick(t)
    assert RUN_A in r.retired
    for t in range(30, 41):
        dgs = run_evt(RUN_B, t - 29)
        if t >= 31:
            dgs.append(run_hb(RUN_B, t - 29, boot=2, prev_stream=RUN_A, prev_last_seq=1))
        feed(r, dgs, t)
        r.tick(t)
    assert RUN_A in r.streams and r.streams[RUN_A].final     # brought back by B's link
    for t in range(41, 50):
        r.tick(t)
    assert faults(out)[-1] == ("red", "e1-sender/boundary", 3), faults(out)


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


def test_sender_time_unavailable_alarms_then_clears():
    """Readable, then unavailable, then readable again: each heartbeat replaces the last one's
    keys, so the alarm clears by itself."""
    r, out = rxf()
    readable = dict(time_synced=True, time_stratum=3, time_offset_ms=0.1)
    for t, info in enumerate((readable, {"time_unavailable": True}, readable)):
        feed(r, hbf(0, **info), t)
        r.tick(t)
    assert [(x["time_status"], x["time_reason"]) for x in out.kinds("time_status")] == [
        ("alarm", "sender: unavailable"), ("ok", None)]


def test_the_final_heartbeats_copies_dont_move_the_clock_offset():
    """#147: the final heartbeat goes out FINAL_COPIES times, unchanged, FINAL_SPACING_S apart.
    Each copy set the offset from the same sender_time, so the last read ~0.1 s: a false "clock
    skew" alarm at every clean stop, up for the whole downtime."""
    from wd2l.sender import FINAL_COPIES, FINAL_SPACING_S
    wall = [1000.0]
    r, out = rxf(record_clock=lambda: wall[0])
    final = hbf(1, sender_time=1000.0, final=True)
    for i in range(FINAL_COPIES):
        wall[0] = 1000.0 + i * FINAL_SPACING_S
        feed(r, final, i * FINAL_SPACING_S)
    r.tick(1)
    assert r.streams[SID].clock_offset == 0.0 and r.last_clock_offset == 0.0
    assert [x for x in out.kinds("time_status") if x["time_status"] == "alarm"] == []
    assert len(out.kinds("stream_end")) == 1
    wall[0] = 1001.0                                   # a new, lower reading still moves it
    feed(r, hbf(2, sender_time=1001.2), 1.5)
    assert r.streams[SID].clock_offset == -0.2


def skew_rx():
    """A receiver whose wall clock the test sets, and a heartbeat sent at s, read at s + offset."""
    wall = [0.0]
    r, out = rxf(record_clock=lambda: wall[0])

    def beat(seq, sent, offset):
        wall[0] = sent + offset
        feed(r, hbf(seq, sender_time=sent), seq)
        r.tick(seq)
    return r, out, beat


def alarms(out):
    return [x["time_reason"] for x in out.kinds("time_status") if x["time_status"] == "alarm"]


def test_a_real_skew_raises_the_time_alarm_from_the_third_reading():
    r, out, beat = skew_rx()
    for seq in range(2):
        beat(seq, 1000.0 + seq, 0.5)
    assert alarms(out) == []                           # fewer than 3 readings: not judged
    beat(2, 1002.0, 0.5)
    assert alarms(out) == ["clock skew 0.500 s > 0.05 s"]


def test_a_delayed_heartbeat_is_not_skew():
    """#157: the receiver's own delay before reading a heartbeat (a busy host, a capture
    backlog) only adds to the reading, so the lowest of the last 10 is the offset."""
    r, out, beat = skew_rx()
    for seq, offset in enumerate((0.236, 0.0, 0.0, 0.068, 0.3, 0.0)):   # start-up lag first
        beat(seq, 1000.0 + seq, offset)
    assert alarms(out) == [] and r.streams[SID].clock_offset == 0.0
    assert r.emit_health(6)["clock_offset_s"] == 0.0


def test_the_lowest_reading_ages_out_of_the_window():
    """A clock that jumps ahead still shows, once the low readings are older than the window."""
    from wd2l import receiver
    r, out, beat = skew_rx()
    beat(0, 1000.0, 0.0)
    for seq in range(1, receiver.OFFSET_WINDOW):
        beat(seq, 1000.0 + seq, 0.2)
    assert alarms(out) == []
    beat(receiver.OFFSET_WINDOW, 1000.0 + receiver.OFFSET_WINDOW, 0.2)
    assert alarms(out) == ["clock skew 0.200 s > 0.05 s"]


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


class PoolTQ:
    def read(self):
        return {"stratum": 5, "offset_ms": 0.2, "synced": True, "source": "pool"}


@pytest.mark.parametrize("kw, status", [({}, "alarm"), ({"max_stratum": 5}, "ok")])
def test_max_stratum_applies_to_both_sides(kw, status):
    # The public NTP pool gave the Pi stratum 4-5 after a reboot: the default 3 suits GPS time.
    r, out = rxf(time_quality=PoolTQ(), **kw)
    feed(r, hbf(0, time_synced=True, time_stratum=5, time_offset_ms=0.2), 0)
    r.tick(0)
    rec = r.emit_health(1)
    assert rec["time_status"] == status
    if status == "alarm":
        assert rec["time_reason"] == "receiver: stratum 5 > 3; sender: stratum 5 > 3"
