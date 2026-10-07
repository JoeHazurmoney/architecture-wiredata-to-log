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


def test_sender_that_cannot_read_chrony_is_a_time_alarm():
    """Final review I1: the sender's "unavailable" alarms like the receiver's own."""
    good = {"stratum": 3, "offset_ms": 0.1, "synced": True}
    assert fault.time_status(good, {"time_unavailable": True}, None) == \
        ("alarm", "sender: unavailable")
    assert fault.time_status(good, {"time_unavailable": False}, None) == ("ok", None)


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
