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
