import sys
import time

import pytest

from wd2l import hostinfo

SYNCED = ("A29FC87B,162.159.200.123,3,1791209000.123456789,0.000012345,-0.000001000,"
          "0.000020000,-12.345,-0.001,0.050,0.012345678,0.000987654,1024.5,Normal")
UNSYNCED = ("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,"
            "1.000000000,1.000000000,0.0,Not synchronised")


def prints(text):
    return [sys.executable, "-c", "print(%r)" % text]


def test_parse_synced_chronyc():
    assert hostinfo.parse_chronyc_tracking(SYNCED) == {
        "stratum": 3, "offset_ms": 0.012, "synced": True, "source": "162.159.200.123"}


def test_parse_unsynced_chronyc():
    q = hostinfo.parse_chronyc_tracking(UNSYNCED)
    assert q["synced"] is False and q["stratum"] == 0


def test_parse_rejects_other_output():
    with pytest.raises(ValueError):
        hostinfo.parse_chronyc_tracking("506 Cannot talk to daemon")


def test_time_quality_reads_then_caches_for_a_minute():
    t = [0.0]
    tq = hostinfo.TimeQuality(prints(SYNCED), clock=lambda: t[0])
    assert tq.read()["stratum"] == 3
    tq.cmd = prints(UNSYNCED)
    t[0] = 30
    assert tq.read()["synced"] is True
    t[0] = 61
    assert tq.read()["synced"] is False


def test_missing_or_hanging_chronyc_is_unavailable_not_fatal():
    assert hostinfo.TimeQuality(["/nonexistent/chronyc"]).read()["source"] == "unavailable"
    t0 = time.monotonic()
    q = hostinfo.TimeQuality([sys.executable, "-c", "import time; time.sleep(5)"],
                             timeout=0.3).read()
    assert q["synced"] is None and time.monotonic() - t0 < 3


@pytest.mark.parametrize("q, want", [
    ({"synced": None}, "unavailable"),
    ({"synced": False, "stratum": 0, "offset_ms": 0.0}, "unsynced"),
    ({"synced": True, "stratum": 4, "offset_ms": 0.1}, "stratum 4 > 3"),
    ({"synced": True, "stratum": 3, "offset_ms": -150.0}, "offset -150.0 ms > 100 ms"),
    ({"synced": True, "stratum": 3, "offset_ms": 0.2}, None),
])
def test_time_alarm(q, want):
    assert hostinfo.time_alarm(q) == want


def fake_proc(tmp_path, **files):
    d = tmp_path / "proc"
    d.mkdir()
    for name, text in files.items():
        (d / name).write_text(text)
    return str(d)


def test_actor_for_a_service(tmp_path):
    p = fake_proc(tmp_path, cgroup="0::/system.slice/wd2l-sender.service\n",
                  loginuid="4294967295")
    assert hostinfo.actor(p, uid=0, environ={}) == "uid=0(root) unit=wd2l-sender.service"


def test_actor_for_a_person_via_sudo(tmp_path):
    p = fake_proc(tmp_path, cgroup="0::/user.slice/user-0.slice/session-3.scope\n",
                  loginuid="0")
    assert hostinfo.actor(p, uid=0, environ={"SUDO_USER": "jdoe"}) == \
        "uid=0(root) auid=0(root) via sudo"


def test_signal_actor_while_the_sender_exists_and_after_it_is_gone(tmp_path):
    root = tmp_path / "proc"
    (root / "4242").mkdir(parents=True)
    (root / "4242" / "comm").write_text("kill\n")
    (root / "4242" / "loginuid").write_text("0")
    assert hostinfo.signal_actor(4242, 0, str(root)) == "uid=0(root) pid=4242 comm=kill auid=0(root)"
    assert hostinfo.signal_actor(4343, 0, str(root)) == "uid=0(root) pid=4343"


def test_build_id_prefers_the_environment_then_the_build_file(tmp_path):
    assert hostinfo.build_id({"WD2L_BUILD": "abc"}, str(tmp_path)) == "abc"
    assert hostinfo.build_id({}, str(tmp_path)) == "unknown"
    (tmp_path / "BUILD").write_text("0123456789abcdef\n")
    assert hostinfo.build_id({}, str(tmp_path)) == "0123456789abcdef"


def test_code_hash_changes_with_the_code(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    (tmp_path / "notes.txt").write_text("not code")
    h1 = hostinfo.code_sha256(str(tmp_path))
    (tmp_path / "notes.txt").write_text("still not code")
    assert hostinfo.code_sha256(str(tmp_path)) == h1
    (tmp_path / "a.py").write_text("x = 2\n")
    assert hostinfo.code_sha256(str(tmp_path)) != h1


def test_proc_stats():
    ps = hostinfo.ProcStats()
    sum(range(10 ** 6))
    r = ps.read()
    assert r["cpu_pct"] >= 0 and r["rss_mb"] > 1


def test_code_sha256_missing_directory(tmp_path):
    missing = str(tmp_path / "nonexistent")
    assert hostinfo.code_sha256(missing) == "unavailable"


def test_proc_stats_with_empty_statm(tmp_path):
    statm = tmp_path / "statm"
    statm.write_text("")
    ps = hostinfo.ProcStats(statm=str(statm))
    r = ps.read()
    assert isinstance(r["cpu_pct"], (int, float)) and r["rss_mb"] is None


def test_proc_stats_with_garbage_statm(tmp_path):
    statm = tmp_path / "statm"
    statm.write_text("not a number at all")
    ps = hostinfo.ProcStats(statm=str(statm))
    r = ps.read()
    assert isinstance(r["cpu_pct"], (int, float)) and r["rss_mb"] is None


import os


def fake_nic(root, name, carrier="1", **counters):
    d = root / name
    (d / "statistics").mkdir(parents=True)
    if carrier is not None:
        (d / "carrier").write_text(carrier + "\n")
    (d / "carrier_changes").write_text("3\n")
    for k, v in counters.items():
        (d / "statistics" / k).write_text("%d\n" % v)


def test_nic_stats_reads_carrier_and_counters(tmp_path):
    fake_nic(tmp_path, "cap0", rx_packets=10, rx_crc_errors=2)
    s = hostinfo.nic_stats("cap0", str(tmp_path))
    assert (s["carrier"], s["carrier_changes"], s["rx_packets"], s["rx_crc_errors"]) == (True, 3, 10, 2)
    assert s["tx_errors"] is None


def test_nic_down_or_missing(tmp_path):
    fake_nic(tmp_path, "cap0", carrier=None)     # reading carrier fails while the link is down
    assert hostinfo.nic_stats("cap0", str(tmp_path))["carrier"] is False
    assert hostinfo.nic_stats("nope", str(tmp_path))["carrier"] is None


def test_archive_status_reports_the_newest_file(tmp_path):
    assert hostinfo.archive_status(str(tmp_path)) == {
        "archive_file": None, "archive_age_s": None, "archive_bytes": None}
    old, new = tmp_path / "cap-1.pcap", tmp_path / "cap-2.pcap"
    old.write_bytes(b"x" * 10)
    new.write_bytes(b"y" * 20)
    os.utime(old, (1000, 1000))
    os.utime(new, (2000, 2000))
    assert hostinfo.archive_status(str(tmp_path), now=2030.0) == {
        "archive_file": "cap-2.pcap", "archive_age_s": 30.0, "archive_bytes": 20}
