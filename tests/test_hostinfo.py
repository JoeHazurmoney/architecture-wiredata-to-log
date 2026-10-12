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


def test_archive_status_survives_missing_files_from_pruning(tmp_path, monkeypatch):
    """When glob returns files but one is deleted before stat, the surviving file is returned."""
    real_file = tmp_path / "cap-keep.pcap"
    real_file.write_bytes(b"z" * 15)
    os.utime(real_file, (3000, 3000))
    missing_file = str(tmp_path / "cap-deleted.pcap")

    # Monkeypatch glob.glob to return both real and missing files
    monkeypatch.setattr(hostinfo.glob, "glob", lambda p: [missing_file, str(real_file)])

    result = hostinfo.archive_status(str(tmp_path), now=3030.0)
    assert result == {
        "archive_file": "cap-keep.pcap", "archive_age_s": 30.0, "archive_bytes": 15}


def test_archive_status_all_none_when_all_files_pruned(tmp_path, monkeypatch):
    """When all files listed by glob are deleted before stat, return all-None dict."""
    missing1 = str(tmp_path / "cap-1.pcap")
    missing2 = str(tmp_path / "cap-2.pcap")

    # Monkeypatch glob.glob to return non-existent files
    monkeypatch.setattr(hostinfo.glob, "glob", lambda p: [missing1, missing2])

    result = hostinfo.archive_status(str(tmp_path), now=3000.0)
    assert result == {
        "archive_file": None, "archive_age_s": None, "archive_bytes": None}


import socket

from lab import fake_chronyd

from helpers import chronyd_server

FLOATS = [(0x00000000, 0.0), (0x04800000, 1.0), (0x03000000, -1.0), (0x02800000, 0.5),
          (0xF0800000, 2.0 ** -10)]


def seq_of(request):
    return int.from_bytes(request[8:12], "big")


def test_chrony_float_known_values():
    for raw, value in FLOATS:
        assert hostinfo.chrony_float(raw) == value
        assert fake_chronyd.float_to_chrony(value) == raw


@pytest.mark.parametrize("v", [0.000012345, -0.000001, 0.0137, -12.345, 1024.5, 3.0e-9])
def test_chrony_float_round_trips(v):
    assert hostinfo.chrony_float(fake_chronyd.float_to_chrony(v)) == pytest.approx(v, rel=1e-7)


def test_request_is_padded_to_the_reply_size():
    # chronyd sends the tracking reply up to, not including, its EOR marker: 28 + 76 bytes.
    r = hostinfo.chrony_request(0x01020304)
    assert len(r) == hostinfo.CHRONY_REPLY_SIZE == 104
    assert r[:4] == bytes([6, 1, 0, 0]) and r[4:6] == (33).to_bytes(2, "big")
    assert r[8:12] == bytes([1, 2, 3, 4]) and r[20:] == bytes(84)


# A real reply, from chronyd 4.8 (Fedora 42) with `local stratum 8`, to a request with sequence
# 12345, and `chronyc -c tracking` from the same daemon at the same moment.
REAL_REPLY = bytes.fromhex(
    "060200000021000500000000000000000000303900000000000000007f7f0101000000000000000000000000"
    "000000000000000000080000000000006ac7db27136c8d310000000000000000000000000000000000000000"
    "00000000000000000000000000000000")
REAL_CHRONYC = ("7F7F0101,,8,1791482663.325881137,0.000000000,0.000000000,0.000000000,0.000,0.000,"
                "0.000,0.000000000,0.000000000,0.0,Normal")


def test_a_real_chronyd_reply_reads_as_chronyc_does():
    assert len(REAL_REPLY) == 104
    want = {"stratum": 8, "offset_ms": 0.0, "synced": True, "source": "7F7F0101"}
    assert hostinfo.parse_chronyc_tracking(REAL_CHRONYC) == want
    assert hostinfo.parse_chrony_tracking(REAL_REPLY, 12345) == want


def test_the_fake_chronyd_sends_what_a_real_one_does():
    assert len(fake_chronyd.tracking_reply(12345)) == len(REAL_REPLY)


def test_query_synced_reference_clock():
    with chronyd_server(lambda req: [fake_chronyd.answer(req)]) as addr:
        assert hostinfo.chrony_tracking(addr) == {
            "stratum": 3, "offset_ms": 0.004, "synced": True, "source": "GPS"}


def test_query_unsynced():
    with chronyd_server(lambda req: [fake_chronyd.answer(req, unsynced=True)]) as addr:
        q = hostinfo.chrony_tracking(addr)
    assert q == {"stratum": 0, "offset_ms": 0.0, "synced": False, "source": "00000000"}


def test_query_ntp_source_over_ipv4():
    ip = socket.inet_aton("162.159.200.123")
    with chronyd_server(lambda req: [fake_chronyd.tracking_reply(
            seq_of(req), ref_id=0xA29FC87B, family=1, addr=ip, correction=0.000012345)]) as addr:
        assert hostinfo.chrony_tracking(addr) == {
            "stratum": 3, "offset_ms": 0.012, "synced": True, "source": "162.159.200.123"}


def test_stale_reply_is_skipped():
    def replies(req):
        return [fake_chronyd.tracking_reply(seq_of(req) ^ 1, stratum=9), fake_chronyd.answer(req)]
    with chronyd_server(replies) as addr:
        assert hostinfo.chrony_tracking(addr)["stratum"] == 3


def test_refused_request_is_unavailable_with_the_status():
    with chronyd_server(lambda req: [fake_chronyd.tracking_reply(seq_of(req), status=2)]) as addr:
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 1.0)).read()
    assert q["synced"] is None and q["source"] == "unavailable" and "status 2" in q["error"]


def test_garbage_reply_is_unavailable():
    with chronyd_server(lambda req: [b"hello"]) as addr:
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 1.0)).read()
    assert q["source"] == "unavailable" and "not a chrony reply" in q["error"]


def test_short_tracking_reply_is_unavailable():
    with chronyd_server(lambda req: [fake_chronyd.answer(req)[:60]]) as addr:
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 1.0)).read()
    assert q["source"] == "unavailable" and "short" in q["error"]


def test_no_answer_times_out():
    with chronyd_server(lambda req: []) as addr:
        t0 = time.monotonic()
        q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 0.3)).read()
    assert q["source"] == "unavailable" and time.monotonic() - t0 < 2


def test_nothing_listening_is_unavailable_quickly():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    addr = s.getsockname()
    s.close()
    t0 = time.monotonic()
    q = hostinfo.TimeQuality(query=lambda: hostinfo.chrony_tracking(addr, 2.0)).read()
    assert q["source"] == "unavailable" and time.monotonic() - t0 < 1.0


@pytest.mark.parametrize("s, want", [
    ("127.0.0.1", ("127.0.0.1", 323)), ("127.0.0.1:1323", ("127.0.0.1", 1323)),
    ("localhost:323", ("localhost", 323)), ("[::1]:323", ("::1", 323)), ("[::1]", ("::1", 323)),
    ("::1", ("::1", 323))])
def test_chrony_hostport(s, want):
    assert hostinfo.chrony_hostport(s) == want
    assert hostinfo.chrony_address(s) == s


@pytest.mark.parametrize("s", ["", ":323", "host:", "host:0", "host:70000", "host:abc", "[::1",
                               "[::1]x"])
def test_chrony_hostport_rejects(s):
    with pytest.raises(ValueError):
        hostinfo.chrony_hostport(s)


def test_fake_chronyd_ignores_short_requests_like_chronyd(tmp_path):
    assert fake_chronyd.answer(hostinfo.chrony_request(1)[:20]) is None
    assert fake_chronyd.answer(b"junk") is None
    flag = tmp_path / "clock-bad"
    req = hostinfo.chrony_request(7)
    assert hostinfo.parse_chrony_tracking(fake_chronyd.respond(req, str(flag)), 7)["synced"]
    flag.write_text("")
    assert not hostinfo.parse_chrony_tracking(fake_chronyd.respond(req, str(flag)), 7)["synced"]


def test_time_quality_uses_udp_when_given_an_address():
    with chronyd_server(lambda req: [fake_chronyd.answer(req)]) as (host, port):
        tq = hostinfo.time_quality("/nonexistent/chronyc", "%s:%d" % (host, port))
        assert tq.read()["source"] == "GPS"


def test_time_quality_runs_chronyc_without_an_address(tmp_path):
    script = tmp_path / "chronyc.py"
    script.write_text("print(%r)\n" % SYNCED)
    tq = hostinfo.time_quality("%s %s" % (sys.executable, script), None, every=5.0)
    assert tq.cmd[-2:] == ["-c", "tracking"] and tq.every == 5.0
    assert tq.read()["source"] == "162.159.200.123"


def test_both_parsers_take_chrony_addr():
    from wd2l import receiver, sender
    assert sender.build_parser().parse_args(["--chrony-addr", "127.0.0.1:323"]).chrony_addr \
        == "127.0.0.1:323"
    assert receiver.build_parser().parse_args(["--pcap", "x", "--chrony-addr", "[::1]"]) \
        .chrony_addr == "[::1]"
    assert sender.build_parser().parse_args([]).chrony_addr is None
    for p, base in ((sender.build_parser(), []), (receiver.build_parser(), ["--pcap", "x"])):
        with pytest.raises(SystemExit):
            p.parse_args(base + ["--chrony-addr", "host:notaport"])


def test_max_stratum_option_and_threshold():
    from wd2l import receiver, sender
    assert sender.build_parser().parse_args([]).max_stratum == 3
    assert receiver.build_parser().parse_args(["--pcap", "x", "--max-stratum", "5"]).max_stratum == 5
    for bad in ("0", "16", "x"):
        with pytest.raises(SystemExit):
            sender.build_parser().parse_args(["--max-stratum", bad])
    q = {"synced": True, "stratum": 5, "offset_ms": 0.1}
    tq = hostinfo.time_quality("chronyc", None, max_stratum=5)
    assert tq.max_stratum == 5 and tq.alarm(q) is None
    assert hostinfo.time_quality("chronyc", None).alarm(q) == "stratum 5 > 3"
