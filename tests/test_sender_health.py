import json
import socket
import threading
import time

from wd2l import audit as auditlog
from wd2l import wire
from wd2l.sender import InputServer, Sender

from helpers import FakeSock


class FakeTQ:
    def read(self):
        return {"stratum": 3, "offset_ms": 0.25, "synced": True, "source": "gps"}

    def alarm(self, q=None):
        return None


def fake_nic(root, name):
    d = root / name
    (d / "statistics").mkdir(parents=True)
    (d / "carrier").write_text("1\n")
    for k, v in (("tx_packets", 10), ("tx_errors", 0), ("tx_dropped", 1)):
        (d / "statistics" / k).write_text("%d\n" % v)


def last_info(sock):
    return json.loads(wire.decode(sock.sent[-1]).payload)


def test_heartbeat_carries_the_snapshot(tmp_path):
    fake_nic(tmp_path, "ens224")
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="h", actor="me", build="b")
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, audit=a, time_quality=FakeTQ(),
               egress_iface="ens224")
    s.sysfs = str(tmp_path)
    s.send_event({"_raw": "x"})
    s.count_bad_input()
    s.send_heartbeat()
    info = last_info(sock)
    assert info["events_in"] == 2 and info["events_sent"] == 1
    assert (info["nic_carrier"], info["nic_tx_packets"], info["nic_tx_dropped"]) == (True, 10, 1)
    assert (info["time_stratum"], info["time_offset_ms"], info["time_synced"]) == (3, 0.25, True)
    assert info["audit_ok"] is True and info["audit_n"] == a.n
    assert info["cpu_pct"] >= 0 and info["rss_mb"] > 0 and info["stall_s"] >= 0
    assert s.health_record()["nic_tx_packets"] == 10


def test_pacing_time_is_counted_as_stall():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=500)
    for _ in range(150):
        s.send_event({"_raw": "x"})
    assert s.stall_s >= 0.1


def test_heartbeat_falls_back_if_the_snapshot_would_not_fit():
    """Review focus 3: a heartbeat that can't be sent would break liveness."""
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=600)
    s.snapshot = lambda: {"pad_%02d" % i: 10 ** 18 for i in range(20)}
    s.send_heartbeat()
    info = last_info(sock)
    assert "pad_00" not in info and info["heartbeat_trimmed"] == 1
    assert len(sock.sent[-1]) <= 600


def test_clients_come_from_the_input_server():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    srv = InputServer(("127.0.0.1", 0), s)
    s.input_server = srv
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    c = socket.create_connection(srv.server_address)
    try:
        end = time.time() + 3
        while srv.client_count() != 1 and time.time() < end:
            time.sleep(0.01)
        snap = s.snapshot()
        assert snap["clients"] == 1 and snap["input_backlog_bytes"] >= 0
    finally:
        c.close()
        srv.shutdown()
        srv.server_close()
