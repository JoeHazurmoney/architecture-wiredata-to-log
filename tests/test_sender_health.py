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


from wd2l.reconcile import SetHash
from helpers import read_audit


def test_heartbeat_events_hash_covers_events_up_to_its_seq():
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=500)
    s.send_heartbeat()
    assert last_info(sock)["events_hash"] == "0" * 64
    for i in range(5):
        s.send_event({"_raw": "line %d " % i * 100})    # several pieces each
    s.send_heartbeat()
    h = SetHash()
    for f in [wire.decode(x) for x in sock.sent]:
        if f.type == wire.TYPE_DATA and f.chunk_idx == 0:
            h.add(f.seq, f.digest)
    assert last_info(sock)["events_hash"] == h.hex() and wire.decode(sock.sent[-1]).seq == 5


def test_worst_case_heartbeat_fits_one_packet():
    """Review focus 3: every key at its largest still fits one packet at MTU 1500."""
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0)
    s.link = {"boot": 2 ** 63, "prev_stream": 2 ** 64 - 1, "prev_last_seq": 2 ** 63}
    s.counters = {k: 2 ** 63 for k in s.counters}
    s.events_hash = SetHash(2 ** 256 - 1)
    snap = {"stall_s": 123456789.123, "cpu_pct": 9999.9, "rss_mb": 1048576.5, "clients": 99999,
            "input_backlog_bytes": 2 ** 63, "nic_carrier": False, "nic_tx_packets": 2 ** 63,
            "nic_tx_errors": 2 ** 63, "nic_tx_dropped": 2 ** 63, "time_stratum": 16,
            "time_offset_ms": -123456789.123, "time_synced": False, "audit_ok": False,
            "audit_n": 2 ** 63}
    frame = s._heartbeat_frame(True, snap)
    info = json.loads(wire.decode(frame).payload)
    assert "nic_tx_dropped" in info and info["events_hash"] == "f" * 64
    assert len(frame) <= wire.DEFAULT_MAX_DATAGRAM, len(frame)


def test_reconcile_records(tmp_path):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="h", actor="me", build="b")
    sock = FakeSock()
    s = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, audit=a)
    for i in range(3):
        s.send_event({"_raw": "x%d" % i})
    s.reconcile_record()
    [r] = [x for x in read_audit(a.dir) if x["event"] == "reconcile"]
    assert (r["cut"], r["last_seq"], r["events_sent"], r["sender_hash"]) == \
        (3, 3, 3, s.events_hash.hex())
