import base64
import gzip
import json
import random
import socket
import threading
import time

import pytest

from wd2l import wire
from wd2l.sender import InputServer, Sender, _bind_addr

from helpers import FakeSock, strip_times


def sender(**kw):
    s = FakeSock()
    kw.setdefault("rate_pps", 0)
    return Sender(("10.255.255.2", 5514), sock=s, **kw), s


def decode_all(sock):
    return [wire.decode(d) for d in sock.sent]


def test_sequence_and_chunks():
    snd, sock = sender(max_datagram=500)
    assert snd.send_event({"_raw": "a"}) == 1
    assert snd.send_event({"_raw": "b" * 2000}) == 2
    frames = decode_all(sock)
    assert [f.seq for f in frames].count(1) == 1
    assert all(f.seq == 2 for f in frames[1:]) and len(frames) > 3
    assert all(len(d) <= 500 for d in sock.sent)
    assert snd.counters["events_sent"] == 2


def test_heartbeat_carries_counters():
    snd, sock = sender()
    snd.send_event({"_raw": "a"})
    snd.send_heartbeat(final=True)
    f = decode_all(sock)[-1]
    info = json.loads(f.payload)
    assert f.type == wire.TYPE_HEARTBEAT and f.seq == 1
    assert info["events_sent"] == 1 and info["final"] is True


def test_oversize_event_truncated_and_flagged():
    snd, sock = sender(max_event=4096)
    snd.send_event({"_raw": "é" * 10000, "host": "h"})
    frames = decode_all(sock)
    data = b"".join(f.payload for f in frames)
    assert len(data) <= 4096
    evt = wire.parse_event(data)
    assert evt["fields"]["wd2l_truncated"] == 20000
    assert evt["_raw"] and set(evt["_raw"]) == {"é"} and evt["host"] == "h"
    assert snd.counters["truncated"] == 1


def test_oversize_metadata_falls_back_to_minimal_event():
    snd, sock = sender(max_event=1024)
    snd.send_event({"_raw": "r", "host": "h" * 5000, "_time": 5})
    evt = wire.parse_event(b"".join(f.payload for f in decode_all(sock)))
    assert evt == {"_raw": "", "_time": 5, "fields": {"wd2l_truncated": 1}}


def test_pacing_limits_rate():
    snd, sock = sender(rate_pps=500)
    t0 = time.monotonic()
    for _ in range(150):
        snd.send_event({"_raw": "x"})
    # burst allowance is rate/10 = 50, remaining 100 packets need ~0.2 s
    assert time.monotonic() - t0 >= 0.15


@pytest.fixture
def server():
    servers = []

    def start(token=None):
        snd, sock = sender()
        srv = InputServer(("127.0.0.1", 0), snd, token)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return srv, snd, sock

    yield start
    for s in servers:
        s.shutdown()
        s.server_close()


def push(srv, payload: bytes):
    c = socket.create_connection(srv.server_address)
    c.sendall(payload)
    c.close()


def wait_for(cond, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_cribl_tcp_json_with_header(server):
    srv, snd, sock = server()
    lines = [{"authToken": "", "fields": {"index": "fw", "site": "a"}},
             {"_raw": "one", "host": "h1"}, {"_raw": "two", "index": "other"}]
    push(srv, b"\n".join(json.dumps(x).encode() for x in lines) + b"\nnot json\n[1]\n\n")
    assert wait_for(lambda: snd.counters["events_sent"] == 2)
    assert wait_for(lambda: snd.counters["bad_input"] == 2)
    evts = [wire.parse_event(f.payload) for f in decode_all(sock)]
    assert strip_times(evts[0]) == {"_raw": "one", "host": "h1", "index": "fw"}
    assert evts[1]["index"] == "other"


def test_no_header_is_fine_without_token(server):
    srv, snd, sock = server()
    push(srv, b'{"_raw":"a"}\n{"_raw":"b"}\n')
    assert wait_for(lambda: snd.counters["events_sent"] == 2)


def test_token_enforced(server):
    srv, snd, sock = server(token="s3cret")
    push(srv, b'{"authToken":"wrong"}\n{"_raw":"a"}\n')
    push(srv, b'{"_raw":"no header"}\n')
    push(srv, b'{"authToken":"s3cret"}\n{"_raw":"ok"}\n')
    assert wait_for(lambda: snd.counters["events_sent"] == 1)
    time.sleep(0.2)
    assert snd.counters["events_sent"] == 1
    assert wire.parse_event(decode_all(sock)[0].payload)["_raw"] == "ok"


def test_gzip_rejected(server):
    srv, snd, sock = server()
    push(srv, gzip.compress(b'{"_raw":"a"}\n'))
    time.sleep(0.3)
    assert snd.counters["events_sent"] == 0


# ---------------------------------------------------------------- restart chain


def test_state_file_links_runs(tmp_path):
    state = str(tmp_path / "sender.json")
    a, sock_a = sender(state_path=state)
    for _ in range(3):
        a.send_event({"_raw": "x"})
    a.send_heartbeat()
    info = json.loads(decode_all(sock_a)[-1].payload)
    assert info["boot"] == 1 and "prev_stream" not in info

    b, sock_b = sender(state_path=state)   # restart (crash or clean, same thing here)
    b.send_heartbeat()
    info = json.loads(decode_all(sock_b)[-1].payload)
    assert info["boot"] == 2
    assert info["prev_stream"] == a.stream_id and info["prev_last_seq"] == 3


def test_corrupt_state_file_starts_over(tmp_path):
    state = tmp_path / "sender.json"
    state.write_text("{not json")
    s, sock = sender(state_path=str(state))
    assert s.link == {"boot": 1}
    assert json.loads(state.read_text())["boot"] == 1


def test_nothing_is_sent_after_the_final_heartbeat():
    s, sock = sender()
    s.send_event({"_raw": "a"})
    s.send_heartbeat(final=True)
    assert s.send_event({"_raw": "late"}) == 0
    s.send_heartbeat()
    frames = decode_all(sock)
    assert frames[-1].type == wire.TYPE_HEARTBEAT and json.loads(frames[-1].payload)["final"]


class FailingSock:
    def sendto(self, data, addr):
        raise OSError(101, "Network is unreachable")


def test_send_errors_are_counted_and_logged_sparingly(caplog):
    s = Sender(("10.255.255.2", 5514), sock=FailingSock(), rate_pps=0)
    with caplog.at_level("ERROR", logger="wd2l.sender"):
        for _ in range(500):
            s.send_event({"_raw": "x"})
    assert s.counters["send_errors"] == 500 and s.counters["sender_drops"] == 500
    assert len([r for r in caplog.records if "send failed" in r.message]) == 1


def test_header_detection_does_not_swallow_events(server):
    srv, snd, sock = server()
    push(srv, b'{"fields":{"a":1},"host":"h1","sourcetype":"x"}\n{"_raw":"two"}\n')
    assert wait_for(lambda: snd.counters["events_sent"] == 2)


def test_drain_reads_what_already_arrived_then_final_heartbeat_is_last(server):
    srv, snd, sock = server()
    c = socket.create_connection(srv.server_address)
    c.sendall(b"".join(b'{"_raw":"e%d"}\n' % i for i in range(200)))
    srv.shutdown()
    srv.drain()
    snd.send_heartbeat(final=True)
    c.close()
    assert snd.counters["events_sent"] == 200
    last = decode_all(sock)[-1]
    assert last.type == wire.TYPE_HEARTBEAT and last.seq == 200
    assert snd.counters["shutdown_unread_bytes"] == 0


def test_drain_gives_up_on_a_connection_that_never_goes_quiet(server):
    srv, snd, sock = server()
    srv.drain_timeout = 0.5
    c = socket.create_connection(srv.server_address)
    stop = threading.Event()

    def firehose():
        line = b'{"_raw":"%s"}\n' % (b"y" * 500)
        try:
            while not stop.is_set():
                c.sendall(line * 50)
        except OSError:
            pass

    threading.Thread(target=firehose, daemon=True).start()
    assert wait_for(lambda: snd.counters["events_sent"] > 100)
    snd.rate = 2000.0           # slow the sender down so input backs up in the socket
    t0 = time.monotonic()
    srv.drain()
    stop.set()
    assert time.monotonic() - t0 < 3
    assert snd.counters["shutdown_unread_bytes"] > 0
    c.close()


def test_source_seq_numbers_each_file_separately():
    snd, sock = sender(source_seq=True)
    for src in ["/var/log/a", "/var/log/b", "/var/log/a", "/var/log/a", "/var/log/b"]:
        snd.send_event({"_raw": "x", "host": "h1", "source": src})
    snd.send_event({"_raw": "x", "host": "h2", "source": "/var/log/a"})
    got = [wire.parse_event(f.payload)["fields"]["wd2l_src_seq"] for f in decode_all(sock)]
    assert got == [1, 1, 2, 3, 2, 1]


def test_source_seq_is_off_by_default():
    snd, sock = sender()
    snd.send_event({"_raw": "x", "host": "h", "source": "/s"})
    assert "wd2l_src_seq" not in wire.parse_event(decode_all(sock)[0].payload).get("fields", {})


# ---------------------------------------------------------------- send time


def tx_times(sock):
    return [wire.parse_event(f.payload)["fields"]["wd2l_tx_time"] for f in decode_all(sock)]


def test_every_event_carries_its_send_time():
    snd, sock = sender()
    before = time.time()
    snd.send_event({"_raw": "a"})
    snd.send_event({"_raw": "b"})
    got = tx_times(sock)
    assert before - 0.001 <= got[0] <= got[1] <= time.time() + 0.001


def test_send_time_replaces_one_from_the_aggregator():
    snd, sock = sender()
    snd.send_event({"_raw": "a", "wd2l_tx_time": 1.0})
    assert tx_times(sock)[0] > 1.0


def test_send_time_can_be_turned_off():
    snd, sock = sender(tx_time=False)
    snd.send_event({"_raw": "a"})
    assert "fields" not in wire.parse_event(decode_all(sock)[0].payload)


def test_send_time_and_line_number_are_stamped_together():
    snd, sock = sender(source_seq=True)
    snd.send_event({"_raw": "a", "host": "h", "source": "/s"})
    fields = wire.parse_event(decode_all(sock)[0].payload)["fields"]
    assert fields["wd2l_src_seq"] == 1 and "wd2l_tx_time" in fields


# ---------------------------------------------------------------- opaque content


BLOB = base64.b64encode(random.Random(1).randbytes(600)).decode()


def fields_of(sock, i=0):
    return wire.parse_event(decode_all(sock)[i].payload).get("fields", {})


def test_opaque_content_is_flagged_and_counted():
    snd, sock = sender()
    snd.send_event({"_raw": "GET /beacon?d=%s HTTP/1.1" % BLOB})
    snd.send_heartbeat()
    f = fields_of(sock)
    assert f["wd2l_opaque"] == "high-entropy" and f["wd2l_opaque_bytes"] == 600
    assert json.loads(decode_all(sock)[-1].payload)["opaque_events"] == 1


def test_clean_event_is_not_flagged():
    snd, sock = sender()
    snd.send_event({"_raw": "Accepted publickey for admin from 10.0.0.1"})
    assert "wd2l_opaque" not in fields_of(sock) and snd.counters["opaque_events"] == 0


def test_aggregator_cannot_set_the_opaque_flag():
    snd, sock = sender()
    snd.send_event({"_raw": "clean", "wd2l_opaque": "high-entropy", "wd2l_opaque_bytes": 1})
    assert "wd2l_opaque" not in fields_of(sock) and "wd2l_opaque_bytes" not in fields_of(sock)


def test_opaque_check_can_be_turned_off():
    snd, sock = sender(opaque_check=False)
    snd.send_event({"_raw": BLOB})
    assert "wd2l_opaque" not in fields_of(sock)


def test_bind_takes_an_ip_and_an_optional_port():
    assert _bind_addr(None) == (None, 0)
    assert _bind_addr("10.255.255.1") == ("10.255.255.1", 0)
    assert _bind_addr("10.255.255.1:5514") == ("10.255.255.1", 5514)


def test_fixed_source_port_is_used_and_held():
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    snd = Sender(("127.0.0.1", 9), "127.0.0.1", rate_pps=0, bind_port=port)
    try:
        assert snd.sock.getsockname() == ("127.0.0.1", port)
        # A second sender can't take the same source port: it fails at start, not silently.
        with pytest.raises(OSError):
            Sender(("127.0.0.1", 9), "127.0.0.1", rate_pps=0, bind_port=port)
    finally:
        snd.sock.close()


def test_the_per_minute_work_keeps_its_own_timer(caplog):
    """#135: periodic() ran only when the --stats-interval log line was due, so raising it to
    quiet the journal slowed the health records, audit summaries and checks as much."""
    import logging
    from wd2l import sender as sender_mod
    from wd2l.sender import _heartbeat_loop
    assert sender_mod.PERIODIC_EVERY == 60
    snd, sock = sender()
    calls = []
    snd.periodic = lambda: calls.append(1)
    stop = threading.Event()
    caplog.set_level(logging.INFO, logger="wd2l.sender")
    t = threading.Thread(target=_heartbeat_loop, args=(snd, 0.01, stop, 3600),
                         kwargs={"periodic_every": 0.02}, daemon=True)
    t.start()
    try:
        end = time.time() + 5
        while len(calls) < 3 and time.time() < end:
            time.sleep(0.01)
        assert len(calls) >= 3
    finally:
        stop.set()
        t.join(2)
    assert not any("last_seq=" in r.getMessage() for r in caplog.records)   # not due for an hour


def test_an_error_in_the_heartbeat_loop_does_not_stop_heartbeats():
    """Uncaught, one exception ended heartbeats, the records stream and state saves for the
    life of the process, while data kept flowing."""
    from wd2l.sender import _heartbeat_loop
    snd, sock = sender()
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    snd.periodic = flaky
    stop = threading.Event()
    t = threading.Thread(target=_heartbeat_loop, args=(snd, 0.01, stop, 0.01),
                         kwargs={"periodic_every": 0.01}, daemon=True)
    t.start()
    try:
        end = time.time() + 5
        while len(calls) < 3 and time.time() < end:
            time.sleep(0.01)
        assert len(calls) >= 3 and t.is_alive()
    finally:
        stop.set()
        t.join(2)
    beats = [f for f in (wire.decode(d) for d in sock.sent) if f.type == wire.TYPE_HEARTBEAT]
    assert len(beats) >= 3


def test_the_final_heartbeat_goes_out_three_times():
    """The end of a run was one unacknowledged datagram on a lossy one-way link (#74): lost,
    Enclave 2 saw stream_lost instead of stream_end, and wrote no reconcile record until its
    hourly pass. Three identical copies; the receiver acts on the first."""
    snd, sock = sender()
    snd.send_event({"_raw": "x"})
    snd.send_heartbeat(final=True)
    frames = [wire.decode(d) for d in sock.sent]
    finals = [d for d, f in zip(sock.sent, frames)
              if f.type == wire.TYPE_HEARTBEAT and json.loads(f.payload).get("final") is True]
    assert len(finals) == 3 and len(set(finals)) == 1
    assert sock.sent[-3:] == finals                 # still the last frames of the run
    n = len(sock.sent)
    snd.send_heartbeat(final=True)
    snd.send_heartbeat()
    assert len(sock.sent) == n                      # closed: nothing after the final copies
