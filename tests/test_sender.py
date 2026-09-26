import gzip
import json
import socket
import threading
import time

import pytest

from wd2l import wire
from wd2l.sender import InputServer, Sender

from helpers import FakeSock


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
    assert evts[0] == {"_raw": "one", "host": "h1", "index": "fw"}
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
