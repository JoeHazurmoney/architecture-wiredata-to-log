import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from wd2l.outputs import HecOutput


class FakeSplunk:
    def __init__(self, port=0):
        self.bodies = []
        self.auth = []
        self.status = 200
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                body = self.rfile.read(n)
                outer.auth.append(self.headers.get("Authorization"))
                if outer.status == 200:
                    outer.bodies.append(body)
                self.send_response(outer.status)
                self.end_headers()
                self.wfile.write(b'{"text":"Success","code":0}')

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", port), H)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def records(self):
        return [json.loads(line) for b in self.bodies for line in b.splitlines() if line]

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def wait_for(cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def splunk():
    s = FakeSplunk()
    yield s
    s.stop()


def hec(url, tmp_path, **kw):
    kw.setdefault("retry_interval", 0.2)
    return HecOutput(url, "tok", str(tmp_path / "spool"), default_index="enclave1", **kw)


def test_event_shape(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path)
    o.event({"_raw": "line", "_time": 12.5, "host": "fw01", "sourcetype": "cisco:asa",
             "fields": {"wd2l_truncated": 9}}, 0xAB, 7)
    o.event({"_raw": "x", "index": "net"}, 0xAB, 8)
    o.health({"type": "gap", "time": 5, "first_seq": 1})
    assert wait_for(lambda: len(splunk.records()) == 3)
    o.close()
    a, b, h = splunk.records()
    assert a == {"event": "line", "time": 12.5, "host": "fw01", "sourcetype": "cisco:asa",
                 "index": "enclave1", "fields": {"wd2l_truncated": 9,
                                                "wd2l_stream": "00000000000000ab", "wd2l_seq": 7}}
    assert b["index"] == "net"
    assert h["sourcetype"] == "wd2l:health" and h["event"]["type"] == "gap" and h["time"] == 5
    assert splunk.auth[0] == "Splunk tok"


def test_outage_spools_then_drains(tmp_path):
    # Grab a free port, then leave it closed so Splunk looks down.
    probe = FakeSplunk()
    port = probe.port
    probe.stop()
    o = hec("http://127.0.0.1:%d" % port, tmp_path)
    for i in range(5):
        o.event({"_raw": "e%d" % i}, 1, i + 1)
    assert wait_for(lambda: o.stats()["hec_spool_files"] >= 1)
    s = FakeSplunk(port)
    try:
        assert wait_for(lambda: len(s.records()) == 5)
        assert wait_for(lambda: o.stats()["hec_spool_files"] == 0)
        o.close()
    finally:
        s.stop()


def test_http_400_goes_to_rejected(splunk, tmp_path):
    splunk.status = 400
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path)
    o.event({"_raw": "bad"}, 1, 1)
    assert wait_for(lambda: o.stats()["hec_rejected_batches"] == 1)
    o.close()
    assert len(os.listdir(tmp_path / "spool" / "rejected")) == 1
    assert o.stats()["hec_spool_files"] == 0


def test_close_spools_unsent(tmp_path):
    probe = FakeSplunk()
    port = probe.port
    probe.stop()
    o = hec("http://127.0.0.1:%d" % port, tmp_path, retry_interval=60)
    for i in range(3):
        o.event({"_raw": "e"}, 1, i)
    o.close()
    spooled = b"".join(open(tmp_path / "spool" / f, "rb").read()
                       for f in os.listdir(tmp_path / "spool") if f.endswith(".ndjson"))
    assert spooled.count(b"\n") == 3


def test_force_index(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path, force_index="imported")
    o.event({"_raw": "x", "index": "net"}, 1, 1)
    o.health({"type": "health"})
    assert wait_for(lambda: len(splunk.records()) == 2)
    o.close()
    assert [r["index"] for r in splunk.records()] == ["imported", "imported"]
