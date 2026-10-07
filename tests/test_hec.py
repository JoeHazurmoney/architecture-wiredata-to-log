import configparser
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from wd2l.outputs import HecOutput
from wd2l.receiver import RX_TIME_FIELD, Receiver
from wd2l.sender import (OPAQUE_BYTES_FIELD, OPAQUE_FIELD, SRC_SEQ_FIELD, TX_TIME_FIELD,
                         Sender)

from helpers import FakeSock, eth


class FakeSplunk:
    def __init__(self, port=0):
        self.bodies = []
        self.auth = []
        self.status = 200
        self.reject_if = None  # callable(line) -> True makes any body holding that line a 400
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                body = self.rfile.read(n)
                outer.auth.append(self.headers.get("Authorization"))
                status = outer.status
                if outer.reject_if and any(outer.reject_if(x) for x in body.splitlines()):
                    status = 400
                if status == 200:
                    outer.bodies.append(body)
                self.send_response(status)
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


def test_wd2l_fields_reach_the_siem_as_indexed_fields(splunk, tmp_path):
    """Sender → receiver → SIEM: the wd2l fields, receive time included, arrive in the HEC
    "fields" object, which the SIEM stores as indexed fields."""
    sock = FakeSock()
    Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0).send_event({"_raw": "line", "host": "h"})
    out = hec("http://127.0.0.1:%d" % splunk.port, tmp_path)
    r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, record_clock=lambda: 1790000000.5)
    for dg in sock.sent:
        r.handle_frame(eth(dg), 0)

    def events():
        return [x for x in splunk.records() if x.get("sourcetype") != "wd2l:health"]
    assert wait_for(lambda: len(events()) == 1)
    out.close()
    fields = events()[0]["fields"]
    assert set(fields) == {TX_TIME_FIELD, RX_TIME_FIELD, "wd2l_stream", "wd2l_seq"}
    assert fields[RX_TIME_FIELD] == 1790000000.5 and fields["wd2l_seq"] == 1


def test_fields_conf_marks_every_wd2l_field_indexed():
    """The example SIEM config has an INDEXED = true stanza for every field wd2l can add."""
    cp = configparser.ConfigParser()
    cp.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy", "receiver",
                         "splunk", "fields.conf"))
    indexed = {s for s in cp.sections() if cp.get(s, "INDEXED", fallback="").lower() == "true"}
    wd2l_fields = {"wd2l_stream", "wd2l_seq", "wd2l_truncated", SRC_SEQ_FIELD, TX_TIME_FIELD,
                   RX_TIME_FIELD, OPAQUE_FIELD, OPAQUE_BYTES_FIELD}
    assert not wd2l_fields - indexed, "not marked indexed: %s" % sorted(wd2l_fields - indexed)


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


def test_spool_bytes_are_reported(tmp_path):
    """Final review Minor 1: the e2-siem panel shows spool bytes, not only files."""
    probe = FakeSplunk()
    port = probe.port
    probe.stop()
    o = hec("http://127.0.0.1:%d" % port, tmp_path, retry_interval=60)
    assert o.stats()["hec_spool_bytes"] == 0
    for i in range(3):
        o.event({"_raw": "e"}, 1, i)
    o.close()
    on_disk = sum(os.path.getsize(tmp_path / "spool" / f)
                  for f in os.listdir(tmp_path / "spool") if f.endswith(".ndjson"))
    assert on_disk > 0 and o.stats()["hec_spool_bytes"] == on_disk


def test_force_index(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path, force_index="imported")
    o.event({"_raw": "x", "index": "net"}, 1, 1)
    o.health({"type": "health"})
    assert wait_for(lambda: len(splunk.records()) == 2)
    o.close()
    assert [r["index"] for r in splunk.records()] == ["imported", "imported"]


def test_400_rejects_only_the_bad_events(splunk, tmp_path):
    splunk.reject_if = lambda line: b'"event":"bad' in line
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path)
    for i in range(6):
        o.event({"_raw": "bad%d" % i if i in (2, 4) else "ok%d" % i}, 1, i + 1)
    assert wait_for(lambda: len(splunk.records()) == 4)
    assert wait_for(lambda: o.pending() == {})
    o.close()
    assert sorted(r["event"] for r in splunk.records()) == ["ok0", "ok1", "ok3", "ok5"]
    rejected = b"".join(open(tmp_path / "spool" / "rejected" / f, "rb").read()
                        for f in os.listdir(tmp_path / "spool" / "rejected"))
    assert rejected.count(b"\n") == 2 and b"bad2" in rejected and b"bad4" in rejected
    assert o.stats()["hec_rejected_events"] == 2


def test_pending_until_posted_or_spooled(tmp_path):
    probe = FakeSplunk()
    port = probe.port
    probe.stop()
    o = hec("http://127.0.0.1:%d" % port, tmp_path, retry_interval=60)
    o.event({"_raw": "a"}, 7, 1)
    o.event({"_raw": "b"}, 7, 2)
    # SIEM down: the batch is spooled to disk, which counts as durable.
    assert wait_for(lambda: o.pending() == {} and o.stats()["hec_spool_files"] == 1)
    assert o.take_failed() == []
    o.close()


def test_queue_overflow_is_reported_not_spooled_per_event(tmp_path):
    probe = FakeSplunk()
    port = probe.port
    probe.stop()
    o = hec("http://127.0.0.1:%d" % port, tmp_path, queue_size=1, retry_interval=60)
    o.stop.set()          # park the consumer so the queue stays full
    o.thread.join(5)
    o.event({"_raw": "kept"}, 3, 1)
    o.event({"_raw": "overflow"}, 3, 2)
    o.health({"type": "gap"})  # health records are never dropped: they go to the spool
    assert o.take_failed() == [(3, 2)]
    assert o.pending() == {3: {1}}
    assert o.stats()["hec_queue_overflow_events"] == 1
    assert o.stats()["hec_spool_files"] == 1
    o.close()
    assert o.pending() == {}


def test_spool_size_is_tracked(tmp_path):
    from wd2l.outputs import Spool
    sp = Spool(str(tmp_path / "s"), max_bytes=10)
    assert sp.write(b"12345") and sp.size() == 5
    assert not sp.write(b"123456")
    name = sp.files()[0]
    sp.replace(name, b"12")
    assert sp.size() == 2
    sp.remove(name)
    assert sp.size() == 0 and sp.files() == []
    assert Spool(str(tmp_path / "s"), 10).size() == 0


from wd2l import audit as auditlog


def test_audit_records_go_to_the_audit_index_as_canonical_text(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path, force_index="everything")
    rec = {"ts": "2026-10-05T14:03:22.500000Z", "event": "gap", "component": "receiver",
           "n": 1, "prev_hash": "0" * 64, "hash": "f" * 64}
    o.audit(rec)
    o.health({"type": "health", "time": 1})
    assert wait_for(lambda: len(splunk.records()) == 2)
    o.close()
    a, h = sorted(splunk.records(), key=lambda r: r["sourcetype"])
    assert (a["sourcetype"], a["index"], a["source"]) == ("wd2l:audit", "wd2l_audit", "wd2l-receiver")
    assert a["event"] == auditlog.canonical(rec).decode() and a["time"] == 1791209002.5
    assert h["index"] == "everything"


def test_data_event_cannot_land_in_the_audit_index(splunk, tmp_path):
    """Review focus 4: an imported event naming the audit index stays with the data."""
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path)
    o.event({"_raw": "x", "index": "wd2l_audit"}, 1, 1)
    assert wait_for(lambda: len(splunk.records()) == 1)
    o.close()
    assert splunk.records()[0]["index"] == "enclave1"
    assert o.stats()["hec_audit_index_refused"] == 1


def test_audit_output_with_its_own_token_and_prefixed_stats(splunk, tmp_path):
    o = HecOutput("http://127.0.0.1:%d" % splunk.port, "audit-tok", str(tmp_path / "sp"),
                  stat_prefix="audit_", retry_interval=0.2)
    o.audit({"ts": "2026-10-05T14:03:22.500000Z", "event": "start", "component": "receiver"})
    assert wait_for(lambda: len(splunk.records()) == 1)
    o.close()
    assert splunk.auth == ["Splunk audit-tok"]
    assert o.stats()["audit_hec_events_sent"] == 1 and "hec_events_sent" not in o.stats()


def test_forwarded_records_keep_their_index_whatever_force_index_says(splunk, tmp_path):
    o = hec("http://127.0.0.1:%d" % splunk.port, tmp_path, force_index="everything",
            health_index="wd2l")
    o.forwarded({"_raw": '{"event":"start"}', "_time": 5, "host": "logsrv01",
                 "source": "wd2l-sender"}, 0x22, 1, "audit")
    o.forwarded({"_raw": '{"type":"health"}', "_time": 6, "host": "logsrv01"}, 0x22, 2, "health")
    assert wait_for(lambda: len(splunk.records()) == 2)
    assert wait_for(lambda: o.pending() == {})
    o.close()
    a, h = sorted(splunk.records(), key=lambda x: x["time"])
    assert (a["index"], a["sourcetype"], a["host"], a["event"]) == \
        ("wd2l_audit", "wd2l:sender:audit", "logsrv01", '{"event":"start"}')
    assert (h["index"], h["sourcetype"]) == ("wd2l", "wd2l:sender:health")
    assert a["fields"] == {"wd2l_stream": "0000000000000022", "wd2l_seq": 1}
