import errno
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time

from wd2l import audit as auditlog
from wd2l import wire
from wd2l.sender import InputServer, Sender

from helpers import FakeSock, read_audit

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CHRONYC = "print('47505300,GPS,3,0,0.000004,0,0,0,0,0,0,0,16,Normal')"


def make(tmp_path, **kw):
    a = auditlog.AuditLog(str(tmp_path / "audit"), "sender", 1, host="logsrv01", actor="me",
                          build="b", forward=False)
    sock = kw.pop("sock", FakeSock())
    kw.setdefault("rate_pps", 0)
    return Sender(("10.255.255.2", 5514), sock=sock, audit=a, **kw), a, sock


def events(a, name):
    return [r for r in read_audit(a.dir) if r["event"] == name]


def wait_for(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_first_start_records_the_missing_state_file(tmp_path):
    _, a, _ = make(tmp_path, state_path=str(tmp_path / "s.json"))
    [r] = events(a, "state_reset")
    assert (r["outcome"], r["reason"], r["path"]) == ("info", "missing", str(tmp_path / "s.json"))


def test_next_start_records_the_state_it_loaded(tmp_path):
    state = str(tmp_path / "s.json")
    s1, a1, _ = make(tmp_path, state_path=state)
    s1.send_heartbeat()
    a1.close()
    with open(state, "rb") as f:
        body = f.read()
    _, a2, _ = make(tmp_path, state_path=state)
    [r] = events(a2, "state_loaded")
    assert r["file_sha256"] == hashlib.sha256(body).hexdigest() and r["boot"] == 1


def test_unreadable_state_is_a_failed_reset(tmp_path):
    state = tmp_path / "s.json"
    state.write_text("{oops")
    _, a, _ = make(tmp_path, state_path=str(state))
    [r] = events(a, "state_reset")
    assert r["outcome"] == "failure" and r["reason"].startswith("unreadable")


def test_config_change_between_runs_is_recorded(tmp_path):
    state = str(tmp_path / "s.json")
    s, a, _ = make(tmp_path, state_path=state, config_sha256="a" * 64)
    a.close()
    s, a, _ = make(tmp_path, state_path=state, config_sha256="a" * 64)
    assert events(a, "config_changed") == []
    a.close()
    _, a, _ = make(tmp_path, state_path=state, config_sha256="b" * 64)
    [r] = events(a, "config_changed")
    assert (r["old_config_sha256"], r["config_sha256"]) == ("a" * 64, "b" * 64)


def test_truncation_and_opaque_content_are_summarised(tmp_path):
    import base64
    s, a, _ = make(tmp_path, max_event=4096)
    s.send_event({"_raw": "x" * 10000, "host": "fw01", "source": "udp:514"})
    s.send_event({"_raw": "x" * 20000, "host": "fw01", "source": "udp:514"})
    s.send_event({"_raw": "blob " + base64.b64encode(os.urandom(900)).decode(), "host": "ws1",
                  "source": "app"})
    s.flush_summaries()
    [t] = events(a, "truncated")
    assert (t["count"], t["host"], t["max_original_bytes"], t["outcome"]) == (2, "fw01", 20000, "info")
    [o] = events(a, "opaque_content")
    assert o["count"] == 1 and o["host"] == "ws1" and o["kinds"]
    assert "x" * 100 not in json.dumps(read_audit(a.dir))      # never any log content


class FailingSock:
    def sendto(self, data, addr):
        raise OSError(errno.EMSGSIZE, "Message too long")


def test_send_failures_are_summarised(tmp_path):
    s, a, _ = make(tmp_path, sock=FailingSock())
    s.send_event({"_raw": "a"})
    s.flush_summaries()
    [r] = events(a, "send_failure")
    assert (r["error"], r["count"], r["outcome"]) == ("EMSGSIZE", 1, "failure")


def noted(s, event):
    """How many times `event` has been noted in the sender's summary so far."""
    with s.summary.lock:
        return sum(v["count"] for (e, _), v in s.summary.items.items() if e == event)


def test_bad_input_and_auth_failures_are_summarised(tmp_path):
    s, a, _ = make(tmp_path)
    srv = InputServer(("127.0.0.1", 0), s, "s3cret")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        for payload in (b'{"authToken":"wrong"}\n', b'{"authToken":"s3cret"}\nnot json\n[1]\n'):
            c = socket.create_connection(srv.server_address)
            c.sendall(payload)
            c.close()
        # Wait on the summary, not the counter: the counter is bumped before the note.
        assert wait_for(lambda: noted(s, "input_rejected") == 2)
        assert wait_for(lambda: noted(s, "auth_failure") == 1)
    finally:
        srv.shutdown()
        srv.server_close()
    s.flush_summaries()
    [af] = events(a, "auth_failure")
    assert (af["client"], af["reason"], af["segment"], af["outcome"]) == \
        ("127.0.0.1", "bad token", "e1-input", "failure")
    got = {r["reason"]: r["count"] for r in events(a, "input_rejected")}
    assert got == {"bad_json": 1, "not_object": 1}


def test_without_audit_nothing_changes(tmp_path):
    s = Sender(("10.255.255.2", 5514), sock=FakeSock(), rate_pps=0)
    s.send_event({"_raw": "a"})
    s.flush_summaries()
    s.periodic()


def free_port():
    with socket.socket() as t:
        t.bind(("127.0.0.1", 0))
        return t.getsockname()[1]


def test_a_sender_run_leaves_a_verifiable_trail(tmp_path):
    chronyc = tmp_path / "chronyc.py"
    chronyc.write_text(CHRONYC)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    port = free_port()
    adir = tmp_path / "audit"
    env = dict(os.environ, PYTHONPATH=REPO)
    p = subprocess.Popen(
        [sys.executable, "-m", "wd2l.sender", "--listen", "127.0.0.1:%d" % port,
         "--dst", "127.0.0.1:%d" % udp.getsockname()[1], "--state", str(tmp_path / "s.json"),
         "--audit-dir", str(adir), "--chronyc", "%s %s" % (sys.executable, chronyc),
         "--log-format", "json", "--heartbeat", "0.2", "--drain-timeout", "0.5"],
        stderr=subprocess.PIPE, env=env)
    try:
        assert wait_for(lambda: socket.socket().connect_ex(("127.0.0.1", port)) == 0)
        c = socket.create_connection(("127.0.0.1", port))
        c.sendall(b'{"_raw":"hello","host":"h1"}\n')
        c.close()

        def got_data():   # the data stream's event (flags 0), not a records-stream frame
            try:
                f = wire.decode(udp.recv(65535))
                return f.type == wire.TYPE_DATA and f.flags == 0
            except socket.timeout:
                return False
        assert wait_for(got_data)
        p.send_signal(signal.SIGUSR1)
        assert wait_for(lambda: any(r["event"] == "debug_toggled" for r in read_audit(adir)))
        p.send_signal(signal.SIGTERM)
        _, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
    recs = read_audit(adir)
    names = [r["event"] for r in recs]
    assert names[:4] == ["start", "config", "time_quality", "state_reset"]
    assert names[-1] == "stop"
    dbg = recs[names.index("debug_toggled")]
    assert "pid=%d" % os.getpid() in dbg["actor"] and dbg["level"] == "DEBUG"
    assert recs[-1]["signal"] == "SIGTERM" and recs[-1]["last_seq"] == 1
    assert recs[0]["config_sha256"] == recs[1]["config_sha256"]
    assert recs[1]["settings"]["state"] == str(tmp_path / "s.json")
    assert recs[2]["outcome"] == "success" and recs[0]["time_quality"]["stratum"] == 3
    assert auditlog.verify_dir(str(adir)).ok
    lines = [json.loads(x) for x in err.decode().splitlines() if x.startswith("{")]
    assert any(x["msg"].startswith("final: last_seq=1 ") and x["segment"] == "e1-sender"
               for x in lines)


def test_a_sender_whose_audit_directory_cant_be_opened_still_sends(tmp_path):
    """It exited at start before: under Restart=always, no events crossed at all."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    port = free_port()
    env = dict(os.environ, PYTHONPATH=REPO)
    p = subprocess.Popen(
        [sys.executable, "-m", "wd2l.sender", "--listen", "127.0.0.1:%d" % port,
         "--dst", "127.0.0.1:%d" % udp.getsockname()[1], "--state", str(tmp_path / "s.json"),
         "--audit-dir", str(blocker / "audit"), "--chronyc", "/bin/false",
         "--log-format", "json", "--heartbeat", "0.2", "--drain-timeout", "0.5"],
        stderr=subprocess.PIPE, env=env)
    seen = {"data": False, "audit_ok": None, "open_failed": False}
    try:
        assert wait_for(lambda: p.poll() is not None
                        or socket.socket().connect_ex(("127.0.0.1", port)) == 0)
        assert p.poll() is None, "the sender stopped at start"
        c = socket.create_connection(("127.0.0.1", port))
        c.sendall(b'{"_raw":"hello","host":"h1"}\n')
        c.close()

        def look():
            try:
                f = wire.decode(udp.recv(65535))
            except socket.timeout:
                return False
            if f.type == wire.TYPE_DATA and not f.flags & wire.FLAG_RECORDS:
                seen["data"] = True
            elif f.type == wire.TYPE_HEARTBEAT and not f.flags & wire.FLAG_RECORDS:
                seen["audit_ok"] = json.loads(f.payload).get("audit_ok")
            elif f.type == wire.TYPE_DATA:
                rec = json.loads(wire.parse_event(f.payload)["_raw"])
                seen["open_failed"] |= rec.get("reason") == "open_failed"
            return seen["data"] and seen["audit_ok"] is False and seen["open_failed"]
        assert wait_for(look), seen
        p.send_signal(signal.SIGTERM)
        _, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
    assert b"final: last_seq=1 " in err
