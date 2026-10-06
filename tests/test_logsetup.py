import io
import json
import logging
import os
import subprocess
import sys

from wd2l import logsetup

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def capture(name):
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    h.setFormatter(logsetup.JsonFormatter())
    lg = logging.getLogger(name)
    lg.addHandler(h)
    lg.setLevel(logging.INFO)
    return lg, buf, h


def test_json_lines_keep_the_message_and_add_the_segment():
    lg, buf, h = capture("wd2l.sender")
    try:
        lg.info("final: last_seq=%d %s", 7, "{}")
        lg.warning("GAP", extra={"stream": "00ab", "seq": 5})
    finally:
        lg.removeHandler(h)
    a, b = [json.loads(x) for x in buf.getvalue().splitlines()]
    assert a["msg"] == "final: last_seq=7 {}" and a["segment"] == "e1-sender"
    assert a["level"] == "INFO" and a["ts"].endswith("Z")
    assert (b["stream"], b["seq"]) == ("00ab", 5)


def test_segments_by_logger():
    assert logsetup.segment_for("wd2l.sender.input") == "e1-input"
    assert logsetup.segment_for("wd2l.sender") == "e1-sender"
    assert logsetup.segment_for("wd2l.receiver") == "e2-receiver"
    assert logsetup.segment_for("wd2l.outputs") == "e2-siem"
    assert logsetup.segment_for("wd2l.audit") is None


def test_toggle_debug_flips_the_root_level():
    root = logging.getLogger()
    old = root.level
    try:
        root.setLevel(logging.INFO)
        assert logsetup.toggle_debug() == "DEBUG" and root.level == logging.DEBUG
        assert logsetup.toggle_debug() == "INFO" and root.level == logging.INFO
    finally:
        root.setLevel(old)


class FakeAudit:
    def __init__(self):
        self.written = []

    def write(self, event, outcome="info", **fields):
        self.written.append(dict(fields, event=event, outcome=outcome))


def test_debug_toggle_is_an_audit_event_naming_who_sent_it():
    root = logging.getLogger()
    old = root.level
    a = FakeAudit()
    try:
        root.setLevel(logging.INFO)
        logsetup.debug_toggle_handler(a)(10, os.getpid(), os.getuid())
    finally:
        root.setLevel(old)
    [w] = a.written
    assert w["event"] == "debug_toggled" and w["level"] == "DEBUG"
    assert "pid=%d" % os.getpid() in w["actor"]


SCRIPT = r"""
import os, signal, sys, time
sys.path.insert(0, sys.argv[1])
from wd2l import logsetup
got = []
logsetup.SignalWatcher({signal.SIGUSR1: lambda s, pid, uid: got.append((s, pid, uid))}).start()
os.kill(os.getpid(), signal.SIGUSR1)
for _ in range(500):
    if got:
        break
    time.sleep(0.01)
print(got[0][0] == signal.SIGUSR1, got[0][1] == os.getpid(), got[0][2] == os.getuid())
"""


def test_signal_watcher_knows_who_sent_the_signal():
    r = subprocess.run([sys.executable, "-c", SCRIPT, REPO], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30)
    assert r.stdout.decode().split() == ["True", "True", "True"], r.stderr.decode()
