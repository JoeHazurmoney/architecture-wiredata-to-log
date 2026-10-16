"""The log lines docs/planned-downtime.md tells operators to look for, as the code writes them
(#143). Each test finds the runbook's wording, then runs the code and matches what it logged, so
rewording either side fails here."""
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time

from wd2l import wire
from wd2l.receiver import Receiver

from helpers import SlowOutput, eth

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SID = 0x1111


def runbook() -> str:
    """planned-downtime.md on one line: it wraps its sentences."""
    with open(os.path.join(REPO, "docs", "planned-downtime.md"), encoding="utf-8") as f:
        return " ".join(f.read().split())


def template(text, holes):
    """The runbook's wording as a regex, each placeholder matching what the code fills in."""
    pattern = re.escape(text)
    for hole, rx in holes.items():
        pattern = pattern.replace(re.escape(hole), rx)
    return re.compile(pattern)


def wait_for(cond, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def free_port():
    with socket.socket() as t:
        t.bind(("127.0.0.1", 0))
        return t.getsockname()[1]


def run_sender(state, events=0, extra=(), run_for=0.0):
    """One sender run with this state file; stderr, after a clean stop (SIGTERM)."""
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    port = free_port()
    p = subprocess.Popen(
        [sys.executable, "-m", "wd2l.sender", "--listen", "127.0.0.1:%d" % port,
         "--dst", "127.0.0.1:%d" % udp.getsockname()[1], "--state", state,
         "--chronyc", "/bin/false", "--heartbeat", "0.1", "--drain-timeout", "0.5"] + list(extra),
        stderr=subprocess.PIPE, env=dict(os.environ, PYTHONPATH=REPO))
    try:
        def listening():
            with socket.socket() as s:
                return p.poll() is not None or s.connect_ex(("127.0.0.1", port)) == 0
        assert wait_for(listening) and p.poll() is None, "the sender stopped at start"
        for i in range(events):
            with socket.create_connection(("127.0.0.1", port)) as c:
                c.sendall(b'{"_raw":"event %d","host":"h"}\n' % i)
        time.sleep(run_for)
        p.send_signal(signal.SIGTERM)
        _, err = p.communicate(timeout=30)
    finally:
        if p.poll() is None:
            p.kill()
        udp.close()
    return err.decode()


def test_the_senders_stop_start_and_minute_lines(tmp_path):
    """Steps 2, 7 and 9: the final line and its two greps, the boot line naming the old run,
    and the per-minute line with last_seq."""
    doc = runbook()
    greps = re.findall(r"journalctl -u wd2l-sender -n 50 -o cat \| grep -o '([^']+)'", doc)
    assert len(greps) == 2 and "# must end in 0" in doc
    boot = "boot <B> after stream <old id> (last seq <N>)"
    assert "The log shows `%s`: the new run names the old one." % boot in doc
    assert "every minute `journalctl -u wd2l-sender` shows `last_seq` climbing" in doc

    state = str(tmp_path / "sender.json")
    first = run_sender(state, events=1, run_for=0.5)
    final = re.search(greps[0], first)
    assert final and final.group(0) == "final: last_seq=1"
    unread = re.search(greps[1], first)
    assert unread and unread.group(0).endswith("0"), unread
    with open(state) as f:
        old = json.load(f)["stream"]

    second = run_sender(state, extra=["--stats-interval", "0.2"], run_for=1.0)
    m = template(boot, {"<B>": r"(\d+)", "<old id>": r"([0-9a-f]{16})", "<N>": r"(\d+)"}).search(second)
    assert m and m.groups() == ("2", old, "1"), second
    assert re.search(r"stream=[0-9a-f]{16} last_seq=\d+ \{", second), second


def test_the_receivers_restart_lines(tmp_path, caplog):
    """Step 6: `loaded state for … streams`, and the warning a clean stop must not give."""
    doc = runbook()
    assert "The log shows `loaded state for … streams` and `capturing on ens256`" in doc
    unclean = "were handed to the output but not confirmed before the last stop"
    assert 'must **not** warn that events "%s"' % unclean in doc
    loaded = template("loaded state for … streams", {"…": r"\d+"})
    caplog.set_level(logging.INFO, logger="wd2l.receiver")
    datagrams = wire.encode_event(SID, 1, json.dumps({"_raw": "e", "host": "h"}).encode())

    def restart(commit):
        state = str(tmp_path / ("state-%s.json" % commit))
        out = SlowOutput()
        r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, state_path=state,
                     health_interval=1e9)
        for d in datagrams:
            r.handle_frame(eth(d), 0)
        if commit:
            out.commit()
        r.save_state()
        caplog.clear()
        Receiver(SlowOutput(), dst_ip="10.255.255.2", dst_port=5514, state_path=state,
                 health_interval=1e9)
        return " ".join(r.getMessage() for r in caplog.records)

    clean = restart(commit=True)
    assert loaded.search(clean) and unclean not in clean, clean
    crashed = restart(commit=False)
    assert loaded.search(crashed) and unclean in crashed, crashed


FAKE_CAPTURE = """
import os, signal, sys
from wd2l import packets, receiver

class Capture:
    rcvbuf = 1 << 30
    down_errors = 0
    def __init__(self, iface, rcvbuf=0):
        pass
    def recv(self):
        os.kill(os.getpid(), signal.SIGTERM)    # one pass of the loop, then a clean stop
        return None
    def kernel_stats(self):
        return 0, 0
    def close(self):
        pass

packets.LiveCapture = Capture
sys.exit(receiver.main(sys.argv[1:]))
"""


def test_the_receiver_names_the_capture_nic(tmp_path):
    """Step 6's `capturing on ens256`, from a live start (the socket faked: CI may not open one)."""
    assert "`capturing on ens256`" in runbook()
    p = subprocess.run(
        [sys.executable, "-c", FAKE_CAPTURE, "--live", "ens256", "--out-dir", str(tmp_path),
         "--chronyc", "/bin/false"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, PYTHONPATH=REPO),
        timeout=60)
    err = p.stderr.decode()
    assert p.returncode == 0, err
    assert template("capturing on <NIC>", {"<NIC>": "ens256"}).search(err), err
