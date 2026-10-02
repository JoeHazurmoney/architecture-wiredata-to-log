"""Whole log files: files -> events -> sender framing -> pcap -> receiver -> rebuilt files.
The rebuilt bytes must hash the same as the originals."""

import hashlib
import json
import os
import sys

import pytest

from wd2l import receiver, wire
from wd2l.sender import Sender

from helpers import FakeSock
from test_end_to_end import write_pcap

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab"))

import files_to_events  # noqa: E402
import rebuild_files  # noqa: E402

SAMPLES = {
    "messages": b"Oct  2 10:00:01 sample-host systemd[1]: Started Session 1.\n"
                b"Oct  2 10:00:02 sample-host kernel: caf\xc3\xa9 \xe2\x9c\x93\n\n"
                b"Oct  2 10:00:03 sample-host app: tab\there\n",
    "secure": b"Oct  2 10:00:04 sample-host sshd[42]: Accepted publickey\r\n"
              b"Oct  2 10:00:05 sample-host sshd[42]: no newline at end",
    "audit.log": b"type=USER_LOGIN msg=audit(1759399205.123:77): pid=42 uid=0 res=success'\n"
                 b"type=BAD bytes=\xff\xfe\x00raw\n",
    "empty.log": b"",
}


def write_samples(d):
    paths = []
    for name, data in SAMPLES.items():
        p = d / name
        p.write_bytes(data)
        paths.append(str(p))
    return paths


def transfer(tmp_path, events, drop_seq=None):
    """Send events through the real sender framing and receiver; return received events."""
    sock = FakeSock()
    snd = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=200,
                 extra_fields=(files_to_events.B64_FIELD,))
    marks = {}
    for e in events:
        start = len(sock.sent)
        seq = snd.send_event(e)
        marks[seq] = (start, len(sock.sent))
    snd.send_heartbeat(final=True)
    drop = set(range(*marks[drop_seq])) if drop_seq else set()
    write_pcap(tmp_path / "x.pcap", sock.sent, lambda i, d: i not in drop)
    receiver.main(["--pcap", str(tmp_path / "x.pcap"), "--out-dir", str(tmp_path / "rx")])
    return rebuild_files.load_events(str(tmp_path / "rx" / "events.jsonl"))


def test_split_lines_round_trips():
    for data in SAMPLES.values():
        assert b"".join(files_to_events.split_lines(data)) == data
    assert files_to_events.split_lines(b"a\r\nb") == [b"a\r\n", b"b"]


def test_files_rebuild_byte_for_byte(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    events, manifest = files_to_events.convert(write_samples(src), host="h")
    assert [m["lines"] for m in manifest] == [4, 2, 2, 0]
    assert sum(1 for e in events if e.get(files_to_events.B64_FIELD)) == 1
    received = transfer(tmp_path, events)
    rows = rebuild_files.rebuild(manifest, received, str(tmp_path / "rebuilt"))
    assert [r["status"] for r in rows] == ["MATCH"] * 4
    for name, data in SAMPLES.items():
        got = (tmp_path / "rebuilt" / name).read_bytes()
        assert got == data
        assert hashlib.sha256(got).hexdigest() == dict((r["name"], r["original"]) for r in rows)[name]


def test_lost_line_makes_file_incomplete_not_a_false_match(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    events, manifest = files_to_events.convert(write_samples(src), host="h")
    secure_first = manifest[1]["first_seq"]
    received = transfer(tmp_path, events, drop_seq=secure_first)
    rows = {r["name"]: r for r in rebuild_files.rebuild(manifest, received, str(tmp_path / "rb"))}
    assert rows["secure"]["status"] == "INCOMPLETE" and rows["secure"]["missing"] == 1
    assert not (tmp_path / "rb" / "secure").exists()
    assert rows["messages"]["status"] == "MATCH" and rows["audit.log"]["status"] == "MATCH"


def test_duplicate_copies_are_ignored(tmp_path):
    p = tmp_path / "events.jsonl"
    e = {"wd2l_seq": 1, "wd2l_stream": "s", "_raw": "a\n", "source": "/x/f"}
    p.write_text(json.dumps(e) + "\n" + json.dumps(e) + "\n")
    got = rebuild_files.load_events(str(p))
    manifest = [{"path": "/x/f", "name": "f", "first_seq": 1, "last_seq": 1,
                 "sha256": hashlib.sha256(b"a\n").hexdigest()}]
    assert rebuild_files.rebuild(manifest, got, str(tmp_path / "o"))[0]["status"] == "MATCH"


def test_oversize_line_is_refused_up_front(tmp_path):
    p = tmp_path / "big.log"
    p.write_bytes(b"x" * 5000 + b"\n")
    with pytest.raises(ValueError, match="too big"):
        files_to_events.convert([str(p)], host="h", max_event=2048)


def test_same_name_twice_is_refused(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    for d in ("a", "b"):
        (tmp_path / d / "messages").write_bytes(b"x\n")
    with pytest.raises(ValueError, match="share a name"):
        files_to_events.convert([str(tmp_path / "a" / "messages"),
                                 str(tmp_path / "b" / "messages")], host="h")


def test_sourcetypes():
    assert files_to_events.sourcetype_for("/var/log/audit/audit.log") == "linux_audit"
    assert files_to_events.sourcetype_for("/var/log/secure") == "linux_secure"
    assert files_to_events.sourcetype_for("/var/log/messages") == "syslog"
    assert files_to_events.sourcetype_for("/tmp/other.txt") == "log_file"
    assert wire.DEFAULT_MAX_EVENT > 1024
