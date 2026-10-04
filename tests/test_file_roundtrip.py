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


def transfer(tmp_path, events, drop_seq=None, source_seq=False):
    """Send events through the real sender framing and receiver; return received events."""
    sock = FakeSock()
    snd = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=200,
                 extra_fields=(files_to_events.B64_FIELD,), source_seq=source_seq)
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
    assert rows["secure"]["status"] == "INCOMPLETE" and rows["secure"]["missing"] == [1]
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


# ---------------------------------------------------------------- interleaved files

AUDIT = (b"type=SYSCALL msg=audit(1759399201.500:1): a\n"
         b"type=PATH msg=audit(1759399201.500:1): b\n"
         b"type=SYSCALL msg=audit(1759399203.250:2): c\n"
         b"no timestamp here\n"
         b"type=SYSCALL msg=audit(1759399202.000:3): earlier than the line above\n")
MESSAGES = (b"Oct  2 10:00:01 h app: one\n"
            b"Oct  2 10:00:02 h app: two\n"
            b"Oct  2 10:00:04 h app: three\n")


def write_live(d):
    (d / "audit.log").write_bytes(AUDIT)
    (d / "messages").write_bytes(MESSAGES)
    t = 1759399200  # 2025-10-02 10:00:00 UTC: gives the syslog lines their year
    for p in ("audit.log", "messages"):
        os.utime(d / p, (t, t))
    return [str(d / "audit.log"), str(d / "messages")]


def test_line_times():
    assert files_to_events.line_time(b"type=X msg=audit(1759399201.5:9): x", 2025) == 1759399201.5
    assert files_to_events.line_time(b"Oct  2 10:00:01 h app: x", 2025) == 1759399201.0
    assert files_to_events.line_time(b"Oct 12 10:00:01 h app: x", 2025) == 1759399201.0 + 10 * 86400
    assert files_to_events.line_time(b"plain text", 2025) is None
    timed = files_to_events.timed_lines([b"no time", b"Oct  2 10:00:01 h a", b"again none"], 1759399200)
    assert [t for t, _ in timed] == [1759399201.0] * 3


def test_interleave_merges_by_time_and_keeps_each_files_order(tmp_path):
    events, manifest = files_to_events.convert(write_live(tmp_path), host="h", interleave=True)
    order = [(os.path.basename(e["source"]), e["_raw"].split(": ", 1)[-1].strip()) for e in events]
    assert order == [("messages", "one"), ("audit.log", "a"), ("audit.log", "b"),
                     ("messages", "two"), ("audit.log", "c"), ("audit.log", "no timestamp here"),
                     ("audit.log", "earlier than the line above"), ("messages", "three")]
    assert files_to_events.switches(events) == 4
    assert all("first_seq" not in m for m in manifest)
    assert [m["lines"] for m in manifest] == [5, 3]


def test_interleaved_files_rebuild_byte_for_byte(tmp_path):
    src, other = tmp_path / "src", tmp_path / "other"
    src.mkdir()
    other.mkdir()
    # live-style files, plus the CRLF / no-final-newline / invalid-UTF-8 / empty samples
    paths = write_live(src) + [p for p in write_samples(other)
                               if os.path.basename(p) in ("secure", "empty.log")]
    events, manifest = files_to_events.convert(paths, host="h", interleave=True)
    received = transfer(tmp_path, events, source_seq=True)
    rows = rebuild_files.rebuild(manifest, received, str(tmp_path / "rebuilt"))
    assert [r["status"] for r in rows] == ["MATCH"] * len(paths)
    for p in paths:
        assert (tmp_path / "rebuilt" / os.path.basename(p)).read_bytes() == open(p, "rb").read()


def test_interleaved_loss_names_the_file_and_line(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    events, manifest = files_to_events.convert(write_live(src), host="h", interleave=True)
    # stream position 5 is audit.log line 3 ("c")
    received = transfer(tmp_path, events, drop_seq=5, source_seq=True)
    rows = {r["name"]: r for r in rebuild_files.rebuild(manifest, received, str(tmp_path / "rb"))}
    assert rows["audit.log"]["status"] == "INCOMPLETE" and rows["audit.log"]["missing"] == [3]
    assert rows["messages"]["status"] == "MATCH"
    assert "line(s) missing: 3;" in rebuild_files.report(list(rows.values()))


def test_interleaved_without_line_numbers_is_refused(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    events, manifest = files_to_events.convert(write_live(src), host="h", interleave=True)
    received = transfer(tmp_path, events)
    rows = rebuild_files.rebuild(manifest, received, str(tmp_path / "rb"))
    assert {r["status"] for r in rows} == {"NO-LINE-NUMBERS"}


def test_ranges():
    assert rebuild_files.ranges([7, 1, 2, 3, 9, 10]) == "1-3, 7, 9-10"
    assert rebuild_files.ranges([]) == ""


def test_adding_hosts_and_logs_mid_stream_needs_no_change(tmp_path):
    """5 hosts x 2 logs, then a new host with 3 logs and a new log on host1 start mid-stream,
    all in one sender run: every file rebuilds, and a lost line is named exactly."""
    first = [("host%d" % h, p) for h in range(1, 6) for p in ("/var/log/messages", "/var/log/secure")]
    added = [("host6", p) for p in ("/var/log/messages", "/var/log/secure", "/var/log/audit/audit.log")]
    added.append(("host1", "/var/log/cron"))
    lines, events = {}, []
    for rnd in range(40):
        for host, path in first + (added if rnd >= 20 else []):
            line = b"round %d %s %s\n" % (rnd, host.encode(), path.encode())
            lines.setdefault((host, path), []).append(line)
            events.append(files_to_events.line_event(line, path, host, "enclave1", 1790000000 + rnd))
    manifest = [{"path": p, "host": h, "name": h + p.replace("/", "_"), "lines": len(ls),
                 "sha256": hashlib.sha256(b"".join(ls)).hexdigest()}
                for (h, p), ls in lines.items()]

    (tmp_path / "a").mkdir()
    received = transfer(tmp_path / "a", events, source_seq=True)
    rows = rebuild_files.rebuild(manifest, received, str(tmp_path / "a" / "rebuilt"))
    assert len(rows) == 14 and {r["status"] for r in rows} == {"MATCH"}
    for host, path in added:            # a log that starts mid-stream is numbered from 1
        mine = [e for e in received.values() if (e["host"], e["source"]) == (host, path)]
        assert min(mine, key=lambda e: e["wd2l_seq"])["fields"]["wd2l_src_seq"] == 1

    # Lose the new host's third log's line 3: exactly that file and line are named.
    lost = [i for i, e in enumerate(events, 1)
            if (e["host"], e["source"]) == ("host6", "/var/log/audit/audit.log")][2]
    (tmp_path / "b").mkdir()
    received = transfer(tmp_path / "b", events, drop_seq=lost, source_seq=True)
    rows = {r["name"]: r for r in rebuild_files.rebuild(manifest, received, str(tmp_path / "b" / "rebuilt"))}
    bad = rows.pop("host6_var_log_audit_audit.log")
    assert bad["status"] == "INCOMPLETE" and bad["missing"] == [3]
    assert {r["status"] for r in rows.values()} == {"MATCH"}
