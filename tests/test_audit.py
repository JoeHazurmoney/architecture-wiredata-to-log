import hashlib
import json

import pytest

from wd2l import audit


def chain(n, start=1, prev=audit.GENESIS):
    """n records chained the way the writer chains them."""
    out = []
    for i in range(start, start + n):
        rec = {"event": "e%d" % i, "n": i, "prev_hash": prev, "ts": "2026-10-05T00:00:00.000000Z"}
        rec["hash"] = audit.record_hash(rec)
        prev = rec["hash"]
        out.append(rec)
    return out


def lines(recs):
    return [audit.canonical(r) + b"\n" for r in recs]


def test_canonical_is_sorted_compact_utf8():
    assert audit.canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode("utf-8")


def test_canonical_refuses_nan():
    with pytest.raises(ValueError):
        audit.canonical({"x": float("nan")})


def test_record_hash_covers_everything_but_the_hash():
    rec = {"n": 1, "prev_hash": audit.GENESIS, "event": "start"}
    want = hashlib.sha256(('{"event":"start","n":1,"prev_hash":"%s"}' % audit.GENESIS)
                          .encode()).hexdigest()
    assert audit.record_hash(rec) == want
    assert audit.record_hash(dict(rec, hash="f" * 64)) == want


def test_timestamps_are_utc_with_microseconds():
    assert audit.utc_ts(1791209002.5) == "2026-10-05T14:03:22.500000Z"
    assert audit.ts_epoch("2026-10-05T14:03:22.500000Z") == 1791209002.5


def test_split_lines_keeps_a_torn_last_piece():
    assert audit.split_lines(b"a\nb\nc") == [b"a\n", b"b\n", b"c"]
    assert audit.split_lines(b"a\n") == [b"a\n"]
    assert audit.split_lines(b"") == []


def test_good_chain_verifies():
    res = audit.verify_lines([("f", lines(chain(5)))])
    assert res.ok and res.records == 5 and (res.first_n, res.last_n) == (1, 5)
    assert res.to_json()["result"] == "ok"


def test_edited_record_is_detected():
    recs = chain(5)
    recs[2]["event"] = "tampered"
    res = audit.verify_lines([("f", lines(recs))])
    assert not res.ok and any("n=3" in p and "edited" in p for p in res.problems)


def test_removed_record_is_detected():
    recs = chain(5)
    del recs[2]
    res = audit.verify_lines([("f", lines(recs))])
    assert any("n jumps from 2 to 4" in p for p in res.problems)


def test_reordered_records_are_detected():
    recs = chain(5)
    recs[1], recs[2] = recs[2], recs[1]
    assert not audit.verify_lines([("f", lines(recs))]).ok


def test_relinked_forgery_is_detected_by_the_next_link():
    recs = chain(4)
    recs[1]["event"] = "forged"
    recs[1]["hash"] = audit.record_hash(recs[1])     # the forger recomputes its own hash
    res = audit.verify_lines([("f", lines(recs))])
    assert any("n=3 does not link to n=2" in p for p in res.problems)


def test_n1_must_start_from_genesis():
    recs = chain(2)
    recs[0]["prev_hash"] = "1" * 64
    recs[0]["hash"] = audit.record_hash(recs[0])
    assert any("genesis" in p for p in audit.verify_lines([("f", lines(recs))]).problems)


def test_chain_may_start_later_after_old_files_are_deleted():
    res = audit.verify_lines([("f", lines(chain(5)[2:]))])
    assert res.ok and res.first_n == 3


def test_torn_last_line_is_reported_not_a_break():
    first = chain(3)
    a = lines(first)
    a[-1] = a[-1][:20]                                  # crash or full disk mid-write
    b = lines(chain(2, start=3, prev=first[1]["hash"]))  # the writer resumes in a new file
    res = audit.verify_lines([("a", a), ("b", b)])
    assert res.ok and res.torn == ["a:3"] and res.last_n == 4


def test_unchained_records_are_counted_not_checked():
    recs = chain(2)
    recs.insert(1, {"event": "gap", "n": None, "prev_hash": None, "hash": None})
    res = audit.verify_lines([("f", lines(recs))])
    assert res.ok and res.unchained == 1


def test_junk_line_is_a_problem():
    res = audit.verify_lines([("f", [b"not json\n"] + lines(chain(1)))])
    assert any("f:1: not JSON" in p for p in res.problems)


def test_upto_stops_at_the_writers_position_and_catches_a_cut_tail():
    recs = chain(5)
    assert audit.verify_lines([("f", lines(recs))], upto=3, upto_hash=recs[2]["hash"]).ok
    cut = audit.verify_lines([("f", lines(recs[:2]))], upto=3)
    assert any("records cut from the end" in p for p in cut.problems)
    wrong = audit.verify_lines([("f", lines(recs))], upto=3, upto_hash="0" * 64)
    assert any("n=3 has hash" in p for p in wrong.problems)


def test_verify_dir_reads_files_in_name_order(tmp_path):
    recs = chain(4)
    (tmp_path / "audit-20261005T000000.000000Z.jsonl").write_bytes(b"".join(lines(recs[:2])))
    (tmp_path / "audit-20261005T010000.000000Z.jsonl").write_bytes(b"".join(lines(recs[2:])))
    (tmp_path / "other.jsonl").write_bytes(b"ignored\n")
    res = audit.verify_dir(str(tmp_path))
    assert res.ok and res.records == 4 and len(res.files) == 2


def test_verify_cli(tmp_path, capsys):
    (tmp_path / "audit-20261005T000000.000000Z.jsonl").write_bytes(b"".join(lines(chain(3))))
    assert audit.main(["verify", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["result"] == "ok" and out["records"] == 3
    assert audit.main(["verify", str(tmp_path), "--upto", "9"]) == 1


def test_nan_record_is_reported_not_crash():
    # A record with NaN in JSON (json.loads accepts NaN, but canonical refuses it)
    recs = chain(2)
    nan_line = b'{"n":2,"prev_hash":"' + recs[0]["hash"].encode() + b'","hash":"x","v":NaN}\n'
    res = audit.verify_lines([("f", lines(recs[:1]) + [nan_line])])
    assert not res.ok and any("n=2" in p and "can't be hashed" in p for p in res.problems)
    # should complete normally and report a problem, not crash


def test_deeply_nested_json_is_reported_not_crash():
    # Very deeply nested JSON causes RecursionError
    deep = b"[" * 100000 + b"]" * 100000 + b"\n"
    res = audit.verify_lines([("f", [deep])])
    assert any("f:1: not JSON" in p for p in res.problems)
    # should complete normally and report as junk, not crash


import collections
import errno
import os
import re
import time

import wd2l
from wd2l import hostinfo

from helpers import read_audit

Usage = collections.namedtuple("Usage", "total used free")


def new_log(tmp_path, **kw):
    kw.setdefault("host", "logsrv01")
    kw.setdefault("actor", "uid=987(wd2l) unit=wd2l-sender.service")
    kw.setdefault("build", "abc123")
    return audit.AuditLog(str(tmp_path / "a"), "sender", 1, **kw)


class FakeTQ:
    def __init__(self):
        self.q = {"stratum": 3, "offset_ms": 0.2, "synced": True, "source": "gps"}

    def read(self):
        return dict(self.q)

    def alarm(self, q=None):
        return hostinfo.time_alarm(self.read() if q is None else q)


def test_records_carry_the_common_fields_and_chain(tmp_path):
    a = new_log(tmp_path, clock=lambda: 1791209002.5, time_quality=FakeTQ())
    r1 = a.write("start", "success", pid=42, absent=None)
    r2 = a.write("config", settings={"listen": "127.0.0.1:10070"})
    assert r1["ts"] == "2026-10-05T14:03:22.500000Z"
    assert {k: r1[k] for k in ("host", "enclave", "component", "segment", "version", "build",
                               "event", "outcome", "actor", "pid")} == {
        "host": "logsrv01", "enclave": 1, "component": "sender", "segment": "e1-sender",
        "version": wd2l.__version__, "build": "abc123", "event": "start", "outcome": "success",
        "actor": "uid=987(wd2l) unit=wd2l-sender.service", "pid": 42}
    assert r1["time_quality"] == {"stratum": 3, "offset_ms": 0.2, "synced": True, "source": "gps"}
    assert "absent" not in r1
    assert (r1["n"], r1["prev_hash"], r2["n"], r2["prev_hash"]) == (1, audit.GENESIS, 2, r1["hash"])
    assert read_audit(tmp_path / "a") == [r1, r2]
    a.close()
    assert audit.verify_dir(str(tmp_path / "a")).ok


def test_one_canonical_line_per_record_in_a_0640_file(tmp_path):
    a = new_log(tmp_path)
    r = a.write("start", "success")
    [path] = audit.audit_files(a.dir)
    assert re.fullmatch(r"audit-\d{8}T\d{6}\.\d{6}Z\.jsonl", os.path.basename(path))
    assert os.stat(path).st_mode & 0o777 == 0o640
    with open(path, "rb") as f:
        assert f.read() == audit.canonical(r) + b"\n"


def test_bad_outcome_is_refused(tmp_path):
    with pytest.raises(ValueError):
        new_log(tmp_path).write("start", "maybe")


def test_restart_continues_the_chain_in_the_same_file(tmp_path):
    a = new_log(tmp_path)
    r1 = a.write("start", "success")
    a.close()
    b = new_log(tmp_path)
    r2 = b.write("start", "success")
    assert (r2["n"], r2["prev_hash"]) == (2, r1["hash"])
    assert len(audit.audit_files(b.dir)) == 1


def test_a_full_file_continues_the_chain_in_a_new_file(tmp_path):
    a = new_log(tmp_path, max_bytes=900)
    for i in range(6):
        a.write("gap", "failure", count=i)
    files = audit.audit_files(a.dir)
    assert len(files) >= 2 and all(os.path.getsize(f) <= 900 for f in files)
    res = audit.verify_dir(a.dir)
    assert res.ok and res.records == 6


def test_new_files_sort_after_old_ones_even_if_the_clock_goes_back(tmp_path):
    t = [1791209002.5]
    a = new_log(tmp_path, max_bytes=500, clock=lambda: t[0])
    a.write("start", "success")
    t[0] -= 3600
    for _ in range(3):
        a.write("gap", "failure")
    assert audit.verify_dir(a.dir).ok


def test_a_second_writer_is_locked_out(tmp_path):
    a = new_log(tmp_path)
    with pytest.raises(audit.AuditLocked, match="in use by another wd2l process"):
        new_log(tmp_path)
    a.close()
    new_log(tmp_path).close()


def test_torn_last_line_starts_a_new_file_and_is_recorded(tmp_path):
    a = new_log(tmp_path)
    r1 = a.write("start", "success")
    a.close()
    [path] = audit.audit_files(str(tmp_path / "a"))
    with open(path, "ab") as f:
        f.write(b'{"event":"gap","n":2,"pre')          # power lost mid-write
    b = new_log(tmp_path)
    note = read_audit(tmp_path / "a")[-1]
    assert note["event"] == "audit_failure" and note["reason"] == "torn_write"
    assert (note["n"], note["prev_hash"]) == (2, r1["hash"])
    assert len(audit.audit_files(b.dir)) == 2
    res = audit.verify_dir(b.dir)
    assert res.ok and len(res.torn) == 1


def test_write_failure_keeps_going_and_chain_still_verifies(tmp_path):
    """Review focus 1: a full disk must not stop anything or break the chain."""
    a = new_log(tmp_path)
    a.write("start", "success")
    real = a._write

    def full(fd, data):
        raise OSError(errno.ENOSPC, "No space left on device")
    a._write = full
    r2 = a.write("gap", "failure", count=3)
    r3 = a.write("gap", "failure", count=4)
    assert r2["n"] is None and r2["hash"] is None and r3["n"] is None
    assert a.status()["audit_ok"] is False and a.missed == 2
    a._write = real
    r4 = a.write("stop", "success")
    assert a.ok and r4["n"] == 3
    on_disk = read_audit(tmp_path / "a")
    assert [r["event"] for r in on_disk] == ["start", "audit_failure", "stop"]
    assert on_disk[1]["reason"] == "recovered" and on_disk[1]["missed"] == 2
    assert [(r["event"], r.get("reason")) for r in a.take_outbox()] == [
        ("start", None), ("audit_failure", "write_failed"), ("gap", None), ("gap", None),
        ("audit_failure", "recovered"), ("stop", None)]
    assert audit.verify_dir(a.dir).ok


def test_a_short_write_moves_on_to_a_new_file(tmp_path):
    a = new_log(tmp_path)
    a.write("start", "success")
    real = a._write
    a._write = lambda fd, data: real(fd, data[:10])     # the disk filled part way
    assert a.write("gap", "failure")["n"] is None
    a._write = real
    a.write("stop", "success")
    res = audit.verify_dir(a.dir)
    assert res.ok and len(res.torn) == 1 and res.last_n == 3
    assert len(audit.audit_files(a.dir)) == 2


def test_fsync_failure_keeps_the_record_but_flags_the_trail(tmp_path):
    a = new_log(tmp_path)

    def bad_fsync(fd):
        raise OSError(errno.EIO, "I/O error")
    a._fsync = bad_fsync
    assert a.write("start", "success")["n"] == 1
    assert not a.ok
    a._fsync = os.fsync
    a.write("stop", "success")
    assert [r["event"] for r in read_audit(a.dir)] == ["start", "audit_failure", "stop"]
    assert a.ok


def test_outbox_is_bounded_and_off_when_not_forwarding(tmp_path):
    a = new_log(tmp_path, outbox_max=2)
    for _ in range(3):
        a.write("gap", "failure")
    assert len(a.take_outbox()) == 2 and a.outbox_dropped == 1 and a.take_outbox() == []
    a.close()
    b = new_log(tmp_path, forward=False)
    b.write("gap", "failure")
    assert b.take_outbox() == []


def test_low_space_is_reported_once_and_clears(tmp_path):
    a = new_log(tmp_path, min_free_bytes=1000)
    free = [10 ** 9]
    a._disk_usage = lambda path: Usage(0, 0, free[0])
    a.check_space()
    free[0] = 10
    a.check_space()
    a.check_space()
    assert a.status()["audit_ok"] is False
    free[0] = 10 ** 9
    a.check_space()
    # Below the floor nothing goes in the file (final review I4): low_space is forwarded only.
    notes = [(r["reason"], r["outcome"]) for r in a.take_outbox() if r["event"] == "audit_failure"]
    assert notes == [("low_space", "failure"), ("recovered", "info"), ("space_ok", "info")]
    assert a.status()["audit_ok"] is True


def test_below_the_floor_every_write_fails_until_space_is_back(tmp_path):
    """Final review I4: the floor is kept, so the state file, spool and archive keep their room."""
    a = new_log(tmp_path, min_free_bytes=1000)
    free = [10 ** 9]
    a._disk_usage = lambda path: Usage(0, 0, free[0])
    a.write("start", "success")
    a.check_space()
    free[0] = 10
    a.check_space()
    r = a.write("gap", "failure", count=3)
    assert r["n"] is None and a.missed == 2 and a.status()["audit_ok"] is False
    free[0] = 10 ** 9
    a.check_space()
    a.write("stop", "success")
    on_disk = read_audit(a.dir)
    assert [(x["event"], x.get("reason")) for x in on_disk] == [
        ("start", None), ("audit_failure", "recovered"), ("audit_failure", "space_ok"),
        ("stop", None)]
    assert on_disk[1]["missed"] == 2 and "floor" in on_disk[1]["error"]
    assert len(audit.audit_files(a.dir)) == 2           # writing resumed in a new file
    forwarded = [(x["event"], x.get("reason"), x["n"]) for x in a.take_outbox()]
    assert ("audit_failure", "low_space", None) in forwarded and ("gap", None, None) in forwarded
    assert not any(x[1] == "write_failed" for x in forwarded)
    assert audit.verify_dir(a.dir).ok


def test_time_quality_is_recorded_first_and_on_each_change(tmp_path):
    tq = FakeTQ()
    a = new_log(tmp_path, time_quality=tq)
    a.check_time()
    a.check_time()
    tq.q = {"stratum": 0, "offset_ms": 0.0, "synced": False, "source": ""}
    a.check_time()
    got = [(r["outcome"], r["reason"]) for r in read_audit(a.dir) if r["event"] == "time_quality"]
    assert got == [("success", "ok"), ("failure", "unsynced")]


def test_self_check_passes_on_a_good_chain(tmp_path):
    a = new_log(tmp_path)
    for e in ("start", "config", "state_loaded"):
        a.write(e)
    assert a.status()["audit_verify"] is None
    a.start_verify()
    res = a.poll_verify(wait=True)
    assert res["result"] == "ok" and a.status()["audit_verify"] == "ok"
    last = read_audit(a.dir)[-1]
    assert (last["event"], last["outcome"], last["records"], last["upto"]) == \
        ("audit_verify", "success", 3, 3)


def test_self_check_fails_on_an_edited_file(tmp_path):
    a = new_log(tmp_path)
    for e in ("start", "config", "stop"):
        a.write(e)
    a.close()
    [path] = audit.audit_files(str(tmp_path / "a"))
    with open(path, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:
        f.write(data.replace(b'"event":"config"', b'"event":"c0nfig"'))
    b = new_log(tmp_path)
    b.start_verify()
    assert b.poll_verify(wait=True)["result"] == "failed"
    assert b.status()["audit_verify"] == "failed"
    last = read_audit(b.dir)[-1]
    assert last["event"] == "audit_verify" and last["outcome"] == "failure"
    assert any("edited" in p for p in last["problems"])


def test_self_check_runs_at_start_then_daily(tmp_path):
    t = [1000.0]
    a = new_log(tmp_path, clock=lambda: t[0])
    a.write("start", "success")
    a.maybe_verify()
    assert a.verify_proc is not None
    a.poll_verify(wait=True)
    t[0] += 3600
    a.maybe_verify()
    assert a.verify_proc is None
    t[0] += 86400
    a.maybe_verify()
    assert a.verify_proc is not None
    a.close()


def test_self_check_output_does_not_block_the_child(tmp_path):
    """Final review I4(c): over 64 KiB of output (one line per file) must not wedge the child
    while the owner only polls."""
    d = tmp_path / "a"
    d.mkdir()
    for i, rec in enumerate(chain(2000)):
        name = "audit-20261005T%02d%02d%02d.000000Z.jsonl" % (i // 3600, i // 60 % 60, i % 60)
        (d / name).write_bytes(audit.canonical(rec) + b"\n")
    a = new_log(tmp_path)
    assert a.n == 2000
    a.start_verify()
    end = time.time() + 60
    res = None
    while res is None and time.time() < end:
        res = a.poll_verify()
        time.sleep(0.05)
    assert res is not None and res["result"] == "ok" and len(res["files"]) == 2000
    assert a.status()["audit_verify"] == "ok"
    a.close()


def test_self_check_that_cannot_start_is_recorded_not_raised(tmp_path, monkeypatch):
    """Final review I4(c), Minor 8: a fork failure must not stop the receiver."""
    a = new_log(tmp_path)
    a.write("start", "success")

    def no_fork(*args, **kw):
        raise OSError(errno.ENOMEM, "Cannot allocate memory")
    monkeypatch.setattr(audit.subprocess, "Popen", no_fork)
    a.maybe_verify()
    assert a.verify_proc is None and a.status()["audit_verify"] == "failed"
    last = read_audit(a.dir)[-1]
    assert (last["event"], last["outcome"], last["reason"]) == \
        ("audit_verify", "failure", "could not start")
    assert "Cannot allocate memory" in last["error"]


class HungChild:
    def __init__(self, *args, **kw):
        self.killed = False

    def poll(self):
        return -9 if self.killed else None

    def kill(self):
        self.killed = True

    def terminate(self):
        self.killed = True

    def wait(self, timeout=None):
        return -9


def test_self_check_still_running_after_six_hours_is_killed(tmp_path, monkeypatch):
    """Final review I4(c), Minor 8: a hung child must not leave audit_verify at its old value."""
    t = [1000.0]
    a = new_log(tmp_path, clock=lambda: t[0])
    a.write("start", "success")
    monkeypatch.setattr(audit.subprocess, "Popen", HungChild)
    a.maybe_verify()
    child = a.verify_proc
    t[0] += 6 * 3600 - 1
    a.maybe_verify()
    assert a.verify_proc is child and not child.killed
    t[0] += 2
    a.maybe_verify()
    assert child.killed and a.verify_proc is None and a.status()["audit_verify"] == "failed"
    last = read_audit(a.dir)[-1]
    assert (last["event"], last["outcome"], last["reason"]) == ("audit_verify", "failure", "timeout")


def test_values_that_cannot_be_json_are_made_safe_not_raised(tmp_path):
    import pathlib
    a = new_log(tmp_path)
    r = a.write("gap", "failure", ratio=float("nan"), raw=b"\x00\x01", where=pathlib.Path("/x"),
                tags={"b", "a"}, nested={1: (float("inf"), 2)})
    assert r["n"] == 1 and a.ok
    assert (r["ratio"], r["raw"], r["where"], r["tags"], r["nested"]) == (
        None, r"b'\x00\x01'", str(pathlib.Path("/x")), ["a", "b"], {"1": [None, 2]})
    assert read_audit(a.dir) == [r] and a.take_outbox() == [r]
    assert audit.verify_dir(a.dir).ok


def test_a_bad_time_quality_reading_does_not_stop_write(tmp_path):
    tq = FakeTQ()
    tq.q = {"stratum": 3, "offset_ms": float("inf"), "synced": True, "source": "gps"}
    a = new_log(tmp_path, time_quality=tq)
    r = a.write("start", "success")
    assert r["n"] == 1 and r["time_quality"]["offset_ms"] is None
    assert audit.verify_dir(a.dir).ok


import threading


def test_summarizer_counts_per_key_and_keeps_extremes():
    s = audit.Summarizer()
    s.note("truncated", {"host": "h1", "source": "s"}, max_original_bytes=300000)
    s.note("truncated", {"host": "h1", "source": "s"}, max_original_bytes=900000)
    s.note("truncated", {"host": "h2", "source": "s"}, max_original_bytes=1)
    s.note("opaque_content", {"host": "h1", "source": "s"}, kinds="encrypted")
    s.note("opaque_content", {"host": "h1", "source": "s"}, kinds="compressed")
    s.note("gap_filled", {"stream": "ab"}, seq_first=9, seq_last=9)
    s.note("gap_filled", {"stream": "ab"}, seq_first=4, seq_last=4)
    got = s.drain()
    assert ("truncated", {"host": "h1", "source": "s", "count": 2,
                          "max_original_bytes": 900000}) in got
    assert ("opaque_content", {"host": "h1", "source": "s", "count": 2,
                               "kinds": ["compressed", "encrypted"]}) in got
    assert ("gap_filled", {"stream": "ab", "count": 2, "seq_first": 4, "seq_last": 9}) in got
    assert len(got) == 4 and s.drain() == []


def test_summarizer_caps_keys_per_event():
    s = audit.Summarizer(max_keys=2)
    for i in range(5):
        s.note("auth_failure", {"client": "10.0.0.%d" % i})
    got = dict((tuple(sorted(f.items())), e) for e, f in s.drain())
    assert (("count", 3), ("overflow", True)) in got and len(got) == 3


def test_summarizer_is_thread_safe():
    s = audit.Summarizer()

    def worker():
        for _ in range(1000):
            s.note("send_failure", {"error": "ENOBUFS"})
    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert s.drain() == [("send_failure", {"error": "ENOBUFS", "count": 4000})]
