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
