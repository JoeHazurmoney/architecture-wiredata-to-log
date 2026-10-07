import csv
import io
import json

from wd2l import audit as auditlog
from wd2l import audit_report

from helpers import read_audit


def trail(tmp_path, name, component, enclave, t0):
    t = [t0]

    def clock():
        t[0] += 60
        return t[0]
    a = auditlog.AuditLog(str(tmp_path / name), component, enclave, host=name, actor="me",
                          build="b", clock=clock)
    return a


def make(tmp_path):
    day1 = 1791158400.0                      # 2026-10-05T00:00:00Z
    snd = trail(tmp_path, "logsrv01", "sender", 1, day1)
    rcv = trail(tmp_path, "rx01", "receiver", 2, day1)
    snd.write("start", "success")
    snd.write("reconcile", "info", stream="ab", cut=10, events_in=10, events_sent=10,
              sender_hash="1" * 64)
    rcv.write("start", "success")
    rcv.write("gap", "failure", stream="ab", seq_first=3, seq_last=3, segment="e2-receiver")
    rcv.write("reconcile", "failure", stream="ab", cut=10, events_delivered=9, gaps_open=1,
              gaps_filled=0, sender_hash="1" * 64, receiver_hash="2" * 64, balanced=False)
    rcv.write("config_changed", "info", old_config_sha256="a" * 64, config_sha256="b" * 64)
    snd.close()
    rcv.close()
    return str(tmp_path / "logsrv01"), str(tmp_path / "rx01")


def run(capsys, argv):
    code = audit_report.main(argv)
    return code, capsys.readouterr().out


def splunk_export(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps({"preview": False, "result": {
                "_raw": auditlog.canonical(r).decode(), "sourcetype": "wd2l:audit"}}) + "\n")


def test_verify_dir(tmp_path, capsys):
    e1, _ = make(tmp_path)
    code, out = run(capsys, ["verify", "--dir", e1])
    assert code == 0 and json.loads(out)["result"] == "ok"


def test_verify_dir_finds_tampering(tmp_path, capsys):
    e1, _ = make(tmp_path)
    [path] = auditlog.audit_files(e1)
    with open(path, "rb") as f:
        data = f.read()
    with open(path, "wb") as f:
        f.write(data.replace(b'"cut":10', b'"cut":11'))
    code, out = run(capsys, ["verify", "--dir", e1])
    assert code == 1 and json.loads(out)["problems"]


def test_verify_a_siem_export_per_chain(tmp_path, capsys):
    e1, e2 = make(tmp_path)
    recs = read_audit(e1) + read_audit(e2)
    exp = tmp_path / "export.json"
    splunk_export(exp, list(reversed(recs)) + recs[:1])     # any order, one duplicate
    code, out = run(capsys, ["verify", "--export", str(exp)])
    res = json.loads(out)
    assert code == 0 and set(res) == {"logsrv01/enclave1", "rx01/enclave2"}
    assert res["rx01/enclave2"]["records"] == 4 and res["rx01/enclave2"]["missing"] == []


def test_export_with_a_record_missing_lists_it_and_complete_fails(tmp_path, capsys):
    _, e2 = make(tmp_path)
    recs = read_audit(e2)
    exp = tmp_path / "export.json"
    splunk_export(exp, recs[:1] + recs[2:])
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 0 and json.loads(out)["rx01/enclave2"]["missing"] == [[2, 2]]
    code, _ = run(capsys, ["verify", "--export", str(exp), "--complete"])
    assert code == 1


def test_export_with_two_different_records_for_one_n_fails(tmp_path, capsys):
    _, e2 = make(tmp_path)
    recs = read_audit(e2)
    other = dict(recs[1], event="forged")
    exp = tmp_path / "export.json"
    splunk_export(exp, recs + [other])
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 1 and any("two different records" in p
                             for p in json.loads(out)["rx01/enclave2"]["problems"])


def test_reconcile_report_joins_both_sides(tmp_path, capsys):
    e1, e2 = make(tmp_path)
    code, out = run(capsys, ["reconcile", "--dir", e1, "--dir", e2])
    [row] = json.loads(out)
    assert (row["day"], row["stream"], row["sender_cut"], row["receiver_cut"]) == \
        ("2026-10-05", "ab", 10, 10)
    assert (row["events_sent"], row["events_delivered"], row["gaps_open"], row["balanced"]) == \
        (10, 9, 1, False)
    code, out = run(capsys, ["reconcile", "--dir", e1, "--dir", e2, "--format", "csv"])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert rows[0]["balanced"] == "False"


def test_events_filters(tmp_path, capsys):
    e1, e2 = make(tmp_path)
    code, out = run(capsys, ["events", "--dir", e1, "--dir", e2, "--event", "gap",
                             "--event", "config_changed"])
    assert [r["event"] for r in json.loads(out)] == ["gap", "config_changed"]
    code, out = run(capsys, ["events", "--dir", e2, "--segment", "e2-receiver",
                             "--since", "2026-10-05T00:02", "--until", "2026-10-05T00:04"])
    assert [r["event"] for r in json.loads(out)] == ["gap"]
    code, out = run(capsys, ["events", "--dir", e1, "--format", "csv"])
    rows = list(csv.DictReader(io.StringIO(out)))
    assert [r["event"] for r in rows] == ["start", "reconcile"] and "details" in rows[0]


def test_needs_a_source(capsys):
    assert audit_report.main(["events"]) == 2


def test_verify_export_bad_json_line(tmp_path, capsys):
    exp = tmp_path / "export.json"
    with open(exp, "w") as f:
        f.write('{"preview": false, "result": {"_raw": "not json"}}\n')
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 1 and "unreadable" in json.loads(out)


def test_verify_export_non_integer_n(tmp_path, capsys):
    _, e2 = make(tmp_path)
    recs = read_audit(e2)
    exp = tmp_path / "export.json"
    bad_rec = dict(recs[0], n="x")
    splunk_export(exp, [bad_rec])
    code, out = run(capsys, ["verify", "--export", str(exp)])
    res = json.loads(out)
    assert code == 1 and any("non-integer n" in p for p in res["rx01/enclave2"]["problems"])


def test_verify_export_result_not_dict(tmp_path, capsys):
    exp = tmp_path / "export.json"
    with open(exp, "w") as f:
        f.write('{"preview": false, "result": "notadict"}\n')
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 1 and "unreadable" in json.loads(out)


def test_verify_export_empty_file(tmp_path, capsys):
    exp = tmp_path / "export.json"
    with open(exp, "w") as f:
        f.write("")
    code = audit_report.main(["verify", "--export", str(exp)])
    _, err = capsys.readouterr()
    assert code == 1 and "nothing to verify" in err


def test_verify_export_keep_first_record(tmp_path, capsys):
    _, e2 = make(tmp_path)
    recs = read_audit(e2)
    original_hash = recs[0]["hash"]
    forged = dict(recs[0], event="forged")
    exp = tmp_path / "export.json"
    splunk_export(exp, [forged, recs[0]])
    code, out = run(capsys, ["verify", "--export", str(exp)])
    res = json.loads(out)
    assert code == 1 and res["rx01/enclave2"]["last_hash"] == original_hash
    assert any("two different records" in p for p in res["rx01/enclave2"]["problems"])


def test_verify_dir_with_garbage_line(tmp_path, capsys):
    e1, _ = make(tmp_path)
    [path] = auditlog.audit_files(e1)
    with open(path, "ab") as f:
        f.write(b'not json\n')
    code, out = run(capsys, ["verify", "--dir", e1])
    res = json.loads(out)
    assert code == 1 and any("not JSON" in p for p in res["problems"])


def test_verify_dir_no_records(tmp_path, capsys):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    code, out = run(capsys, ["verify", "--dir", str(empty_dir)])
    res = json.loads(out)
    assert code == 1 and any("no audit records found" in p for p in res["problems"])


def test_events_with_unreadable_lines(tmp_path, capsys):
    e1, _ = make(tmp_path)
    [path] = auditlog.audit_files(e1)
    with open(path, "ab") as f:
        f.write(b'garbage\n')
    code = audit_report.main(["events", "--dir", e1])
    out, err = capsys.readouterr()
    recs = json.loads(out)
    assert code == 0 and len(recs) == 2  # start and reconcile
    assert "skipped 1 unreadable lines" in err


DEEP = "[" * 100000 + "]" * 100000


def test_deeply_nested_lines_are_unreadable_not_a_crash(tmp_path, capsys):
    """Final review Minor 9: json.loads raises RecursionError, not ValueError, on these."""
    e1, _ = make(tmp_path)
    [path] = auditlog.audit_files(e1)
    with open(path, "a") as f:
        f.write(DEEP + "\n")
    assert audit_report.main(["events", "--dir", e1]) == 0
    out, err = capsys.readouterr()
    assert len(json.loads(out)) == 2 and "skipped 1 unreadable lines" in err
    exp = tmp_path / "export.json"
    with open(exp, "w") as f:
        f.write(DEEP + "\n")
        f.write(json.dumps({"result": {"_raw": DEEP}}) + "\n")
    code, out = run(capsys, ["verify", "--export", str(exp)])
    assert code == 1 and len(json.loads(out)["unreadable"]) == 2


def test_help_returns_zero(capsys):
    code = audit_report.main(["--help"])
    assert code == 0


def test_nonexistent_dir_returns_two(capsys):
    code = audit_report.main(["events", "--dir", "/nonexistent"])
    assert code == 2


def test_nonexistent_export_file_returns_two(capsys):
    code = audit_report.main(["verify", "--export", "/nonexistent.json"])
    assert code == 2
