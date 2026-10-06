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
