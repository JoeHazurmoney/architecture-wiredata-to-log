import json

from wd2l import audit as auditlog
from wd2l.outputs import FileOutput, MultiOutput

from helpers import MemOutput


def test_file_output_writes_audit_lines_canonically(tmp_path):
    o = FileOutput(str(tmp_path))
    assert not (tmp_path / "audit.jsonl").exists()        # opened only when needed
    rec = {"event": "start", "n": 1, "b": "é"}
    o.audit(rec)
    o.close()
    assert (tmp_path / "audit.jsonl").read_bytes() == auditlog.canonical(rec) + b"\n"


def test_multi_output_fans_audit_out():
    a, b = MemOutput(), MemOutput()
    MultiOutput([a, b]).audit({"event": "x"})
    assert a.audits == b.audits == [{"event": "x"}]
