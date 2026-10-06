import os
import shlex
import subprocess
import time

from wd2l import receiver, sender

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SENDER_UNIT = os.path.join(REPO, "deploy", "log-server", "wd2l-sender.service")
RECEIVER_UNIT = os.path.join(REPO, "deploy", "receiver", "wd2l-receiver.service")
SEAL = os.path.join(REPO, "deploy", "common", "wd2l-audit-seal.sh")


def unit(path):
    with open(path) as f:
        text = f.read().replace("\r\n", "\n").replace("\\\n", " ")
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def args(path, module):
    argv = shlex.split(unit(path)["ExecStart"][0])
    assert argv[1:3] == ["-m", module]
    return argv[3:]


def test_sender_unit_turns_audit_and_health_on():
    a = sender.build_parser().parse_args(args(SENDER_UNIT, "wd2l.sender"))
    assert (a.audit_dir, a.log_format, a.egress_iface) == ("/var/log/wd2l", "json", "ens224")
    u = unit(SENDER_UNIT)
    assert "/var/log/wd2l" in " ".join(u["ReadWritePaths"]) and u["UMask"] == ["0027"]


def test_receiver_unit_turns_audit_and_health_on():
    a = receiver.build_parser().parse_args(args(RECEIVER_UNIT, "wd2l.receiver"))
    assert (a.audit_dir, a.log_format, a.pcap_dir) == ("/var/log/wd2l", "json", "/var/lib/wd2l/pcap")
    assert a.hec_audit_token_file == "/etc/wd2l/hec-audit.token" and a.audit_index == "wd2l_audit"
    paths = " ".join(unit(RECEIVER_UNIT)["ReadWritePaths"])
    assert "/var/lib/wd2l" in paths and "/var/log/wd2l" in paths


def test_seal_script_makes_files_append_only_and_deletes_after_a_year(tmp_path):
    d = tmp_path / "audit"
    d.mkdir()
    old = d / "audit-20250101T000000.000000Z.jsonl"
    new = d / "audit-20261005T000000.000000Z.jsonl"
    other = d / "notes.txt"
    for f in (old, new, other):
        f.write_text("x\n")
    t = time.time() - 400 * 86400
    os.utime(str(old), (t, t))
    calls = tmp_path / "chattr.log"
    fake = tmp_path / "chattr"
    fake.write_text('#!/bin/sh\necho "$@" >> "%s"\n' % calls)
    fake.chmod(0o755)
    r = subprocess.run(["sh", SEAL], env=dict(os.environ, WD2L_AUDIT_DIR=str(d), CHATTR=str(fake)),
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr
    assert not old.exists() and new.exists() and other.exists()
    log = calls.read_text().splitlines()
    assert "-a %s" % old in log and "+a %s" % new in log and not any("notes" in x for x in log)


def test_auditd_rules_are_well_formed():
    for side in ("log-server", "receiver"):
        with open(os.path.join(REPO, "deploy", side, "wd2l.rules")) as f:
            rules = [x for x in f.read().splitlines() if x.strip() and not x.startswith("#")]
        assert rules
        for r in rules:
            assert r.startswith(("-w ", "-a always,exit ")) and " -k wd2l-" in r, r
        assert any("dir=/var/log/wd2l" in r and "auid!=unset" in r for r in rules)
