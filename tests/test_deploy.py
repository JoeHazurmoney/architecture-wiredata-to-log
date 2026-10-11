import os
import shlex
import subprocess
import time

import pytest

from wd2l import receiver, sender

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SENDER_UNIT = os.path.join(REPO, "deploy", "log-server", "wd2l-sender.service")
RECEIVER_UNIT = os.path.join(REPO, "deploy", "receiver", "wd2l-receiver.service")
SEAL = os.path.join(REPO, "deploy", "common", "wd2l-audit-seal.sh")
SENDER_ENV = os.path.join(REPO, "deploy", "log-server", "sender.env")
RECEIVER_ENV = os.path.join(REPO, "deploy", "receiver", "receiver.env")
CAPTURE_UNIT = os.path.join(REPO, "deploy", "receiver", "wd2l-capture.service")
CAPTURE_ENV = os.path.join(REPO, "deploy", "receiver", "capture.env")
EGRESS_NIC_UNIT = os.path.join(REPO, "deploy", "log-server", "wd2l-egress-nic.service")
ARP_UNIT = os.path.join(REPO, "deploy", "log-server", "wd2l-egress-arp.service")

# What the units passed before the options moved into env files (they must not change).
SENDER_ARGS_BEFORE = [
    "--listen", "127.0.0.1:10070", "--bind", "10.255.255.1:5514", "--dst", "10.255.255.2:5514",
    "--max-datagram", "1472", "--auth-token-file", "/etc/wd2l/aggregator.token",
    "--state", "/var/lib/wd2l/sender.json", "--audit-dir", "/var/log/wd2l",
    "--egress-iface", "ens224", "--log-format", "json"]
RECEIVER_ARGS_BEFORE = [
    "--live", "ens256", "--dst-ip", "10.255.255.2", "--dst-port", "5514",
    "--src-ip", "10.255.255.1", "--src-port", "5514", "--state", "/var/lib/wd2l/state.json",
    "--spool-dir", "/var/lib/wd2l/spool", "--hec-url", "https://siem.enclave2.example:8088",
    "--hec-token-file", "/etc/wd2l/hec.token", "--hec-ca", "/etc/wd2l/siem-ca.pem",
    "--default-index", "enclave1", "--health-index", "wd2l",
    "--hec-audit-token-file", "/etc/wd2l/hec-audit.token", "--audit-index", "wd2l_audit",
    "--audit-dir", "/var/log/wd2l", "--pcap-dir", "/var/lib/wd2l/pcap", "--log-format", "json"]


def unit(path):
    with open(path) as f:
        text = f.read().replace("\r\n", "\n").replace("\\\n", " ")
    out = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out.setdefault(k.strip(), []).append(v.strip())
    return out


def env_file(path):
    """KEY=VALUE lines as systemd's EnvironmentFile= reads them: a backslash at the end of a
    line joins the next one, and double quotes around a value are removed."""
    with open(path) as f:
        text = f.read().replace("\r\n", "\n").replace("\\\n", "")
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, v = line.split("=", 1)
        if len(v) >= 2 and v[0] == v[-1] == '"':
            v = v[1:-1]
        out[k.strip()] = v
    return out


def args(unit_path, env_path, var, module):
    u = unit(unit_path)
    assert u["EnvironmentFile"] == ["/etc/wd2l/" + os.path.basename(env_path)]
    argv = shlex.split(u["ExecStart"][0])
    assert argv == ["/usr/bin/python3", "-m", module, "$" + var]
    return shlex.split(env_file(env_path)[var])


def test_moving_the_options_into_env_files_changed_none_of_them():
    assert args(SENDER_UNIT, SENDER_ENV, "WD2L_SENDER_ARGS", "wd2l.sender") == SENDER_ARGS_BEFORE
    assert args(RECEIVER_UNIT, RECEIVER_ENV, "WD2L_RECEIVER_ARGS", "wd2l.receiver") \
        == RECEIVER_ARGS_BEFORE


def test_sender_unit_turns_audit_and_health_on():
    a = sender.build_parser().parse_args(
        args(SENDER_UNIT, SENDER_ENV, "WD2L_SENDER_ARGS", "wd2l.sender"))
    assert (a.audit_dir, a.log_format, a.egress_iface) == ("/var/log/wd2l", "json", "ens224")
    u = unit(SENDER_UNIT)
    assert "/var/log/wd2l" in " ".join(u["ReadWritePaths"]) and u["UMask"] == ["0027"]
    assert u["StateDirectoryMode"] == ["0750"]


def test_receiver_unit_turns_audit_and_health_on():
    a = receiver.build_parser().parse_args(
        args(RECEIVER_UNIT, RECEIVER_ENV, "WD2L_RECEIVER_ARGS", "wd2l.receiver"))
    assert (a.audit_dir, a.log_format, a.pcap_dir) == ("/var/log/wd2l", "json", "/var/lib/wd2l/pcap")
    assert a.hec_audit_token_file == "/etc/wd2l/hec-audit.token" and a.audit_index == "wd2l_audit"
    paths = " ".join(unit(RECEIVER_UNIT)["ReadWritePaths"])
    assert "/var/lib/wd2l" in paths and "/var/log/wd2l" in paths


def test_capture_unit_reads_the_interface_from_capture_env():
    u = unit(CAPTURE_UNIT)
    assert u["EnvironmentFile"] == ["/etc/wd2l/capture.env"]
    assert shlex.split(u["ExecStart"][0])[:3] == ["/usr/sbin/tcpdump", "-i", "${IFACE}"]
    assert env_file(CAPTURE_ENV)["IFACE"] == "ens256"


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


def test_host_rules_load_without_podman():
    # auditd refuses a watch whose directory is missing (/etc/containers/systemd comes with
    # Podman), and augenrules stops loading there. So the Quadlet watch has its own file, which
    # only the containers guide installs.
    with open(os.path.join(REPO, "docs", "deployment", "containers.md")) as f:
        guide = f.read()
    for side, unit in (("log-server", "wd2l-sender"), ("receiver", "wd2l-receiver")):
        with open(os.path.join(REPO, "deploy", side, "wd2l.rules")) as f:
            assert "/etc/containers" not in f.read()
        with open(os.path.join(REPO, "deploy", side, "wd2l-quadlet.rules")) as f:
            rules = [x for x in f.read().splitlines() if x.strip() and not x.startswith("#")]
        assert rules == ["-w /etc/containers/systemd/%s.container -p wa -k wd2l-units" % unit]
        assert "/usr/share/wd2l/audit/%s-quadlet.rules" % side in guide


import wd2l


def quadlet(path):
    """A Quadlet/systemd unit as {section: {key: [values]}}; continuation lines joined."""
    with open(path) as f:
        text = f.read().replace("\r\n", "\n").replace("\\n", " ")
    out, sec = {}, None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            sec = out.setdefault(line[1:-1], {})
            continue
        k, v = line.split("=", 1)
        sec.setdefault(k.strip(), []).append(v.strip())
    return out


QUADLETS = [
    ("log-server", "wd2l-sender", "WD2L_SENDER_ARGS", SENDER_UNIT, 30, []),
    ("receiver", "wd2l-receiver", "WD2L_RECEIVER_ARGS", RECEIVER_UNIT, 60, ["NET_RAW"]),
]


@pytest.mark.parametrize("side, name, var, native_path, stop, caps", QUADLETS)
def test_quadlet_unit_matches_the_native_one(side, name, var, native_path, stop, caps):
    q = quadlet(os.path.join(REPO, "deploy", side, name + ".container"))
    native, c = unit(native_path), q["Container"]
    assert c["Image"] == ["ghcr.io/joehazurmoney/wd2l:" + wd2l.__version__]
    assert c["Pull"] == ["never"] and c["Network"] == ["host"]
    assert c["DropCapability"] == ["all"] and c.get("AddCapability", []) == caps
    assert c["NoNewPrivileges"] == ["true"] and c["ReadOnly"] == ["true"]
    assert c["StopTimeout"] == [str(stop)] and native["TimeoutStopSec"] == [str(stop)]
    assert int(q["Service"]["TimeoutStopSec"][0]) > stop
    assert q["Service"]["EnvironmentFile"] == native["EnvironmentFile"]
    assert shlex.split(c["Exec"][0]) == [name, "$" + var, "--chrony-addr", "127.0.0.1:323"]
    for k in ("After", "Requires", "Wants"):
        assert q["Unit"].get(k) == native.get(k), k
    assert "--umask=0027" in " ".join(c.get("PodmanArgs", []))


def test_arp_watch_runs_whenever_the_egress_nic_does():
    nic, arp = unit(EGRESS_NIC_UNIT), unit(ARP_UNIT)
    assert "wd2l-egress-arp.service" in nic["Wants"][0].split()
    assert arp["After"] == ["wd2l-egress-nic.service"] and arp["PartOf"] == ["wd2l-egress-nic.service"]
    assert arp["ExecStart"] == ["/opt/wd2l/deploy/log-server/egress-arp-watch.sh"]
    assert arp["Restart"] == ["always"] and arp["CapabilityBoundingSet"] == ["CAP_NET_ADMIN"]
    assert "WantedBy" not in arp          # started by wd2l-egress-nic's Wants=, never enabled alone
    with open(os.path.join(REPO, "deploy", "log-server", "wd2l.rules")) as f:
        assert "-w /etc/systemd/system/wd2l-egress-arp.service -p wa -k wd2l-units" in f.read().splitlines()
