"""The deploy NIC scripts, run against stub ip/nft/ethtool/nmcli/lldpcli, so no root is needed.
lab/check-nic-scripts.sh runs the real ones as root in network namespaces (CI's lab job)."""
import json
import os
import subprocess

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CAPTURE = os.path.join(REPO, "deploy", "receiver", "capture-nic.sh")
EGRESS = os.path.join(REPO, "deploy", "log-server", "egress-nic.sh")
WATCH = os.path.join(REPO, "deploy", "log-server", "egress-arp-watch.sh")

# A stub command: records "name args" (and stdin for `-f -`), then answers from rules.json,
# {"call prefix": [exit code, stdout, stderr]}; the first matching prefix wins, else exit 0.
STUB = '''#!/usr/bin/env python3
import json, os, sys
d = os.environ["STUBS"]
call = " ".join([os.path.basename(sys.argv[0])] + sys.argv[1:])
data = sys.stdin.read() if call.endswith(" -f -") else ""
with open(os.path.join(d, "calls.jsonl"), "a") as f:
    f.write(json.dumps({"call": call, "stdin": data}) + "\\n")
with open(os.path.join(d, "rules.json")) as f:
    rules = json.load(f)
for prefix, (code, out, err) in rules.items():
    if call.startswith(prefix):
        sys.stdout.write(out)
        sys.stderr.write(err)
        sys.exit(code)
'''


def run_script(tmp_path, script, env, rules, names=("ip", "nft", "ethtool", "nmcli", "lldpcli")):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for n in names:
        p = stubs / n
        p.write_text(STUB)
        p.chmod(0o755)
    (stubs / "rules.json").write_text(json.dumps(rules))
    r = subprocess.run(["bash", script], universal_newlines=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env=dict(os.environ, PATH="%s:%s" % (stubs, os.environ["PATH"]),
                                STUBS=str(stubs), **env))
    log = stubs / "calls.jsonl"
    calls = [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    return r, calls


def capture_env(tmp_path):
    f = tmp_path / "capture.env"
    f.write_text("IFACE=test0\n")
    return {"WD2L_CAPTURE_ENV": str(f)}


def test_capture_nic_keeps_going_when_the_nic_has_no_ring_settings(tmp_path):
    # veth and many USB NICs answer `ethtool -g` with "Operation not supported".
    r, calls = run_script(tmp_path, CAPTURE, capture_env(tmp_path),
                          {"ethtool -g": [1, "", "netlink error: Operation not supported\n"]})
    assert r.returncode == 0, r.stderr
    names = [c["call"] for c in calls]
    assert "ip link set test0 up" in names
    assert not any(c.startswith("ethtool -G") for c in names)
    assert "nft -f -" in names


def test_capture_nic_checks_the_same_ruleset_it_loads(tmp_path):
    r, calls = run_script(tmp_path, CAPTURE, capture_env(tmp_path), {})
    assert r.returncode == 0, r.stderr
    nft = [c for c in calls if c["call"].startswith("nft")]
    assert [c["call"] for c in nft] == ["nft -c -f -", "nft -f -"]
    assert nft[0]["stdin"] == nft[1]["stdin"]
    text = nft[1]["stdin"]
    assert text.splitlines()[:2] == ["table netdev wd2l_notx", "delete table netdev wd2l_notx"]
    assert 'hook egress device "test0"' in text and "policy drop;" in text


def test_capture_nic_says_why_when_nft_refuses_the_egress_drop(tmp_path):
    r, calls = run_script(tmp_path, CAPTURE, capture_env(tmp_path),
                          {"nft -c": [1, "", "Error: syntax error, unexpected '}'\n"]})
    assert r.returncode == 0, r.stderr
    assert "syntax error" in r.stderr
    assert "kernel has no netdev egress hook" not in r.stderr
    assert "nft -f -" not in [c["call"] for c in calls]
