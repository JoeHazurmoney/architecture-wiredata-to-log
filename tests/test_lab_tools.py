import os
import socket
import threading
import time

from lab import fake_cribl

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_the_stand_in_aggregator_waits_for_a_sender_that_starts_late():
    # The lab starts the sender, then the stand-in; on a slow runner the sender may not be
    # listening yet. A real aggregator retries, and so does the stand-in.
    port = free_port()
    accepted = []

    def listen_late():
        time.sleep(0.5)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(5)
        try:
            accepted.append(srv.accept()[0])
        except socket.timeout:
            pass
        srv.close()

    t = threading.Thread(target=listen_late, daemon=True)
    t.start()
    s = fake_cribl.connect("127.0.0.1", port, wait=5.0)
    t.join(6)
    assert accepted
    s.close()
    accepted[0].close()


def test_the_stand_in_aggregator_gives_up_after_its_wait():
    port = free_port()
    start = time.monotonic()
    try:
        fake_cribl.connect("127.0.0.1", port, wait=0.3)
    except ConnectionRefusedError:
        pass
    else:
        raise AssertionError("connected to nothing")
    assert time.monotonic() - start < 2


def test_lab_names_its_packages_for_both_families():
    # `tc` is its own package (iproute-tc) on RHEL; the hint named only Ubuntu's packages.
    with open(os.path.join(REPO, "lab", "run-lab.sh"), encoding="utf-8") as f:
        text = f.read()
    assert "dnf install iproute iproute-tc nftables tcpdump" in text
    assert "apt install iproute2 nftables tcpdump" in text
    for doc in ("docs/running-the-lab.md", "README.md"):     # README "Try it" left out tc (#114)
        with open(os.path.join(REPO, doc), encoding="utf-8") as f:
            text = f.read()
        assert "iproute iproute-tc nftables tcpdump" in text, doc
        assert "python3-venv iproute2 nftables tcpdump" in text, doc
        assert "--require-hashes -r packaging/release/requirements.txt" in text, doc


# ---------------------------------------------------------------- the fault list, everywhere

import re


def _read(*rel):
    with open(os.path.join(REPO, *rel), encoding="utf-8") as f:
        return f.read()


def _between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def lab_faults():
    """Each place a lab fault is named, as a set (or a mapping to what it expects)."""
    lab = _read("lab", "run-lab.sh")
    usage = _between(lab, "#   --fault NAME", "see docs/running-the-lab.md")
    usage = re.sub(r"\s*#\s*", " ", usage)
    usage = set(re.findall(r"[a-z]+(?:-[a-z]+)*", usage.split("(", 1)[1].split(")", 1)[0]))
    inject = _between(lab, 'echo "== fault run: $FAULT"', "sleep 13")
    inject = set(re.findall(r"^\s+([a-z]+(?:-[a-z]+)*)\)", inject, re.M))
    expect = _between(lab, 'echo "== checking where the receiver placed the fault"', "  esac")
    expect = dict(re.findall(r"^\s+([a-z-]+)\)\s+EXPECT=\(([^)]*)\) ;;$", expect, re.M))
    ci = set(re.findall(r"run-lab\.sh --fault ([a-z-]+)", _read(".github", "workflows", "tests.yml")))
    doc = _between(_read("docs", "running-the-lab.md"), "## 9.", "\n## ")
    doc = dict(re.findall(r"^\| `([a-z][a-z-]*)` \| [^|]+ \| (.+) \|$", doc, re.M))
    return usage, inject, expect, ci, doc


def test_every_place_names_the_same_lab_faults():
    """#149: a fault left out of CI, a dropped CI step, or a script and docs that disagree
    passed every check (audit mutation s7-expect: 686 passed)."""
    usage, inject, expect, ci, doc = lab_faults()
    assert len(usage) == 9, usage
    assert usage == inject == set(expect) == ci == set(doc), (usage, inject, set(expect), ci, set(doc))


def test_each_fault_expects_what_the_docs_and_the_rules_say():
    _, _, expect, _, doc = lab_faults()
    rules = _between(_read("docs", "audit-and-health.md"), "**Decision order**", "\n\n**")
    rules = {int(n): (seg, status.split(";")[0].strip()) for n, seg, status in re.findall(
        r"^\| (\d+) \| [^|]+ \| `([^`]+)`[^|]* \| ([^|]+?) \|$", rules, re.M)}
    assert len(rules) == 11, rules
    for name, args in expect.items():
        if args == "--time-alarm":
            assert doc[name] == "a time alarm", name
            continue
        a = dict(re.findall(r"--(\w+) (\S+)", args))
        want = (a["segment"], a["status"], int(a["rule"]))
        assert doc[name] == "`%s`, %s, rule %d" % want, (name, doc[name], want)
        assert rules[want[2]] == want[:2], (name, rules[want[2]], want)


def check_fault(tmp_path, records, *args):
    import json
    import subprocess
    import sys
    path = tmp_path / "health.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return subprocess.run([sys.executable, os.path.join(REPO, "lab", "check_fault.py"), str(path)]
                          + list(args), stdout=subprocess.PIPE, universal_newlines=True)


def fault(status, segment, rule):
    return {"type": "fault", "fault_status": status, "fault_segment": segment, "fault_rule": rule}


def test_check_fault_first_wants_the_expected_fault_reported_first(tmp_path):
    """#149: CI's foreign-only run placed rule 5 first, and the check still passed."""
    ci = [fault("amber", "e1-input", 5), fault("red", "boundary", 4), fault("ok", None, 0)]
    want = ["--segment", "boundary", "--status", "red", "--rule", "4"]
    assert check_fault(tmp_path, ci, *want).returncode == 0                 # anywhere: passes
    r = check_fault(tmp_path, ci, "--first", *want)
    assert r.returncode == 1 and "reported ('amber', 'e1-input', 5) first" in r.stdout
    assert check_fault(tmp_path, ci[1:], "--first", *want).returncode == 0


def test_check_fault_none_refuses_a_false_fault_or_time_alarm(tmp_path):
    loss = [fault("amber", "boundary", 9), fault("ok", None, 0)]
    assert check_fault(tmp_path, [], "--none").returncode == 0
    assert check_fault(tmp_path, loss, "--none").returncode == 1
    assert check_fault(tmp_path, loss, "--none", "--allow-rule", "9").returncode == 0
    skew = [{"type": "time_status", "time_status": "alarm", "time_reason": "clock skew 0.100 s"}]
    r = check_fault(tmp_path, skew, "--none", "--allow-rule", "9")
    assert r.returncode == 1 and "clock skew" in r.stdout
