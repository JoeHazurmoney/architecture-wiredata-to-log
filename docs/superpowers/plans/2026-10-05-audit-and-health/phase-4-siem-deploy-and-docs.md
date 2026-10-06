# Phase 4: deployment, SIEM, dashboard and docs

Part of the [audit and health implementation plan](README.md). Read its **Global constraints**
first. Spec: [docs/audit-and-health-plan.md](../../../audit-and-health-plan.md) §10 (files, timer,
SIEM, auditd), §12 (dashboard), §13 (alerts), §14–§17.

**Delivers:** the units turn everything on; a root timer makes audit files append-only and keeps
them a year; host auditd rules; the SIEM example gains the audit index, token, auditor role,
alerts and a daily review report; **a new state-of-health page explains what the dashboard shows
and how to read it, with an SVG mockup and Mermaid scenario strips**; a Dashboard Studio JSON
matches the page panel for panel; runbooks and guides catch up; and the audit plan becomes
"as built vs proposed" without losing its content.

Run tests with `T` from the plan README.

---

### Task 4.1: Deployment: units, the append-only timer, auditd rules

**Files:**
- Modify: `deploy/log-server/wd2l-sender.service`, `deploy/receiver/wd2l-receiver.service`
- Create: `deploy/common/wd2l-audit-seal.sh`, `deploy/common/wd2l-audit-seal.service`,
  `deploy/common/wd2l-audit-seal.timer`
- Create: `deploy/log-server/wd2l.rules`, `deploy/receiver/wd2l.rules`
- Create: `tests/test_deploy.py`
- Modify: `docs/deployment/log-server.md`, `docs/deployment/receiver.md`

**Interfaces:**
- Consumes: `sender.build_parser()`, `receiver.build_parser()`.
- Produces: units whose `ExecStart` flags parse with those parsers (a test keeps them in step);
  `wd2l-audit-seal.sh` honours `WD2L_AUDIT_DIR`, `WD2L_AUDIT_KEEP_DAYS` and `CHATTR` (for tests).

- [ ] **Step 1: Write the failing tests**

`tests/test_deploy.py`:

```python
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
        text = f.read().replace("\\\n", " ")
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
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_deploy.py -q`
Expected: `AssertionError` on the unit flags, and the seal script and rules files are missing.

- [ ] **Step 3: Write the deploy files**

`deploy/log-server/wd2l-sender.service`: extend `ExecStart` (keep every existing line):

```
    --state /var/lib/wd2l/sender.json \
    --audit-dir /var/log/wd2l \
    --egress-iface ens224 \
    --log-format json
```

and after `StateDirectory=wd2l` add:

```
# Audit records (docs/audit-and-health-plan.md section 10). The install step creates
# /var/log/wd2l (owner wd2l, group wd2l-audit, mode 2750); wd2l-audit-seal.timer makes the files
# append-only and keeps them a year.
ReadWritePaths=/var/log/wd2l
UMask=0027
```

`deploy/receiver/wd2l-receiver.service`: extend `ExecStart` with
`--hec-audit-token-file /etc/wd2l/hec-audit.token`, `--audit-index wd2l_audit`,
`--audit-dir /var/log/wd2l`, `--pcap-dir /var/lib/wd2l/pcap`, `--log-format json`; change
`ReadWritePaths=/var/lib/wd2l` to `ReadWritePaths=/var/lib/wd2l /var/log/wd2l`; add `UMask=0027`
with the same comment.

`deploy/common/wd2l-audit-seal.sh`:

```sh
#!/bin/sh
# wd2l-audit-seal, hourly as root (wd2l-audit-seal.timer), on both hosts:
#  * makes every wd2l audit file append-only (chattr +a). The wd2l processes only ever append,
#    and can't set the flag themselves (no CAP_LINUX_IMMUTABLE);
#  * deletes files last written more than 366 days ago: each host keeps its own 1-year copy.
# See docs/audit-and-health-plan.md section 10.
set -eu
DIR="${WD2L_AUDIT_DIR:-/var/log/wd2l}"
DAYS="${WD2L_AUDIT_KEEP_DAYS:-366}"
CHATTR="${CHATTR:-chattr}"
find "$DIR" -maxdepth 1 -type f -name 'audit-*.jsonl' -mtime +"$DAYS" | while IFS= read -r f; do
  "$CHATTR" -a "$f"
  rm -f -- "$f"
  echo "wd2l-audit-seal: deleted $f (last written more than $DAYS days ago)"
done
find "$DIR" -maxdepth 1 -type f -name 'audit-*.jsonl' | while IFS= read -r f; do
  "$CHATTR" +a "$f"
done
```

`deploy/common/wd2l-audit-seal.service`:

```
[Unit]
Description=wd2l: make audit files append-only; delete those older than 366 days
ConditionPathIsDirectory=/var/log/wd2l

[Service]
Type=oneshot
ExecStart=/bin/sh /opt/wd2l/deploy/common/wd2l-audit-seal.sh
```

`deploy/common/wd2l-audit-seal.timer`:

```
[Unit]
Description=wd2l: hourly append-only flag and 1-year retention for audit files

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

`deploy/log-server/wd2l.rules`:

```
## wd2l host audit rules, Enclave 1 log server (docs/audit-and-health-plan.md section 10).
## Copy to /etc/audit/rules.d/wd2l.rules, then: sudo augenrules --load
## Who changes wd2l's programs, settings and units:
-w /opt/wd2l/ -p wa -k wd2l-code
-w /etc/wd2l/ -p wa -k wd2l-config
-w /etc/systemd/system/wd2l-sender.service -p wa -k wd2l-units
-w /etc/systemd/system/wd2l-egress-nic.service -p wa -k wd2l-units
-w /etc/systemd/system/wd2l-audit-seal.service -p wa -k wd2l-units
-w /etc/systemd/system/wd2l-audit-seal.timer -p wa -k wd2l-units
## State and audit files: only changes made from a login session (auid set). The daemons write
## there all the time.
-a always,exit -F dir=/var/lib/wd2l -F perm=wa -F auid!=unset -k wd2l-state
-a always,exit -F dir=/var/log/wd2l -F perm=wa -F auid!=unset -k wd2l-audit-files
```

`deploy/receiver/wd2l.rules`: the same, headed "Enclave 2 receiver host", with the unit lines for
`wd2l-receiver.service`, `wd2l-capture.service`, `wd2l-capture-nic.service`,
`wd2l-pcap-prune.service`, `wd2l-pcap-prune.timer`, `wd2l-audit-seal.service` and
`wd2l-audit-seal.timer`.

- [ ] **Step 4: Update the deployment guides**

`docs/deployment/log-server.md` §1, after the token lines:

```bash
sudo groupadd --system wd2l-audit                                # who may read audit files
sudo install -d -o wd2l -g wd2l-audit -m 2750 /var/log/wd2l      # setgid: files get the group
git rev-parse HEAD | sudo tee /opt/wd2l/wd2l/BUILD >/dev/null    # the build audit records name
```

§4: add the new options to the table (`--audit-dir`: unit `/var/log/wd2l`, hash-chained audit
records, see [the audit plan](../audit-and-health-plan.md); `--egress-iface`: unit `ens224`, NIC
carrier and transmit counters in every heartbeat; `--chronyc`: `chronyc`, time quality;
`--log-format`: unit `json`; `--audit-min-free-mb`: 256). Add a subsection **Audit files** with:
the seal timer (`sudo cp deploy/common/wd2l-audit-seal.* /etc/systemd/system/ && sudo systemctl
enable --now wd2l-audit-seal.timer`), the auditd rules (`sudo cp deploy/log-server/wd2l.rules
/etc/audit/rules.d/ && sudo augenrules --load`), how to check the chain
(`sudo -u wd2l python3 -m wd2l.audit verify /var/log/wd2l`, or `wd2l-audit-report verify --dir
/var/log/wd2l` once installed with pip), and how to toggle debug so the record names you:
`sudo kill -USR1 "$(systemctl show -p MainPID --value wd2l-sender)"` (not `systemctl kill`, which
makes systemd the sender of the signal). Note that the log aggregator copies these files to the
log retention server ([retention-server.md](retention-server.md#6-wd2l-audit-files)).

`docs/deployment/receiver.md` §1: the same three lines, plus the audit token:
`echo '<HEC audit token>' | sudo tee /etc/wd2l/hec-audit.token >/dev/null` with the same
`chown root:wd2l` / `chmod 640`. §4: the new options (`--audit-dir`, `--hec-audit-token-file`,
`--audit-index`, `--pcap-dir`, `--capture-iface`, `--capture-rcvbuf`, `--fault-interval`,
`--fault-window`, `--input-flat-after`, `--time-check-interval`, `--chronyc`, `--log-format`,
`--audit-min-free-mb`) and the same **Audit files** subsection (receiver rules file, and: an
archive replay writes to the same directory, so stop the live receiver first; the replay refuses
to start otherwise).

- [ ] **Step 5: Run the tests**

Run: `T tests/test_deploy.py -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add deploy/ tests/test_deploy.py docs/deployment/log-server.md docs/deployment/receiver.md
git commit -m "Deploy: audit and health on in the units; append-only timer; auditd rules" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.2: SIEM example: audit index, token, auditor role, alerts, daily review

**Files:**
- Modify: `deploy/receiver/splunk/indexes.conf`, `inputs.conf`, `props.conf`, `savedsearches.conf`
- Create: `deploy/receiver/splunk/authorize.conf`
- Create: `tests/test_siem_config.py`

**Interfaces:**
- Produces: alert names `WD2L - Fault segment`, `WD2L - Reconciliation not balanced`,
  `WD2L - Audit trail`, `WD2L - Time quality`, and the scheduled report
  `WD2L - Audit review (daily)`. Alerts read only `index=wd2l` (health), so an operator can own
  them; the daily review reads `index=wd2l_audit` and its owner needs `wd2l_auditor`.

- [ ] **Step 1: Write the failing tests**

`tests/test_siem_config.py`:

```python
import configparser
import glob
import os
import re

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SPLUNK = os.path.join(REPO, "deploy", "receiver", "splunk")


def conf(name):
    with open(os.path.join(SPLUNK, name)) as f:
        text = re.sub(r"\\\n", " ", f.read())
    cp = configparser.ConfigParser(interpolation=None, strict=False, delimiters=("=",))
    cp.optionxform = str
    cp.read_string(text)
    return cp


def test_every_alert_the_docs_name_exists():
    names = set(conf("savedsearches.conf").sections())
    named = set()
    for path in glob.glob(os.path.join(REPO, "docs", "**", "*.md"), recursive=True):
        if os.sep + "superpowers" + os.sep in path:
            continue    # implementation plans, not user docs
        with open(path, encoding="utf-8") as f:
            named |= set(re.findall(r'"(WD2L - [^"]+)"', f.read()))
    assert named and not named - names, sorted(named - names)


def test_new_alerts_and_review_report():
    s = conf("savedsearches.conf")
    for name in ("WD2L - Fault segment", "WD2L - Reconciliation not balanced",
                 "WD2L - Audit trail", "WD2L - Time quality"):
        assert "index=wd2l " in s[name]["search"] and "wd2l_audit" not in s[name]["search"]
    assert "index=wd2l_audit" in s["WD2L - Audit review (daily)"]["search"]


def test_audit_index_token_and_role():
    idx = conf("indexes.conf")
    assert idx["wd2l_audit"]["frozenTimePeriodInSecs"] == "31622400"
    inp = conf("inputs.conf")
    assert "wd2l_audit" not in inp["http://wd2l"]["indexes"]
    assert inp["http://wd2l_audit"]["indexes"] == "wd2l_audit"
    auth = conf("authorize.conf")
    assert "wd2l_audit" in auth["role_wd2l_auditor"]["srchIndexesAllowed"]
    for role in ("role_user", "role_power"):
        allowed = auth[role]["srchIndexesAllowed"]
        assert "wd2l_audit" not in allowed and "*" not in allowed


def test_json_parsing_for_every_wd2l_sourcetype():
    props = conf("props.conf")
    for st in ("wd2l:health", "wd2l:audit", "wd2l:sender:audit", "wd2l:sender:health"):
        assert props[st]["KV_MODE"] == "json"
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_siem_config.py -q`
Expected: `KeyError` for the new sections and `FileNotFoundError` for `authorize.conf`.
(`test_every_alert_the_docs_name_exists` may already pass; it guards later doc edits.)

- [ ] **Step 3: Write the configs**

`indexes.conf`, append:

```
# wd2l audit records from both enclaves (sourcetypes wd2l:audit, wd2l:sender:audit). Readable only
# by the wd2l_auditor role (authorize.conf). Kept 1 year (366 days), like the files on each host.
[wd2l_audit]
homePath   = $SPLUNK_DB/wd2l_audit/db
coldPath   = $SPLUNK_DB/wd2l_audit/colddb
thawedPath = $SPLUNK_DB/wd2l_audit/thaweddb
frozenTimePeriodInSecs = 31622400
```

`inputs.conf`: above `indexes = enclave1,wd2l` add
`# Never wd2l_audit: audit records come in on their own token (below).`, and append:

```
# Audit records only (wd2l-receiver --hec-audit-token-file /etc/wd2l/hec-audit.token).
[http://wd2l_audit]
disabled = 0
token = 11111111-1111-1111-1111-111111111111
index = wd2l_audit
indexes = wd2l_audit
useACK = false
```

`props.conf`, append `[wd2l:audit]`, `[wd2l:sender:audit]`, `[wd2l:sender:health]`, each with
`KV_MODE = json`.

`authorize.conf`:

```
# Example SIEM configuration (Splunk). Any SIEM works; see docs/deployment/receiver.md.
#
# Who may read wd2l's audit records: only the wd2l_auditor role (access limited to a few
# privileged users; e.g. NIST AU-9(4), SOC 2 CC6.3). Give it to the people your security owner
# names (docs/audit-and-health-plan.md section 17, item 4). Check against your Splunk version.

[role_wd2l_auditor]
search = enabled
schedule_search = enabled
srchIndexesAllowed = wd2l_audit;wd2l
srchIndexesDefault = wd2l_audit

# Splunk's built-in user and power roles search every non-internal index ("*"), which would include
# wd2l_audit. List their indexes instead (add your own), so it stays out.
[role_user]
srchIndexesAllowed = enclave1;wd2l

[role_power]
srchIndexesAllowed = enclave1;wd2l
```

`savedsearches.conf`, append (same schedule keys as the existing alerts unless noted):

```
[WD2L - Fault segment]
description = The receiver's answer to "where is the fault" moved away from ok. fault_segment is the segment (e1-input, e1-sender, boundary, e2-capture, e2-receiver, e2-siem), fault_rule the rule that matched, fault_detail what to check. See docs/state-of-health.md. Mute it during planned downtime (docs/planned-downtime.md).
search = index=wd2l sourcetype=wd2l:health type=fault fault_status!=ok \
| table _time host fault_status fault_segment fault_rule fault_detail previous_status
cron_schedule = */5 * * * *
dispatch.earliest_time = -5m@m
dispatch.latest_time = @m
enableSched = 1
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.track = 1

[WD2L - Reconciliation not balanced]
description = A sender run hasn't balanced end to end for an hour: the SIEM doesn't hold exactly what Enclave 1 sent. With open gaps, "Events lost in transfer" has already fired: replay or re-send. With no open gaps, events were changed or misnumbered on the way: treat it as an incident. See docs/audit-and-health-plan.md section 9.
search = index=wd2l sourcetype=wd2l:health type=reconcile \
| stats count(eval(balanced="true")) as balanced_checks latest(cut) as cut latest(gaps_open) as gaps_open by host, stream \
| where balanced_checks=0
cron_schedule = 0 * * * *
dispatch.earliest_time = -65m@m
dispatch.latest_time = @m
enableSched = 1
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.track = 1

[WD2L - Audit trail]
description = An audit file can't be written or its disk is low (audit_ok=false), or the daily self-check of the hash chain failed (audit_verify=failed), on either side. The transfer keeps going. See docs/operations.md.
search = index=wd2l type=health (sourcetype=wd2l:health OR sourcetype=wd2l:sender:health) (audit_ok=false OR audit_verify=failed) \
| stats latest(_time) as last latest(audit_ok) as audit_ok latest(audit_verify) as audit_verify latest(audit_n) as audit_n by host, component
cron_schedule = */15 * * * *
dispatch.earliest_time = -20m@m
dispatch.latest_time = @m
enableSched = 1
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.track = 1

[WD2L - Time quality]
description = Time is unsynchronised, above stratum 3 or more than 100 ms off on either side, or the two enclaves' clocks differ by more than 50 ms. Events still arrive, but their times can't be trusted. See docs/operations.md.
search = index=wd2l sourcetype=wd2l:health ((type=time_status time_status=alarm) OR (type=health time_status=alarm)) \
| stats latest(_time) as last latest(time_reason) as reason by host
cron_schedule = */15 * * * *
dispatch.earliest_time = -20m@m
dispatch.latest_time = @m
enableSched = 1
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.track = 1

[WD2L - Audit review (daily)]
description = Changes and operator actions for review, yesterday: configuration changed, state file reset, archive replays, debug toggled, audit failures, self-checks, time quality changes. A report, not an alert. Its owner needs the wd2l_auditor role.
search = index=wd2l_audit event IN (config_changed, state_reset, replay_run, debug_toggled, audit_failure, audit_verify, time_quality) \
| table _time host component event outcome actor reason level files old_config_sha256 config_sha256
cron_schedule = 0 7 * * *
dispatch.earliest_time = -1d@d
dispatch.latest_time = @d
enableSched = 1
```

- [ ] **Step 4: Run the tests**

Run: `T tests/test_siem_config.py tests/test_hec.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add deploy/receiver/splunk/ tests/test_siem_config.py
git commit -m "SIEM example: audit index, own token, auditor role, four alerts and a daily review" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.3: The state-of-health page, with mockups

**Files:**
- Create: `docs/state-of-health.md`
- Create: `docs/images/state-of-health-mockup.svg`

**Interfaces:**
- Produces: a panel table whose bold titles are the contract with the dashboard JSON (Task 4.4
  tests that every title on the dashboard is in this table and the other way round).

**Audience:** Enclave 2 operators (SOC/NOC) who glance at a wall screen or open it when an alert
fires; the on-call engineer working out where a fault is; the security owner and auditors who
check the trail. Plain words, short sentences, like the rest of `docs/`. Framework-neutral.

**Mockup format:** an SVG drawn as code, checked in under `docs/images/` and shown inline with
`![...](images/state-of-health-mockup.svg)`. GitHub, GitLab and VS Code render it; it stays
text, so a PR shows what changed; it carries the real colors. Scenario variants are Mermaid
pipeline strips (GitHub renders them, and the repo already uses Mermaid). The SVG is marked
"Mockup: illustrative values" so nobody takes it for real data.

- [ ] **Step 1: Write the page**

`docs/state-of-health.md`, title **"wd2l state of health"**, with these sections:

1. **Intro** (3–4 sentences): what "state of health" means here; that one dashboard in the
   Enclave 2 SIEM answers it; that the receiver itself decides where a fault is (so any SIEM can
   draw it) and this page says what to show and how to read it. Links: the audit plan
   [§12](audit-and-health-plan.md#12-the-where-is-the-fault-dashboard),
   [operations.md](operations.md), [planned-downtime.md](planned-downtime.md), the example
   dashboard `deploy/receiver/splunk/wd2l-health-dashboard.json`.
2. **The questions, in order.** A numbered list; the dashboard is laid out in this order:
   1. Is the transfer working right now? If not, where is the fault?
   2. Is the receiver itself alive? (It can't report its own absence.)
   3. Is anything lost, and does the SIEM hold exactly what Enclave 1 sent?
   4. Is it keeping up?
   5. Can we trust the timestamps?
   6. Are both audit trails being written and intact?
   7. For diagnosis: what does each segment's detail say?
3. **Who looks, and when.** A short table: operator (glance, top row only; acts on red), on-call
   (alert fired: status tile, pipeline, fault history, the segment's detail row), security owner
   / auditor (weekly: reconciliation, audit trail, the daily review report; needs the
   `wd2l_auditor` role for the last panel).
4. **The mockup.** `![wd2l state of health dashboard, mockup](images/state-of-health-mockup.svg)`
   and one sentence: "This shows a fiber or optic fault (rule 7). Panel numbers match the table
   below." Then a sentence that the values are illustrative.
5. **The six segments.** A Mermaid strip of the healthy pipeline (template below) and a table:
   segment, where it is, what it covers (from the spec §8).
6. **Panels.** One table, with these exact rows. Columns: `#`, `Panel` (bold title), `Answers`,
   `Data`, `Green / amber / red`, `If not green`.

   | # | Panel | Answers | Data | Green / amber / red | If not green |
   |---|---|---|---|---|---|
   | 1 | **Transfer status** | Is it working? | Latest `type=health` summary: `fault_status` | `ok` / `amber` / `red`, as the receiver says | Read panel 1b, then the segment's detail row |
   | 1b | **Where and why** | Where is the fault? | Same record: `fault_segment`, `fault_rule`, `fault_detail` | — | The rule's row in the scenario table below |
   | 2 | **Receiver last heard** | Is the receiver alive? | Age of the newest `wd2l:health` record | < 90 s / 90–900 s / > 900 s | Receiver host and service; the "WD2L - Receiver silent" alert |
   | 3 | **Pipeline** | Which segment? | Latest summary: `seg_e1_input` … `seg_e2_siem` | per box: green / amber / red; grey = can't be seen right now | That box's detail row (panels 14–19) |
   | 4 | **Open gap events** | Is anything missing now? | Latest summary: `open_gap_events` | 0 / — / > 0 | [operations.md, events lost](operations.md#alert-events-lost-typegap) |
   | 5 | **Reconciliation** | Does the SIEM hold exactly what was sent? | Latest `type=reconcile` per stream, last 25 h | all balanced / — / any not | Panel 12; replay or re-send; unbalanced with no gaps is an incident |
   | 6 | **Time** | Can we trust timestamps? | Latest summary: `time_status`, `clock_offset_s` | `ok` / — / `alarm` | `time_reason`; chrony and the GPS receiver on that side |
   | 7 | **Audit trail** | Are both trails written and intact? | Latest health from each side: `audit_ok`, `audit_verify` | both ok / self-check not run yet / any `false` or `failed` | [operations.md, audit trail](operations.md) |
   | 8 | **Events in vs delivered** | Does everything that enters Enclave 1 leave Enclave 2? | Summaries: per-minute growth of `sender_events_in` and `events_delivered` | the lines overlap | A gap between the lines is loss or backlog: panels 4, 11, 19 |
   | 9 | **Delay by segment** | Is it keeping up? | Imported events: `wd2l_tx_time − _time`, `wd2l_rx_time − wd2l_tx_time`, `_indextime − wd2l_rx_time` | site values; e.g. under 60 s, 50 ms, 60 s | [operations.md, measuring delays](operations.md#measuring-delays) |
   | 10 | **Clock skew** | Do the two enclaves agree on time? | Summaries: `clock_offset_s` | inside ±50 ms | Time sync, not the network |
   | 11 | **Gaps by reason** | What kind of loss? | `type=gap` records, `count` by `reason` (records-stream gaps marked) | none | The reason table in operations.md |
   | 12 | **Reconciliation by stream** | Which run doesn't balance, and since when? | `type=reconcile`: `cut`, `balanced`, `gaps_open` per stream | all balanced | As panel 5 |
   | 13 | **Fault history** | What changed, when? | `type=fault` and `type=time_status` records | — | Attach to the incident ticket |
   | 14 | **Enclave 1 input** | Is the aggregator feeding the sender? | Latest `wd2l:sender:health`: `events_in`, `clients`, `input_backlog_bytes`, `bad_input` | — | Enclave 1 team: the aggregator |
   | 15 | **Enclave 1 sender** | Is the sender keeping up? | Latest `wd2l:sender:health`: `stall_s`, `sender_drops`, `send_errors`, `cpu_pct`, `nic_carrier`, `nic_tx_errors` | — | Enclave 1 team: the log server |
   | 16 | **Boundary** | Is the tap, fiber and optic clean? | Latest summary: `nic_carrier`, `nic_carrier_changes`, `nic_rx_crc_errors`, `nic_rx_frame_errors`, `other_packets`, `bad_frames` | — | Optics, fiber, tap ports, tap filter |
   | 17 | **Enclave 2 capture** | Is every packet captured and archived? | Latest summary: `nic_rx_packets`, `kernel_drops`, `archive_file`, `archive_age_s` | — | Host capacity; `wd2l-capture` |
   | 18 | **Enclave 2 receiver** | Is the receiver keeping up? | Latest summary: `heartbeat_age_s`, `open_gap_events`, `reasm_expired`, `cpu_pct`, `rss_mb` | — | Receiver host |
   | 19 | **Enclave 2 SIEM** | Is the SIEM taking everything? | Latest summary: `hec_queue`, `hec_spool_files`, `hec_posts_failed`, `hec_rejected_events`, `output_dropped` | — | The SIEM; `<spool>/rejected/` |
   | 20 | **Audit events to review** | What did people change? | `index=wd2l_audit`: `config_changed`, `state_reset`, `replay_run`, `debug_toggled`, `audit_failure`, `audit_verify` | — | Needs the `wd2l_auditor` role; others see it empty |

7. **Reading it: scenarios.** For each row, a Mermaid strip (template below, with the classes
   given) and one table row: what you see, what it means, what to do, link. Rows:

   | Scenario | Rule | Status tile | Boxes (`ok` unless listed) |
   |---|---|---|---|
   | Healthy | — | green | all ok |
   | Planned downtime: sender stopped cleanly | 2 | amber, `e1-sender` | e1-input unknown, e1-sender amber |
   | Nothing arriving: sender down, or the link | 3 | red, `e1-sender/boundary` | e1-input unknown, e1-sender red, boundary red |
   | Tap, fiber or optic down | 1 | red, `boundary` | boundary red |
   | Packets but no wd2l frames | 4 | red, `boundary` | e1-input unknown, e1-sender unknown, boundary red |
   | Aggregator stopped sending | 5 | amber, `e1-input` | e1-input amber |
   | Sender dropping or backed up | 6 | amber, `e1-sender` | e1-sender amber |
   | Loss with receive errors on the capture NIC | 7 | red, `boundary` | boundary red |
   | Loss with kernel drops | 8 | red, `e2-capture` | e2-capture red, e2-receiver red |
   | Loss, nothing else wrong | 9 | amber, `boundary` | boundary amber |
   | SIEM slow, down or refusing | 10 | amber (red if dropped), `e2-siem` | e2-siem amber or red |
   | Archive not being written | 11 | amber, `e2-capture` | e2-capture amber |
   | Time fault | — | unchanged; Time tile red | — |
   | Audit trail fault | — | unchanged; Audit tile red | — |
   | Receiver down | — | stale; "Receiver last heard" red | — (the receiver can't report itself) |

   Mermaid template (one per scenario; set each node's class from the table):

   ````markdown
   ```mermaid
   flowchart LR
     subgraph E1["Enclave 1"]
       A["e1-input"] --> B["e1-sender"]
     end
     B --> C{{"boundary"}}
     subgraph E2["Enclave 2"]
       D["e2-capture"] --> E["e2-receiver"] --> F["e2-siem"]
     end
     C ==> D
     classDef ok fill:#dafbe1,stroke:#1a7f37,color:#1a7f37
     classDef amber fill:#fff8c5,stroke:#9a6700,color:#9a6700
     classDef red fill:#ffebe9,stroke:#cf222e,color:#cf222e
     classDef unknown fill:#eaeef2,stroke:#6e7781,color:#6e7781
     class A,B,C,D,E,F ok
   ```
   ````

8. **Limits.** Three bullets from the spec: while nothing reaches Enclave 2 it can't tell
   "sender down" from "fiber cut" (rule 3), and after recovery an unchanged `boot` means the link
   was the problem; the receiver can't report its own absence (panel 2 and "WD2L - Receiver
   silent"); Enclave 1 has no live view of its own, and its state is only as fresh as the last
   heartbeat that arrived.
9. **Building it in your SIEM.** The Splunk example
   (`deploy/receiver/splunk/wd2l-health-dashboard.json`, Dashboard Studio: Dashboards → Create
   new → Dashboard Studio → Source, paste, save). For another SIEM, the data contract is the
   field list in the Panels table and [operations.md](operations.md); the receiver does the
   reasoning, so each panel is a "latest value" or a "count over time". The example was checked
   for structure, not in a live Splunk: adjust index names (`enclave1`) to yours.
10. **Alerts that go with it.** Table: alert name, fires when, panel. The existing six plus the
    four from Task 4.2, with the daily review report.

- [ ] **Step 2: Draw the mockup**

`docs/images/state-of-health-mockup.svg`: `viewBox="0 0 1440 1730"`, `width="1440"`; a `<title>`
and `<desc>` for accessibility; fonts `system-ui, -apple-system, "Segoe UI", Helvetica, Arial,
sans-serif`; text sizes 11–28; page background `#f4f5f7`; panels white, `stroke="#d0d4da"`,
`rx="6"`; status colors: ok `#1a7f37` on `#dafbe1`, amber `#9a6700` on `#fff8c5`, red `#cf222e`
on `#ffebe9`, unknown `#6e7781` on `#eaeef2`; Enclave 1 series `#0969da`, Enclave 2 series
`#8250df`. Every panel shows its number in a small grey badge at its top-left, matching the
table. Scenario: **fiber or optic errors (rule 7)** at 14:03Z, after a clean planned stop that
morning. Content, top to bottom (x, y, width, height in px):

| Panel | Box | Content |
|---|---|---|
| Header | 0, 0, 1440, 56, fill `#24292f` | "wd2l state of health" (white, 22 px); right: "Last 4 hours ▾", "Refreshed 14:03:22Z"; an amber pill "Mockup: illustrative values" |
| 1 + 1b | 16, 72, 560, 160, red fill | "RED" (28 px bold); "boundary · rule 7" ; "37 events lost with capture NIC receive errors: fiber or optic"; "since 13:41:05Z" |
| 2 | 592, 72, 160, 160, ok | "Receiver last heard"; "12 s" |
| 4 | 768, 72, 152, 160, red | "Open gap events"; "37" |
| 5 | 936, 72, 152, 160, red | "Reconciliation"; "1 of 2 balanced" |
| 6 | 1104, 72, 152, 160, ok | "Time"; "OK"; "skew 0.4 ms" |
| 7 | 1272, 72, 152, 160, ok | "Audit trail"; "E1 ok · E2 ok"; "self-check ok 03:00Z" |
| 3 | 16, 248, 1408, 160 | Three labeled bands: "Enclave 1" (x 16–600), "One-way link" (600–840), "Enclave 2" (840–1424). Six 176×84 boxes at y 296: e1-input x 56 ok "812 events/s in · 3 clients"; e1-sender x 316 ok "0 drops · stall 0.0 s"; boundary x 632 **red** "CRC errors +214 · 37 events lost"; e2-capture x 864 ok "0 kernel drops · archive 0.4 s"; e2-receiver x 1052 ok "CPU 21% · 0 expired"; e2-siem x 1240 ok "spool 0 · 0 rejected". Arrows between boxes; a thick arrow from boundary into e2-capture labeled "TX only" |
| 8 | 16, 424, 1408, 240 | Title "Events in (Enclave 1) vs delivered (Enclave 2), per minute"; y axis 0–60k; x axis 10:00–14:00; blue line ~48–49k/min throughout; purple line overlapping except a shallow dip 13:41–13:58 (to ~47.6k); a flat zero section for both lines 09:12–09:31 shaded grey and labeled "planned downtime" |
| 9 | 16, 680, 696, 200 | "Delay by segment (median, log scale)"; three lines: Enclave 1 ~2 s, Link ~2 ms, SIEM ingest ~3 s; legend |
| 10 | 728, 680, 696, 200 | "Clock skew (ms)"; line near 0.4 ms; dashed lines at +50 and −50 labeled |
| 11 | 16, 896, 696, 200 | "Gaps by reason (events, 5 min)"; stacked columns: `not_received` bars 13:40–14:00 (5, 9, 12, 11); legend shows `not_received`, `receiver_restart`, `output_dropped` |
| 12 | 728, 896, 696, 200 | "Reconciliation by stream" table: header Stream · Last check · Cut · Balanced · Open gaps; row "9f3c41e2a07b55d1 · 14:00:00Z · 4,812,330 · **no** (red) · 37"; row "51aa0c97de3f2b07 · 09:12:31Z · 2,104,880 · yes · 0" |
| 13 | 16, 1112, 1408, 160 | "Fault history" table: 13:41:05Z red boundary rule 7 "37 events lost with capture NIC receive errors: fiber or optic"; 09:31:44Z ok "—"; 09:12:36Z amber e1-sender rule 2 "the sender stopped cleanly (planned downtime?) …" |
| 14–19 | y 1288, height 240; x 16, 254, 492, 730, 968, 1206; width 218 | One key/value table each. 14 Enclave 1 input: events_in 1,284,551,020 · clients 3 · input_backlog_bytes 0 · bad_input 0. 15 Enclave 1 sender: stall_s 0.0 · sender_drops 0 · send_errors 0 · cpu_pct 7.5 · nic_carrier true · nic_tx_errors 0. 16 Boundary (red title bar): nic_carrier true · nic_carrier_changes 2 · nic_rx_crc_errors **+214** · nic_rx_frame_errors +3 · other_packets 0 · bad_frames 0. 17 Enclave 2 capture: nic_rx_packets 9.1 M · kernel_drops 0 · archive_file cap-20261005140000.pcap · archive_age_s 0.4. 18 Enclave 2 receiver: heartbeat_age_s 0.6 · open_gap_events 37 · reasm_expired 0 · cpu_pct 21 · rss_mb 96. 19 Enclave 2 SIEM: hec_queue 12 · hec_spool_files 0 · hec_posts_failed 0 · hec_rejected_events 0 · output_dropped 0 |
| 20 | 16, 1544, 1408, 170 | "Audit events to review (wd2l_auditor role)" table: Time · Host · Component · Event · Actor · Detail. Rows: 09:28:10Z rx01 receiver config_changed "uid=987(wd2l) unit=wd2l-receiver.service" "config hash 3be1… → 9a07…"; 09:12:36Z logsrv01 sender stop "uid=987(wd2l) unit=wd2l-sender.service" "SIGTERM, last_seq 2,104,880"; 03:00:04Z rx01 receiver audit_verify "…" "ok, 41,220 records"; 02:10:55Z logsrv01 sender debug_toggled "uid=0(root) pid=88121 comm=kill auid=1001(jdoe)" "DEBUG" |

Keep the source readable: one `<g>` per panel with an `id` (`p1`, `p2`, … `p20`) and a comment
naming the panel; no scripts, no external fonts or images (GitHub strips them).

- [ ] **Step 3: Check it renders**

Open `docs/state-of-health.md` in VS Code's Markdown preview (or push the branch and view it on
GitHub): the SVG shows inline, every Mermaid strip renders, and the colors match the table. Check
the SVG is well-formed: `T -q` won't, so run
`MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src wd2l-test python -c "import xml.etree.ElementTree as E; E.parse('docs/images/state-of-health-mockup.svg'); print('ok')"`.

- [ ] **Step 4: Commit**

```bash
git add docs/state-of-health.md docs/images/state-of-health-mockup.svg
git commit -m "State-of-health page: what the dashboard shows and how to read it, with a mockup" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.4: The example dashboard

**Files:**
- Create: `deploy/receiver/splunk/wd2l-health-dashboard.json`
- Create: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: the panel table in `docs/state-of-health.md` (titles are the contract) and the field
  names from Phases 1–3.

- [ ] **Step 1: Write the failing tests**

`tests/test_dashboard.py`:

```python
import json
import os
import re

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DASH = os.path.join(REPO, "deploy", "receiver", "splunk", "wd2l-health-dashboard.json")
DOC = os.path.join(REPO, "docs", "state-of-health.md")


def load():
    with open(DASH, encoding="utf-8") as f:
        return json.load(f)


def test_references_resolve_and_everything_is_placed():
    d = load()
    ds, viz = d["dataSources"], d["visualizations"]
    for vid, v in viz.items():
        for ref in v.get("dataSources", {}).values():
            assert ref in ds, (vid, ref)
    for k, s in ds.items():
        if s["type"] == "ds.chain":
            assert s["options"]["extend"] in ds, k
        else:
            q = s["options"]["query"]
            assert "index=wd2l" in q or "index=enclave1" in q or "tstats" in q, k
    width = d["layout"]["options"]["width"]
    placed = {b["item"] for b in d["layout"]["structure"]}
    assert set(viz) <= placed
    for b in d["layout"]["structure"]:
        p = b["position"]
        assert 0 <= p["x"] and p["x"] + p["w"] <= width, b["item"]


def test_dashboard_panels_match_the_state_of_health_page():
    with open(DOC, encoding="utf-8") as f:
        doc_titles = set(re.findall(r"^\| *\d+[a-z]? *\| \*\*(.+?)\*\* \|", f.read(), re.M))
    titles = {v["title"] for v in load()["visualizations"].values() if v.get("title")}
    assert doc_titles and titles == doc_titles, (sorted(doc_titles - titles), sorted(titles - doc_titles))


def test_only_the_review_panel_reads_the_audit_index():
    d = load()
    readers = [k for k, s in d["dataSources"].items()
               if "wd2l_audit" in s["options"].get("query", "")]
    assert readers == ["ds_audit_review"]
```

- [ ] **Step 2: Run them to see them fail**

Run: `T tests/test_dashboard.py -q`
Expected: `FileNotFoundError` for the dashboard.

- [ ] **Step 3: Write the dashboard**

`deploy/receiver/splunk/wd2l-health-dashboard.json`, Dashboard Studio, absolute layout 1440 wide,
positions copied from the mockup table in Task 4.3 (so the dashboard and the picture line up).
Top level:

```json
{
  "title": "wd2l state of health",
  "description": "Where is the fault? Transfer status, pipeline, loss, reconciliation, time and audit trail. See docs/state-of-health.md in the wd2l repo.",
  "inputs": {
    "input_time": {"type": "input.timerange", "title": "Time range",
                   "options": {"token": "tr", "defaultValue": "-4h@m,now"}}
  },
  "defaults": {"dataSources": {"ds.search": {"options": {"queryParameters": {
    "earliest": "$tr.earliest$", "latest": "$tr.latest$"}}}}},
  "dataSources": {},
  "visualizations": {},
  "layout": {"type": "absolute", "options": {"width": 1440, "height": 1730, "backgroundColor": "#f4f5f7"},
             "globalInputs": ["input_time"], "structure": []}
}
```

`dataSources` (every `ds.search` has `"type": "ds.search"` and `"options": {"query": …}`; every
chain has `"type": "ds.chain"` and `"options": {"extend": "ds_latest", "query": …}`, except the
two marked "chain on `ds_sender`", which extend `ds_sender`):

| id | type | query |
|---|---|---|
| `ds_latest` | search | `index=wd2l sourcetype=wd2l:health type=health \| head 1` |
| `ds_status` | chain | `\| eval status=upper(coalesce(fault_status,"unknown")) \| table status` |
| `ds_where` | chain | `\| eval where=if(fault_status="ok","All segments ok",fault_segment." (rule ".fault_rule.")") \| table where fault_detail` |
| `ds_segments` | chain | `\| table seg_e1_input seg_e1_sender seg_boundary seg_e2_capture seg_e2_receiver seg_e2_siem \| foreach seg_* [eval <<FIELD>>=upper('<<FIELD>>')]` |
| `ds_open_gaps` | chain | `\| table open_gap_events` |
| `ds_time` | chain | `\| eval time=upper(coalesce(time_status,"unknown")), skew_ms=round(clock_offset_s*1000,1) \| table time skew_ms` |
| `ds_d_boundary` | chain | `\| table nic_carrier nic_carrier_changes nic_rx_crc_errors nic_rx_frame_errors other_packets bad_frames \| transpose 0 column_name=signal \| rename "row 1" as value` |
| `ds_d_capture` | chain | same pattern with `nic_rx_packets kernel_drops archive_file archive_age_s` |
| `ds_d_receiver` | chain | same pattern with `heartbeat_age_s open_gap_events reasm_expired cpu_pct rss_mb` |
| `ds_d_siem` | chain | same pattern with `hec_queue hec_spool_files hec_posts_failed hec_rejected_events output_dropped` |
| `ds_heard` | search | `\| tstats latest(_time) as t where index=wd2l sourcetype=wd2l:health \| eval age_s=round(now()-t) \| table age_s` |
| `ds_reconcile` | search | `index=wd2l sourcetype=wd2l:health type=reconcile earliest=-25h \| stats latest(balanced) as b by stream \| stats count as streams count(eval(b="true")) as ok \| eval shown=ok." of ".streams." balanced", state=if(ok=streams,"OK","RED") \| table shown state` |
| `ds_audit` | search | `index=wd2l type=health (sourcetype=wd2l:health OR sourcetype=wd2l:sender:health) \| stats latest(audit_ok) as ok latest(audit_verify) as verify by component \| eval good=if(ok="true" AND coalesce(verify,"")!="failed",1,0) \| stats min(good) as all_good values(component) as sides \| eval state=if(all_good=1,"OK","RED") \| table state sides` |
| `ds_flow` | search | `index=wd2l sourcetype=wd2l:health type=health \| sort 0 _time \| streamstats current=f last(sender_events_in) as p_in last(events_delivered) as p_out \| eval e1=if(sender_events_in>=p_in,sender_events_in-p_in,null()), e2=if(events_delivered>=p_out,events_delivered-p_out,null()) \| timechart span=1m sum(e1) as "Events in (Enclave 1)" sum(e2) as "Delivered (Enclave 2)"` |
| `ds_delay` | search | `index=enclave1 \| eval e1=wd2l_tx_time-_time, link=wd2l_rx_time-wd2l_tx_time, siem=_indextime-wd2l_rx_time \| timechart span=5m median(e1) as "Enclave 1 (s)" median(link) as "Link (s)" median(siem) as "SIEM ingest (s)"` |
| `ds_skew` | search | `index=wd2l sourcetype=wd2l:health type=health \| eval skew_ms=clock_offset_s*1000 \| timechart span=1m max(skew_ms) as "Clock skew (ms)" \| eval "+50 ms"=50, "-50 ms"=-50` |
| `ds_gaps` | search | `index=wd2l sourcetype=wd2l:health type=gap \| eval reason=coalesce(reason,"not_received").if(records="true"," (records)","") \| timechart span=5m sum(count) by reason` |
| `ds_reconcile_table` | search | `index=wd2l sourcetype=wd2l:health type=reconcile \| stats latest(_time) as t latest(cut) as cut latest(balanced) as balanced latest(gaps_open) as open_gaps by stream \| sort - t \| eval "last check"=strftime(t,"%F %TZ") \| fields - t \| head 10` |
| `ds_faults` | search | `index=wd2l sourcetype=wd2l:health type IN (fault, time_status) \| eval what=if(type="fault",fault_status." ".coalesce(fault_segment,"").if(fault_rule>0," rule ".fault_rule,""),"time ".time_status), detail=coalesce(fault_detail,time_reason) \| table _time what detail \| head 50` |
| `ds_sender` | search | `index=wd2l sourcetype=wd2l:sender:health type=health \| head 1` |
| `ds_d_input` | chain on `ds_sender` | `\| table events_in clients input_backlog_bytes bad_input \| transpose 0 column_name=signal \| rename "row 1" as value` |
| `ds_d_sender` | chain on `ds_sender` | same pattern with `stall_s sender_drops send_errors cpu_pct nic_carrier nic_tx_errors` |
| `ds_audit_review` | search | `index=wd2l_audit event IN (config_changed, state_reset, replay_run, debug_toggled, audit_failure, audit_verify) \| table _time host component event outcome actor reason level \| head 50` |

`visualizations` (ids → type → title → data source), one per panel-table row in Task 4.3, with
the **exact** titles from that table:

| id | type | title | primary |
|---|---|---|---|
| `viz_status` | `splunk.singlevalue` | Transfer status | `ds_status` |
| `viz_where` | `splunk.table` | Where and why | `ds_where` |
| `viz_heard` | `splunk.singlevalue` | Receiver last heard | `ds_heard` |
| `viz_pipeline` | `splunk.table` | Pipeline | `ds_segments` |
| `viz_open_gaps` | `splunk.singlevalue` | Open gap events | `ds_open_gaps` |
| `viz_reconcile` | `splunk.singlevalue` | Reconciliation | `ds_reconcile` |
| `viz_time` | `splunk.singlevalue` | Time | `ds_time` |
| `viz_audit` | `splunk.singlevalue` | Audit trail | `ds_audit` |
| `viz_flow` | `splunk.line` | Events in vs delivered | `ds_flow` |
| `viz_delay` | `splunk.line` | Delay by segment | `ds_delay` |
| `viz_skew` | `splunk.line` | Clock skew | `ds_skew` |
| `viz_gaps` | `splunk.column` | Gaps by reason | `ds_gaps` |
| `viz_reconcile_table` | `splunk.table` | Reconciliation by stream | `ds_reconcile_table` |
| `viz_faults` | `splunk.table` | Fault history | `ds_faults` |
| `viz_d_input` | `splunk.table` | Enclave 1 input | `ds_d_input` |
| `viz_d_sender` | `splunk.table` | Enclave 1 sender | `ds_d_sender` |
| `viz_d_boundary` | `splunk.table` | Boundary | `ds_d_boundary` |
| `viz_d_capture` | `splunk.table` | Enclave 2 capture | `ds_d_capture` |
| `viz_d_receiver` | `splunk.table` | Enclave 2 receiver | `ds_d_receiver` |
| `viz_d_siem` | `splunk.table` | Enclave 2 SIEM | `ds_d_siem` |
| `viz_audit_review` | `splunk.table` | Audit events to review | `ds_audit_review` |

The single values color by text. For example `viz_status`:

```json
"viz_status": {
  "type": "splunk.singlevalue",
  "title": "Transfer status",
  "dataSources": {"primary": "ds_status"},
  "options": {
    "majorValue": "> primary | seriesByName('status') | lastPoint()",
    "majorColor": "> majorValue | matchValue(statusColors)"
  },
  "context": {"statusColors": [
    {"match": "OK", "value": "#1a7f37"}, {"match": "AMBER", "value": "#9a6700"},
    {"match": "RED", "value": "#cf222e"}, {"match": "UNKNOWN", "value": "#6e7781"}]}
}
```

`viz_time`, `viz_reconcile` (`seriesByName('state')`, showing `shown` as the trend label is not
needed) and `viz_audit` use the same `statusColors` on their `time` / `state` field.
`viz_open_gaps` and `viz_heard` color by number:

```json
"options": {
  "majorValue": "> primary | seriesByName('open_gap_events') | lastPoint()",
  "majorColor": "> majorValue | rangeValue(gapRanges)"
},
"context": {"gapRanges": [{"to": 1, "value": "#1a7f37"}, {"from": 1, "value": "#cf222e"}]}
```

(`viz_heard`: ranges `to 90` green, `90–900` amber, `from 900` red on `age_s`.) The line and
column charts use `"options": {"legendDisplay": "bottom"}`; `viz_delay` adds
`"yAxisScale": "log"`. `viz_pipeline` is a one-row table of the six `seg_*` columns, each cell
colored by its value (same `statusColors` context):

```json
"options": {"columnFormat": {
  "seg_e1_input": {"rowBackgroundColors": "> table | seriesByName(\"seg_e1_input\") | matchValue(statusColors)"},
  "seg_e1_sender": {"rowBackgroundColors": "> table | seriesByName(\"seg_e1_sender\") | matchValue(statusColors)"}
}}
```

with the same entry for the other four columns. (If your Splunk version formats tables
differently, use six single values instead, one per segment, colored like `viz_status`, and keep
the title "Pipeline" on a rectangle behind them.) Layout
`structure`: one `{"item": id, "type": "block", "position": {"x", "y", "w", "h"}}` per
visualization at the mockup's box (1 and 1b share the first box: status in the top 80 px, where
in the bottom 80 px).

- [ ] **Step 4: Run the tests**

Run: `T tests/test_dashboard.py -q`
Expected: all pass. If `test_dashboard_panels_match_the_state_of_health_page` fails, fix the
title on whichever side drifted, keeping the page's wording.

- [ ] **Step 5: Commit**

```bash
git add deploy/receiver/splunk/wd2l-health-dashboard.json tests/test_dashboard.py
git commit -m "Example Dashboard Studio dashboard matching the state-of-health page" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.5: Runbooks and guides

**Files:**
- Modify: `docs/operations.md`, `docs/planned-downtime.md`, `docs/deployment/receiver.md` (§5),
  `docs/deployment/retention-server.md` (§6), `docs/architecture.md`, `README.md`

No code. Each edit is listed so nothing is missed; write it in the docs' style.

- [ ] **Step 1: `docs/operations.md`**

* Intro: health records are in `index=wd2l` (`wd2l:health` from the receiver,
  `wd2l:sender:health` from the sender, in-band); audit records in `index=wd2l_audit` (auditor
  role); the dashboard is described in [state-of-health.md](state-of-health.md).
* Health records table: add `fault` (fields from Task 2.8), `time_status`, `reconcile`
  (Task 3.3); note that every record now carries `host`, `enclave`, `component`, `version`,
  and that records-stream records carry `records: true`.
* `health` counters table: add `records_delivered`, `records_bad`, `fault_status`,
  `fault_segment`, `fault_rule`, `fault_detail`, `seg_*`, `time_status`, `time_reason`,
  `time_quality`, `audit_ok`, `audit_n`, `audit_hash`, `audit_verify`, `reconcile_unbalanced`,
  `sender_events_in`, `packet_age_s`, `frame_age_s`, `nic_*`, `archive_*`, `cpu_pct`, `rss_mb`,
  each with "Healthy" values.
* New section **Alert: fault segment**: read `fault_segment` and `fault_rule`, then the scenario
  table in state-of-health.md; what to check per segment; rule 3's boot check after recovery.
* New section **Alert: reconciliation not balanced**: with open gaps, replay or re-send; with
  none, compare `wd2l-audit-report reconcile` for the day, check for `digest_mismatch` /
  `boundary_anomaly`, treat as an incident. Then the part the receiver can't see, the SIEM's own
  completeness (§9): count what the SIEM holds per stream and compare it with what the receiver
  delivered:

  ```
  index=enclave1 wd2l_stream=<stream> | stats dc(wd2l_seq) as in_siem max(wd2l_seq) as max_seq
  index=wd2l sourcetype=wd2l:health type=reconcile stream=<stream> | head 1 | table cut events_delivered gaps_open
  ```

  `in_siem` should equal `events_delivered`. Fewer means the SIEM lost or refused events after
  accepting them; look at `<spool>/rejected/` and the SIEM's own ingest errors.
* New section **Alert: audit trail**: `audit_ok=false` (disk space, permissions, the
  `audit_failure` reason); `audit_verify=failed` (run `wd2l-audit-report verify --dir
  /var/log/wd2l`, compare with the log retention server's copy and the SIEM export, follow the
  incident process). The transfer keeps going (§10).
* New section **Alert: time quality**: which side, `chronyc tracking`, the GPS receiver and the
  stratum-2 switch.
* New section **Audit records**: where they are (files on each host, SIEM index, log retention
  server for Enclave 1), how to verify (`python3 -m wd2l.audit verify`, `wd2l-audit-report
  verify --dir` / `--export`), the reports (`reconcile`, `events`, with one example each), and
  `SIGUSR1` (`sudo kill -USR1 "$(systemctl show -p MainPID --value wd2l-receiver)"`).
* Routine → Disk: add `/var/log/wd2l` (under 2 GB a year).

- [ ] **Step 2: `docs/planned-downtime.md`**

* "Mute two SIEM alerts" becomes three: add "WD2L - Fault segment". Add one sentence: while the
  sender is stopped cleanly the dashboard shows amber, `e1-sender`, rule 2, not red.
* Step 2: with `--log-format json` the last journal line is JSON; "The last line reads `final:
  last_seq=<N> …`" becomes "The last line's message reads …", and give
  `journalctl -u wd2l-sender -n 3 -o cat | grep -o '"msg": "[^"]*"'`.
* Step 10: add a check for auditors:
  `index=wd2l_audit earliest=-2h event IN (stop, start, state_loaded, config_changed) | table _time host component event actor`
  (expect a `stop` and a `start` on each side you restarted, and `state_loaded`, not
  `state_reset`), and that the alerts to re-enable are three.

- [ ] **Step 3: The other guides**

* `docs/deployment/receiver.md` §5: indexes now `enclave1`, `wd2l`, `wd2l_audit` (1 year,
  auditor role only); two tokens (the main one must not be allowed to write `wd2l_audit`); JSON
  parsing for the four sourcetypes; the alerts list grows to ten plus the daily review; the
  dashboard JSON and [state-of-health.md](../state-of-health.md). Splunk file list: add
  `authorize.conf` and `wd2l-health-dashboard.json`. §6 checks: add
  `index=wd2l sourcetype=wd2l:health type=health | head 1 | table fault_status time_status audit_ok audit_verify reconcile_unbalanced`
  and `index=wd2l sourcetype=wd2l:sender:health | head 1`.
* `docs/deployment/retention-server.md` §6: heading "wd2l audit files" (drop "proposed"); the
  files now exist (`/var/log/wd2l/audit-*.jsonl` on the log server); the 1-year home is still to
  be confirmed by the security owner (audit plan §17, item 5); how to check a copy:
  `wd2l-audit-report verify --dir <copy>`.
* `docs/architecture.md`, "Pieces": one bullet each for audit records (hash-chained, both hosts,
  in-band from Enclave 1) and fault location (the receiver decides; the dashboard draws it),
  linking to the audit plan and state-of-health.md.
* `README.md`: repo map rows for `wd2l/audit.py`, `wd2l/hostinfo.py`, `wd2l/logsetup.py`,
  `wd2l/fault.py`, `wd2l/reconcile.py`, `wd2l/audit_report.py`, `deploy/common/`; the test count
  in "Try it" (run `T -q` and use the number it prints); the lab line for `--fault`; Deploying
  gains "7. [State of health](docs/state-of-health.md): what the dashboard shows and how to read
  it"; Status: replace the "Next: …" paragraph with one saying audit records, reconciliation and
  fault location are built and verified in the lab (link the audit plan, now "as built", and
  state-of-health.md), keeping the framework examples as examples.

- [ ] **Step 4: Check links and alert names**

Run: `T tests/test_siem_config.py tests/test_dashboard.py -q` (alert names quoted in the docs
must exist; dashboard titles must match the page). Then check every relative link you added
resolves: `git grep -n "state-of-health.md\|audit-and-health-plan.md" docs README.md` and open
each target.

- [ ] **Step 5: Commit**

```bash
git add docs/ README.md
git commit -m "Runbooks and guides: fault, reconciliation, audit and time alerts; audit records; dashboard" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4.6: The audit plan, as built; final verification

**Files:**
- Modify: `docs/audit-and-health-plan.md`
- Modify: `docs/superpowers/plans/2026-10-05-audit-and-health/README.md` (close out the
  As-built log)

**Goal:** the page keeps every section and sentence of the proposal (the user wants none of it
lost) and says, section by section, what was built and how it differs. It points to
[state-of-health.md](../../../state-of-health.md) as the way to monitor it.

- [ ] **Step 1: Header and a summary section**

* Title: "# Audit records and health monitoring for wd2l" (drop "Plan:").
* Replace the status paragraph with: "**Status: built in wd2l 0.2.0 (<date of the merge>).** This
  page keeps the proposal as it was reviewed on 2026-10-05. Each section ends with an **As
  built** note saying what was built and where it differs. To watch the system day to day, use
  the dashboard described in [state-of-health.md](state-of-health.md); to act on alerts, see
  [operations.md](operations.md)." Keep the sentence about the interface description, runbook
  and ADR-0003.
* Add a new section right after §2, **"2a. As built at a glance"**: a table with one row per
  section (§3–§17): `Section` | `Proposed` (a few words) | `As built` ("as proposed", or the
  difference in a few words) | `Where` (code path, doc, test file). Fill it from the As-built log
  in the plan README and from the code.

- [ ] **Step 2: One "As built" note per section**

At the end of each section §3–§17, add a blockquote starting `> **As built:**`. Write each from
the code and the As-built log, not from memory. At minimum:

* §3: add a column `Closed by` to the gaps table (G1: sender audit catalog, records stream; G2:
  `start`/`config`/`config_changed` with `code_sha256`; G3: `actor`, `debug_toggled` via
  `sigwaitinfo`, `replay_run`; G4: set hashes, `reconcile`; G5: hash chain, own index and token,
  `wd2l_auditor`; G6: chrony `time_quality`, `time_status`; G7: heartbeat snapshot, NIC and
  archive probes, fault rules; G8: 1-year timer, 366 days; G9: rule 2 amber, `stop`/`start`
  records).
* §4: the three kinds exist as proposed; forwarded Enclave 1 health lands in `wd2l` with
  sourcetype `wd2l:sender:health`.
* §5: fields as proposed, plus `code_sha256` and `python` on `start`; unchained records.
* §6: the summarised events (auth_failure, gap_filled), the two added events, the
  `audit_failure` reasons.
* §7: records stream as proposed; not linked across runs; index chosen by the receiver; data
  events can't reach the audit index; `heartbeat_trimmed`; `events_in` meaning.
* §8: every signal named, with the `archive_stale` approach.
* §9: as proposed, plus `type=reconcile` health records and balance-change records;
  `wd2l-audit-report` subcommands as built (with `--export` and `--complete`).
* §10: failure handling details, torn lines, self-check in a child process, the lock, the timer
  and rules files by path.
* §11: as proposed, with `type=time_status` records.
* §12: rules 1–11 as built (segment names, `unknown`), and: **"How to present this to an
  operator, panel by panel, with a mockup: [state-of-health.md](state-of-health.md)."** The
  example dashboard path.
* §13: the alert names as they are in `savedsearches.conf`, and the daily review report.
* §14: unchanged mapping; one sentence that the rows now point at built features (the `Where`
  column of 2a).
* §15: measured sizes from a lab run (`du -sh lab/out/audit-e*` after `sudo lab/run-lab.sh
  --events 25000 --eps 5000`), scaled to 1,000 events/s, next to the estimates.
* §16: each phase marked done with its commits or PR; the test files per area; the nine lab
  fault runs with their results as CI prints them.
* §17: each open item is still open for the owners; say which default the code implements
  (keep transferring; 100 ms / 50 ms; the retention server as the proposed home).

- [ ] **Step 3: Check nothing was lost**

Compare old and new: every line of the original must still be there, unchanged, except the title
and status paragraph:

```bash
git diff main --word-diff=porcelain -- docs/audit-and-health-plan.md | grep '^-[^-]'
```

The only removed words printed should be from the old title and status paragraph. Fix anything
else.

- [ ] **Step 4: Final verification**

* `T -q` on 3.9, and once on 3.12:
  `printf 'FROM python:3.12-slim\nRUN pip install -q pytest\n' | docker build -q -t wd2l-test-312 -`
  then the same `T` command with `wd2l-test-312`.
* The byte-compile command from the plan README.
* Push; the CI `tests` and `lab` jobs (16 lab runs: the 7 existing plus 9 faults) pass.
* README test count matches what pytest printed.
* In the plan README, close the As-built log (every row has a matching "As built" note in the
  page).

- [ ] **Step 5: Commit**

```bash
git add docs/audit-and-health-plan.md docs/superpowers/plans/2026-10-05-audit-and-health/README.md
git commit -m "Audit plan: as built vs proposed, section by section; points to the state-of-health page" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**Phase 4 checkpoint:** everything green; ready for `superpowers:finishing-a-development-branch`.
