# Audit records and health monitoring: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build what [docs/audit-and-health-plan.md](../../../audit-and-health-plan.md) proposes:
hash-chained audit records on both sides, Enclave 1's records carried in-band to Enclave 2, new
health signals, fault location by segment, end-to-end reconciliation, an audit report tool, the
SIEM pieces and a state-of-health dashboard. Then rewrite the proposal as "as built vs
proposed" without losing its content.

**Architecture:** Four new standard-library modules carry the new logic: `wd2l/audit.py` (record
format, hash chain, append-only writer, verification), `wd2l/hostinfo.py` (identity, build,
chrony, NIC, archive, CPU/memory), `wd2l/fault.py` (decision rules) and `wd2l/reconcile.py` (set
hash). `wd2l/logsetup.py` handles JSON logs and `SIGUSR1`, and `wd2l/audit_report.py` is the
report command. `sender.py`, `receiver.py`, `outputs.py` and `wire.py` get hooks into them.
Everything is off unless the new flags are given, so existing behavior, tests and lab runs are
unchanged until the systemd units turn it on (Phase 4).

**Tech Stack:** Python ≥ 3.9, standard library only. pytest. Bash, iproute2, nftables and tcpdump
for the namespace lab. Splunk example configs and a Dashboard Studio JSON (examples only; any
SIEM works). SVG and Mermaid for the dashboard mockups.

**Spec:** [docs/audit-and-health-plan.md](../../../audit-and-health-plan.md). Executors read it
and this plan together. Section numbers (§n) below refer to it.

## Phases

| Phase | File | Delivers | Tasks |
|---|---|---|---|
| 1 | [phase-1-audit-records.md](phase-1-audit-records.md) | Audit records on both sides: format, hash chain, files, self-check, the event catalog, JSON logs, `SIGUSR1`, time quality | 1.1–1.10 |
| 2 | [phase-2-records-stream-and-fault-location.md](phase-2-records-stream-and-fault-location.md) | Enclave 1 records in-band (records stream), heartbeat snapshot, new health signals, fault rules, lab `--fault` runs | 2.1–2.9 |
| 3 | [phase-3-reconciliation-and-report.md](phase-3-reconciliation-and-report.md) | Set hashes, `reconcile` records, `wd2l-audit-report` | 3.1–3.5 |
| 4 | [phase-4-siem-deploy-and-docs.md](phase-4-siem-deploy-and-docs.md) | Units, append-only timer, auditd rules, SIEM configs, alerts, **state-of-health doc with dashboard mockups**, Dashboard Studio JSON, runbooks, and the as-built rewrite of the audit plan | 4.1–4.6 |

Each phase ends with the full test suite green and can be merged on its own. Phases depend on
the ones before them. Tasks inside a phase are in order: later tasks use names defined by
earlier ones (see each task's **Interfaces** block).

## Global constraints

Every task's requirements include these. Values are copied from the spec or the repo.

* **Python ≥ 3.9, standard library only.** No new dependencies (`pyproject.toml`
  `dependencies = []`). No 3.10+ syntax: no `match`, no `X | Y` outside annotations, no
  `dataclass(slots=...)`, no `zip(strict=...)`. CI byte-compiles with 3.9
  (`python -m compileall -q wd2l lab tests`).
* **Linux only at run time** (`fcntl`, `/proc`, `/sys`, `AF_PACKET`, `sigwaitinfo`). Tests run on
  Linux: in CI, or in Docker locally (below).
* **Direction:** audit and health data stays in the enclave where it was made, or moves from
  Enclave 1 to Enclave 2 with the logs. Nothing goes back. Link to the README's direction rule;
  don't restate it.
* **No log content in health or audit records.** Only metadata, counts and hashes, never a data
  event's `_raw` (§4).
* **Wire version stays 1.** New things use `flags` bit 0 and new optional heartbeat keys. Any
  change to what crosses the link updates
  [interface-description.md](../../../interface-description.md) and
  [wire-format.md](../../../wire-format.md) **in the same commit** (§2, "Interface").
* **Every heartbeat must fit one packet** at MTU 1500: body ≤ 1,404 bytes
  (`wire.DEFAULT_MAX_DATAGRAM − wire.OVERHEAD`).
* **Health records keep `type` and `time`** (epoch seconds) and every existing key. New keys only
  (§5).
* **Operational log texts stay the same:** `final: last_seq=…`, `boot … after stream …`, and the
  per-minute `stream=… last_seq=…` line, which [planned-downtime.md](../../../planned-downtime.md)
  checks (§4).
* **Audit files:** `<dir>/audit-<UTC start time>.jsonl`, mode 0640, one `write` + one `fsync` per
  record, a new file past 64 MiB, never renamed or truncated, one writer per directory (lock
  file) (§10).
* **Hash chain:** `hash` = SHA-256 of the record as canonical JSON (keys sorted, no spaces, UTF-8)
  without `hash`; the first `prev_hash` is 64 zeros; `n` counts 1, 2, 3, … (§5, §10).
* **Audit failure:** keep transferring (§10, open item 2).
* **Retention:** 1 year; the timer deletes files older than 366 days (§10).
* **Time thresholds:** alarm when unsynced, stratum > 3, or |offset| > 100 ms; skew alarm over
  50 ms (§11, open item 3).
* **Defaults don't change behavior.** Without `--audit-dir` and the other new flags, the sender
  and receiver behave exactly as today. Existing tests pass unchanged unless a task says why.
* **Docs:** framework-neutral (controls named in plain words; NIST SP 800-53 and SOC 2 only as
  examples, "e.g. NIST AU-11; SOC 2 CC7.2"). Say "security owner". Don't rewrite the ADRs or
  `accreditation-notes.md`. Product-neutral: Splunk files are examples. Plain, short sentences,
  like the existing docs.

## Review focus

Inputs and failure modes the spec implies but is quiet about, most likely to bite first. Each
one has a test in the task that owns the code.

1. **The audit disk fills, or the audit file can't be written, mid-run.** The transfer must keep
   going, records must still be forwarded, `audit_ok` must turn false, and afterwards the chain on
   disk must still verify (a partial last line reported as torn, not as tampering). Test:
   Task 1.3 `test_write_failure_keeps_going_and_chain_still_verifies`.
2. **An archive replay started while the live receiver is running** on the same audit directory.
   It must refuse with a clear message, not interleave two chains. Test: Task 1.8
   `test_replay_refuses_while_another_process_holds_the_audit_dir`.
3. **The largest possible heartbeat.** With every counter at 19 digits, `prev_stream` at 20
   digits and `events_hash` at 64 hex digits, it must still fit one packet, and a heartbeat that
   wouldn't fit must fall back rather than fail to send forever. Tests: Task 2.5
   `test_heartbeat_falls_back_if_the_snapshot_would_not_fit`, Task 3.2
   `test_worst_case_heartbeat_fits_one_packet`.
4. **Aggregator events posing as audit records** (`sourcetype=wd2l:sender:audit`,
   `index=wd2l_audit`), and `--force-index`. They must stay in the data stream and out of the
   audit index; audit records must never move. Tests: Task 2.3
   `test_aggregator_event_claiming_audit_sourcetype_stays_data`, Task 1.7
   `test_data_event_cannot_land_in_the_audit_index`.
5. **Receiver crash, restart and archive replay in the middle of reconciliation.** The set hash
   must survive the restart, re-delivered events must count once, and the balance must return
   once the replay fills the gaps. Test: Task 3.3
   `test_crash_replay_restores_the_balance`.

Also covered: `chronyc` missing or hanging (Task 1.2), a clock step while running (existing
steady clock), audit records too big for one event (Task 2.2).

## File map

| File | Status | Responsibility |
|---|---|---|
| `wd2l/audit.py` | new | Canonical JSON, record hash, chain verification, `AuditLog` writer, `Summarizer`, `python -m wd2l.audit verify` (self-check) |
| `wd2l/hostinfo.py` | new | Hostname, actor, signal actor, build id, code hash, chrony time quality, CPU/memory, NIC counters, capture archive age |
| `wd2l/logsetup.py` | new | Text or JSON operational logs tagged by segment; `SignalWatcher` (`sigwaitinfo`) and the `SIGUSR1` debug toggle |
| `wd2l/fault.py` | new | `Signals`, `Fault`, `evaluate()` (rules 1–11), `time_status()`, `FaultTracker` |
| `wd2l/reconcile.py` | new | `SetHash`, `StreamReconciler` |
| `wd2l/audit_report.py` | new | `wd2l-audit-report` CLI: `verify`, `reconcile`, `events` |
| `wd2l/wire.py` | modify | `FLAG_RECORDS`, `flags=` and `digest=` on the encoders, `event_digest()` |
| `wd2l/sender.py` | modify | Audit catalog, records stream, heartbeat snapshot, set hash, new CLI flags, `build_parser()` |
| `wd2l/receiver.py` | modify | Audit catalog, records-stream routing, signals, fault evaluation, reconciliation, new CLI flags, `build_parser()` |
| `wd2l/outputs.py` | modify | `audit()` and `forwarded()` on every output; HEC audit token and index; audit-index guard |
| `wd2l/packets.py` | modify | `iter_pcap_paths(..., digests=)` hashes files while reading |
| `wd2l/__init__.py`, `pyproject.toml` | modify | Version 0.2.0; `wd2l-audit-report` script |
| `tests/helpers.py` | modify | `MemOutput.audit/forwarded`, `write_pcap`, `read_audit` |
| `tests/test_audit.py`, `test_hostinfo.py`, `test_logsetup.py`, `test_sender_audit.py`, `test_outputs_audit.py`, `test_receiver_audit.py`, `test_records_stream.py`, `test_sender_health.py`, `test_receiver_signals.py`, `test_fault.py`, `test_reconcile.py`, `test_receiver_reconcile.py`, `test_audit_report.py`, `test_deploy.py`, `test_siem_config.py`, `test_dashboard.py` | new | Unit and integration tests per task |
| `lab/run-lab.sh`, `lab/verify.py`, `lab/fake_cribl.py` | modify | Audit on in every run, `--fault NAME`, audit and reconciliation checks |
| `lab/fake_chronyc.py`, `lab/fake_siem.py`, `lab/check_fault.py` | new | Lab stand-ins and the fault check |
| `.github/workflows/tests.yml` | modify | Nine `--fault` lab runs |
| `deploy/log-server/wd2l-sender.service`, `deploy/receiver/wd2l-receiver.service` | modify | Audit dir, JSON logs, egress/capture probes, audit token |
| `deploy/common/wd2l-audit-seal.{sh,service,timer}` | new | Hourly `chattr +a`, delete after 366 days |
| `deploy/log-server/wd2l.rules`, `deploy/receiver/wd2l.rules` | new | Host auditd rules |
| `deploy/receiver/splunk/*.conf`, `authorize.conf`, `wd2l-health-dashboard.json` | modify/new | Audit index, token, auditor role, alerts, dashboard |
| `docs/state-of-health.md`, `docs/images/state-of-health-mockup.svg` | new | What the dashboard shows and how to read it, with mockups |
| `docs/audit-and-health-plan.md` | modify (last) | As built vs proposed, cross-referenced to the state-of-health doc |
| `docs/*.md` (ICD, wire format, operations, planned downtime, deployment, running the lab, README, architecture) | modify | In the task whose change needs them |

## Running tests on this machine

There is no Python on the Windows host. CI (`.github/workflows/tests.yml`) runs pytest on Ubuntu
with 3.9 and 3.12, and the namespace lab as root. Locally, use Docker Desktop (start it first).
From Git Bash at the repo root:

```bash
# once: a small image with pytest
printf 'FROM python:3.9-slim\nRUN pip install -q pytest\n' | docker build -q -t wd2l-test -

# T runs pytest in it; extra arguments go to pytest
T() { MSYS_NO_PATHCONV=1 docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
      -v "$(pwd -W)":/src -w /src wd2l-test python -m pytest -p no:cacheprovider "$@"; }

T -q                                   # whole suite
T tests/test_audit.py::test_name -v    # one test
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src wd2l-test \
    python -m compileall -q wd2l lab tests     # what CI's 3.9 byte-compile step checks
```

Every "Run:" line in the tasks uses `T`. Tests write only to pytest's `tmp_path` inside the
container, so file modes and `flock` behave as on Linux.

The lab needs root and network namespaces. Try it in a privileged container; Docker Desktop's
kernel may lack `act_mirred`, in which case the CI `lab` job is the check:

```bash
MSYS_NO_PATHCONV=1 docker run --rm --privileged -v "$(pwd -W)":/src -w /src ubuntu:24.04 bash -c \
  "apt-get update -qq && apt-get install -y -qq iproute2 nftables tcpdump python3 >/dev/null && lab/run-lab.sh"
```

## As-built log

The final task (4.6) turns this list into the "as built" notes in the audit plan. **Whenever an
implementation differs from the spec, add a line here in the same commit:** task, spec section,
what was built instead, and why. These differences are already decided by this plan:

| Task | Spec | Built | Why |
|---|---|---|---|
| 1.3 | §10 failure handling | A record the file can't hold is still forwarded, with `n`, `prev_hash` and `hash` set to null ("unchained"). After any failed write, writing resumes in a new file. `audit_failure` has `reason` `write_failed`, `recovered` (with `missed`), `torn_write`, `low_space` or `space_ok` | Never append after a partial line; the file chain stays verifiable |
| 1.3 | §10 self-check | Runs `python3 -m wd2l.audit verify DIR --upto N --upto-hash H` as a child process, checking up to the writer's position at that moment | A daily full read in-process would compete with the receiver's capture loop for the interpreter lock |
| 1.1 | §10 verify | A partial last line of a file is reported as `torn`, not as a break | A crash or full disk mid-write isn't tampering |
| 1.6 | §6 `auth_failure` | Summarised per minute, like `input_rejected` | An aggregator retrying a bad token every second would write 86,400 records a day |
| 1.8 | §6 `gap_filled` | Summarised per minute per stream (`count`, `seq_first`, `seq_last`) | An archive replay can fill 100,000 events at once |
| 1.8 | §6 catalog | `sender_boot_reset` and `stream_evicted` are audited too | They are evidence about completeness, like `stream_missing` |
| 1.6, 1.8 | §6 `config_changed` | Compares with the config hash saved in the state file, so it needs `--state` | The state file already holds "the previous run" |
| 1.6, 1.8 | §5 `start` | Adds `code_sha256` (SHA-256 over the package's `.py` files) and `python` | Proves the running code, not only the configuration |
| 2.2 | §7 records stream | Exists when `--audit-dir` is set. Not linked across runs (no `boot`/`prev_stream`). The receiver chooses the index; the sender doesn't set one | Lost records are already visible as records-stream gaps, and the local files are the official copy |
| 2.3 | §7 routing | Data events naming the audit index are moved to the default index and counted (`hec_audit_index_refused`) | Defense in depth beside the token's index list |
| 2.3 | §7 file output | Forwarded Enclave 1 health goes to `e1-health.jsonl`, forwarded audit to `audit.jsonl` | Keeps the lab's `health.jsonl` the receiver's own |
| 2.5 | §7 `events_in` | Input lines that were events or were rejected | Same signal as "events in", and cheap |
| 2.5 | §7 heartbeat | If the snapshot would make the heartbeat too big for one packet, the snapshot keys are dropped and `heartbeat_trimmed` counts it | A heartbeat that can't be sent breaks liveness |
| 2.6 | §8 `tcpdump running` | Measured as "packets arrive but the newest archive file isn't being written" (`archive_stale`) | Works without seeing other users' processes (`ProtectProc`, `hidepid`) and catches a stuck tcpdump too |
| 2.7 | §12 rules | Segment colors include `unknown` (grey) for what the receiver can't see during silence. Rule 3's segment is `e1-sender/boundary`; rule 8's is `e2-capture` | One value for alerts to group on; grey is more honest than green |
| 2.8 | §12 time | Time status changes are also written as `type=time_status` records | Lets the time alert fire at once, not on the next summary |
| 3.3 | §9 `reconcile` | Also written when an ended stream's balance changes (for example after a replay fills its gaps) | That is the evidence the replay worked |
| 3.3 | §9, §12 | Each reconcile result is also a `type=reconcile` health record (stream, cut, balanced, open gaps) | Operators can't read the audit index; the dashboard and the alert need the balance |
| 1.3 | §10, §12 | Health records carry `audit_verify` (the last self-check: `ok`, `failed` or null) next to `audit_ok` | Same reason: the audit-trail tile and alert read the health index |
| 4.2 | §13 | Every alert reads only the health index; only the daily review report reads `wd2l_audit` | Alert owners don't need the auditor role |
| 1.1 | §10 verify | Lines that aren't valid JSON for the chain (NaN/Infinity numbers, too deeply nested) are reported as problems; the verifier never crashes on them (`wd2l/audit.py` ChainChecker.add, verify_lines) | A tamper check must report hostile input, not stop |
| 1.3 | §5, §10 | Field values JSON can't hold (NaN, Infinity, bytes, sets, paths) are written as null or as text before chaining (`_jsonable` in `wd2l/audit.py`); `write()` never raises on them | Audit trouble never stops the transfer |
| 1.8 | §6 `config_changed` | Archive replays (`wd2l-receiver --pcap ...`) don't update the config hash saved in the state file | Otherwise every replay sharing `--state` would make the next live start log a false `config_changed` |
| 2.2 | §5 `host` | The sender's in-band records use the audit log's host name (`Sender.hostname = audit.host`) | One name for the log server in local and forwarded records |
| 3.3 | §9 | A stream restored from history (a retired stream seen again, e.g. in a replay) is not reconciled | Its earlier history is unknown; it would report a false "not balanced" |
| 3.3 | §9 | An event is counted as delivered only after the outputs' failures are applied (snapshot, apply failures, then settle) | An event the SIEM output failed must not count as delivered |
| 3.3 | §9 | At receiver stop, the final reconcile runs before the outputs close | Its health record must reach an open output |
| 3.4 | §9 report | `wd2l-audit-report` treats its input as untrusted: `verify` lists unreadable lines (and fails), `reconcile` and `events` skip them and say how many; the first copy of each `n` is kept; exit 0 ok / 1 problem or nothing to verify / 2 missing dir or file | It is the tool assessors use on files that may have been tampered with |
| 3.5 | §9 stream end | The stream-end `reconcile` record is written when the stream has ended and the last written record doesn't already state the same cut and balance. (Found by the lab: the record was never written; fixed in 205b7b0 with a test.) Note: if an hourly record just before the end already stated the same cut and balance, no separate stream-end record is written | No duplicate records; the evidence is the same |
| 4.3 | §12 | The state-of-health mockup and the example dashboard default to the last 12 hours; panel 20 (audit review) also lists `start` and `stop` | 12 h fits a planned-downtime window and the nightly audit events on one screen; start/stop show change windows |
| 4.4 | §12 time | The time tile shows ALARM in red | A time alarm must read red |
| final review | §11 time | When the sender can't read chrony, its heartbeat carries `time_unavailable: true` and Enclave 2's time check alarms "sender: unavailable"; the next readable heartbeat clears it | The None values were dropped on both sides, so a sender without chrony was never alarmed |
| final review | §12 rules | The fault rules read the data stream whose latest heartbeat is the newest (`last_hb` per stream, kept in the state file). Streams with no heartbeat info (a never-seen run's placeholder, a retired stream brought back) are skipped; with none heard, the stream first seen last, as before | A placeholder could count as the newest run: rule 5 while events flowed, rule 6 and the sender's time check blind, a crash read as rule 2 |
| final review | §7 routing | The receiver passes on only records with `enclave` 1 and `component` `sender`; anything else, including JSON too deeply nested to read, counts in `records_bad`. The dashboard audit tile takes each side from its own sourcetype; the daily review report shows `sourcetype` | Enclave 1 must not be able to plant records about Enclave 2 |
| final review | §10 failure handling | Below `--audit-min-free-mb` every audit write is a failed write (forwarded unchained, counted in `missed`, `audit_ok` false); writing resumes in a new file at `space_ok`. The floor is checked at start, then once a minute | The audit directory shares a disk with the state file, spool and archive; "must keep" has to be true |
| final review | §6 `gap` | Summarised per minute per stream and reason: `count` (events), `gaps`, `seq_first`, `seq_last`, outcome `failure`. Health `gap` records stay one per gap. Summaries noted before a stop are written at the stop | One audit record and fsync per gap: about 200 GB a year at 1% loss |
| final review | §10 self-check | The child writes to temporary files. A child that can't start, or still runs after 6 hours (killed), is a failed `audit_verify` with `reason` `could not start` or `timeout` | A pipe read after exit filled past about 1,700 files and stalled the check; a fork failure stopped the receiver |
| final review | §10 SIEM | With `--audit-dir` and `--hec-url`, the receiver refuses to start without `--hec-audit-token-file` (exit 2). The replay runbook passes `--audit-dir` and the audit token; the lab's `siem-down` run passes the token | On the data token the SIEM refuses every audit record; the runbook's replays went unaudited |
| final review | §9, §13 | "WD2L - Reconciliation not balanced" fires only when the latest record has `gaps_open=0`. A gap closed by a re-send stays unbalanced for good; open item 7 asks how to close it | Re-sent events come back with new numbers, so the alert fired every hour, for good |
| final review | §8 e2-siem | `hec_spool_bytes` in every summary (from the spool's running total) | §8 asks for spool bytes |
| final review | §12 | The reconciliation tile shows UNKNOWN (grey) with no reconcile records | "0 of 0 balanced" must not read green |
| final review | §10 verify | `python3 -m wd2l.audit verify DIR` without `--upto` fails when it finds no records ("no audit records found") | An empty or wiped directory proves nothing |
| final review | §9 report | `wd2l-audit-report` treats a line too deeply nested to parse as unreadable | It must report hostile input, not crash |
| final review | §9 stream end | Writing a reconcile record marks the state file to be saved | A crash while idle wrote the stream-end record again |
| final review | §15 | Audit volume recomputed with summarised gaps: heavy loss adds about 1 MB a day; the ">10 GB a day" caveat is gone | Measured in the lab's `wire-loss` run |

**Closed by Task 4.6 (2026-10-06).** Every row above has a matching **As built** note in the
[audit plan](../../../audit-and-health-plan.md), at the end of the section its Spec column names;
section 2a of the page sums them up. The "final review" rows were added with the fixes from the
whole-branch review, and their notes say "final review".
