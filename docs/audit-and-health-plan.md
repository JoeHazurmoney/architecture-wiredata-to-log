# Audit records and health monitoring for wd2l

**Status: built in wd2l 0.2.0 (2026-10-06).** This page keeps the proposal as it was reviewed on
2026-10-05. Each section ends with an **As built** note saying what was built and where it
differs. To watch the system day to day, use the dashboard described in
[state-of-health.md](state-of-health.md); to act on alerts, see [operations.md](operations.md).
The 2026-10-05 update made the plan framework-neutral. It also brought it in line with the
[interface description](interface-description.md), the
[planned-downtime runbook](planned-downtime.md) and
[ADR-0003](decisions/0003-receiver-to-siem-delivery.md).

## 1. Purpose

Two goals, one design:

1. **Audit records** for the wd2l transfer that meet common audit-control requirements: what gets
   logged, what each record holds, time stamps, protection, review and retention. The design
   doesn't depend on one framework. Section 14 maps it to two examples: the NIST SP 800-53 AU
   family, and SOC 2 (mainly criterion CC7.2).
2. **Health monitoring** that tells an operator, from one SIEM dashboard, whether a problem is
   in **Enclave 1, the boundary (tap/fiber), or Enclave 2**, and which part. The aim is to cut
   mean time to repair (MTTR).

## 2. Decisions and environment

| Item | Decision / fact |
|---|---|
| Control framework | Not tied to one. Section 14 gives examples (NIST SP 800-53, SOC 2). Which framework applies is open item 6 (section 17) |
| Audit record retention | 1 year, both enclaves (audit record retention, e.g. NIST AU-11, or the period a SOC 2 retention policy sets) |
| Direction | Audit and health data stays in the enclave where it was made, or moves from Enclave 1 to Enclave 2 with the logs. Nothing goes back. See the direction rule in the [README](../README.md) |
| SIEM | Splunk in Enclave 2. **No SIEM in Enclave 1**: logs are collected on the central log server, and a copy of everything is kept for 1 year on the log retention server. |
| Delivery to the SIEM | The receiver posts straight to the SIEM's HTTP event collector, with no event files and no log forwarder ([ADR-0003](decisions/0003-receiver-to-siem-delivery.md)). Its audit records go the same way, with their own token and index |
| Interface | Anything new that crosses the link is an interface change. [interface-description.md](interface-description.md) and [wire-format.md](wire-format.md) are updated in the same change |
| Enclave 1 retention | Log retention server ([deployment/retention-server.md](deployment/retention-server.md)): 1-year copy of every event the aggregator collects, the source for replaying lost events, and the proposed 1-year home of wd2l's Enclave 1 audit files (section 17, item 5) |
| Time | GPS (SAASM) receiver in each enclave → a switch serving time as stratum 2 → hosts running chrony (stratum 3) |
| Where the health view lives | Enclave 2 SIEM. Enclave 1 has no live view; see section 7 for how Enclave 1's state still reaches it |

## 2a. As built at a glance

One row per section. "As proposed" means it was built as the section says; otherwise the cell
names the difference. Each section's **As built** note has the details.

| Section | Proposed | As built | Where |
|---|---|---|---|
| [3. Gaps](#3-what-exists-today-and-the-gaps) | Close gaps G1–G9 | All nine closed (the `Closed by` column) | `wd2l/audit.py`, `wd2l/sender.py`, `wd2l/receiver.py`, `deploy/` |
| [4. Three kinds of records](#4-three-kinds-of-records) | Operational log, health, audit; JSON logs; `SIGUSR1` | As proposed. Enclave 1 health lands in `wd2l` as `wd2l:sender:health` | `wd2l/logsetup.py`, `wd2l/outputs.py`, `tests/test_logsetup.py`, `tests/test_records_stream.py` |
| [5. Record format](#5-common-record-format) | Common fields, hash chain; identity in health records | As proposed, plus `code_sha256` and `python` on `start`; unchained copies; unusable values written as null or text | `wd2l/audit.py`, `wd2l/hostinfo.py`, `tests/test_audit.py`, `tests/test_hostinfo.py` |
| [6. Event catalog](#6-audit-event-catalog-event-logging) | The audit events, some summarised | As proposed, plus `sender_boot_reset` and `stream_evicted`; `auth_failure` and `gap_filled` summarised too; `config_changed` needs `--state` | `wd2l/sender.py`, `wd2l/receiver.py`, `tests/test_sender_audit.py`, `tests/test_receiver_audit.py` |
| [7. Records stream](#7-getting-enclave-1s-records-to-enclave-2-no-enclave-1-siem) | Enclave 1 records in-band on a flagged stream; heartbeat snapshot | As proposed; only with `--audit-dir`; not linked across runs; the receiver picks the index; `heartbeat_trimmed` | `wd2l/wire.py`, `wd2l/sender.py`, `wd2l/outputs.py`, `docs/interface-description.md`, `docs/wire-format.md`, `tests/test_records_stream.py`, `tests/test_sender_health.py` |
| [8. Health signals](#8-health-signals-by-segment) | New signals per segment | As proposed; "tcpdump running" is `archive_stale`; spool bytes not reported | `wd2l/hostinfo.py`, `wd2l/receiver.py`, `tests/test_hostinfo.py`, `tests/test_receiver_signals.py` |
| [9. Reconciliation](#9-reconciliation-completeness-and-accuracy) | Set hashes, hourly `reconcile`, `wd2l-audit-report` | As proposed, plus `type=reconcile` health records and a record when an ended stream's balance changes; report has `--export` and `--complete` | `wd2l/reconcile.py`, `wd2l/audit_report.py`, `tests/test_reconcile.py`, `tests/test_receiver_reconcile.py`, `tests/test_audit_report.py` |
| [10. Protection](#10-protecting-the-audit-trail-protection-storage-failure-response) | Chain, self-check, append-only files, 1 year, own index, auditd rules, keep transferring | As proposed; self-check in a child process; new file after a failed write; torn and hostile lines reported | `wd2l/audit.py`, `deploy/common/wd2l-audit-seal.sh`, `deploy/common/wd2l-audit-seal.timer`, `deploy/log-server/wd2l.rules`, `deploy/receiver/wd2l.rules`, `tests/test_audit.py`, `tests/test_deploy.py` |
| [11. Time](#11-time-time-stamps) | chrony every 60 s; thresholds; skew alarm | As proposed, plus `type=time_status` records | `wd2l/hostinfo.py`, `wd2l/fault.py`, `tests/test_hostinfo.py`, `tests/test_fault.py` |
| [12. Fault dashboard](#12-the-where-is-the-fault-dashboard) | Rules 1–11 in the receiver; six-part layout | Rules as proposed; `unknown` segments; rule 3 `e1-sender/boundary`, rule 8 `e2-capture`; 20 panels | `wd2l/fault.py`, `wd2l/receiver.py`, `docs/state-of-health.md`, `deploy/receiver/splunk/wd2l-health-dashboard.json`, `tests/test_fault.py`, `tests/test_dashboard.py` |
| [13. Alerts](#13-alerts-added-or-changed) | Fault, reconciliation, audit and time alerts; daily review report | As proposed; every alert reads only the health index | `deploy/receiver/splunk/savedsearches.conf`, `docs/operations.md`, `docs/planned-downtime.md`, `tests/test_siem_config.py` |
| [14. Control mapping](#14-control-mapping-examples) | Examples per control | Unchanged; the rows point at built features | This table's `Where` column |
| [15. Storage](#15-storage-estimate-storage-capacity-retention) | Audit 1–5 MB/day per side; health ~10 MB/day | Measured: audit about 16 KB on a quiet day, about 2.8 MB with three summaries a minute; health about 5.4 MB/day; heavy loss writes far more (one record per gap) | `lab/run-lab.sh`, `lab/verify.py` |
| [16. Phases](#16-implementation-phases) | Four phases; unit tests; nine lab fault runs | Done: four phases, 354 tests; all nine fault runs pass | `tests/`, `lab/run-lab.sh`, `lab/check_fault.py`, `.github/workflows/tests.yml` |
| [17. Open items](#17-open-items-for-the-security-and-system-owners) | Six questions for the owners | Still open; the code uses the proposed defaults | `deploy/receiver/splunk/authorize.conf`, `docs/deployment/retention-server.md` |

## 3. What exists today, and the gaps

Today the receiver writes `wd2l:health` records to the SIEM:

* gaps, stale and restored heartbeats, and stream start, end and loss;
* a summary every 60 s with its counters, the sender's heartbeat counters and the clock offset.

The sender writes free-text lines to journald, including the `final: last_seq=…` line that the
[planned-downtime runbook](planned-downtime.md) checks. Its counters reach Enclave 2 only inside
heartbeats. Everything that crosses is described packet by packet in
[interface-description.md](interface-description.md), down to the fixed UDP source port.

| # | Gap | Why it matters | Closed by |
|---|---|---|---|
| G1 | No structured record of the sender's activity in Enclave 1 | Event logging where events happen (e.g. AU-2, AU-12; SOC 2 CC7.2). There's nothing to review in Enclave 1 | sender audit catalog, records stream |
| G2 | No record of version, configuration, or the account that started each side | Record content and configuration control: proving the running configuration is the approved one (e.g. AU-3, CM-3, CM-6; SOC 2 CC8.1) | `start`/`config`/`config_changed` with `code_sha256` |
| G3 | Operator actions (archive replay, state-file reset) aren't attributed | Identity in records, and review (e.g. AU-3, AU-6; SOC 2 CC7.2) | `actor`, `debug_toggled` via `sigwaitinfo`, `replay_run` |
| G4 | Completeness is checked by counts; content isn't reconciled end to end | Integrity: proof the SIEM holds exactly what Enclave 1 sent (e.g. SI-7; SOC 2 PI1.4) | set hashes, `reconcile` |
| G5 | Health records aren't tamper-evident and share the data's index and token | Protection of audit information, and access limited to a few privileged users (e.g. AU-9, AU-9(4); SOC 2 CC6.1) | hash chain, own index and token, `wd2l_auditor` |
| G6 | No time-quality data (chrony stratum/offset). *Partly addressed:* sender-vs-receiver offset (`clock_offset_s`) and per-event send/arrival times (`wd2l_tx_time` / `wd2l_rx_time`) are built | Time stamps (e.g. AU-8); troubleshooting misordered events | chrony `time_quality`, `time_status` |
| G7 | Health signals don't cover the NIC/link layer or the aggregator → sender hand-off | Can't say *where* a fault is | heartbeat snapshot, NIC and archive probes, fault rules |
| G8 | Packet archive kept 7 days; no retention plan for audit records | Retention, 1 year (e.g. AU-11) | 1-year timer, 366 days |
| G9 | A planned stop looks like a fault. The runbook mutes alerts for the window, and nothing records who stopped and started what | Telling planned work from faults. Evidence for change windows (e.g. CM-3; SOC 2 CC8.1) | rule 2 amber, `stop`/`start` records |

> **As built:** All nine gaps are closed; the `Closed by` column says how, and sections 4–13
> give the details. For G3, a state-file reset is on record too: `state_reset` and
> `state_loaded`, with the `actor` like every audit record. The 7-day packet archive (G8) is
> unchanged; only audit records are kept for a year. The sender's journald lines, including
> `final: last_seq=…`, keep their texts (section 4).

## 4. Three kinds of records

| Kind | Purpose | Volume | Enclave 1 destination | Enclave 2 destination |
|---|---|---|---|---|
| **Operational log** | Troubleshooting detail | Medium; debug on demand | journald (JSON) | journald (JSON) |
| **Health** (`wd2l:health`) | Dashboard, alerts, fault location | One summary a minute per side, plus immediate change records | journald + **in-band to Enclave 2** (section 7) | SIEM index `wd2l` |
| **Audit** (`wd2l:audit`) | Audit events, evidence, reconciliation | Low: events and hourly summaries | Local append-only files (**official copy**), kept 1 year on the host and on the log retention server, + in-band copy | Local append-only files kept 1 year, + SIEM index `wd2l_audit` (restricted) |

None of the three ever contains log content (`_raw`), only metadata, counts and hashes.

Enclave 1 health goes only to journald and in-band. A separate health file would be one more file
to rotate, and [ADR-0003](decisions/0003-receiver-to-siem-delivery.md) explains why rotation is a
loss risk. The sender's per-minute summary line already reaches the journal.

Operational logs move from free text to one JSON object per line on both sides (`--log-format
json` in the systemd units). Each line is tagged with `segment` (section 8) and, where relevant,
`stream` / `seq`. The message texts stay the same, so the planned-downtime runbook's checks still
find `final: last_seq=…`, `boot … after stream …` and the per-minute `last_seq` line.
`SIGUSR1` toggles debug level without a restart; the toggle is itself an audit event.

> **As built:** The three kinds exist as proposed.
>
> * **Operational log:** both units run with `--log-format json` (`wd2l/logsetup.py`). Each
>   line has `ts`, `level`, `logger`, `msg` and `segment`, plus `stream` and `seq` where they
>   apply. The message texts are the same as in text format.
> * **Health:** the sender's per-minute summary goes to journald (the `stream=… last_seq=…`
>   line) and in-band. In Enclave 2 it lands in `wd2l` with sourcetype `wd2l:sender:health`,
>   beside the receiver's own `wd2l:health`. The receiver's file output writes it to
>   `e1-health.jsonl`.
> * **Audit:** local files on both hosts. Enclave 1's records also cross in-band as
>   `wd2l:sender:audit`; the receiver's own are `wd2l:audit`. Both go to `wd2l_audit`. The
>   aggregator's copy to the log retention server is set up as
>   [retention-server.md](deployment/retention-server.md#6-wd2l-audit-files) describes (open
>   item 5).
> * **`SIGUSR1`** switches between INFO and DEBUG. A thread waiting in `sigwaitinfo` learns who
>   sent the signal, and the `debug_toggled` record names them. Signal the process from your own
>   session: with `systemctl kill`, systemd is the sender
>   ([operations.md](operations.md#audit-records)). An archive replay doesn't listen for
>   `SIGUSR1`.

## 5. Common record format

Every audit record, on both sides:

| Field | Example | Notes |
|---|---|---|
| `ts` | `2026-10-02T14:03:22.418213Z` | UTC, microseconds (time stamps) |
| `host` | `logsrv01` | |
| `enclave` | `1` / `2` | |
| `component` | `sender`, `receiver`, `replay`, `capture` | |
| `segment` | `e1-input`, `e1-sender`, `boundary`, `e2-capture`, `e2-receiver`, `e2-siem` | for the fault view |
| `version`, `build` | `0.2.0`, git commit | |
| `event` | `start`, `config`, `auth_failure`, `gap`, `reconcile`, … | from the catalog in section 6 |
| `outcome` | `success` / `failure` / `info` | |
| `actor` | `uid=987(wd2l) unit=wd2l-sender.service` or `uid=987(wd2l) auid=1001(jdoe) via sudo` | who caused it |
| `stream`, `seq_first`, `seq_last` | | ties a record to the data it's about |
| `time_quality` | `{"stratum":3,"offset_ms":0.21,"synced":true}` | from `chronyc -c tracking` |
| `n` | `1834` | record number in this host's chain: 1, 2, 3, … |
| `prev_hash`, `hash` | SHA-256 | hash chain (section 10). `hash` is the SHA-256 of the record as canonical JSON (keys sorted, no spaces) without `hash`. The first record's `prev_hash` is 64 zeros |
| event-specific fields | | e.g. `count`, `reason`, `config_sha256` |

Health records keep the keys they have today, `type` and `time` (epoch seconds), because the
alerts, the runbooks and the lab's checks use them. They gain the identity fields `host`,
`enclave`, `component` and `version`, and every summary gains `time_quality`.

> **As built:** The fields are as proposed (`wd2l/audit.py`), with these differences:
>
> * `start` also has `code_sha256`, one SHA-256 over the package's `.py` files, and `python`, the
>   interpreter's version. They prove which code ran, not only which settings.
> * `build` is `$WD2L_BUILD`, else a `BUILD` file next to the code, else `unknown`.
> * `host` is the host name. The sender's in-band records use the same name as its audit log
>   (`Sender.hostname = audit.host`), so local and forwarded records name the log server the
>   same way.
> * There is no `capture` component: tcpdump writes no audit records, and its state is in the
>   receiver's health records (section 8). An archive replay's records say `replay`.
> * `time_quality` also has `source`, the chrony reference. When chrony can't be read it is
>   `synced: null` with `source: "unavailable"` and the error.
> * Canonical JSON writes non-ASCII text as UTF-8, not as `\u` escapes, and it refuses NaN and
>   Infinity.
> * A record the file couldn't hold is still forwarded, with `n`, `prev_hash` and `hash` set to
>   null ("unchained"). Verification counts these apart (section 10).
> * Field values JSON can't hold (NaN, Infinity, bytes, sets, paths) are written as null or as
>   text before the record is chained (`_jsonable`). `write()` never raises on them, because
>   audit trouble must never stop the transfer.
> * Health records keep `type`, `time` and every older key, and gain `host`, `enclave`,
>   `component` and `version`. Every summary has `time_quality`, and also `audit_ok`, `audit_n`,
>   `audit_hash` and `audit_verify` (section 10).

## 6. Audit event catalog (event logging)

| Event | Side | When | Key fields |
|---|---|---|---|
| `start` / `stop` | both | process start; clean stop (with final counters). Together they record each stop and start of a planned-downtime window | version, build, actor, pid, `config_sha256`, stop signal |
| `config` | both | at start | full settings with secrets removed, and their hash |
| `config_changed` | both | `config_sha256` differs from the previous run | old/new hash |
| `state_loaded` / `state_reset` | both | state file read; missing, unreadable or deleted | path, file hash, streams loaded |
| `auth_failure` | sender | bad or missing aggregator token | client address |
| `input_rejected` | sender | gzip input, line too long, bad JSON (summarised per minute) | count, reason |
| `truncated` | sender | event cut to fit (summarised per minute) | count, host, source, original size (not content) |
| `opaque_content` | sender | events flagged `wd2l_opaque` (summarised per minute) | count, kinds, host, source (not content) |
| `send_failure` | sender | UDP send errors, drops (summarised) | count, errno |
| `boundary_anomaly` | receiver | packets that aren't the log flow (including the wrong UDP source port), corrupt frames, digest mismatch (summarised) | count, reason |
| `gap` / `gap_filled` | receiver | events declared lost; later recovered | stream, range, count, reason |
| `stream_start` / `stream_end` / `stream_lost` / `stream_missing` | receiver | sender run seen, ended, vanished, never seen | stream, boot |
| `output_failure` | receiver | SIEM rejected or dropped events; spool overflow | count, reason |
| `replay_run` | replay | archive replay started/finished | actor, files and their SHA-256 (computed while reading them), events filled, duplicates skipped |
| `debug_toggled` | both | `SIGUSR1` | actor (who sent the signal), new level |
| `time_quality` | both | at start, and whenever unsynced, stratum > 3, or \|offset\| > 100 ms | stratum, offset, source |
| `audit_failure` | both | audit file can't be written, disk below threshold | reason, free space, records the file missed (failure response) |
| `audit_verify` | both | at start and daily: the process re-checks its own hash chain | files, records, result (section 10) |
| `reconcile` | both | hourly, and at stream end | section 9 |

> **As built:** The catalog is as proposed (`wd2l/sender.py`, `wd2l/receiver.py`), with these
> differences:
>
> * **Summarised per minute:** `input_rejected`, `truncated`, `opaque_content` and
>   `send_failure`, as proposed, and also `auth_failure` and `gap_filled`. An aggregator retrying
>   a bad token every second would write 86,400 records a day, and an archive replay can fill
>   100,000 events at once. Each summary is one record per event, key and minute, with a
>   `count`. The key is, for example, the client and reason, the host and source, or the stream
>   (`gap_filled` gives `seq_first` and `seq_last`). Past 100 keys in a minute, the rest share
>   one `overflow` record.
> * **`boundary_anomaly` and `output_failure`** are written once a minute from the growth of
>   the receiver's counters. `reason` names the counter: for example `other_packets` (which
>   includes the wrong UDP source port), `bad_frames`, `digest_mismatch`, `output_dropped` or
>   `hec_rejected_events`.
> * **Two added events:** `sender_boot_reset` and `stream_evicted`. Like `stream_missing`, they
>   are evidence about completeness.
> * **`gap`** is one record per declared gap, with `seq_first`, `seq_last`, `count` and
>   `reason`.
> * **`config_changed`** compares with the config hash saved in the state file, so it needs
>   `--state`. Archive replays (`wd2l-receiver --pcap …`) don't update that hash: otherwise every
>   replay sharing `--state` would make the next live start log a false `config_changed`.
> * **`state_reset`** has `reason` `missing` or `unreadable: …`. A receiver with an unreadable
>   state file records it and refuses to start; the sender starts over at boot 1.
> * **`replay_run`** is written at `phase` `start` (the file names) and `finish` (each file's
>   SHA-256 and size, `events_filled`, `duplicates_skipped`, `open_gap_events`).
> * **`time_quality`** is written at start and then whenever the alarm state changes, with
>   `reason` `ok` or what is wrong.
> * **`audit_failure`** has `reason` `write_failed`, `recovered` (with `missed`), `torn_write`,
>   `low_space` or `space_ok`.
> * **`start`** has `pid`, `config_sha256`, `code_sha256` and `python`. **`stop`** has the final
>   counters and, for a live process, the stop signal. The sender's also name its stream.
> * **`reconcile`:** the sender writes one hourly and at its stop. The receiver's timing is in
>   section 9.

## 7. Getting Enclave 1's records to Enclave 2 (no Enclave 1 SIEM)

The sender sends its own health and audit records **in-band**, as ordinary DATA events in **a
second stream of its own, the records stream**:

* The records stream uses the same frame format. Every frame in it has bit 0 of `flags` set. It
  has its own `stream_id`, its own sequence numbers and its own heartbeat every second.
* It's a separate stream so that the data stream's `seq` keeps its meaning: the order of the
  aggregator's events ([interface description, section 9](interface-description.md#9-streams-and-sequence-numbers)).
  The lab matches sequence numbers to lines, and the reconciliation hash (section 9) covers only
  the aggregator's events.
* Loss on the records stream is detected like any other loss: the receiver reports a gap, marked
  `records: true`.
* The receiver routes the records stream by the flag, never by sourcetype. An aggregator event
  that claims `sourcetype=wd2l:sender:audit` stays in the data stream and lands with the other
  logs, not in the audit index.
* The events are `sourcetype=wd2l:sender:health` / `wd2l:sender:audit`, `index=wd2l` /
  `wd2l_audit`, `host=` the log server, with the record as JSON in `_raw`.
* Volume is bounded (summaries, not per event), so there's no feedback loop.
* This changes the interface but not the frame version. The interface description gains the
  flag, a new message, two streams per sender run and new heartbeat keys, and
  [wire-format.md](wire-format.md) changes with it. Older receivers ignore `flags` and would
  treat the records stream as one more data stream. Still, update the receiver first.
* **The local files in Enclave 1 stay the official audit copy.** The aggregator copies them to
  the log retention server, which keeps them for 1 year. Records written while the link is down
  don't reach Enclave 2 live. They show up as a records-stream gap, and the local files and the
  retention copy have them.

The data stream's heartbeat also carries a compact health snapshot every second. New keys:

* input: `events_in`, `clients`, `input_backlog_bytes`;
* the sender process: `stall_s`, `cpu_pct`, `rss_mb`;
* the egress NIC: `nic_carrier`, `nic_tx_packets`, `nic_tx_errors`, `nic_tx_dropped`;
* time: `time_stratum`, `time_offset_ms`, `time_synced`;
* audit: `audit_ok`, `audit_n`, and `events_hash` (section 9).

The body grows from about 200–300 bytes to about 700, still one packet. Enclave 2 sees Enclave
1's state within about a second while the link is up.

> **As built:** The records stream is as proposed (`FLAG_RECORDS` in `wd2l/wire.py`,
> `wd2l/sender.py`, `wd2l/receiver.py`), with these differences:
>
> * It exists only when the sender has `--audit-dir`. Its heartbeat has `events_sent`,
>   `records_too_big`, `outbox_dropped`, `sender_time`, `uptime` and, at the end, `final`.
> * It isn't linked across runs: no `boot` or `prev_stream`. Lost records already show as
>   records-stream gaps, and the local files are the official copy.
> * The sender sets no index. The receiver chooses it: `--audit-index` (default `wd2l_audit`)
>   for audit records, and `--health-index` for health, so forwarded Enclave 1 health lands in
>   `wd2l` as `wd2l:sender:health`.
> * The receiver re-serializes each record canonically before passing it on, so a record can't
>   smuggle an extra line into a file. Its file output writes forwarded audit records to
>   `audit.jsonl` and forwarded health to `e1-health.jsonl`, which keeps the lab's
>   `health.jsonl` the receiver's own.
> * Data events can't reach the audit index. An aggregator event claiming
>   `sourcetype=wd2l:sender:audit` stays in the data stream. A data event naming `wd2l_audit` is
>   moved to the default index and counted (`hec_audit_index_refused`), and the data token's
>   index list leaves `wd2l_audit` out (`deploy/receiver/splunk/inputs.conf`).
> * `events_in` counts input lines that were events or were rejected.
> * If the snapshot would make a heartbeat too big for one packet, the snapshot keys are left
>   out of that heartbeat and `heartbeat_trimmed` counts it. `events_hash` is never left out.
>   With the deployed unit the body is about 600–800 bytes.
> * The heartbeat carries `audit_ok` and `audit_n`; the hash of the last record is in the
>   sender's health summary (`audit_hash`).
> * [interface-description.md](interface-description.md) (sections 8 and 9) and
>   [wire-format.md](wire-format.md) describe the flag, the records stream and every new
>   heartbeat key.

## 8. Health signals by segment

| Segment | Where | Signals (new in **bold**) |
|---|---|---|
| `e1-input` (aggregator → sender) | Enclave 1 | **events in per second, connected clients, input backlog (bytes the aggregator has handed over that the sender hasn't read yet)**, bad input, auth failures |
| `e1-sender` | Enclave 1 | heartbeats, send errors, drops, restarts (`boot`), **time stalled on pacing or a full send buffer, process CPU/memory, egress NIC carrier and tx packets/errors (`--egress-iface`), chrony stratum/offset** |
| `boundary` (tap, fiber) | seen from Enclave 2 | **capture NIC carrier, carrier-change count, rx CRC/frame errors** (`/sys/class/net/<nic>/carrier` and `statistics/`; `ethtool -S` by hand for driver-specific counters), packets that aren't the log flow |
| `e2-capture` | Enclave 2 | **NIC rx packets/bytes**, kernel drops, **tcpdump running, newest archive file age/size** |
| `e2-receiver` | Enclave 2 | gaps by reason, reassembly expiry, lag from sender time to delivery (built: `wd2l_rx_time − wd2l_tx_time`), **chrony stratum/offset**, process CPU/memory |
| `e2-siem` | Enclave 2 | spool files/bytes, collector errors and rejections, SIEM ingest delay (built: index time − `wd2l_rx_time`) |

> **As built:** Every signal is built except spool bytes (`wd2l/hostinfo.py`,
> `wd2l/sender.py`, `wd2l/receiver.py`). The receiver reads its own probes every 5 s and puts
> them in every summary. Field names by segment:
>
> * `e1-input`: `events_in`, `clients`, `input_backlog_bytes` and `bad_input`, in every
>   heartbeat and in the sender's summary. Events in per second is the growth of `events_in`.
>   Auth failures are `auth_failure` audit records only.
> * `e1-sender`: `send_errors`, `sender_drops`, `boot`, `stall_s`, `cpu_pct`, `rss_mb`,
>   `time_stratum`, `time_offset_ms` and `time_synced`; with `--egress-iface`, `nic_carrier`,
>   `nic_tx_packets`, `nic_tx_errors` and `nic_tx_dropped`.
> * `boundary`: the capture NIC's `nic_carrier`, `nic_carrier_changes`, `nic_rx_crc_errors` and
>   `nic_rx_frame_errors` (also `nic_rx_errors` and `nic_rx_missed_errors`), and
>   `other_packets`. The NIC is `--capture-iface`, by default the `--live` one.
> * `e2-capture`: `nic_rx_packets`, `nic_rx_bytes` and `kernel_drops`; with `--pcap-dir`,
>   `archive_file`, `archive_age_s` and `archive_bytes`.
> * `e2-receiver`: `gap` records by `reason`, `reasm_expired`, `time_quality`, `cpu_pct` and
>   `rss_mb`, plus `packet_age_s` and `frame_age_s`. The lag is a SIEM search, as before.
> * `e2-siem`: `hec_spool_files`, `hec_queue`, `hec_posts_failed`, `hec_rejected_events` and
>   `output_dropped`. **Spool bytes aren't reported**; the fault rule watches the number of
>   spool files. Ingest delay is a SIEM search, as before.
> * **"tcpdump running"** is measured another way: packets arrive, but the newest archive file
>   hasn't been written for 15 s (`archive_stale`, rule 11). This works without seeing other
>   users' processes (`ProtectProc`, `hidepid`), and it catches a stuck tcpdump too.

## 9. Reconciliation (completeness and accuracy)

* **Each side keeps a set hash per data stream.** It's the sum, modulo 2^256, of SHA-256(`seq` ‖
  event SHA-256) over every event. The event SHA-256 is the frame's `digest`, which the receiver
  already checks on arrival.
* **The sender** adds each event as it numbers it. It sends the running value in every heartbeat
  (`events_hash`, 64 hex digits). The heartbeat's `seq` is the cut: the value covers events 1 …
  `seq`.
* **The receiver** adds each event when it delivers it. "Delivered" is the point
  [ADR-0003](decisions/0003-receiver-to-siem-delivery.md) defines: the SIEM answered HTTP 200, or
  the event is in the on-disk spool. Once every number up to a cut is resolved (delivered, or
  declared a gap), it compares its value up to the cut with the sender's.
* **Equal values** prove that the receiver delivered exactly the events the sender numbered up to
  that point, unchanged and under the right numbers.
* **Why a sum and not a chain.** A sum doesn't depend on order. An event that arrives out of
  order, or fills a gap days later from an archive replay, just adds its term, and the values
  agree again. A chain can't be checked past a gap that is still open, and it needs the events in
  order. An event delivered twice (re-sent after `output_dropped` or `receiver_restart`) is
  counted once.
* **What it detects:** accidental loss, duplication, change or misnumbering. It doesn't defend
  against someone who controls the sender, who could produce any value. That's the authenticity
  question in the [accreditation notes](accreditation-notes.md#integrity-and-authenticity).
* **The `reconcile` record.** Each side writes one every hour. It holds `events_in`,
  `events_sent`, `events_delivered`, `gaps_open`, `gaps_filled`, `last_seq`, the cut, both hash
  values, and `balanced`. `balanced` is true when the values agree at the cut and no gap at or
  below the cut is open. One more `reconcile` is written when a stream ends and everything in it
  is resolved.
* **The SIEM's own completeness.** The receiver's knowledge ends at the SIEM's collector. A SIEM
  search that counts events by `wd2l_stream` and `wd2l_seq` checks the rest against
  `events_delivered`.
* **`wd2l-audit-report`** (new command) builds daily or ranged reports (JSON/CSV) for assessors
  and audit reviews (review, analysis and reporting; e.g. AU-6, AU-7; SOC 2 CC7.2). It reads the
  audit files or a SIEM export. Subcommands:
  * `verify`: checks the hash chain (section 10);
  * `reconcile`: reconciliation per day and stream;
  * `events`: filters by time, stream, event and segment.

> **As built:** As proposed (`wd2l/reconcile.py`: `SetHash`, `StreamReconciler`), with these
> details:
>
> * Each term is SHA-256(`seq` as 8 bytes big-endian ‖ event SHA-256).
> * An event counts as delivered only after the outputs' failures are applied: the receiver
>   takes a snapshot of what is still pending, applies the failures, then settles. An event the
>   SIEM output gave up on never counts as delivered.
> * The receiver compares at the highest cut whose events are all resolved and durable. Events
>   added later below an earlier cut make it compare again.
> * The records stream isn't reconciled. Nor is a stream restored from history (a retired
>   stream seen again, for example in a replay): its earlier history is unknown, so it would
>   report a false "not balanced".
> * Each side writes its own `reconcile` audit record. The sender's has `cut`, `last_seq`,
>   `events_in`, `events_sent` and `sender_hash`. The receiver's has `events_in` and
>   `events_sent` from the heartbeat, `events_delivered`, `gaps_open`, `gaps_filled`,
>   `last_seq`, both hashes and `balanced`. `wd2l-audit-report reconcile` puts the two sides on
>   one row per day and stream.
> * The receiver writes one hourly for each stream seen in the last hour or not balanced. For
>   an ended stream it also writes one whenever the cut or the balance changes, for example
>   after a replay fills its gaps. That is the evidence the replay worked.
> * The stream-end record is written once the stream has ended, unless the last written record
>   already states the same cut and balance. So if an hourly record just before the end already
>   did, there is no separate stream-end record: the evidence is the same. (The lab found the
>   record missing; fixed in 205b7b0, with a test.)
> * At receiver stop, the final reconcile runs before the outputs close, so its records reach
>   an open output.
> * Each result is also a `type=reconcile` health record (`stream`, `cut`, `balanced`,
>   `gaps_open`, `events_delivered`), and every summary has `reconcile_unbalanced`. Operators
>   can't read the audit index; the dashboard and the alert need the balance.
> * The SIEM's own completeness is a search, in
>   [operations.md](operations.md#alert-reconciliation-not-balanced).
> * `wd2l-audit-report` (`wd2l/audit_report.py`) has `verify`, `reconcile` and `events`. Each
>   reads `--dir` (audit files) or `--export` (a SIEM export: JSON lines holding the record, or
>   the record as text in `_raw`, also inside Splunk's `result`), and writes `--format json` or
>   `csv`. `reconcile` and `events` take `--since` and `--until`; `events` also filters by
>   component and host. `verify` takes one `--dir` (one chain, with `--upto` and `--upto-hash`)
>   or `--export`. With `--export`, `--complete` also fails when records are missing.
> * The report treats its input as untrusted, because assessors use it on files that may have
>   been tampered with. `verify` lists unreadable lines and fails; `reconcile` and `events` skip
>   them and say how many. From an export it keeps the first copy of each `n`; a different
>   second copy is a problem. It exits 0 when all is well, 1 on a problem or when there is
>   nothing to verify, and 2 for a missing directory or file.

## 10. Protecting the audit trail (protection, storage, failure response)

* **Hash chain.** Each audit record's `hash` covers its content plus `prev_hash`, and `n` counts
  the records in the chain. `wd2l-audit-report verify` detects any edited, removed or reordered
  record. The latest `n` and hash are copied into every health summary, so they also live in the
  SIEM, and records cut from the end of a file show up too.
* **Self-check.** Each process verifies its own chain at start and once a day, and records the
  result as `audit_verify`. A failure raises an alert in the SIEM. Enclave 1's result arrives
  in-band.
* **Files.** `/var/log/wd2l/audit-<UTC start time>.jsonl`, group `wd2l-audit`, mode 0640.
  * The process only appends: one write and one fsync per record.
  * Past a size limit (64 MiB, months of records) it starts a new file and carries the chain
    across. It never renames or truncates a file, so no log rotation tool is involved.
    [ADR-0003](decisions/0003-receiver-to-siem-delivery.md)'s lesson applies here too: rotating
    a file under a running process can lose records.
  * One process writes a directory at a time (a lock file), so an archive replay can't interleave
    its records with the live receiver's chain.
* **Append-only and 1-year retention.** An hourly root timer sets `chattr +a` on the files. The
  wd2l process can't do that itself; it lacks the capability. The same timer deletes files older
  than 366 days, so each host keeps its own 1-year copy. In Enclave 1 the aggregator also copies
  each line unchanged to the log retention server, so the chain still verifies on that copy.
* **SIEM.** A `wd2l_audit` index with its own collector token, readable only by an auditor role
  (access limited to a few privileged users; e.g. AU-9(4), SOC 2 CC6.3). The receiver's
  `--force-index` never moves audit records.
* **Host auditd rules** on both hosts watch wd2l's programs, settings, state files and audit
  files. The rules on the state and audit directories match only changes made from a login
  session (`auid` set), because the daemons write there all the time.
* **Failure handling (failure response; e.g. AU-5).** If the audit file can't be written, the
  process logs to journald, raises `audit_failure` in health, and **keeps transferring**.
  Stopping the transfer would lose data that can't be re-sent.
  * The record itself still goes in-band (sender) or to the SIEM (receiver).
  * Once writing works again, an `audit_failure` record notes how many records the file missed.
  * Free space below a set threshold raises `audit_failure` before writes start failing.

  Confirm this choice with the security owner.
* **Stronger options**, if the framework or assessor asks for them (e.g. NIST AU-9(2), AU-10): a
  keyed hash (HMAC) on each record, or a separate backup copy. The design leaves room for them.

> **As built:** As proposed (`wd2l/audit.py`), with these details:
>
> * **Files:** `<dir>/audit-<UTC start time>.jsonl`, for example
>   `audit-20261005T140322.418213Z.jsonl`, mode 0640 whatever the umask. The units use
>   `/var/log/wd2l`; the install step creates it (owner `wd2l`, group `wd2l-audit`, mode 2750).
>   One `write` and one `fsync` per record. A new file starts past 64 MiB, and also after any
>   failed write, so nothing is ever appended after a partial line.
> * **Lock:** a `.lock` file in the directory, held with `flock`. An archive replay started while
>   the live receiver runs refuses with "audit directory … is in use by another wd2l process".
> * **Verification** reports a partial last line as `torn`, not as a break: a crash or a full
>   disk mid-write isn't tampering. Lines that aren't valid JSON for the chain (NaN or Infinity
>   numbers, too deeply nested) are reported as problems, and the verifier never crashes on them.
>   A tamper check must report hostile input, not stop.
> * **Self-check:** at start and once a day, in a child process:
>   `python3 -m wd2l.audit verify DIR --upto N --upto-hash H`, up to where the writer stood at
>   that moment. A full read inside the receiver would compete with its capture loop for the
>   interpreter lock. Health summaries carry `audit_verify` (`ok`, `failed`, or null before the
>   first check) next to `audit_ok`, `audit_n` and `audit_hash`.
> * **Append-only and 1 year:** `deploy/common/wd2l-audit-seal.sh`, run hourly as root by
>   `wd2l-audit-seal.timer`, sets `chattr +a` on the files and deletes those last written more
>   than 366 days ago. The wd2l units grant no `CAP_LINUX_IMMUTABLE`.
> * **SIEM:** the `wd2l_audit` index, kept 366 days, with its own collector token and the
>   `wd2l_auditor` role. The Splunk examples are `indexes.conf`, `inputs.conf` and
>   `authorize.conf` in `deploy/receiver/splunk/`. `--force-index` never moves audit records.
> * **Host auditd rules:** `deploy/log-server/wd2l.rules` and `deploy/receiver/wd2l.rules`. They
>   watch `/opt/wd2l/`, `/etc/wd2l/` and the wd2l units. On `/var/lib/wd2l` and `/var/log/wd2l`
>   they match only changes with `auid` set.
> * **Failure handling:** the process keeps transferring. A record the file can't hold is still
>   forwarded, unchained (section 5), and health shows `audit_ok=false`. Once writing works
>   again, an `audit_failure` with `reason=recovered` gives the number `missed`. Free space below
>   `--audit-min-free-mb` (256 by default) raises `audit_failure` with `reason=low_space`, and
>   `space_ok` when it recovers; section 6 lists every `reason`. Field values JSON can't hold
>   never make a write fail (section 5).
> * **Stronger options** (a keyed hash, a separate backup copy) aren't built. The room for them
>   is still there.

## 11. Time (time stamps)

* Timestamps are UTC with microseconds, from chrony.
* Both sides read `chronyc -c tracking` every 60 s. The resulting `time_quality` (stratum, offset,
  synced) goes in every health summary and audit record.
* Expected stratum on the hosts is **3** (GPS → switch at stratum 2 → hosts).
* Alert when unsynced, stratum > 3, or |offset| > 100 ms (threshold to confirm).
* The receiver records **sender-vs-receiver clock skew** from the heartbeat's `sender_time`, minus
  the one-way network delay (well under 1 ms on a direct fiber). With both sides GPS-disciplined,
  skew over ~50 ms points to a time-sync fault, not the network. *Built:* `clock_offset_s` in
  every health summary (see [operations.md](operations.md#measuring-delays)). The alert is still
  to do (section 13).

> **As built:** As proposed (`TimeQuality` in `wd2l/hostinfo.py`, `time_status` in
> `wd2l/fault.py`), with `type=time_status` records added:
>
> * Both sides read `chronyc -c tracking` at most every 60 s. `--chronyc` names the command; the
>   receiver also has `--time-check-interval`. `time_quality` is in every health summary and
>   every audit record.
> * The thresholds are defaults in the code: an alarm when unsynced, above stratum 3 or more than
>   100 ms off, and a skew alarm over 50 ms. There is no command-line option for them yet.
> * When chrony can't be read (missing or hanging), `time_quality` says `unavailable`, and the
>   `time_quality` audit record marks it a failure. On the receiver it is also a time alarm. A
>   sender that can't read chrony leaves the time keys out of its heartbeat, so Enclave 2 shows
>   no time alarm for it; the in-band audit record and the daily review report still show it.
> * The receiver works out `time_status` (`ok` or `alarm`, with `time_reason`) from its own
>   clock, the sender's heartbeat keys and the skew. It is in every summary, and each change is
>   also a `type=time_status` record, so the time alert fires at once, not on the next summary.
> * The alert is built: "WD2L - Time quality" (section 13).

## 12. The "where is the fault" dashboard

**The receiver decides where the fault is.** It has nearly every signal: its own NIC, capture
and SIEM output, plus Enclave 1's state from the heartbeat. So the rules live in wd2l, not in
SIEM searches. They work with any SIEM and are tested in the lab (section 16).

* It re-evaluates every few seconds.
* It writes a `type=fault` health record whenever the result changes.
* It puts `fault_status`, `fault_segment` and `fault_rule` in every summary.

The SIEM alerts on these records and draws the dashboard. The one thing the receiver can't report
is its own absence; the existing "Receiver silent" SIEM alert covers that. The example dashboard
is for Splunk Dashboard Studio, shipped as `deploy/receiver/splunk/wd2l-health-dashboard.json`.

**Decision order** (first match wins):

| # | Condition | Fault segment | Status |
|---|---|---|---|
| 1 | Capture NIC carrier down | `boundary`: tap, fiber or optic | red |
| 2 | No packets for longer than the heartbeat timeout, and the last sender run ended cleanly (`stream_end`, no newer run) | `e1-sender`: stopped cleanly, for example planned downtime | amber |
| 3 | No packets for longer than the heartbeat timeout | `e1-sender` or `boundary`: the sender, its egress NIC, or the tap (see heartbeat history after recovery) | red |
| 4 | Packets arriving, no valid wd2l frames | `boundary`: tap filter or wiring | red |
| 5 | Heartbeats arriving, sender events-in flat for a set time (5 min to start with) | `e1-input`: log aggregator or its sources | amber |
| 6 | Heartbeats show sender drops, send errors, or a growing input backlog | `e1-sender` | amber |
| 7 | New gaps (`not_received`) with capture NIC rx/CRC errors | `boundary`: fiber or optic | red |
| 8 | New gaps with kernel drops, no NIC errors | `e2-capture` / `e2-receiver`: host capacity | red |
| 9 | New gaps with neither | `boundary`: loss on the path | amber |
| 10 | `output_dropped` gaps, spool growing, collector errors or rejections | `e2-siem` | amber; red if events were dropped |
| 11 | tcpdump not running | `e2-capture`: the archive isn't being written, so a replay would have nothing | amber |
| — | Time quality alarm, or clock skew | time sync: shown separately (`time_status`), not a transfer fault | |

**Layout:**

1. Status tile: green / amber / red, plus the suspected segment and the rule that matched.
2. Pipeline picture: the six segments, each colored by its own health.
3. Events in (Enclave 1) vs events delivered (Enclave 2) over time.
4. End-to-end delay and clock skew.
5. Gaps by reason; reconciliation balance.
6. One row of detail panels per segment.

**Limit of a one-way link:** while nothing reaches Enclave 2, it can't tell "sender down" from
"fiber cut" in real time; rule 3 narrows it to that pair. Once the link returns, the
heartbeat's `boot` and `uptime` settle it: unchanged `boot` means the sender stayed up and the
link was the problem. A planned stop doesn't have this problem: the sender's final heartbeat
says so before it goes quiet (rule 2).

> **As built:** The rules live in the receiver, as proposed (`evaluate()` in `wd2l/fault.py`,
> called from `wd2l/receiver.py`).
>
> * It re-evaluates every 5 s (`--fault-interval`; live capture only). "New" means growth over
>   the last 60 s (`--fault-window`). Rule 5 waits 300 s (`--input-flat-after`). Rule 6's
>   growing backlog means over 1 MiB and growing. Rule 11 is `archive_stale` (section 8).
> * Each change is a `type=fault` record with `fault_status`, `fault_segment`, `fault_rule`,
>   `fault_detail`, `segments` and the previous status, segment and rule. Every summary carries
>   `fault_status`, `fault_segment`, `fault_rule`, `fault_detail` and each segment's color
>   (`seg_e1_input` … `seg_e2_siem`).
> * Segment names: rule 3 reports `e1-sender/boundary`, one value for alerts to group on. Rule 8
>   reports `e2-capture`, and colors `e2-capture` and `e2-receiver`.
> * Every matching rule colors its own segments, so more than one box can be off green. Segments
>   the receiver can't see while nothing arrives are `unknown` (grey): grey is more honest than
>   green.
> * Time is shown apart, as `time_status`, and each change is a `type=time_status` record
>   (section 11).
> * The six-part layout became 20 panels. The mockup and the example dashboard show the last 12
>   hours by default, so a planned-downtime window and the nightly audit events fit on one
>   screen. Panel 20 (audit review) also lists `start` and `stop`, which show change windows.
>   The time tile shows ALARM in red.
> * The example dashboard is `deploy/receiver/splunk/wd2l-health-dashboard.json`, for Splunk
>   Dashboard Studio. The mockup is `docs/images/state-of-health-mockup.svg`.
>
> **How to present this to an operator, panel by panel, with a mockup: [state-of-health.md](state-of-health.md).**

## 13. Alerts (added or changed)

* Fault status changed from `ok` (`type=fault`), with the segment and rule in the alert text.
* Reconciliation not balanced for an hour.
* Audit trail: `audit_failure`, or a failed `audit_verify`.
* Time quality out of bounds; skew above threshold.
* `config_changed`, `state_reset`, `replay_run`, `debug_toggled`: a daily report for review, not
  an alert.
* The [planned-downtime runbook](planned-downtime.md) adds "WD2L - Fault segment" to the alerts it
  mutes for the window. Rule 2 shows the stop as amber, not red.

> **As built:** As proposed. The Splunk example is
> `deploy/receiver/splunk/savedsearches.conf`:
>
> * "WD2L - Fault segment": a `type=fault` record whose `fault_status` isn't `ok`. The alert
>   lists `fault_segment`, `fault_rule` and `fault_detail`.
> * "WD2L - Reconciliation not balanced": a stream with no balanced `type=reconcile` record in
>   the last hour. It runs hourly.
> * "WD2L - Audit trail": `audit_ok=false` or `audit_verify=failed` in either side's health
>   records.
> * "WD2L - Time quality": `time_status=alarm`, which covers both sides' time quality and the
>   skew.
> * "WD2L - Audit review (daily)": a report, not an alert. Every morning it lists the previous
>   day's `config_changed`, `state_reset`, `replay_run` and `debug_toggled`, and also
>   `audit_failure`, `audit_verify` and `time_quality`. Its owner needs the `wd2l_auditor` role.
>
> Every alert reads only the health index (`wd2l`), so the people who own them don't need the
> auditor role; only the daily report reads `wd2l_audit`. The planned-downtime runbook mutes
> "WD2L - Fault segment" as proposed, and [operations.md](operations.md) has a section for each
> new alert.

## 14. Control mapping (examples)

The design isn't tied to one framework. The table maps each audit control it addresses to two
examples: NIST SP 800-53 Rev 5 and the SOC 2 Trust Services Criteria. These are examples, not
claims of compliance. Confirm them against the framework the system is assessed under and its
control documentation (for example a system security plan, or a SOC 2 system description).
Values the organization sets are marked *org-defined*.

| Audit control | How this design meets it | e.g. NIST SP 800-53 | e.g. SOC 2 |
|---|---|---|---|
| Event logging | The catalog in section 6 (*org-defined*: the event list itself; confirm with the security owner). Both components generate the catalog events | AU-2, AU-12 | CC7.2 |
| Content of records | The common format in section 5: what, when, where, source, outcome, identity, plus stream/sequence, config hash, time quality and segment | AU-3, AU-3(1) | CC7.2, CC7.3 |
| Storage capacity | Size estimates (section 15); a free-space check raises `audit_failure` before writes fail | AU-4 | A1.1 |
| Response to logging failures | `audit_failure` record and alert; keep transferring (section 10) | AU-5 | CC7.2 |
| Review, analysis and reporting | Dashboard, alerts, `wd2l-audit-report`. Enclave 1 and Enclave 2 records are joined by stream/sequence and GPS time | AU-6, AU-6(1), AU-6(3) | CC4.1, CC7.2, CC7.3 |
| Record reduction and report generation | `wd2l-audit-report`, filtering by time, stream, event and segment | AU-7, AU-7(1) | CC7.2 |
| Time stamps | UTC, microseconds, chrony to GPS; time quality recorded | AU-8 | No direct criterion; supports CC7.2 |
| Protection of audit information | Hash chain, daily self-check, append-only files, permissions, copies off the host | AU-9 | CC6.1 |
| Access limited to a few privileged users | `wd2l_audit` index and files restricted to an auditor role | AU-9(4) | CC6.1, CC6.3 |
| Retention | 1 year (*org-defined*) on both hosts. Also on the log retention server in Enclave 1 (proposed; section 17, item 5) and in the SIEM in Enclave 2 | AU-11 | Set by the retention policy; supports CC7.2 |

Related controls this supports, mostly with evidence:

| Control | How | e.g. NIST SP 800-53 | e.g. SOC 2 |
|---|---|---|---|
| Information flow enforcement | Boundary-anomaly records | AC-4 | CC6.7 |
| System monitoring | The dashboard and alerts | SI-4 | CC7.2 |
| Integrity and completeness of processing | End-to-end reconciliation (section 9) | SI-7 | PI1.3–PI1.5, if Processing Integrity is in scope |
| Configuration change control and settings | Config hash at every start; `config_changed` | CM-3, CM-6 | CC8.1, CC7.1 |
| Incident handling and monitoring | Fault-segment records attached to incident tickets | IR-4, IR-5 | CC7.3–CC7.5 |
| Backup and recovery | State file, spool and archive replay | CP-9, CP-10 | A1.2, A1.3 |

Some frameworks or assessors ask for more (for example NIST's High-baseline enhancements
AU-5(1)/(2), AU-9(2)/(3), AU-10, AU-12(1)/(3)). They're optional here, and the design leaves room
for them.

> **As built:** The mapping is unchanged. Its rows now point at built features: the `Where`
> column of [section 2a](#2a-as-built-at-a-glance) names the code, deployment files and tests
> behind each one.

## 15. Storage estimate (storage capacity, retention)

At the planned < 1,000 events/s:

* **Audit files:** a few thousand records a day per side, ~1–5 MB/day → **under 2 GB per year per
  side**, kept on each host for 1 year.
* **Audit in the SIEM:** the same again in `wd2l_audit`, for both sides (Enclave 1's records
  arrive in-band). The receiver's audit spool only fills while the SIEM is unreachable.
* **Health:** one summary a minute per side plus change records, ~10 MB/day → ~4 GB/year in the
  SIEM.
* **Packet archive:** unchanged (7 days, ~600 GB at full rate). It's raw data for replay, not an
  audit record.
* **Log retention server (Enclave 1):** the logs themselves, roughly 3–6 TB/year compressed at
  full rate ([deployment/retention-server.md](deployment/retention-server.md)). wd2l's audit files
  add under 2 GB.

> **As built:** Measured in the lab at f0c5cbd, then scaled to a day. The command was
> `sudo lab/run-lab.sh --events 25000 --eps 5000`. The audit directories come from one run of
> it, the receiver's output files from a second.
>
> **How it was scaled.** Audit and health records don't grow with the event rate. They are
> written per minute, per hour, per day, or when something changes. So the figures below are per
> day, by record kind, and hold at 1,000 events/s. Only the packet archive and the retention
> server grow with the event rate, and they are unchanged.
>
> | What | Measured | Per day, scaled | Per year | Estimate above |
> |---|---|---|---|---|
> | Audit record, average size | 611 bytes (Enclave 1), 693 bytes (Enclave 2) | — | — | — |
> | One whole run, start to stop | 11 records per side: 6,725 bytes (`audit-e1`), 7,619 bytes (`audit-e2`) | a few KB per restart | — | — |
> | Audit files, quiet day | — | 24 hourly `reconcile` + 1 `audit_verify` = 25 records, about 16 KB per side | about 6 MB per side | 1–5 MB/day, under 2 GB/year per side |
> | Audit files, busy day | — | plus 3 summary kinds every minute (3 × 1,440 records): about 4,350 records, about 2.8 MB per side | about 1 GB per side | same as the row above |
> | Audit in the SIEM | The receiver's copy of both trails: 22 records, 14,344 bytes, the two directories together | the two sides' figures added | 12 MB to 2 GB | the same again |
> | Receiver health summary | 3 records, 8,847 bytes: about 2.9 KB each | 1,440 a day: about 4.2 MB | — | — |
> | Sender health summary (in-band) | 1 record, 789 bytes | 1,440 a day: about 1.1 MB | — | — |
> | Health change records | `reconcile` 234 bytes; `stream_start` about 170, `stream_end` about 580 each | 24 `reconcile` a day: about 6 KB; others only on change | — | — |
> | Health in the SIEM, total | — | about 5.4 MB | about 2 GB | about 10 MB/day, 4 GB/year |
>
> So the audit files are well under the 2 GB a year estimated, and health is about half its
> estimate. Each summary kind adds one record per key a minute only while it happens, and past
> 100 keys in a minute the rest share one record.
>
> * **Loss is the exception.** Each declared gap is its own `gap` record, in health and in
>   audit; gaps aren't summarised. In the lab's `wire-loss` run (20% of packets lost for 10 s,
>   at 1,000 events/s) the receiver's audit trail reached 2,076 records. Loss like that, left
>   running, would write over 10 GB a day. The alerts fire within minutes, and the free-space
>   check raises `audit_failure` before the disk fills (section 10).
> * The lab writes to files, so its receiver summary lacks the SIEM output's counters, a few
>   hundred bytes more when deployed.
> * The receiver's audit records have their own spool (`<spool-dir>/audit`), which fills only
>   while the SIEM is unreachable.

## 16. Implementation phases

| Phase | Work | Rough effort |
|---|---|---|
| 1 | Shared module `wd2l/audit.py`: record format, hash chain, segment files, self-check, the catalog wired into sender and receiver; JSON operational logs, `SIGUSR1`; time quality | 3–4 days |
| 2 | Records stream (flag, its own heartbeat), receiver routing and the audit collector token; new health signals per segment; heartbeat snapshot; fault rules in the receiver | 3–4 days |
| 3 | Set hashes, hourly `reconcile`, `wd2l-audit-report` (verify, reconcile, events) | 2–3 days |
| 4 | SIEM: `wd2l_audit` index, token and auditor role, alerts, dashboard. Root timer for append-only files and 1-year retention; host auditd rules. Interface description, wire format, deployment, operations and planned-downtime docs | 2–3 days |

**Testing.**

* Unit tests for the record format, the hash chain (edits detected), reconciliation, and every
  fault rule.
* In the lab, `lab/run-lab.sh --fault <name>` injects a fault in one segment at a time and checks
  that the receiver names the right segment. These run beside the existing loss, outage, crash
  and maintenance runs.

| `--fault` | What it does | Expected |
|---|---|---|
| `aggregator-stop` | the aggregator stand-in pauses | `e1-input` |
| `sender-stop` | clean stop, then restart (as in planned downtime) | `e1-sender`, stopped cleanly |
| `sender-hang` | the sender is frozen, then resumed | `e1-sender` or `boundary` |
| `tap-down` | the tap link goes down | `boundary`, carrier down |
| `foreign-only` | sender frozen, other traffic on the cable | `boundary`, no wd2l frames |
| `wire-loss` | packets dropped on the cable | `boundary`, loss |
| `receiver-slow` | the receiver is throttled until the kernel drops packets | `e2-capture` |
| `siem-down` | the SIEM stand-in is unreachable | `e2-siem` |
| `clock` | chrony reports "not synchronised" | `time_status` alarm |

> **As built:** All four phases are done, on branch `audit-and-health` (no pull request yet).
> The plan is in `docs/superpowers/plans/2026-10-05-audit-and-health/` (commit 0bde5cb).
>
> | Phase | Commits | Tests at its end |
> |---|---|---|
> | 1. Audit records | 0bde5cb..39cc5d6 | 235 |
> | 2. Records stream and fault location | 39cc5d6..719e938 | 298 |
> | 3. Reconciliation and report | 719e938..205b7b0 | 342 |
> | 4. SIEM, deployment, docs | 205b7b0 to the commit that adds these notes | 354 |
>
> **Unit tests per area** (`tests/`):
>
> * Record format, hash chain, writer, summaries, self-check: `test_audit.py`
> * Actor, build, chrony, CPU and memory, NIC and archive probes: `test_hostinfo.py`
> * JSON logs and `SIGUSR1`: `test_logsetup.py`
> * The catalog on each side, and outputs: `test_sender_audit.py`, `test_receiver_audit.py`,
>   `test_outputs_audit.py`
> * Records stream and the flag: `test_records_stream.py`, `test_wire.py`
> * Heartbeat snapshot and the receiver's signals: `test_sender_health.py`,
>   `test_receiver_signals.py`
> * Fault rules and time status: `test_fault.py`
> * Reconciliation: `test_reconcile.py`, `test_receiver_reconcile.py`
> * `wd2l-audit-report`: `test_audit_report.py`
> * Units, seal script and auditd rules: `test_deploy.py`
> * SIEM configs and the example dashboard: `test_siem_config.py`, `test_dashboard.py`
>
> **Lab.** Every lab run now writes audit records on both sides, verifies both chains, checks
> that the sender's records arrived in-band, and checks reconciliation (`lab/verify.py`).
> `lab/run-lab.sh --fault NAME` runs the faults above, and `lab/check_fault.py` checks that the
> receiver placed each one and then cleared it. `sender-hang` expects the one segment value
> `e1-sender/boundary` (section 12). See
> [running-the-lab.md](running-the-lab.md#9-inject-faults-and-see-where-the-receiver-places-them).
> The nine fault runs passed locally at f0c5cbd (this commit changes only docs), and CI runs the
> same nine on every push (`.github/workflows/tests.yml`). What they printed:
>
> | `--fault` | Records, in order, as `(status, segment, rule)` | Check | Reconcile |
> |---|---|---|---|
> | `aggregator-stop` | `('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | balanced |
> | `sender-stop` | `('amber', 'e1-sender', 2), ('ok', None, 0), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | both runs balanced |
> | `sender-hang` | `('red', 'e1-sender/boundary', 3), ('ok', None, 0), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | balanced |
> | `tap-down` | `('red', 'boundary', 1), ('ok', None, 0), ('amber', 'boundary', 9), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | not balanced: 10,002 events lost to the fault |
> | `foreign-only` | `('amber', 'e1-input', 5), ('red', 'boundary', 4), ('ok', None, 0), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | balanced |
> | `wire-loss` | `('amber', 'boundary', 9), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | not balanced: 2,784 events lost to the fault |
> | `receiver-slow` | `('red', 'e2-capture', 8), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | not balanced: 5,387 events lost to the fault |
> | `siem-down` | `('amber', 'e2-siem', 10), ('ok', None, 0), ('amber', 'e1-input', 5), ('ok', None, 0)` | PASS | balanced |
> | `clock` | `time_status`: `('alarm', 'receiver: unsynced'), ('ok', None)` | PASS | balanced |
>
> Each run also printed "PASS: every event arrived intact or is accounted for in a reported
> gap" and "chain ok" for both audit directories. The amber `e1-input` near the end of most runs
> is the stand-in aggregator running out of input: the lab's rule 5 waits only 5 s. The check
> needs the expected record and a later `ok`. The sizing run for section 15 passed too.

## 17. Open items for the security and system owners

1. Event list (section 6): confirm, or add events your control documentation requires.
2. Failure response: keep transferring when the audit log can't be written (proposed), or stop.
3. Time thresholds: |offset| 100 ms, skew 50 ms. Adjust as needed.
4. Who gets the auditor role in the SIEM for `wd2l_audit`.
5. Enclave 1 audit files: confirm the log retention server as their 1-year home (proposed), so
   they survive a rebuild of the log server.
6. Which framework the system is assessed under, and its retention period (1 year is assumed
   throughout).

> **As built:** All six items are still open for the security and system owners. Until they
> decide, the code and the examples do this:
>
> 1. **Event list:** the catalog in section 6, as built.
> 2. **Failure response:** keep transferring (section 10).
> 3. **Time thresholds:** |offset| 100 ms and skew 50 ms, and stratum above 3 is an alarm too.
>    They are defaults in the code (`wd2l/hostinfo.py`, `wd2l/fault.py`), with no command-line
>    option yet.
> 4. **Auditor role:** `wd2l_auditor` exists in the example
>    (`deploy/receiver/splunk/authorize.conf`). Who holds it is still to be named.
> 5. **Enclave 1 audit files:** the log retention server is the proposed 1-year home
>    ([deployment/retention-server.md](deployment/retention-server.md#6-wd2l-audit-files)).
>    Until that is confirmed, the official copy is the one on the log server.
> 6. **Framework and retention:** 1 year throughout: the seal timer deletes files after 366
>    days, and the example keeps `wd2l_audit` for 366 days.
