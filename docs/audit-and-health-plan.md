# Plan: audit records and health monitoring for wd2l

**Status: proposal for review, updated 2026-10-05. Nothing here is built yet.** This update makes
the plan framework-neutral. It also brings it in line with the
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

## 3. What exists today, and the gaps

Today the receiver writes `wd2l:health` records to the SIEM:

* gaps, stale and restored heartbeats, and stream start, end and loss;
* a summary every 60 s with its counters, the sender's heartbeat counters and the clock offset.

The sender writes free-text lines to journald, including the `final: last_seq=…` line that the
[planned-downtime runbook](planned-downtime.md) checks. Its counters reach Enclave 2 only inside
heartbeats. Everything that crosses is described packet by packet in
[interface-description.md](interface-description.md), down to the fixed UDP source port.

| # | Gap | Why it matters |
|---|---|---|
| G1 | No structured record of the sender's activity in Enclave 1 | Event logging where events happen (e.g. AU-2, AU-12; SOC 2 CC7.2). There's nothing to review in Enclave 1 |
| G2 | No record of version, configuration, or the account that started each side | Record content and configuration control: proving the running configuration is the approved one (e.g. AU-3, CM-3, CM-6; SOC 2 CC8.1) |
| G3 | Operator actions (archive replay, state-file reset) aren't attributed | Identity in records, and review (e.g. AU-3, AU-6; SOC 2 CC7.2) |
| G4 | Completeness is checked by counts; content isn't reconciled end to end | Integrity: proof the SIEM holds exactly what Enclave 1 sent (e.g. SI-7; SOC 2 PI1.4) |
| G5 | Health records aren't tamper-evident and share the data's index and token | Protection of audit information, and access limited to a few privileged users (e.g. AU-9, AU-9(4); SOC 2 CC6.1) |
| G6 | No time-quality data (chrony stratum/offset). *Partly addressed:* sender-vs-receiver offset (`clock_offset_s`) and per-event send/arrival times (`wd2l_tx_time` / `wd2l_rx_time`) are built | Time stamps (e.g. AU-8); troubleshooting misordered events |
| G7 | Health signals don't cover the NIC/link layer or the aggregator → sender hand-off | Can't say *where* a fault is |
| G8 | Packet archive kept 7 days; no retention plan for audit records | Retention, 1 year (e.g. AU-11) |
| G9 | A planned stop looks like a fault. The runbook mutes alerts for the window, and nothing records who stopped and started what | Telling planned work from faults. Evidence for change windows (e.g. CM-3; SOC 2 CC8.1) |

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

## 8. Health signals by segment

| Segment | Where | Signals (new in **bold**) |
|---|---|---|
| `e1-input` (aggregator → sender) | Enclave 1 | **events in per second, connected clients, input backlog (bytes the aggregator has handed over that the sender hasn't read yet)**, bad input, auth failures |
| `e1-sender` | Enclave 1 | heartbeats, send errors, drops, restarts (`boot`), **time stalled on pacing or a full send buffer, process CPU/memory, egress NIC carrier and tx packets/errors (`--egress-iface`), chrony stratum/offset** |
| `boundary` (tap, fiber) | seen from Enclave 2 | **capture NIC carrier, carrier-change count, rx CRC/frame errors** (`/sys/class/net/<nic>/carrier` and `statistics/`; `ethtool -S` by hand for driver-specific counters), packets that aren't the log flow |
| `e2-capture` | Enclave 2 | **NIC rx packets/bytes**, kernel drops, **tcpdump running, newest archive file age/size** |
| `e2-receiver` | Enclave 2 | gaps by reason, reassembly expiry, lag from sender time to delivery (built: `wd2l_rx_time − wd2l_tx_time`), **chrony stratum/offset**, process CPU/memory |
| `e2-siem` | Enclave 2 | spool files/bytes, collector errors and rejections, SIEM ingest delay (built: index time − `wd2l_rx_time`) |

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

## 13. Alerts (added or changed)

* Fault status changed from `ok` (`type=fault`), with the segment and rule in the alert text.
* Reconciliation not balanced for an hour.
* Audit trail: `audit_failure`, or a failed `audit_verify`.
* Time quality out of bounds; skew above threshold.
* `config_changed`, `state_reset`, `replay_run`, `debug_toggled`: a daily report for review, not
  an alert.
* The [planned-downtime runbook](planned-downtime.md) adds "WD2L - Fault segment" to the alerts it
  mutes for the window. Rule 2 shows the stop as amber, not red.

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

## 17. Open items for the security and system owners

1. Event list (section 6): confirm, or add events your control documentation requires.
2. Failure response: keep transferring when the audit log can't be written (proposed), or stop.
3. Time thresholds: |offset| 100 ms, skew 50 ms. Adjust as needed.
4. Who gets the auditor role in the SIEM for `wd2l_audit`.
5. Enclave 1 audit files: confirm the log retention server as their 1-year home (proposed), so
   they survive a rebuild of the log server.
6. Which framework the system is assessed under, and its retention period (1 year is assumed
   throughout).
