# Plan: audit records and health monitoring for wd2l

**Status: proposal for review. Nothing here is built yet.**

## 1. Purpose

Two goals, one design:

1. **Audit records** that meet NIST SP 800-53 Rev 5, **Moderate baseline**, Audit and
   Accountability (AU) family, for the wd2l transfer capability.
2. **Health monitoring** that tells an operator, from one Splunk dashboard, whether a problem is
   in **Enclave 1, the boundary (tap/fiber), or Enclave 2**, and which part, to cut mean time to
   repair (MTTR).

## 2. Decisions and environment

| Item | Decision / fact |
|---|---|
| Control baseline | NIST SP 800-53 Rev 5, Moderate |
| Audit record retention (AU-11) | 1 year, both enclaves |
| SIEM | Splunk in Enclave 2. **No SIEM in Enclave 1**: logs are collected on the central log server only. |
| Time | GPS (SAASM) receiver in each enclave → a switch serving time as stratum 2 → hosts running chrony (stratum 3) |
| Where the health view lives | Enclave 2 Splunk. Enclave 1 has no live view; see section 7 for how Enclave 1's state still reaches it |

## 3. What exists today, and the gaps

Today the receiver writes `wd2l:health` records to Splunk (gaps, stream changes, stale heartbeat,
counters every 60 s). The sender writes free-text lines to journald; its counters reach
Enclave 2 only inside heartbeats.

| # | Gap | Why it matters |
|---|---|---|
| G1 | No structured record of the sender's activity in Enclave 1 | AU-2/AU-12: events must be logged where they happen; nothing to review in Enclave 1 |
| G2 | No record of version, configuration, or the account that started each side | AU-3, CM-3/CM-6: proving the running configuration is the approved one |
| G3 | Operator actions (archive replay, state-file reset) aren't attributed | AU-3 identity; AU-6 review |
| G4 | Completeness is checked by counts; content isn't reconciled end to end | SI-7 integrity; proof the SIEM holds exactly what Enclave 1 sent |
| G5 | Health records aren't tamper-evident and share the data's index and token | AU-9, AU-9(4) |
| G6 | No time-quality data (chrony stratum/offset, sender-vs-receiver skew) | AU-8; troubleshooting misordered events |
| G7 | Health signals don't cover the NIC/link layer or the aggregator → sender hand-off | Can't say *where* a fault is |
| G8 | Packet archive kept 7 days; no retention plan for audit records | AU-11 (1 year) |

## 4. Three kinds of records

| Kind | Purpose | Volume | Enclave 1 destination | Enclave 2 destination |
|---|---|---|---|---|
| **Operational log** | Troubleshooting detail | Moderate; debug on demand | journald (JSON) | journald (JSON) |
| **Health** (`wd2l:health`) | Dashboard, alerts, fault location | One summary a minute per side, plus immediate change records | Local file + **in-band to Enclave 2** (section 7) | Splunk index `wd2l` |
| **Audit** (`wd2l:audit`) | AU-2 events, evidence, reconciliation | Low: events and hourly summaries | Local append-only file (**official copy**, 1 year) + in-band copy | Local append-only file + Splunk index `wd2l_audit` (restricted) |

None of the three ever contains log content (`_raw`), only metadata, counts and hashes.

Operational logs move from free text to one JSON object per line on both sides, each tagged with
`segment` (section 8) and, where relevant, `stream` / `seq`. `SIGUSR1` toggles debug level
without a restart; the toggle is itself an audit event.

## 5. Common record format

Every health and audit record, on both sides:

| Field | Example | Notes |
|---|---|---|
| `ts` | `2026-10-02T14:03:22.418213Z` | UTC, microseconds (AU-8) |
| `host` | `logsrv01` | |
| `enclave` | `1` / `2` | |
| `component` | `sender`, `receiver`, `replay`, `capture` | |
| `segment` | `e1-input`, `e1-sender`, `boundary`, `e2-capture`, `e2-receiver`, `e2-siem` | for the fault view |
| `version`, `build` | `0.2.0`, git commit | |
| `event` | `start`, `config`, `auth_failure`, `gap`, `reconcile`, … | from the catalog in section 6 |
| `outcome` | `success` / `failure` / `info` | |
| `actor` | `uid=987(wd2l) unit=wd2l-sender.service` or `uid=1001(jdoe) via sudo` | who caused it (AU-3) |
| `stream`, `seq_first`, `seq_last` | | ties a record to the data it's about |
| `time_quality` | `{"stratum":3,"offset_ms":0.21,"synced":true}` | from `chronyc -c tracking` (AU-8) |
| `prev_hash`, `hash` | SHA-256 | audit records only: hash chain (section 10) |
| event-specific fields | | e.g. `count`, `reason`, `config_sha256` |

## 6. Audit event catalog (AU-2)

| Event | Side | When | Key fields |
|---|---|---|---|
| `start` / `stop` | both | process start; clean stop (with final counters) | version, build, actor, pid, `config_sha256`, stop reason |
| `config` | both | at start | full settings with secrets removed, and their hash |
| `config_changed` | both | `config_sha256` differs from the previous run | old/new hash |
| `state_loaded` / `state_reset` | both | state file read; missing, unreadable or deleted | path, file hash, streams loaded |
| `auth_failure` | sender | bad or missing aggregator token | client address |
| `input_rejected` | sender | gzip input, line too long, bad JSON (summarised per minute) | count, reason |
| `truncated` | sender | event cut to fit | host, source, original size (not content) |
| `send_failure` | sender | UDP send errors, drops (summarised) | count, errno |
| `boundary_anomaly` | receiver | non-wd2l packets, corrupt frames, digest mismatch (summarised) | count, reason |
| `gap` / `gap_filled` | receiver | events declared lost; later recovered | stream, range, count, reason |
| `stream_start` / `stream_end` / `stream_lost` / `stream_missing` | receiver | sender run seen, ended, vanished, never seen | stream, boot |
| `output_failure` | receiver | SIEM rejected or dropped events; spool overflow | count, reason |
| `replay_run` | replay | archive replay started/finished | actor, files and their hashes, events filled, duplicates skipped |
| `debug_toggled` | both | `SIGUSR1` | actor, new level |
| `time_quality` | both | at start, and whenever unsynced, stratum > 3, or \|offset\| > 100 ms | stratum, offset, source |
| `audit_failure` | both | audit file can't be written, disk below threshold | reason, free space (AU-5) |
| `reconcile` | both | hourly, and at stream end | section 9 |

## 7. Getting Enclave 1's records to Enclave 2 (no Enclave 1 SIEM)

The sender sends its own health and audit records **in-band**, as ordinary events in its own
stream:

* `sourcetype=wd2l:sender:health` / `wd2l:sender:audit`, `index=wd2l` / `wd2l_audit`,
  `host=` the log server.
* They get sequence numbers like everything else, so their loss is detected and reported too.
* Volume is bounded (summaries, not per event), so there's no feedback loop.
* No wire-format change: they're normal DATA events.
* **The local file in Enclave 1 stays the official audit copy** (AU-11, 1 year). Records written
  while the link is down don't reach Enclave 2 live. Their absence is visible as a gap, and the
  local file has them.

The heartbeat also carries a compact health snapshot every second (some fields already there; new
ones: events-in rate, stall time, egress NIC tx errors, chrony offset/stratum, running hash). So
Enclave 2 sees Enclave 1's state within about a second while the link is up.

## 8. Health signals by segment

| Segment | Where | Signals (new in **bold**) |
|---|---|---|
| `e1-input` (aggregator → sender) | Enclave 1 | **events in per second, connected clients, seconds stalled waiting on the sender**, bad input, auth failures |
| `e1-sender` | Enclave 1 | heartbeats, send errors, drops, restarts (`boot`), **process CPU/memory, egress NIC tx packets/errors, chrony stratum/offset** |
| `boundary` (tap, fiber) | seen from Enclave 2 | **capture NIC carrier, carrier-change count, rx CRC/frame errors** (`/sys/class/net/*/statistics`, `ethtool -S`) |
| `e2-capture` | Enclave 2 | **NIC rx packets/bytes**, kernel drops, **tcpdump running, newest archive file age/size**, non-wd2l packets |
| `e2-receiver` | Enclave 2 | gaps by reason, reassembly expiry, **lag from sender time to delivery**, **chrony stratum/offset**, process CPU/memory |
| `e2-siem` | Enclave 2 | spool files/bytes, HEC errors and rejections, **SIEM ingest delay** (index time − event time) |

## 9. Reconciliation (completeness and accuracy)

* The sender keeps a **running SHA-256** per stream: `H(n) = SHA256(H(n-1) ‖ seq ‖ event_sha256)`.
  The receiver computes the same over events once they're **durable in the SIEM** (the existing
  "delivered" point).
* The sender's value travels in the heartbeat. Equal values for the same `seq` prove nothing was
  lost, added, changed or reordered up to that point.
* An hourly `reconcile` record on each side holds: `events_in`, `events_sent`, `events_delivered`,
  `gaps_open`, `gaps_filled`, `last_seq`, running hash, and `balanced` (true when
  sent = delivered + open gaps and the hashes agree at the last common `seq`).
* Gaps break the chain. After a gap, the receiver keeps a separate hash per contiguous run, and a
  replay that fills the gap restores the single chain.
* **`wd2l-audit-report`** (new command) builds daily or ranged reconciliation reports (JSON/CSV)
  from the audit files or a Splunk export, for assessors and AU-6/AU-7 reviews.

## 10. Protecting the audit trail (AU-9, AU-9(4), AU-4, AU-5)

* **Hash chain:** each audit record's `hash` covers its content plus `prev_hash`.
  `wd2l-audit-report verify` detects any edited, removed or reordered record. The latest hash is
  copied into the hourly health record, so it also lives in Splunk.
* **Files:** `/var/log/wd2l/audit.jsonl`, owned by a separate `wd2l-audit` group, mode 0640,
  `chattr +a` (append-only), rotated by size with the chain carried across files.
* **Splunk:** `wd2l_audit` index, its own HEC token, readable only by an auditor role
  (AU-9(4): only a subset of privileged users manage audit data).
* **Host auditd rules** on both hosts watch wd2l's programs, settings, state files and audit files.
* **Failure handling (AU-5):** if the audit file can't be written, the process logs to journald,
  raises `audit_failure` in health, and **keeps transferring**. Stopping the transfer would lose
  data that can't be re-sent. Confirm this choice with the ISSO.
* **Optional (High baseline only, not required):** keyed hash (HMAC) on each record, separate
  backup copy (AU-9(2)).

## 11. Time (AU-8)

* Timestamps are UTC with microseconds, from chrony.
* Both sides record `time_quality` (stratum, offset, synced) in every health summary.
* Expected stratum on the hosts is **3** (GPS → switch at stratum 2 → hosts).
* Alert when unsynced, stratum > 3, or |offset| > 100 ms (threshold to confirm).
* The receiver records **sender-vs-receiver clock skew** from the heartbeat's `sender_time`, minus
  the one-way network delay (well under 1 ms on a direct fiber). With both sides GPS-disciplined,
  skew over ~50 ms points to a time-sync fault, not the network.

## 12. The "where is the fault" dashboard

Splunk Dashboard Studio, shipped as `deploy/receiver/splunk/wd2l-health-dashboard.json`.

**Decision order** (first match wins), computed by a saved search every minute:

| # | Condition | Fault segment |
|---|---|---|
| 1 | Capture NIC carrier down | `boundary`: tap or fiber |
| 2 | Carrier up, NIC rx packets flat | `e1-sender` or `boundary`: sender, its egress NIC, or the tap filter (see heartbeat history after recovery) |
| 3 | Packets arriving, no valid wd2l frames | `boundary`: tap filter or wiring |
| 4 | Heartbeats arriving, sender events-in = 0 | `e1-input`: log aggregator or its sources |
| 5 | Heartbeats show sender drops / send errors / stalls | `e1-sender` |
| 6 | Gaps (`not_received`) with NIC CRC/rx errors | `boundary`: fiber or optic |
| 7 | Gaps with kernel drops, no NIC errors | `e2-capture` / `e2-receiver`: host capacity |
| 8 | Spool growing, HEC errors or rejections | `e2-siem` |
| 9 | Clock skew or time_quality alarm | time sync (shown separately, not a transfer fault) |

**Layout:**

1. Status tile: green / amber / red, plus the suspected segment and the rule that matched.
2. Pipeline picture: the six segments, each colored by its own health.
3. Events in (Enclave 1) vs events delivered (Enclave 2) over time.
4. End-to-end delay and clock skew.
5. Gaps by reason; reconciliation balance.
6. One row of detail panels per segment.

**Limit of a one-way link:** while nothing reaches Enclave 2, it can't tell "sender down" from
"fiber cut" in real time; rule 2 narrows it to that pair. Once the link returns, the
heartbeat's `boot` and `uptime` settle it: unchanged `boot` means the sender stayed up and the
link was the problem.

## 13. Alerts (added or changed)

* Fault segment changed from `ok` (with the segment in the alert text).
* Reconciliation not balanced for an hour.
* Audit chain verification failed; `audit_failure`.
* Time quality out of bounds; skew above threshold.
* `config_changed`, `state_reset`, `replay_run` (informational, for review).

## 14. NIST SP 800-53 Rev 5 mapping (Moderate)

Confirm against the system security plan (SSP); organization-defined values are marked *ODV*.

| Control | Meets it by |
|---|---|
| AU-2 Event Logging | The catalog in section 6 (*ODV*: the event list itself; coordinate with the ISSO) |
| AU-3 Content of Audit Records | The common format in section 5: what, when, where, source, outcome, identity |
| AU-3(1) Additional Audit Information | Stream/sequence, config hash, time quality, segment |
| AU-4 Audit Log Storage Capacity | Size estimates below; disk headroom checks in health |
| AU-5 Response to Audit Logging Process Failures | `audit_failure` record and alert; keep transferring (section 10) |
| AU-6 Audit Record Review, Analysis, and Reporting | Dashboard, alerts, `wd2l-audit-report` |
| AU-6(1) Automated Process Integration | Saved searches and alerts feed the review process |
| AU-6(3) Correlate Audit Record Repositories | Enclave 1 and Enclave 2 records joined by stream/sequence and GPS time |
| AU-7 Audit Record Reduction and Report Generation | `wd2l-audit-report` |
| AU-7(1) Automatic Processing | Report filters by time, stream, event and segment |
| AU-8 Time Stamps | UTC, microseconds, chrony to GPS; time quality recorded |
| AU-9 Protection of Audit Information | Hash chain, append-only files, permissions |
| AU-9(4) Access by Subset of Privileged Users | `wd2l_audit` index and files restricted to an auditor role |
| AU-11 Audit Record Retention | 1 year, both enclaves |
| AU-12 Audit Record Generation | Both components generate the catalog events |

Related controls this supports (mostly with evidence):

* **AC-4** information flow enforcement: boundary-anomaly records.
* **SI-4** system monitoring: the dashboard and alerts.
* **SI-7** software, firmware and information integrity: end-to-end reconciliation.
* **CM-3, CM-6** configuration change control and settings: config hash at every start.
* **IR-4, IR-5** incident handling and monitoring: fault-segment records attached to incident tickets.
* **CP-9, CP-10** backup and recovery: state file, spool and archive replay.

High-baseline enhancements (AU-5(1)/(2), AU-9(2)/(3), AU-10, AU-12(1)/(3)) are optional here; the
design leaves room for them.

## 15. Storage estimate (AU-4, AU-11)

At the planned < 1,000 events/s:

* **Audit:** a few thousand records a day per side, ~1–5 MB/day → **under 2 GB per year per side**.
* **Health:** one summary a minute per side plus change records, ~10 MB/day → ~4 GB/year in Splunk.
* **Packet archive:** unchanged (7 days, ~600 GB at full rate). It's raw data for replay, not an
  audit record.

## 16. Implementation phases

| Phase | Work | Rough effort |
|---|---|---|
| 1 | Shared module `wd2l/audit.py`: record format, hash chain, file writer, audit catalog wired into sender and receiver, JSON operational logs, `SIGUSR1`, time quality | 3–4 days |
| 2 | New health signals per segment (NIC/link counters, events-in, stalls, CPU/memory, archive age, ingest delay); in-band Enclave 1 records; heartbeat snapshot | 2–3 days |
| 3 | Running hashes, hourly `reconcile`, `wd2l-audit-report` (report + verify) | 2–3 days |
| 4 | Splunk: `wd2l_audit` index and token, fault-segment saved search, dashboard, new alerts; host auditd rules; deployment and operations docs | 2–3 days |

**Testing:** unit tests for the record format, hash chain (edits detected), reconciliation and
fault-segment rules. A lab mode that **injects a fault in each segment**, one at a time, and
checks that the dashboard search names the right segment:

* stop the aggregator stand-in;
* kill the sender;
* bring the tap link down;
* inject non-wd2l traffic;
* drop packets on the cable;
* throttle the receiver;
* stop the SIEM stand-in;
* skew a clock.

## 17. Open items for the ISSO / owner

1. AU-2 event list (section 6): confirm, or add events your SSP requires.
2. AU-5 behavior: keep transferring when the audit log can't be written (proposed), or stop.
3. Time thresholds: |offset| 100 ms, skew 50 ms. Adjust as needed.
4. Who gets the auditor role in Splunk for `wd2l_audit`.
5. Whether Enclave 1 audit files need copying off the log server (for example to backup media)
   to meet 1-year retention if the server is rebuilt.
