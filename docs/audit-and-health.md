# Audit records and health monitoring

How wd2l records what it does and how it shows where a fault is: the design as built (wd2l 0.2.0
and later). To watch the system day to day, use the dashboard in
[state-of-health.md](state-of-health.md); to act on an alert, [operations.md](operations.md).
Decisions still open for the security and system owners are in the
[accreditation notes](accreditation-notes.md#open-items-for-the-security-and-system-owners).

## 1. Purpose and environment

Two goals, one design:

1. **Audit records** that meet common audit-control requirements: what is logged, what each
   record holds, time stamps, protection, review and retention. Section 11 maps them to two
   example frameworks; the design isn't tied to either.
2. **Health monitoring** that tells an operator, from one SIEM dashboard, whether a problem is in
   **Enclave 1, the boundary (tap and fiber) or Enclave 2**, and which part, to cut the time to
   repair.

| Item | As built |
|---|---|
| Retention | 1 year for audit records, on both sides (e.g. NIST AU-11, or the period a SOC 2 retention policy sets) |
| Direction | Audit and health data stays in the enclave that made it, or crosses from Enclave 1 to Enclave 2 with the logs. Nothing goes back ([the direction rule in the README](../README.md)) |
| SIEM | In Enclave 2 only. Enclave 1 has a central log server and a log retention server, no SIEM |
| Delivery | The receiver posts straight to the SIEM's HTTP event collector, with no event files and no forwarder ([ADR-0003](decisions/0003-receiver-to-siem-delivery.md)). Audit records go the same way, on their own token and index |
| Enclave 1 copy | The log retention server keeps every event for 1 year, and is the proposed 1-year home of wd2l's Enclave 1 audit files ([retention-server.md](deployment/retention-server.md#6-wd2l-audit-files)) |
| Time | A GPS receiver in each enclave → a switch serving time at stratum 2 → hosts running chrony at stratum 3 |
| Health view | In Enclave 2's SIEM. Enclave 1 has no live view; section 5 shows how its state still reaches Enclave 2 |

## 2. Three kinds of records

| Kind | Purpose | Enclave 1 | Enclave 2 |
|---|---|---|---|
| **Operational log** | Troubleshooting | journald, one JSON object per line | journald, one JSON object per line |
| **Health** (`wd2l:health`, `wd2l:sender:health`) | Dashboard, alerts, fault location | journald, and in-band to Enclave 2 | SIEM index `wd2l` |
| **Audit** (`wd2l:audit`, `wd2l:sender:audit`) | Evidence, review, reconciliation | Append-only files kept 1 year (the **official copy**), copied to the log retention server, and sent in-band | Append-only files kept 1 year, and SIEM index `wd2l_audit` (restricted) |

None of them ever holds log content (`_raw`): only metadata, counts and hashes.

* **Operational logs** (`--log-format json`): each line has `ts`, `level`, `logger`, `msg` and
  `segment` (section 6), plus `stream` and `seq` where they apply. The message texts are the
  same as in text format, so the runbooks' checks (`final: last_seq=…`, `boot … after stream …`)
  still match.
* **Enclave 1 health** goes only to journald and in-band. A separate file would be one more file
  to rotate, and ADR-0003 explains why rotation risks loss.
* **`SIGUSR1`** switches between INFO and DEBUG without a restart. A thread waiting in
  `sigwaitinfo` learns who sent the signal, and the `debug_toggled` audit record names them.
  Signal the process from your own session: with `systemctl kill`, systemd is the sender. An
  archive replay doesn't listen for it.

**Code:** `wd2l/logsetup.py`, `wd2l/outputs.py`.

## 3. Common record format

Every audit record, on both sides:

| Field | Example | Notes |
|---|---|---|
| `ts` | `2026-10-02T14:03:22.418213Z` | UTC, microseconds |
| `host` | `logsrv01` | The sender's in-band records use the same name as its audit files |
| `enclave` | `1` / `2` | |
| `component` | `sender`, `receiver`, `replay` | tcpdump writes no records; its state is in the receiver's health |
| `segment` | `e1-input` … `e2-siem` | For the fault view (section 6) |
| `version`, `build` | `0.3.0`, a git commit | `build` is `$WD2L_BUILD`, else a `BUILD` file beside the code, else `unknown` |
| `event`, `outcome` | `gap`, `failure` | From the catalog (section 4); outcome `success`, `failure` or `info` |
| `actor` | `uid=987(wd2l) unit=wd2l-sender.service` or `… auid=1001(jdoe) via sudo` | Who caused it |
| `stream`, `seq_first`, `seq_last` | | Ties a record to the data it is about |
| `time_quality` | `{"stratum":3,"offset_ms":0.21,"synced":true,"source":"…"}` | `synced: null`, `source: "unavailable"` and the error when chrony can't be read |
| `n`, `prev_hash`, `hash` | `1834`, SHA-256 | The chain (section 8). `hash` is SHA-256 of the record as canonical JSON (keys sorted, no spaces, UTF-8, no NaN or Infinity) without `hash`. The first `prev_hash` is 64 zeros |
| event fields | `count`, `reason`, `config_sha256` | `start` also has `code_sha256` (one SHA-256 over the package's `.py` files) and `python`: they prove which code ran |

* A record the file couldn't hold is still forwarded, with `n`, `prev_hash` and `hash` null
  ("unchained"). Verification counts these apart.
* Values JSON can't hold (NaN, bytes, sets, paths) are written as null or text before the record
  is chained, so a write never fails on them: audit trouble must never stop the transfer.
* **Health records** keep their `type` and `time` keys (the alerts and runbooks use them) and
  carry `host`, `enclave`, `component` and `version`. Every summary also has `time_quality`,
  `audit_ok`, `audit_n`, `audit_hash` and `audit_verify`.

**Code:** `wd2l/audit.py`, `wd2l/hostinfo.py`.

## 4. Audit event catalog

| Event | Side | When | Key fields |
|---|---|---|---|
| `start` / `stop` | both | Process start; clean stop. Together they record every planned-downtime window | `pid`, `config_sha256`, `code_sha256`, `python`; at stop the final counters and the signal |
| `config` | both | At start | The settings with secrets removed, and their hash |
| `config_changed` | both | The hash differs from the one saved in the state file (needs `--state`; archive replays don't update it) | Old and new hash |
| `state_loaded` / `state_reset` | both | State file read; or `reason` `missing` / `unreadable: …` (a receiver with an unreadable file records it and won't start; the sender starts over at boot 1) | Path, hash, streams |
| `auth_failure` | sender | Bad or missing aggregator token | Client address |
| `input_rejected`, `truncated`, `opaque_content`, `send_failure` | sender | Gzip or bad input; an event cut to fit; flagged blobs; UDP send errors | Count, reason, host and source (never content) |
| `boundary_anomaly` | receiver | Once a minute, from counter growth, for example `other_packets` (including the wrong source port), `bad_frames`, `bad_events`, `digest_mismatch`, `event_too_big`, `reasm_inconsistent`, `records_bad` | Count, reason |
| `gap` / `gap_filled` | receiver | Events declared lost; later recovered | Stream, `seq_first`, `seq_last`, count, reason |
| `stream_start` / `stream_end` / `stream_lost` / `stream_missing` | receiver | A sender run seen, ended, vanished, never seen | Stream, boot |
| `sender_boot_reset` | receiver | The sender's boot counter went back. Evidence about completeness | Stream, `boot`, `previous_boot` |
| `stream_evicted` | receiver | A stream with open gaps dropped from tracking (too many streams). Evidence about completeness | Stream, `open_gap_events`, `gaps` |
| `gaps_forgotten` | receiver | A stream passed 100,000 open gap ranges, so its oldest are dropped from tracking; once per stream. Evidence about completeness | Stream, `forgotten_gap_events`, `max_gap_ranges` |
| `output_failure` | receiver | Once a minute, from counter growth, for example `output_dropped`, `hec_rejected_events`, the HEC queue and spool overflows and `hec_records_lost` (and the same for the audit HEC) | Count, reason |
| `replay_run` | replay | `phase` `start` (the files) and `finish` (each file's SHA-256 and size, events filled, duplicates skipped, open gaps) | Actor |
| `debug_toggled` | both | `SIGUSR1` | Who sent it, the new level |
| `time_quality` | both | At start, and whenever the alarm state changes | `reason` `ok` or what is wrong |
| `audit_failure` | both | `write_failed`, `recovered` (with `missed`), `torn_write`, `low_space`, `space_ok` | Free space, records missed |
| `audit_verify` | both | At start and daily: the process checks its own chain; also `could not start` or `timeout` | Files, records, result |
| `reconcile` | both | Hourly, and at stream end | Section 7 |

**Summaries.** `auth_failure`, `input_rejected`, `truncated`, `opaque_content`, `send_failure`,
`gap_filled` and `gap` are written as one record per event, key and minute, with a `count` (the
key is, for example, the client and reason, the host and source, or the stream). Past 100 keys in
a minute the rest share one `overflow` record. Without this, a client retrying a bad token every
second writes 86,400 records a day, and chronic loss ten gaps a second. A `gap` summary gives
`count` (events lost), `gaps`, and the lowest and highest number lost; the health index still
gets one `gap` record per gap, with its range. Summaries pending at a stop are written at the
stop.

**Code:** `wd2l/sender.py`, `wd2l/receiver.py`.

## 5. Enclave 1's records in Enclave 2

With no SIEM in Enclave 1, the sender sends its own health and audit records **in-band**, as
ordinary DATA events in a **records stream** of its own (with `--audit-dir`):

* Every frame of it has bit 0 of `flags` set. It has its own stream id, sequence numbers and
  heartbeat, so the data stream's `seq` keeps meaning only the aggregator's events. It isn't
  linked across runs.
* Loss is detected like any loss: a gap marked `records: true`. The local files and the retention
  copy hold the records the link missed.
* The receiver routes by the flag, never by sourcetype, and chooses the index (`--audit-index`,
  `--health-index`): `wd2l:sender:audit` to `wd2l_audit`, `wd2l:sender:health` to `wd2l`.
* It passes on only records that name the Enclave 1 sender (`enclave` 1, `component` `sender`),
  re-serialized canonically. Anything else is dropped and counted in `records_bad`, which fires
  "WD2L - Unexpected traffic or damage on the tap". So Enclave 1 can't plant records about
  Enclave 2.
* A data event can't reach the audit index: one claiming `sourcetype=wd2l:sender:audit` stays
  with the logs, one naming `wd2l_audit` goes to the default index (`hec_audit_index_refused`),
  and the data token's index list leaves `wd2l_audit` out.
* The file output writes forwarded records to `audit.jsonl` and `e1-health.jsonl`.

The data stream's heartbeat also carries a snapshot of Enclave 1 every second:

* input: `events_in`, `clients`, `input_backlog_bytes`;
* the sender: `stall_s`, `cpu_pct`, `rss_mb`;
* the egress NIC (`--egress-iface`): `nic_carrier`, `nic_tx_packets`, `nic_tx_errors`,
  `nic_tx_dropped`;
* time: `time_stratum`, `time_offset_ms`, `time_synced`, or `time_unavailable: true`;
* audit: `audit_ok`, `audit_n`, and `events_hash` (section 7).

The body is about 600–800 bytes, one packet. If the snapshot would make it too big, its keys are
left out and `heartbeat_trimmed` counts it; `events_hash` is never left out. The bytes are in the
[interface description](interface-description.md).

**Code:** `wd2l/wire.py` (`FLAG_RECORDS`), `wd2l/sender.py`, `wd2l/receiver.py`.

## 6. Health signals by segment

The receiver reads its own probes every 5 s and puts them in every summary.

| Segment | Where | Fields |
|---|---|---|
| `e1-input` (aggregator → sender) | Enclave 1, via the heartbeat | `events_in`, `clients`, `input_backlog_bytes`, `bad_input`; auth failures are audit records |
| `e1-sender` | Enclave 1, via the heartbeat | `send_errors`, `sender_drops`, `boot`, `stall_s`, `cpu_pct`, `rss_mb`, time keys, egress NIC keys |
| `boundary` (tap, fiber) | Enclave 2 | The capture NIC's `nic_carrier`, `nic_carrier_changes`, `nic_rx_crc_errors`, `nic_rx_frame_errors` (also `nic_rx_errors`, `nic_rx_missed_errors`); `other_packets` |
| `e2-capture` | Enclave 2 | `nic_rx_packets`, `nic_rx_bytes`, `kernel_drops`; with `--pcap-dir`, `archive_file`, `archive_age_s`, `archive_bytes` |
| `e2-receiver` | Enclave 2 | `gap` records by reason, `reasm_expired`, `time_quality`, `cpu_pct`, `rss_mb`, `packet_age_s`, `frame_age_s` |
| `e2-siem` | Enclave 2 | `hec_spool_files`, `hec_spool_bytes`, `hec_queue`, `hec_posts_failed`, `hec_rejected_events`, `output_dropped` (and `audit_…` for the audit output) |

"Is tcpdump running?" is answered without seeing other users' processes: if packets arrive but
the newest archive file hasn't been written for 15 s, `archive_stale` is set (rule 11). That also
catches a stuck tcpdump. The delays (`wd2l_rx_time − wd2l_tx_time`, index time − `wd2l_rx_time`)
are SIEM searches ([operations.md](operations.md#measuring-delays)).

**Code:** `wd2l/hostinfo.py`, `wd2l/sender.py`, `wd2l/receiver.py`, `wd2l/outputs.py`.

## 7. Reconciliation

Each side keeps a **set hash** per data stream: the sum, modulo 2^256, of
SHA-256(`seq` as 8 bytes big-endian ‖ event SHA-256) over every event. The event SHA-256 is the
frame's `digest`.

* **The sender** adds each event as it numbers it and sends the running value in every heartbeat
  (`events_hash`). The heartbeat's `seq` is the cut: the value covers events 1 … `seq`.
* **The receiver** adds each event once it is delivered, as
  [ADR-0003](decisions/0003-receiver-to-siem-delivery.md) defines it (the SIEM answered 200, or the
  event is in the on-disk spool), after the outputs' failures are applied. It compares at the
  highest cut whose events are all resolved (delivered or declared a gap) and durable.
* **Equal values** prove the receiver delivered exactly the events the sender numbered up to the
  cut, unchanged and under the right numbers. A sum doesn't depend on order, so a late or
  replayed event just adds its term, and an event delivered twice counts once.
* **What it detects:** accidental loss, duplication, change or misnumbering. It doesn't defend
  against someone who controls the sender: that is the authenticity question in the
  [accreditation notes](accreditation-notes.md#integrity-and-authenticity).
* The records stream isn't reconciled, nor a stream restored from history (its earlier history
  is unknown).

**`reconcile` records.** The sender writes one hourly and at its stop (`cut`, `last_seq`,
`events_in`, `events_sent`, `sender_hash`). The receiver writes one hourly for every stream seen
in the last hour or not balanced, one when a stream ends and is resolved, and one whenever an
ended stream's cut or balance changes (for example after a replay fills its gaps); the end record
is skipped when the last one already states the same cut and balance. A stream with open gaps is
not retired (unless `stream_evicted`), so while it is unbalanced it keeps its hourly record. A
stream tracks at most 100,000 open gap ranges; past that the oldest are dropped and counted
(`gaps_forgotten`). The record has the sender's counters, `events_delivered`, `gaps_open`,
`gaps_filled`, `gaps_forgotten`, `last_seq`, both hashes and `balanced` (values agree at the cut
and no gap at or below it is open). Each result is also a
`type=reconcile` health record, and every summary has `reconcile_unbalanced`, because operators
can't read the audit index.

**Permanent gaps.** An archive replay fills gaps whose packets reached the capture NIC, and the
stream balances again. Events re-sent from Enclave 1 come back with new numbers in the sender's
current run, so a stream with `not_received` loss stays unbalanced for good. The reconciliation
alert therefore fires only for an unbalanced stream with no open or dropped gaps; how to close a
permanent gap is open item 7 in the accreditation notes.

**The SIEM's own completeness** (from its collector on) is a search in
[operations.md](operations.md#alert-reconciliation-not-balanced).

**`wd2l-audit-report`** is for assessors and reviews. `verify` checks one chain (`--dir`, with
`--upto` and `--upto-hash`) or a SIEM export (`--export`; `--complete` also fails on missing
records). `reconcile` puts both sides on one row per day and stream. `events` filters by time,
stream, event, segment, component and host. Output is `--format json` or `csv`. It treats its
input as untrusted: `verify` lists unreadable lines and fails, the others skip and count them,
and from an export it keeps the first copy of each `n` (a different second copy is a problem).
It exits 0 when all is well, 1 on a problem or nothing to verify, 2 when it could read nothing:
a missing file or directory, or one it may not read (run it as `wd2l`, or join `wd2l-audit`).

**Code:** `wd2l/reconcile.py` (`SetHash`, `StreamReconciler`), `wd2l/audit_report.py`.

## 8. Protecting the audit trail

* **Hash chain.** Each record's `hash` covers its content and `prev_hash`; `n` counts the records.
  Any edited, removed or reordered record breaks it. The latest `n` and hash are copied into
  every health summary, so the SIEM also holds them, and records cut from the end show up too.
* **Files.** `/var/log/wd2l/audit-<UTC start>.jsonl` (for example
  `audit-20261005T140322.418213Z.jsonl`), mode 0640, group `wd2l-audit` (directory 2750,
  setgid). One `write` and one `fsync` per record; files are only appended to. A new file starts
  past 64 MiB, after a short write (nothing is ever appended to a partial line) and when space
  returns. Nothing is renamed or truncated, so no rotation tool is involved. A `.lock` file
  (`flock`) keeps a second writer out: an archive replay started while the live receiver runs
  refuses.
* **Self-check.** At start and once a day each process runs
  `python3 -m wd2l.audit verify DIR --upto N --upto-hash H` in a child process, and records
  `audit_verify`. The result goes to temporary files (a full pipe would hang the child). A child
  that can't start, or still runs after 6 hours, is a failed check with `reason`
  `could not start` or `timeout`; neither stops the transfer. Verification reports a partial last
  line as `torn` (a crash isn't tampering) and hostile lines as problems, never crashing. Without
  `--upto`, an empty directory fails: it proves nothing.
* **Append-only, 1 year.** `wd2l-audit-seal.timer` runs hourly as root
  (`deploy/common/wd2l-audit-seal.sh`): `chattr +a` on every file, and deletes those last written
  more than 366 days ago. The wd2l units have no `CAP_LINUX_IMMUTABLE`. In Enclave 1 the
  aggregator copies each line unchanged to the log retention server, where the chain still
  verifies.
* **SIEM.** The `wd2l_audit` index, kept 366 days, on its own collector token, readable only by an
  auditor role (e.g. NIST AU-9(4); SOC 2 CC6.3). `--force-index` never moves audit records. With
  `--audit-dir` and `--hec-url`, the receiver won't start without `--hec-audit-token-file` (the
  data token can't write `wd2l_audit`); a site with one token names the same file twice. Without
  that token, it passes Enclave 1's audit records only to `--out-dir`, if it has one.
* **Host auditd rules** (`deploy/*/wd2l.rules`) watch wd2l's code, settings and units, and, for
  changes from a login session (`auid` set), its state and audit directories.
* **Failure response** (e.g. AU-5). If the audit file can't be written, the process **keeps
  transferring**: stopping would lose data that can't be re-sent. The record is still forwarded,
  unchained; health shows `audit_ok=false`; when writing works again an `audit_failure` with
  `reason=recovered` gives the number `missed`. Below `--audit-min-free-mb` (256 MB) every write
  counts as failed, so audit files never take the room the state file, spool and archive need;
  the floor is checked at start and once a minute. The same holds at start: if the directory
  can't be opened, the process runs without an audit file until restarted, forwarding every
  record (`reason=open_failed`). The security owner confirms this choice (open item 2).
* **Not built:** a keyed hash (HMAC) per record, or a separate backup copy (e.g. AU-9(2), AU-10).
  The design leaves room for them.

**Code:** `wd2l/audit.py`, `deploy/common/wd2l-audit-seal.*`, `deploy/*/wd2l.rules`,
`deploy/receiver/splunk/{indexes,inputs,authorize}.conf`.

## 9. Time

* Time stamps are UTC with microseconds. Each side reads chrony at most every 60 s: `chronyc -c
  tracking`, or with `--chrony-addr HOST[:PORT]` the same request over UDP to chronyd (the
  container images have no `chronyc`). `time_quality` is in every summary and audit record.
* **Thresholds** (defaults in the code; the stratum limit is the receiver's `--max-stratum`, for
  both sides' readings): an alarm when unsynced, above stratum 3
  or more than 100 ms off, and when the two clocks differ by more than 50 ms. Hosts are expected
  at stratum 3.
* **Unreadable chrony** is an alarm too, on either side. The sender then sends
  `time_unavailable: true` in place of its time keys.
* **Skew.** The receiver records `clock_offset_s` from each heartbeat's `sender_time`, minus the
  sub-millisecond fiber delay. With both sides GPS-disciplined, skew over ~50 ms points at time
  sync, not the network.
* The receiver works out `time_status` (`ok` or `alarm`, with `time_reason`) from both sides and
  the skew. It is in every summary, and each change is a `type=time_status` record, so "WD2L -
  Time quality" fires at once. Bad time doesn't lose events, so it is shown apart from the
  transfer's fault status.

**Code:** `wd2l/hostinfo.py` (`TimeQuality`), `wd2l/fault.py` (`time_status`).

## 10. Where is the fault: the rules

The receiver has nearly every signal (its own NIC, capture and SIEM output, plus Enclave 1's state
from the heartbeat), so it decides where a fault is. The rules work with any SIEM. All eleven are
unit-tested; rules 1–5 and 8–10 are also injected in the lab (`lab/run-lab.sh --fault NAME`).

* It re-evaluates every 5 s (`--fault-interval`, live capture only). "New" means growth over the
  last 60 s (`--fault-window`).
* Each change is a `type=fault` record (`fault_status`, `fault_segment`, `fault_rule`,
  `fault_detail`, `segments`, and the previous status, segment and rule). Every summary carries
  them and each segment's colour (`seg_e1_input` … `seg_e2_siem`).
* It reads the sender run whose latest heartbeat is the newest; a run never seen or a retired one
  brought back is skipped.
* Every matching rule colours its segments, so more than one can be off green. Segments it can't
  see while nothing arrives are `unknown` (grey), not green.
* It can't report its own absence: "WD2L - Receiver silent" covers that.

**Decision order** (the first match names the fault):

| # | Condition | Segment | Status |
|---|---|---|---|
| 1 | Capture NIC carrier down | `boundary`: tap, fiber or optic | red |
| 2 | No packets past the heartbeat timeout, and the last run ended cleanly (`stream_end`, no newer run) | `e1-sender`: stopped cleanly, e.g. planned downtime | amber |
| 3 | No packets past the heartbeat timeout | `e1-sender/boundary`: the sender, its egress NIC, or the tap | red |
| 4 | Packets arriving, no valid wd2l frames | `boundary`: tap filter or wiring | red |
| 5 | Heartbeats arriving, sender `events_in` flat for 300 s (`--input-flat-after`) | `e1-input`: the aggregator or its sources | amber |
| 6 | Sender drops or send errors, or an input backlog over 1 MiB and growing | `e1-sender` | amber |
| 7 | New `not_received` gaps with capture NIC receive or CRC errors | `boundary`: fiber or optic | red |
| 8 | New gaps with kernel drops, no NIC errors | `e2-capture` (colours `e2-capture` and `e2-receiver`): host capacity | red |
| 9 | New gaps with neither | `boundary`: loss on the path, or the receiver was down (capture still running; a replay fills those) | amber |
| 10 | `output_dropped` gaps, spool growing, collector errors or rejections | `e2-siem` | amber; red if events were dropped |
| 11 | `archive_stale` (section 6) | `e2-capture`: a replay would have nothing | amber |
| — | Time alarm or clock skew | Shown apart, as `time_status` | |

**The limit of a one-way link:** while nothing reaches Enclave 2, it can't tell "sender down"
from "fiber cut"; rule 3 narrows it to that pair. Once the link returns, the heartbeat's `boot`
and `uptime` settle it: an unchanged `boot` means the sender stayed up and the link was the
problem. A planned stop doesn't have this problem, because the final heartbeat says so (rule 2).

The dashboard that draws these records (20 panels, a mockup, and the Splunk Dashboard Studio file
`deploy/receiver/splunk/wd2l-health-dashboard.json`) is described in
[state-of-health.md](state-of-health.md).

**Code:** `wd2l/fault.py` (`evaluate`), `wd2l/receiver.py`, `lab/check_fault.py`.

## 11. Control mapping (examples)

The design isn't tied to one framework. Each audit control it addresses is mapped to two examples,
NIST SP 800-53 Rev 5 and the SOC 2 Trust Services Criteria. These are examples, not claims of
compliance: confirm them against the framework the system is assessed under. Values the
organization sets are marked *org-defined*.

| Audit control | How this design meets it | e.g. NIST SP 800-53 | e.g. SOC 2 |
|---|---|---|---|
| Event logging | The catalog in section 4 (*org-defined*: the list itself) | AU-2, AU-12 | CC7.2 |
| Content of records | The common format in section 3: what, when, where, source, outcome, identity, plus stream and sequence, config hash, time quality and segment | AU-3, AU-3(1) | CC7.2, CC7.3 |
| Storage capacity | Sizes in section 12; a free-space floor raises `audit_failure` before writes fail | AU-4 | A1.1 |
| Response to logging failures | `audit_failure` record and alert; keep transferring (section 8) | AU-5 | CC7.2 |
| Review, analysis and reporting | Dashboard, alerts, `wd2l-audit-report`; both enclaves' records joined by stream, sequence and GPS time | AU-6, AU-6(1), AU-6(3) | CC4.1, CC7.2, CC7.3 |
| Record reduction and report generation | `wd2l-audit-report`, filtering by time, stream, event and segment | AU-7, AU-7(1) | CC7.2 |
| Time stamps | UTC, microseconds, chrony to GPS; time quality recorded | AU-8 | No direct criterion; supports CC7.2 |
| Protection of audit information | Hash chain, daily self-check, append-only files, permissions, copies off the host | AU-9 | CC6.1 |
| Access limited to a few privileged users | `wd2l_audit` index and files restricted to an auditor role | AU-9(4) | CC6.1, CC6.3 |
| Retention | 1 year (*org-defined*) on both hosts, on the log retention server (open item 5) and in the SIEM | AU-11 | Set by the retention policy; supports CC7.2 |

Related controls this supports, mostly with evidence:

| Control | How | e.g. NIST SP 800-53 | e.g. SOC 2 |
|---|---|---|---|
| Information flow enforcement | Boundary-anomaly records | AC-4 | CC6.7 |
| System monitoring | The dashboard and alerts | SI-4 | CC7.2 |
| Integrity and completeness of processing | End-to-end reconciliation (section 7) | SI-7 | PI1.3–PI1.5, if Processing Integrity is in scope |
| Configuration change control and settings | Config hash at every start; `config_changed` | CM-3, CM-6 | CC8.1, CC7.1 |
| Incident handling and monitoring | Fault-segment records attached to incident tickets | IR-4, IR-5 | CC7.3–CC7.5 |
| Backup and recovery | State file, spool and archive replay | CP-9, CP-10 | A1.2, A1.3 |

Some frameworks or assessors ask for more (for example NIST's AU-5(1)/(2), AU-9(2)/(3), AU-10,
AU-12(1)/(3)). They're optional here, and the design leaves room for them.

## 12. Storage

Audit and health records don't grow with the event rate: they are written per minute, per hour,
per day or on a change. Measured in the lab (`sudo lab/run-lab.sh --events 25000 --eps 5000`)
and scaled to a day, at up to 1,000 events/s:

| What | Per day | Per year |
|---|---|---|
| Audit files, quiet day (24 hourly `reconcile` + 1 `audit_verify`, about 650 bytes each) | about 16 KB per side | about 6 MB per side |
| Audit files, busy day (plus three summary kinds every minute) | about 2.8 MB per side | about 1 GB per side |
| Audit files, heavy loss (`gap` summarised once a minute per stream and reason) | at most about 1 MB more | about 0.4 GB more |
| Audit in the SIEM | both sides' trails | 12 MB to 2 GB |
| Health in the SIEM (summaries about 4.2 MB receiver + 1.1 MB sender) | about 5.4 MB, plus one `gap` record (about 234 bytes) per gap | about 2 GB |

So the audit files stay **under 2 GB a year per side**, even with heavy loss. Chronic loss of ten
gaps a second adds about 200 MB a day to the health index, and the alerts fire within minutes.
The receiver's audit spool (`<spool-dir>/audit`) fills only while the SIEM is unreachable and is
capped at 10 GiB, like the data spool. For scale, the packet archive is raw data for replay, not
an audit record: 7 days, about 600 GB at full rate. The log retention server holds the logs
themselves, roughly 3–6 TB a year compressed at full rate.
