# Operations runbook

The receiver's records about itself are in the SIEM (`index=wd2l sourcetype=wd2l:health`) and in
`journalctl -u wd2l-receiver`. The sender's health arrives in-band as `wd2l:sender:health`, in the
same index. Audit records are in `index=wd2l_audit`, readable only by the auditor role
([Audit records](#audit-records)). The dashboard is described in
[state-of-health.md](state-of-health.md); the design behind both is in
[audit-and-health.md](audit-and-health.md).

## Health records

| `type` | When | Key fields |
|---|---|---|
| `gap` | Events declared lost | `stream`, `first_seq`, `last_seq`, `count`, `reason` (below) |
| `heartbeat_stale` / `heartbeat_restored` | No heartbeat for `--hb-timeout` s / back | `age_s` |
| `stream_start` | A sender run seen for the first time | `stream` |
| `stream_end` | The sender stopped cleanly (final heartbeat) | `stream`, `last_seq`, `sender` counters |
| `stream_lost` | A stream went quiet without a clean stop | `stream`, `last_seq`, `idle_s`, `replaced_by` |
| `stream_missing` | A sender run never reached Enclave 2 (needs sender `--state`) | `stream`, `boot`, `last_seq`; or `first_boot`, `last_boot`, `runs` |
| `sender_boot_reset` | The sender's restart count went down (its state file was lost or replaced) | `boot`, `previous_boot` |
| `stream_evicted` | Over 1,000 streams tracked: one with open gaps was dropped | `stream`, `open_gap_events`, `gaps` |
| `gaps_forgotten` | A stream passed 100,000 open gap ranges: its oldest are no longer tracked, and a replay can't fill them. Once per stream | `stream`, `forgotten_gap_events`, `max_gap_ranges` |
| `fault` | The fault status, segment or rule changed | `fault_status`, `fault_segment`, `fault_rule`, `fault_detail`, `segments`, `previous_*` |
| `time_status` | The time check changed | `time_status` (`ok` or `alarm`), `time_reason` |
| `reconcile` | A comparison of what the sender numbered with what the receiver delivered, up to a cut | `stream`, `cut`, `balanced`, `gaps_open`, `gaps_forgotten`, `events_delivered` |
| `health` | Every 60 s | The counters below |

Every record carries `host`, `enclave`, `component` and `version`. Records about the records stream
carry `records: true`. The `health` counters, cumulative since the receiver started:

| Field | Meaning | Healthy |
|---|---|---|
| `events_delivered` | Events handed to the SIEM (or file) | growing |
| `gap_events` / `open_gap_events` | Events declared lost / still missing (includes earlier runs) | 0 |
| `forgotten_gap_events` | Missing events no longer tracked: a stream keeps at most 100,000 open gap ranges, and drops the oldest past that | 0 |
| `uncommitted_at_start` | Events the last run handed over but didn't see confirmed before it stopped | 0 |
| `output_dropped` | Events the output gave up on (queue or spool full) | 0 |
| `late_fills`, `duplicates` | Gaps filled later (replay); copies ignored | any |
| `heartbeats`, `heartbeat_age_s`, `heartbeat_stale` | Sender liveness | age ≤ ~1 s |
| `clock_offset_s` | Receiver clock minus sender clock at the last heartbeat (plus under 1 ms of fiber delay) | within a few ms of 0 |
| `other_packets`, `bad_frames`, `bad_events`, `digest_mismatch` (with `*_reasons`) | Traffic that isn't the log flow; corrupt or malformed input | 0 |
| `kernel_drops` | Packets the kernel dropped before the receiver read them | 0 |
| `capture_down_errors` | Reads that failed because the capture NIC went down, since the receiver started: usually one per outage (rule 1 says where and for how long) | 0 |
| `reasm_expired`, `reasm_evicted`, `event_too_big` | Split events that never completed | 0 |
| `sender_drops`, `sender_truncated`, `sender_bad_input`, `sender_unread_bytes`, `sender_opaque_events`, `sender_events_in` | From the sender's heartbeat | 0; truncated and opaque at your sources' usual level; `sender_events_in` grows with `events_delivered` |
| `hec_*` (`events_sent`, `spool_files`, `spool_bytes`, `posts_failed`, `rejected_events`, `queue_overflow_events`, `thread_errors`) | SIEM delivery; `audit_hec_*` for the audit output. `thread_errors`: unexpected errors in delivery, which goes on (the journal has the traceback) | spool, rejected, overflow, thread errors 0 |
| `records_delivered`, `records_bad` | Enclave 1 records passed on, and refused | growing; 0 |
| `fault_*`, `seg_*` | The receiver's verdict, and each segment's colour | `ok` (`unknown` while unseen) |
| `time_status`, `time_reason`, `time_quality` | The time check and chrony's numbers | `ok`; synced, stratum 3 |
| `audit_ok`, `audit_n`, `audit_hash`, `audit_verify` | This host's audit trail | `true`, growing, a hash, `ok` (empty until the first check) |
| `reconcile_unbalanced` | Sender runs whose last comparison didn't balance | 0 |
| `packet_age_s`, `frame_age_s` | Since any packet, and any wd2l frame, arrived | under ~1 s |
| `nic_*`, `archive_*`, `cpu_pct`, `rss_mb` | The capture NIC, the newest pcap file, the receiver process | carrier true; archive age under an hour |
| `state_save_failed` | The state file can't be written (disk full, or `/var/lib/wd2l` read-only). Receiving goes on and the save is retried each second | false |
| `streams`, `retired_streams` | Per sender run, with `open_gap_events` and `forgotten_gap_events`; finished runs with nothing open retire after `--stream-retention` (7 days) | |

### Gap reasons

| `reason` | Meaning | What to do |
|---|---|---|
| `not_received` | The packets never reached the capture NIC, or the receiver was down when they arrived | [Events lost](#alert-events-lost-typegap) |
| `receiver_restart` | Unresolved when the receiver last stopped, or received but not confirmed before a crash | Replay the archive |
| `output_dropped` | Received, but the output gave up (queue or spool full) | Fix the SIEM or disk, then replay the archive |

## Alerts

The Splunk examples are in `deploy/receiver/splunk/savedsearches.conf`. Every alert reads only the
health index (`index=wd2l`), so their owners don't need the auditor role; only the daily review
report reads `wd2l_audit`. The panels are those of [state-of-health.md](state-of-health.md#panels).

| Alert | Fires when | Panel |
|---|---|---|
| "WD2L - Events lost in transfer" | The receiver declared a gap (`type=gap`) | 4, 11 |
| "WD2L - Heartbeat stale" | No sender heartbeat for the heartbeat timeout, or a sender run went quiet without a clean end | 1, 3 |
| "WD2L - Sender run missing or restart chain broken" | A whole sender run never reached Enclave 2, the sender's restart count went back, or a stream with open gaps was dropped from tracking | — ([health records](#health-records)) |
| "WD2L - Receiver silent" | No health record from the receiver for 15 minutes | 2 |
| "WD2L - Unexpected traffic or damage on the tap" | In the last 20 minutes: packets that aren't the log flow, corrupt frames, refused Enclave 1 records (`records_bad`), kernel drops, sender drops, truncation, unread input at a sender stop, SIEM rejections or dropped output | 15–19 |
| "WD2L - Opaque content in imported logs" | Imported events carry a blob that can't be inspected (`wd2l_opaque`) | — (in the imported events) |
| "WD2L - Fault segment" | The receiver's fault status moved away from `ok` (`type=fault`) | 1, 1b, 3, 13 |
| "WD2L - Reconciliation not balanced" | A sender run with no open gaps hasn't balanced for an hour | 5, 12 |
| "WD2L - Audit trail" | `audit_ok` false or `audit_verify` failed, on either side | 7 |
| "WD2L - Time quality" | A clock unsynchronised, above stratum 3, more than 100 ms off or unreadable, or skew over 50 ms | 6, 10 |
| "WD2L - Audit review (daily)" | A report, not an alert: each morning, the previous day's configuration changes, state resets, archive replays, debug toggles, audit failures, self-checks and time quality changes. Its owner needs the `wd2l_auditor` role | 20 |

**Fault segment, heartbeat stale, time quality:** find the rule in the dashboard's
[Reading it](state-of-health.md#reading-it) table, which says what you see, what it means and what
to do. The latest verdicts:

```
index=wd2l sourcetype=wd2l:health type=fault | head 5
| table _time fault_status fault_segment fault_rule fault_detail previous_status
```

For a time alarm saying "unavailable" in a container (`--chrony-addr`), check that chronyd answers
on 127.0.0.1:323: as a normal user on the host, `chronyc -h 127.0.0.1 tracking` asks the same way.

## Alert: events lost (`type=gap`)

1. **Check `reason`.** `receiver_restart` and `output_dropped` are recovered by
   [replay](#replay-from-the-capture-archive). For `not_received`, go on.
2. **Was the receiver down or restarted?** `journalctl -u wd2l-receiver` around the gap time. If
   so, the packets are probably in the archive: replay.
3. **Kernel drops?** `kernel_drops` rising means the host can't keep up: check CPU and the NIC's
   ring size. A replay may still recover them (tcpdump has its own buffer). A
   `capture receive buffer is … KiB` warning in the receiver's log means `90-wd2l.conf` isn't
   applied ([receiver guide](deployment/receiver.md#kernel-receive-buffer)).
4. **Heartbeat stale at the same time?** The link or Enclave 1 was down, the packets never
   arrived, and a replay won't help: [re-send from Enclave 1](#re-sending-from-enclave-1).
5. **Isolated single-event gaps with a live heartbeat** are loss on the path: check the optics and
   the error counters on the log server's NIC, the tap ports and the receiver's NIC.

## Alert: reconciliation not balanced

The sender's heartbeats carry a hash of every event it numbered, up to a cut; the receiver keeps
the same hash of what it delivered ([how](audit-and-health.md#7-reconciliation)). The alert fires
when a stream has had no balanced `type=reconcile` record for an hour **and** its latest record
has no open gaps, and none dropped past the cap (`gaps_forgotten`). A stream with gaps is
"WD2L - Events lost in transfer"'s job.

1. **Open gaps** explain an unbalanced stream. A replay of the capture archive brings events back
   under their old numbers, and the stream balances at the next cut. A re-send from Enclave 1
   brings them back under new numbers in the current run, so the old stream stays unbalanced for
   good: expected, and this alert stays quiet for it.
2. **No open gaps** isn't normal: events were counted on one side and not the other, or changed
   on the way. Compare the audit reports. The receiver's files hold only Enclave 2's side; a SIEM
   export of `index=wd2l_audit` holds both:
   ```bash
   wd2l-audit-report reconcile --export siem-export.json --since 2026-10-05 --until 2026-10-06
   wd2l-audit-report events --dir /var/log/wd2l --event boundary_anomaly --since 2026-10-05
   ```
   A `boundary_anomaly` in the window, above all `digest_mismatch`, `bad_frames` or
   `reasm_inconsistent`, points to damage or tampering on the link: tell the security owner and
   follow the incident process.
3. **Whether the SIEM still holds what it accepted** is beyond the receiver. Compare:
   ```
   index=enclave1 wd2l_stream=<stream> | stats dc(wd2l_seq) as in_siem max(wd2l_seq) as max_seq
   index=wd2l sourcetype=wd2l:health type=reconcile stream=<stream> | head 1 | table cut events_delivered gaps_open
   ```
   `in_siem` should equal `events_delivered`. Fewer means the SIEM lost or refused events after
   accepting them: see `<spool>/rejected/` and the SIEM's ingest errors.

## Alert: audit trail

The transfer keeps going; the audit records are what is at risk.

* **`audit_ok=false`.** The host can't write its audit file, or its disk is below
  `--audit-min-free-mb` (256 MB). Records are still forwarded, and once writing works a new file
  starts with an `audit_failure` (`reason=recovered`) giving the number `missed`. Check free
  space and permissions on `/var/log/wd2l`; the `audit_failure` record gives the reason
  (`low_space`, `torn_write`, …). `open_failed`: the directory couldn't be opened at start, so
  this run keeps no audit file until it is fixed and the service restarted.
* **`audit_verify=failed`.** The daily self-check found the chain broken (a record changed,
  removed or reordered, or a file damaged), or couldn't run (it could not start, or was killed
  after 6 hours). On that host:
  ```bash
  journalctl -u wd2l-receiver | grep 'self-check'     # wd2l-sender on the log server
  sudo -u wd2l wd2l-audit-report verify --dir /var/log/wd2l
  ```
  If the chain verifies and the journal says `could not start` or `timeout`, fix the cause
  (memory, a very large directory); the flag clears at the next check. Otherwise compare the other
  copies (the retention server's for Enclave 1, `verify --dir <copy>`; the index,
  `verify --export FILE`), tell the security owner and follow the incident process. Don't edit or
  delete the files.

## Alert: opaque content (`wd2l_opaque`)

The sender found a long blob it can't inspect: `encrypted`, `compressed` or `high-entropy`. The
events crossed unchanged, so nothing needs replaying; the question is whether the content is
expected ([ADR-0002](decisions/0002-opaque-content.md)).

1. **Look at the events:**
   ```
   index=enclave1 wd2l_opaque=* earliest=-24h
   | table _time host source sourcetype wd2l_opaque wd2l_opaque_bytes _raw
   ```
2. **A source known and approved to log such data** (a proxy logging encrypted URL parameters, an
   application dumping compressed state): record the source, owner and reason, and exclude that
   host and source in the alert search.
3. **New or unexplained:** a possible security event. Tell the Enclave 1 system owner and follow
   the incident process. The original is also on the log retention server.

## Audit records

Each host records starts and stops, who changed what, replays, debug toggles, and the boundary
and delivery failures the counters show, in a hash chain: a changed, removed or reordered record
breaks it. Records hold metadata, counts and hashes, never log content. The catalog is in
[audit-and-health.md](audit-and-health.md#4-audit-event-catalog).

| Copy | Where | Who reads it |
|---|---|---|
| Official, each host | `/var/log/wd2l/audit-*.jsonl` (append-only, kept 1 year) | Group `wd2l-audit` |
| Enclave 1, second copy | The log retention server ([retention-server.md](deployment/retention-server.md#6-wd2l-audit-files)) | Auditors, administrators |
| SIEM | `index=wd2l_audit`: `wd2l:audit` (receiver), `wd2l:sender:audit` (sender, in-band) | The auditor role only |

**Verify a copy.** Each prints a JSON result (`ok`, or `failed` with the problems) and exits 1 on
a problem or when there is nothing to verify, or 2 when it can't read the directory: run it as
`wd2l`, as below. Each host also checks itself daily (`audit_verify`).

```bash
sudo -u wd2l python3 -m wd2l.audit verify /var/log/wd2l      # on the host
sudo -u wd2l wd2l-audit-report verify --dir /var/log/wd2l     # or a copy of the files
wd2l-audit-report verify --export siem-export.json --complete  # a SIEM export, none missing
```

**Reports** (`--format csv` for a spreadsheet; `--since`/`--until` are UTC; `events` also filters
by `--stream`, `--segment`, `--component` and `--host`):

```bash
wd2l-audit-report reconcile --export siem-export.json --since 2026-10-05 --until 2026-10-06
wd2l-audit-report events --dir /var/log/wd2l --event config_changed --since 2026-10-01
```

**Debug logging.** To switch it on or off so that the audit record names you, signal the service
from your own session, not with `systemctl kill` (then systemd is the sender):

```bash
sudo kill -USR1 "$(systemctl show -p MainPID --value wd2l-receiver)"     # or wd2l-sender
```

## Replay from the capture archive

Fills open gaps from the pcap files. Events already delivered are skipped, so replaying more files
than needed is safe. The replay and the live receiver share the state file and the audit
directory, so stop the receiver first (the replay refuses to start otherwise):

```bash
sudo systemctl stop wd2l-receiver
sudo -u wd2l python3 -m wd2l.receiver \
    --pcap /var/lib/wd2l/pcap/cap-20260925*.pcap \
    --state /var/lib/wd2l/state.json \
    --hec-url https://siem.enclave2.example:8088 --hec-token-file /etc/wd2l/hec.token \
    --hec-ca /etc/wd2l/siem-ca.pem --spool-dir /var/lib/wd2l/spool \
    --default-index enclave1 --health-index wd2l \
    --audit-dir /var/log/wd2l --hec-audit-token-file /etc/wd2l/hec-audit.token
sudo systemctl start wd2l-receiver
```

On a manual install (code in `/opt/wd2l`), put `env PYTHONPATH=/opt/wd2l` after `sudo -u wd2l`, here
and for `python3 -m wd2l.audit verify` above. In a container, see
[containers.md](deployment/containers.md#replay-from-the-archive).
`--audit-dir` records the replay (`replay_run`, naming you); it needs the audit token too (name the
same file twice if the site uses one token). A start can wait up to about 3 minutes for the clock
([waiting for the clock](planned-downtime.md#start)).

The summary's `late_fills` is how many gap events it recovered, and `open_gap_events` what is still
missing. tcpdump keeps capturing while the receiver is stopped, so the stop loses nothing: the
restarted receiver reports it as a gap, and the next replay fills it. After a **crash**, a replay
can re-send events that had already reached the SIEM (duplicates over loss): remove them in
searches with `| dedup wd2l_stream wd2l_seq`.

## Re-sending from Enclave 1

Events that never reached Enclave 2 (link down, receiver host down, loss on the wire, a run that
never arrived) must be sent again from Enclave 1, from the log retention server's 1-year copy.

1. **Find the window.** The gap record gives the stream and range; for tighter bounds, find the
   events on either side:
   `index=enclave1 wd2l_stream=<stream> (wd2l_seq=<first_seq-1> OR wd2l_seq=<last_seq+1>)`. Add a
   margin: numbering follows the aggregator's delivery order, close to time order but not exact.
2. **Replay it in Enclave 1.** The aggregator reads that window back from the retention server
   and routes it to `wd2l-sender` only ([retention-server.md](deployment/retention-server.md)).
3. **Check in Enclave 2.** The events arrive as new events with new numbers. Ones that had already
   arrived land twice: `| dedup host source _time _raw`. The old stream never balances again;
   the `gap` records and the re-sent events are the record of what happened.

## Measuring delays

Every event carries three times: `_time` (when the source wrote it), `wd2l_tx_time` (when the
sender sent it, Enclave 1's clock) and `wd2l_rx_time` (when the receiver got it, Enclave 2's
clock). With the SIEM's index time they split the delay by segment:

| Segment | Delay | Healthy |
|---|---|---|
| Enclave 1: source → forwarder → aggregator → sender | `wd2l_tx_time − _time` | a few seconds |
| Link and receiver | `wd2l_rx_time − wd2l_tx_time` | a few milliseconds |
| SIEM ingest | `_indextime − wd2l_rx_time` | a few seconds |

```
index=enclave1 earliest=-1h
| eval e1_s=wd2l_tx_time-_time, link_ms=(wd2l_rx_time-wd2l_tx_time)*1000, siem_s=_indextime-wd2l_rx_time
| stats median(e1_s) perc95(e1_s) median(link_ms) max(link_ms) median(siem_s) perc95(siem_s) by host
```

* **Check `clock_offset_s` first.** Off by more than a few milliseconds, the link delay is wrong by
  the same amount: fix time sync first.
* **Link delay high, offset fine:** the receiver is falling behind (`kernel_drops`, CPU). Replayed
  events keep their capture time, so a replay doesn't inflate it.
* **Enclave 1 delay odd or negative:** usually the source's clock or the aggregator's time parsing
  (`_time` often has whole seconds), not a slow pipeline.
* **SIEM delay rising** with `hec_spool_files` > 0: the SIEM was unreachable and the spool is
  draining.

## Routine

* **Planned downtime:** stop and start in the order of [planned-downtime.md](planned-downtime.md),
  and nothing is lost.
* **Sender restarts** start a new stream: `stream_end` (clean) or `stream_lost` (crash), then
  `stream_start`. With `--state` the new run names the old one. **Don't delete
  `/var/lib/wd2l/sender.json`**: the restart count starts over (`sender_boot_reset`).
* **Receiver restarts** are safe while `--state` is kept. **Don't delete
  `/var/lib/wd2l/state.json`**: without it, everything before the first event seen is reported
  missing.
* **Disk:** `/var/lib/wd2l/pcap` (hourly files, pruned after 7 days); `/var/lib/wd2l/spool` (grows
  only while the SIEM is unreachable; capped at 10 GB, its `audit/` part at 10 GB more);
  `/var/log/wd2l` (under 2 GB a year; nothing more is written below `--audit-min-free-mb`). In
  Enclave 1, the retention server's disk and the aggregator's queue for it: a full queue means a
  window with no copy to replay from.
* **Rejected SIEM events** (`hec_rejected_events` > 0) are in `/var/lib/wd2l/spool/rejected/`,
  only the events the SIEM refused, usually for an index that doesn't exist. Fix the index, then
  move the files back into `/var/lib/wd2l/spool/` to send them again (this can duplicate events
  the SIEM already took from that batch).
