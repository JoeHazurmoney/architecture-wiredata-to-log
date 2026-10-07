# Operations runbook

All receiver output about itself is in the SIEM: `index=wd2l sourcetype=wd2l:health`, and in
`journalctl -u wd2l-receiver`. The sender's own health records come across in-band as
`sourcetype=wd2l:sender:health`, in the same index. Audit records (who started, stopped or
changed what, in a hash chain that shows nothing was edited) are in `index=wd2l_audit`, which
only the auditor role can read; see [Audit records](#audit-records). The dashboard that draws all
of this is described in [state-of-health.md](state-of-health.md).

## Health records

| `type` | When | Key fields |
|---|---|---|
| `gap` | Events declared lost | `stream`, `first_seq`, `last_seq`, `count`, `reason` (below) |
| `heartbeat_stale` | No heartbeat for `--hb-timeout` s | `age_s` |
| `heartbeat_restored` | Heartbeats back | |
| `stream_start` | A sender run seen for the first time (the sender restarted) | `stream` |
| `stream_end` | Sender shut down cleanly (final heartbeat) | `stream`, `last_seq`, `sender` counters |
| `stream_lost` | A stream went quiet without a clean shutdown | `stream`, `last_seq`, `idle_s`, `replaced_by` (if the next run already started) |
| `stream_missing` | A sender run never reached Enclave 2 (needs sender `--state`) | `stream`, `boot`, `last_seq`; or `first_boot`, `last_boot`, `runs` when even the stream id is unknown |
| `sender_boot_reset` | The sender's restart count went down (its state file was lost or replaced) | `boot`, `previous_boot` |
| `stream_evicted` | Over 1,000 streams tracked: one with open gaps was dropped from tracking | `stream`, `open_gap_events`, `gaps` |
| `fault` | The fault status, segment or rule changed | `fault_status` (`ok`, `amber`, `red`), `fault_segment`, `fault_rule`, `fault_detail`, `segments` (the state of each box), `previous_status`, `previous_segment`, `previous_rule` |
| `time_status` | The time check changed | `time_status` (`ok` or `alarm`), `time_reason` |
| `reconcile` | A comparison of what the sender numbered with what the receiver delivered, up to a cut (a sequence number) | `stream`, `cut`, `balanced`, `gaps_open`, `events_delivered` |
| `health` | Every 60 s | counters below |

Every record carries `host`, `enclave`, `component` and `version`, so a search can tell the
receiver's records from the sender's. Records about the audit-record stream itself (see
[Audit records](#audit-records)) carry `records: true`, so the dashboard keeps them apart from the
log flow.

`health` counters are cumulative since the receiver started:

| Field | Meaning | Healthy |
|---|---|---|
| `events_delivered` | Events handed to the SIEM (or file) | growing |
| `gap_events` / `open_gap_events` | Events declared lost / still missing (includes earlier runs, from the state file) | 0 |
| `uncommitted_at_start` | Events the last run handed to the SIEM output that were not confirmed before it stopped | 0 |
| `output_dropped` | Events the output gave up on (memory queue or spool full) | 0 |
| `late_fills` | Gaps filled later (archive replay) | — |
| `duplicates` | Copies ignored | any (normal during replay) |
| `heartbeats`, `heartbeat_age_s`, `heartbeat_stale` | Sender liveness | age ≤ ~1 s |
| `clock_offset_s` | Receiver clock minus sender clock at the last heartbeat, plus the one-way delay (under 1 ms on the fiber). Also per stream in `streams` | within a few ms of 0 |
| `other_packets`, `other_reasons` | Frames on the tap that aren't the log flow | 0 |
| `bad_frames`, `bad_events`, `digest_mismatch`, `bad_reasons` | Corrupt or malformed input | 0 |
| `kernel_drops` | Packets the kernel dropped before the receiver read them | 0 |
| `reasm_expired`, `reasm_evicted`, `event_too_big` | Split events that never completed | 0 |
| `sender_drops`, `sender_truncated`, `sender_bad_input`, `sender_unread_bytes` | From the sender's heartbeat | 0 (truncated: expected if you have huge events) |
| `sender_opaque_events` | Events the sender flagged for an opaque blob (`wd2l_opaque`), this sender run | 0, or the level known for your sources |
| `hec_events_sent`, `hec_spool_files`, `hec_posts_failed`, `hec_rejected_events`, `hec_queue_overflow_events` | SIEM delivery | spool 0, rejected 0, overflow 0 |
| `records_delivered`, `records_bad` | Audit and health records from Enclave 1 handed to the SIEM, and ones that were refused: malformed, or not naming the Enclave 1 sender (`enclave` 1, `component` `sender`) | growing; 0 |
| `fault_status`, `fault_segment`, `fault_rule`, `fault_detail` | The receiver's verdict on where the fault is ([state-of-health.md](state-of-health.md)) | `ok`; the rest empty |
| `seg_e1_input`, `seg_e1_sender`, `seg_boundary`, `seg_e2_capture`, `seg_e2_receiver`, `seg_e2_siem` | State of each segment | `ok` (`unknown` while it can't be seen) |
| `time_status`, `time_reason`, `time_quality` | The time check, why it is in alarm, and chrony's own numbers (synced, stratum, offset) | `ok`; synced, stratum 2 |
| `audit_ok`, `audit_n`, `audit_hash`, `audit_verify` | This host's audit trail: writable, number and hash of the last record, result of the daily self-check | `true`, growing, a hash, `ok` (empty until the first check) |
| `reconcile_unbalanced` | Sender runs whose last comparison did not balance | 0 |
| `sender_events_in` | Events the aggregator has handed to the sender (from its heartbeat) | growing, at the rate of `events_delivered` |
| `packet_age_s`, `frame_age_s` | Seconds since any packet, and since a valid wd2l frame, arrived on the capture NIC | under ~1 s |
| `nic_carrier`, `nic_carrier_changes`, `nic_rx_*`, `nic_tx_*` | The capture NIC: link state, link flaps, and its receive and transmit counters | carrier true, no changes, error counters not rising |
| `archive_file`, `archive_age_s`, `archive_bytes` | The newest pcap file | age under the capture's file rotation (an hour) |
| `cpu_pct`, `rss_mb` | The receiver's CPU and resident memory | steady |
| `streams`, `retired_streams` | Per sender run: `next_seq`, `known_seq`, `open_gap_events`, `boot`, `sender` counters. Finished runs with nothing open are retired after `--stream-retention` (7 days) | |

### Gap reasons

| `reason` | Meaning | What to do |
|---|---|---|
| `not_received` | The packets never arrived on the capture NIC | Follow the steps below |
| `receiver_restart` | Unresolved when the receiver last stopped: not received yet, or received but not confirmed by the SIEM before a crash | Replay the archive |
| `output_dropped` | Received, but the receiver's output gave up (memory queue or spool disk full) | Fix the SIEM or disk, then replay the archive |

## Alert: events lost (`type=gap`)

1. **Check `reason`.** `receiver_restart` and `output_dropped` are recovered by **replay**
   (below). For `not_received`, go on.
2. **Was the receiver down or restarted?** `journalctl -u wd2l-receiver` around the gap time.
   If yes, the packets are probably in the archive. **Replay** (below).
3. **Kernel drops?** `kernel_drops` rising means the host can't keep up. Check CPU and the NIC
   ring size. Replay may still recover them, because tcpdump has its own buffer.
4. **Heartbeat stale at the same time?** Then the link (cable, network tap, fiber) or Enclave 1
   was down. The packets never arrived and archive replay won't help. Ask the Enclave 1 team to
   replay that time window from the log retention server (below).
5. **Isolated single-event gaps with a live heartbeat** = packet loss on the path. Check optics
   and interface error counters on the log server NIC, tap ports and receiver NIC.

## Alert: fault segment

"WD2L - Fault segment" fires when the receiver's fault status is not `ok`. It says where the
trouble is, not only that there is some.

1. **Read `fault_segment` and `fault_rule`** on the latest `type=health` record (panel 1b on the
   dashboard shows them). `fault_detail` says why in words:
   ```
   index=wd2l sourcetype=wd2l:health type=fault | head 5
   | table _time fault_status fault_segment fault_rule fault_detail previous_status
   ```
2. **Find the rule in the scenario table** in
   [state-of-health.md](state-of-health.md#reading-it-scenarios). Each row says what you see,
   what it means and what to do. Rule 2 (amber, `e1-sender`) is planned downtime: the sender
   stopped cleanly.
3. **Check the segment**, in the order the data flows:

   | Segment | Check |
   |---|---|
   | `e1-input` | The aggregator's output to the sender is on, connected and has events to send (Enclave 1 team) |
   | `e1-sender` | `systemctl status wd2l-sender` on the log server, and its egress NIC carrier (Enclave 1 team) |
   | `boundary` | Tap, fiber and optics; `ethtool -S` on the capture NIC for CRC and frame errors; only `10.255.255.1.5514 > 10.255.255.2.5514` on the tap |
   | `e2-capture` | `systemctl status wd2l-capture`, kernel drops, free space under `/var/lib/wd2l/pcap` |
   | `e2-receiver` | `journalctl -u wd2l-receiver`, CPU and memory |
   | `e2-siem` | The SIEM's collector, the token, `<spool>/rejected/` |

4. **After recovery from rule 3** (nothing arriving: the sender or the link), check the
   heartbeat's `boot`. Unchanged means the sender stayed up and the link was the problem. A
   higher number means the sender restarted. Either way, look for `gap` records and re-send those
   windows from Enclave 1 ([below](#re-sending-from-enclave-1)).

## Alert: reconciliation not balanced

The sender's heartbeats carry a count and a hash of every event it has numbered, up to a cut. The
receiver keeps the same hash of what it delivered and compares them at each cut.
"WD2L - Reconciliation not balanced" fires when a stream has had no balanced `type=reconcile`
record for an hour (`balanced=true` is what a healthy stream keeps writing) **and** its latest
record has no open gaps (`gaps_open=0`). A stream with open gaps is the job of
"WD2L - Events lost in transfer", which has already fired for it.

1. **Open gaps** (`gaps_open` above 0, on the dashboard) explain an unbalanced stream: events
   are missing. Follow [events lost](#alert-events-lost-typegap). Whether the stream balances
   again depends on how the events come back:
   * **A replay of the capture archive** fills gaps whose packets reached the capture NIC
     (`receiver_restart`, `output_dropped`, and kernel drops that tcpdump still caught). They
     arrive under their old numbers, and the stream balances at the next cut.
   * **A re-send from Enclave 1** brings the events back as new events with new numbers, in the
     sender's current run. They don't fill the old stream's gaps, so that stream stays
     unbalanced for good. That is expected: the gap is permanent, and the `gap` records and the
     re-send are the evidence. This alert stays quiet for it.
2. **No open gaps** is not normal. Events were counted on one side and not the other, or changed
   on the way, and nothing says why. Compare with the audit reports:
   ```bash
   wd2l-audit-report reconcile --dir /var/log/wd2l --since 2026-10-05 --until 2026-10-06
   wd2l-audit-report events --dir /var/log/wd2l --event digest_mismatch --event boundary_anomaly --since 2026-10-05
   ```
   A `digest_mismatch` or `boundary_anomaly` in the window points to damage or tampering on the
   link. Treat it as an incident: tell the security owner and follow the incident process.
3. **The part the receiver can't see** is whether the SIEM still holds what it accepted. Count
   what the SIEM has for a stream and compare it with what the receiver delivered:
   ```
   index=enclave1 wd2l_stream=<stream> | stats dc(wd2l_seq) as in_siem max(wd2l_seq) as max_seq
   index=wd2l sourcetype=wd2l:health type=reconcile stream=<stream> | head 1 | table cut events_delivered gaps_open
   ```
   `in_siem` should equal `events_delivered`. Fewer means the SIEM lost or refused events after
   accepting them. Look at `<spool>/rejected/` and the SIEM's own ingest errors.

## Alert: audit trail

"WD2L - Audit trail" fires when either host reports a problem with its audit files. The transfer
keeps going while the trail is broken. The audit records are what is at risk.

* **`audit_ok=false`.** The host can't write its audit file, or its disk is below the free-space
  limit (`--audit-min-free-mb`, 256 by default). Below the limit the host writes nothing more to
  its audit files, so the state file, spool and archive keep their room. Records are still
  forwarded, and once there is space again a new file starts with an `audit_failure` record
  (`reason=recovered`) giving the number `missed`. Check free space and permissions on
  `/var/log/wd2l`. The `audit_failure` record in the SIEM gives the reason (for example
  `low_space` or `torn_write`).
* **`audit_verify=failed`.** The daily self-check found the hash chain broken: a record was
  changed, removed or reordered, or a file is damaged. On that host:
  ```bash
  wd2l-audit-report verify --dir /var/log/wd2l
  ```
  Then compare with the other copies: the log retention server's copy for Enclave 1
  (`verify --dir <copy>`) and the `wd2l_audit` index (`verify --export FILE`). Tell the security
  owner and follow the incident process. Don't edit or delete the files.

## Alert: time quality

"WD2L - Time quality" fires when `time_status` is `alarm`. `time_reason` names the side and why,
for example "receiver: unsynced", "sender: stratum 5 > 3", "sender: unavailable" or "clock skew
0.081 s > 0.05 s". The alarm is for a clock that isn't synchronised, a stratum above 3, an offset
over 100 ms, a side that can't read chrony at all, or the two enclaves differing by more than
50 ms.

1. **On the side named**, run `chronyc tracking`: reference, stratum and offset. For
   "unavailable", check that `chronyd` is running and that the wd2l service can run `chronyc`.
2. **Check that enclave's GPS receiver**, then the switch that serves time at stratum 2.
3. **Skew while both sides are synced** points to one side's GPS receiver or switch.

Events still arrive, but their times and the delays in [Measuring delays](#measuring-delays) can't
be trusted until it clears.

## Alert: opaque content (`wd2l_opaque`)

The sender found a long blob it can't inspect: `encrypted` (a marker says so), `compressed`, or
`high-entropy` (random-looking, likely encrypted). The events crossed unchanged, so nothing
needs replaying. The question is whether the content is expected. See
[ADR-0002](decisions/0002-opaque-content.md).

1. **Look at the events:**
   ```
   index=enclave1 wd2l_opaque=* earliest=-24h
   | table _time host source sourcetype wd2l_opaque wd2l_opaque_bytes _raw
   ```
2. **Is this source known to log such data?** For example, a proxy logging encrypted URL
   parameters, an application dumping compressed state, or certificate logging. If it is, and
   it's approved, record the source, owner and reason, and exclude that host and source in the
   alert search.
3. **New or unexplained:** treat it as a possible security event. Tell the Enclave 1 system
   owner and follow the incident process. The original is also on the Enclave 1 log retention
   server.

## Audit records

wd2l writes audit records on each host: starts and stops, who changed what, replays, debug
toggles, and the boundary and delivery failures the health counters show. Each record carries the
hash of the one before it, so a changed, removed or reordered record breaks the chain. Records
hold metadata, counts and hashes, never log content. The record types are in the
[audit plan](audit-and-health-plan.md).

**Where they are**

| Copy | Where | Who reads it |
|---|---|---|
| Official copy, each host | `/var/log/wd2l/audit-*.jsonl` (a new file past 64 MiB, kept 1 year) | Members of group `wd2l-audit` |
| Enclave 1, second copy | The log aggregator copies the log server's files to the log retention server ([retention-server.md](deployment/retention-server.md#6-wd2l-audit-files)) | Auditors, administrators |
| SIEM | `index=wd2l_audit`: `sourcetype=wd2l:audit` (receiver), `wd2l:sender:audit` (sender, in-band) | The auditor role only |

The receiver passes on only in-band records that name the Enclave 1 sender (`enclave` 1,
`component` `sender`), so Enclave 1 can't put records about Enclave 2 in the index. Anything else
is counted in `records_bad`. The daily review report shows each record's `sourcetype`.

**Verify a copy**

```bash
sudo -u wd2l python3 -m wd2l.audit verify /var/log/wd2l      # on the host
wd2l-audit-report verify --dir /var/log/wd2l                 # once installed with pip
wd2l-audit-report verify --dir <copy of the files>           # the retention server's copy
wd2l-audit-report verify --export siem-export.json           # a SIEM export
```

Each prints `ok` or the problems it found, and exits 1 on a problem. With `--export`, `--complete`
also fails when records are missing from the export. Each host also runs the check by itself every
day and reports it as `audit_verify`.

**Reports.** `--dir` can be repeated, `--export` reads a SIEM export, and `--format csv` gives a
spreadsheet.

```bash
# What the sender numbered against what the receiver delivered, per day and stream
wd2l-audit-report reconcile --dir /var/log/wd2l --since 2026-10-05 --until 2026-10-06
# Who changed the configuration this month
wd2l-audit-report events --dir /var/log/wd2l --event config_changed --since 2026-10-01
```

`--since` and `--until` are UTC. `events` also filters by `--stream`, `--segment`, `--component`
and `--host`. The SIEM runs the report "WD2L - Audit review (daily)" for the security owner.

**Operational logs and debug.** With `--log-format json` (the units use it) each journal line is
one JSON object with `ts`, `level`, `logger`, `msg` and `segment`, plus `stream` and `seq` where
they apply. The message texts are the same as in text format. To switch debug logging on or off
so that the audit record names you, signal the service from your own session:

```bash
sudo kill -USR1 "$(systemctl show -p MainPID --value wd2l-receiver)"     # or wd2l-sender
```

Don't use `systemctl kill`: systemd becomes the sender of the signal, and the record can't name
you.

**Replays.** An archive replay writes to the same audit directory, so stop the live receiver
first (see below). The replay refuses to start while another process holds the directory.

## Replay from the capture archive

Fills open gaps from the pcap files. Events already delivered are skipped, so it is safe to replay
more files than you need.

```bash
sudo systemctl stop wd2l-receiver            # the replay and live receiver share the state file
sudo -u wd2l env PYTHONPATH=/opt/wd2l python3 -m wd2l.receiver \
    --pcap /var/lib/wd2l/pcap/cap-20260925*.pcap \
    --state /var/lib/wd2l/state.json \
    --hec-url https://siem.enclave2.example:8088 --hec-token-file /etc/wd2l/hec.token \
    --hec-ca /etc/wd2l/siem-ca.pem --spool-dir /var/lib/wd2l/spool \
    --default-index enclave1 --health-index wd2l \
    --audit-dir /var/log/wd2l --hec-audit-token-file /etc/wd2l/hec-audit.token
sudo systemctl start wd2l-receiver
```

`--audit-dir` makes the replay write its `replay_run` records, naming you, to the receiver's
audit trail. Audit records need their own token: with `--audit-dir` and `--hec-url`, the receiver
refuses to start without `--hec-audit-token-file`. If the site uses one token for both, name the
same file twice.

It prints a summary. `late_fills` is how many gap events it recovered; `open_gap_events` is
what's still missing. tcpdump keeps capturing while the receiver is stopped, so the stop itself
loses nothing. The restarted receiver reports the stop as a gap, and the next replay fills it.

After a **crash** (not a clean stop) a replay can re-send some events that had already reached
the SIEM: the ones that arrived after the last state save (it is saved every second) and the
ones the SIEM accepted just before the crash. That is by design (duplicates over loss). To remove
them in searches: `| dedup wd2l_stream wd2l_seq`. Nothing is lost: events that were still in
memory are reported as `reason=receiver_restart` gaps at startup, and the replay fills them.

## Re-sending from Enclave 1

Events that never reached Enclave 2 (link down, receiver host down, loss on the wire, a sender
run that never arrived) have to be sent again from Enclave 1. The log retention server keeps a
1-year copy of everything the aggregator collected for this.

1. **Find the time window.** The gap record gives the stream and the sequence range; its `_time`
   is when the gap was declared. For tighter bounds, look up the events on either side of the gap:
   `index=enclave1 wd2l_stream=<stream> (wd2l_seq=<first_seq-1> OR wd2l_seq=<last_seq+1>)`.
   Add a margin: events are numbered in the order the aggregator delivered them, which is close
   to time order but not exact.
2. **Replay it in Enclave 1.** The aggregator reads that window back from the log retention
   server and routes it to `wd2l-sender` only, not back to the retention server. See
   [deployment/retention-server.md](deployment/retention-server.md).
3. **Check in Enclave 2.** The replayed events arrive as normal new events with new sequence
   numbers. Events in the window that had already arrived land a second time, with a different
   `wd2l_seq`. Remove them in searches with `| dedup host source _time _raw`. The re-sent events
   don't fill the old stream's gaps, so that stream never balances again (dashboard panels 5 and
   12 stay red for it). That is expected; the `gap` records and the re-sent events are the
   record of what happened.

## Measuring delays

Every event carries three times: `_time` (when the source wrote it, as set by the aggregator),
`wd2l_tx_time` (when `wd2l-sender` sent it, Enclave 1 clock) and `wd2l_rx_time` (when
`wd2l-receiver` got it, Enclave 2 clock). With the SIEM's index time, they split the delay by
segment:

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

Reading the numbers:

* **Check `clock_offset_s` first** (latest `type=health` record). Each enclave takes its time from
  its own GPS receiver, so the offset should be within a few milliseconds of 0. If it isn't, the
  link delay is wrong by the same amount: fix time sync before trusting delays.
* **Link delay high, clock offset fine:** the receiver is falling behind. Check `kernel_drops`
  and CPU. Replayed events keep the time the archive captured them, so a replay doesn't inflate
  it.
* **Enclave 1 delay odd or negative:** `_time` comes from the log text (often whole seconds) and
  the source's own clock. Large or negative values usually mean that source's clock, or the
  aggregator's time parsing, is wrong, not a slow pipeline.
* **SIEM delay rising:** `_indextime` is whole seconds. Together with `hec_spool_files` > 0, the
  SIEM was unreachable and the spool is draining.

## Routine

* **Planned downtime** (patching, reboots, link work): stop and start in the order given in
  [planned-downtime.md](planned-downtime.md) and nothing is lost or needs replaying.
* **Sender restarts** start a new stream. You'll see `stream_end` (clean) or `stream_lost` (crash)
  for the old one, and `stream_start` for the new one. Not a problem. With `--state` the new run
  names the old one, so a lost tail shows up as a `gap` and a run that never arrived as
  `stream_missing`. **Don't delete the sender's state file** (`/var/lib/wd2l/sender.json`):
  the restart count starts over and the receiver reports `sender_boot_reset`.
* **Receiver restarts** are safe as long as `--state` is kept. **Don't delete the state file**:
  without it the receiver reports everything before the first event it sees in the current stream
  as missing.
* **Disk**: watch `/var/lib/wd2l/pcap` (hourly files, 7-day prune), `/var/lib/wd2l/spool`
  (only grows while the SIEM is unreachable; capped at 10 GB, and its `audit/` subdirectory,
  the audit records' own spool, at 10 GB more) and `/var/log/wd2l` (the audit files, deleted
  after a year). The audit files stay under 2 GB a year only because frequent events are
  summarised: heavy loss writes at most one `gap` audit record a minute per stream and reason,
  not one per gap. Below `--audit-min-free-mb` free, nothing more is written to them until
  there is space again (see [Alert: audit trail](#alert-audit-trail)). In Enclave 1, watch the log
  retention server's disk against its 1-year estimate, and the aggregator's queue for it. A full
  queue means a window with no copy to replay from.
* **Rejected HEC events** (`hec_rejected_events` > 0): look in `/var/lib/wd2l/spool/rejected/`.
  When the SIEM refuses a batch, the receiver re-sends it one event at a time, so these files
  hold only the events the SIEM refused. Usually an index that doesn't exist in Enclave 2. Fix
  the index, then move the files back into `/var/lib/wd2l/spool/` to resend them. The re-send
  of a refused batch can duplicate events the SIEM had already taken from it.

## Lab

`sudo lab/run-lab.sh` builds the whole path in network namespaces on one Linux box.

```bash
sudo lab/run-lab.sh                     # clean run: 0 gaps, byte-for-byte match
sudo lab/run-lab.sh --loss 1            # 1% wire loss: every lost event reported exactly
sudo lab/run-lab.sh --receiver-outage   # stop the receiver mid-run, then replay: nothing lost
sudo lab/run-lab.sh --receiver-crash    # kill it instead: nothing lost, a few duplicates
sudo lab/run-lab.sh --maintenance       # planned downtime on both sides: nothing lost, no replay
sudo lab/run-lab.sh --fault tap-down    # inject one fault: the receiver names the segment and rule
sudo lab/run-lab.sh --events 25000 --eps 5000
```

Output, logs and the pcap archive are in `lab/out/`.
