# Operations runbook

All receiver output about itself is in the SIEM: `index=wd2l sourcetype=wd2l:health`, and in
`journalctl -u wd2l-receiver`.

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
| `health` | Every 60 s | counters below |

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
    --default-index enclave1 --health-index wd2l
sudo systemctl start wd2l-receiver
```

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
   `wd2l_seq`. Remove them in searches with `| dedup host source _time _raw`.

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

* **Sender restarts** start a new stream. You'll see `stream_end` (clean) or `stream_lost` (crash)
  for the old one, and `stream_start` for the new one. Not a problem. With `--state` the new run
  names the old one, so a lost tail shows up as a `gap` and a run that never arrived as
  `stream_missing`. **Don't delete the sender's state file** (`/var/lib/wd2l/sender.json`):
  the restart count starts over and the receiver reports `sender_boot_reset`.
* **Receiver restarts** are safe as long as `--state` is kept. **Don't delete the state file**:
  without it the receiver reports everything before the first event it sees in the current stream
  as missing.
* **Disk**: watch `/var/lib/wd2l/pcap` (hourly files, 7-day prune) and `/var/lib/wd2l/spool`
  (only grows while the SIEM is unreachable; capped at 10 GB). In Enclave 1, watch the log
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
sudo lab/run-lab.sh --events 25000 --eps 5000
```

Output, logs and the pcap archive are in `lab/out/`.
