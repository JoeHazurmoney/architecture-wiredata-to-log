# Operations runbook

All receiver output about itself is in the SIEM: `index=wd2l sourcetype=wd2l:health`, and in
`journalctl -u wd2l-receiver`.

## Health records

| `type` | When | Key fields |
|---|---|---|
| `gap` | Events declared lost | `stream`, `first_seq`, `last_seq`, `count` |
| `heartbeat_stale` | No heartbeat for `--hb-timeout` s | `age_s` |
| `heartbeat_restored` | Heartbeats back | |
| `stream_start` | A sender run seen for the first time (the sender restarted) | `stream` |
| `stream_end` | Sender shut down cleanly (final heartbeat) | `stream`, `last_seq`, `sender` counters |
| `stream_lost` | A stream went quiet without a clean shutdown | `stream`, `last_seq`, `idle_s` |
| `health` | Every 60 s | counters below |

`health` counters are cumulative since the receiver started:

| Field | Meaning | Healthy |
|---|---|---|
| `events_delivered` | Events handed to the SIEM (or file) | growing |
| `gap_events` / `open_gap_events` | Events declared lost / still missing (includes earlier runs, from the state file) | 0 |
| `late_fills` | Gaps filled later (archive replay) | — |
| `duplicates` | Copies ignored | any (normal during replay) |
| `heartbeats`, `heartbeat_age_s`, `heartbeat_stale` | Sender liveness | age ≤ ~1 s |
| `other_packets`, `other_reasons` | Frames on the tap that aren't the log flow | 0 |
| `bad_frames`, `bad_events`, `digest_mismatch`, `bad_reasons` | Corrupt or malformed input | 0 |
| `kernel_drops` | Packets the kernel dropped before the receiver read them | 0 |
| `reasm_expired`, `reasm_evicted`, `event_too_big` | Split events that never completed | 0 |
| `sender_drops`, `sender_truncated`, `sender_bad_input` | From the sender's heartbeat | 0 (truncated: expected if you have huge events) |
| `hec_events_sent`, `hec_spool_files`, `hec_posts_failed`, `hec_rejected_batches` | SIEM delivery | spool 0, rejected 0 |
| `streams` | Per sender run: `next_seq`, `known_seq`, `open_gap_events`, `sender` counters | |

## Alert: events lost (`type=gap`)

1. **Was the receiver down or restarted?** `journalctl -u wd2l-receiver` around the gap time.
   If yes, the packets are probably in the archive. **Replay** (below).
2. **Kernel drops?** `kernel_drops` rising means the host can't keep up. Check CPU and the NIC
   ring size. Replay may still recover them, because tcpdump has its own buffer.
3. **Heartbeat stale at the same time?** Then the link (cable, network tap, fiber) or Enclave 1
   was down. The packets never arrived and replay won't help. Ask the Enclave 1 team to re-send that
   time window (below).
4. **Isolated single-event gaps with a live heartbeat** = packet loss on the path. Check optics
   and interface error counters on the log server NIC, tap ports and receiver NIC.

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

Only after a **crash** (not a clean stop) a replay can re-send up to about one second of events
that had already reached the SIEM, because the state file is saved every second. To remove those
duplicates in searches: `| dedup wd2l_stream wd2l_seq`.

## Re-sending from Enclave 1

Events that never reached Enclave 2 (link down, receiver host down) have to be sent again from
Enclave 1. The gap record gives the time (`_time` of the gap record) and the stream. In Enclave 1,
pull that time window from the log aggregator's persistent queue/archive or the source systems,
and push it through the aggregator again. It arrives as normal new events with new sequence numbers.

## Routine

* **Sender restarts** start a new stream. You'll see `stream_end` (clean) or `stream_lost` (crash)
  for the old one, and `stream_start` for the new one. Not a problem.
* **Receiver restarts** are safe as long as `--state` is kept. **Don't delete the state file**:
  without it the receiver reports everything before the first event it sees in the current stream
  as missing.
* **Disk**: watch `/var/lib/wd2l/pcap` (hourly files, 7-day prune) and `/var/lib/wd2l/spool`
  (only grows while the SIEM is unreachable; capped at 10 GB).
* **Rejected HEC batches** (`hec_rejected_batches` > 0): look in `/var/lib/wd2l/spool/rejected/`.
  Usually an index that doesn't exist in Enclave 2. Fix the index, then move the files back
  into `/var/lib/wd2l/spool/` to resend them.

## Lab

`sudo lab/run-lab.sh` builds the whole path in network namespaces on one Linux box.

```bash
sudo lab/run-lab.sh                     # clean run: 0 gaps, byte-for-byte match
sudo lab/run-lab.sh --loss 1            # 1% wire loss: every lost event reported exactly
sudo lab/run-lab.sh --receiver-outage   # stop the receiver mid-run, then replay: nothing lost
sudo lab/run-lab.sh --events 25000 --eps 5000
```

Output, logs and the pcap archive are in `lab/out/`.
