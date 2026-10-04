# Enclave 2: receiver host and SIEM

Linux host with Python 3.9+, `tcpdump`, `nftables`, `ethtool`, and a NIC for the one-strand fiber
(examples use `ens256`). It also needs normal Enclave 2 network access to the SIEM's HTTP event collector port.

## 1. Install

```bash
sudo useradd --system --no-create-home --shell /sbin/nologin wd2l
sudo mkdir -p /opt/wd2l /etc/wd2l /var/lib/wd2l/pcap /var/lib/wd2l/spool
sudo chown -R wd2l:wd2l /var/lib/wd2l
sudo cp -r wd2l deploy /opt/wd2l/                      # from this repo
echo '<HEC token>' | sudo tee /etc/wd2l/hec.token >/dev/null
sudo chown root:wd2l /etc/wd2l/hec.token && sudo chmod 640 /etc/wd2l/hec.token
sudo cp <SIEM CA bundle> /etc/wd2l/siem-ca.pem
```

## 2. Capture NIC

```bash
echo 'IFACE=ens256' | sudo tee /etc/wd2l/capture.env
sudo cp deploy/receiver/wd2l-capture-nic.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wd2l-capture-nic
ip -d link show ens256        # UP, PROMISC, NOARP, no inet address
```

`capture-nic.sh`: no IP, ARP off, IPv6 off, promiscuous, GRO/LRO off (so the capture matches the
wire), largest RX ring, and on kernel 5.16+ an nftables rule dropping anything the host tries to
send on that NIC.

## 3. Capture archive

```bash
sudo cp deploy/receiver/wd2l-capture.service deploy/receiver/wd2l-pcap-prune.* /etc/systemd/system/
# edit the interface name in wd2l-capture.service if it isn't ens256
sudo systemctl daemon-reload
sudo systemctl enable --now wd2l-capture wd2l-pcap-prune.timer
ls -l /var/lib/wd2l/pcap/
```

One pcap file per hour, kept 7 days. At 1,000 events/s × ~1 KB that's about 3.6 GB/hour, 600 GB
per week. Size the disk, or shorten the retention in `wd2l-pcap-prune.service`.

## 4. Receiver

Edit the SIEM URL and index names in `deploy/receiver/wd2l-receiver.service`, then:

```bash
sudo cp deploy/receiver/wd2l-receiver.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wd2l-receiver
journalctl -u wd2l-receiver -f
```

It runs as `wd2l` with only `CAP_NET_RAW`. Options (`python3 -m wd2l.receiver --help`):

| Option | Default | Notes |
|---|---|---|
| `--live IFACE` / `--pcap FILES` | | Live capture, or read pcap files (replay) |
| `--dst-ip`, `--dst-port`, `--src-ip` | `10.255.255.2`, `5514`, any | Which packets are the log flow. Everything else is counted as `other_packets` |
| `--state` | none | Gap tracking that survives restarts, including which events the SIEM has not confirmed yet. Always set it in production |
| `--hec-url`, `--hec-token-file`, `--hec-ca` | | SIEM HTTP event collector. `--hec-insecure` is for labs only |
| `--spool-dir` | `/var/lib/wd2l/spool` | Where batches wait while the SIEM is unreachable |
| `--default-index` | none | For events that arrive without an index |
| `--force-index` | none | Put every event in this one index |
| `--health-index` | default index | Index for `wd2l:health` |
| `--out-dir` | none | Also (or instead) write `events.jsonl` + `health.jsonl` |
| `--gap-window` | `2` s | How long a missing event may be late before it's a gap |
| `--reasm-timeout` | `5` s | How long to hold part of a split event |
| `--hb-timeout` | `5` s | No heartbeat for this long → `heartbeat_stale` |
| `--health-interval` | `60` s | Summary record interval |
| `--max-event`, `--max-buffer` | 256 KB, 64 MB | Input caps |
| `--hec-queue` | `100000` | Events held in memory for the SIEM. Overflow is reported as `reason=output_dropped` gaps (replay recovers them) |
| `--stream-retention` | 7 days | How long finished sender runs with nothing open stay fully tracked. Keep it at least as long as the pcap archive |
| `--no-rx-time` | stamping on | Stop stamping each event's arrival time (`wd2l_rx_time`). Leave it on: it's how delays are measured ([operations.md](../operations.md#measuring-delays)) |

## 5. SIEM

The receiver sends events over HTTPS to an HTTP event collector interface in the format Splunk
calls HEC (`POST /services/collector/event`, one JSON object per event, `Authorization: Splunk
<token>` header). Splunk accepts it natively. For another SIEM, put a log pipeline that can
receive this format in front of it (e.g. Vector, Fluent Bit or Cribl), or use the `--out-dir`
file output and the SIEM's own file ingestion. The SIEM needs:

* **Indexes** (or the SIEM's equivalent): one for the imported events and one for `wd2l`
  health records. **Every index name Enclave 1 uses must exist**, and the token must be allowed to
  write to it. Otherwise the collector rejects the batch with HTTP 400; the receiver re-sends it
  one event at a time, moves only the refused events to `<spool>/rejected/` and counts
  `hec_rejected_events`. Or run with `--force-index` and put everything in one index.
* **A token** for the receiver, over TLS.
* **Indexed (searchable) fields**, sent in each event's `fields` object: `wd2l_stream`,
  `wd2l_seq`, `wd2l_truncated`, `wd2l_src_seq` (with the sender's `--source-seq`), and the send
  and arrival times `wd2l_tx_time` and `wd2l_rx_time`.
* **JSON parsing** for the `wd2l:health` records.
* **Alerts** on lost events, stale heartbeat, silent receiver, and unexpected traffic or damage
  (see [operations.md](../operations.md)).
* **The same parsing add-ons** you use in Enclave 1 for each log source. Events keep their source
  type, so parsed fields come out the same.

### Example: Splunk

Ready-made files for Splunk are in [`deploy/receiver/splunk/`](../../deploy/receiver/splunk/). Put
them in an app, e.g. `$SPLUNK_HOME/etc/apps/wd2l/local/`:

* `indexes.conf`: `enclave1` and `wd2l`.
* `inputs.conf`: HEC on 8088 with TLS, and the `wd2l` token.
* `fields.conf`: marks `wd2l_stream`, `wd2l_seq`, `wd2l_truncated`, `wd2l_src_seq`,
  `wd2l_tx_time` and `wd2l_rx_time` as indexed fields.
* `props.conf`: JSON field extraction for `wd2l:health`.
* `savedsearches.conf`: the four alerts. Add your alert actions.

## 6. Check end to end

In the SIEM (Splunk search syntax shown):

```
index=enclave1 earliest=-15m | stats count by host, sourcetype
index=wd2l sourcetype=wd2l:health type=health | head 1
    | table _time events_delivered gap_events open_gap_events heartbeat_age_s other_packets kernel_drops hec_spool_files
index=wd2l sourcetype=wd2l:health type!=health earliest=-24h | table _time type stream first_seq last_seq count
index=enclave1 earliest=-15m | eval link_ms=(wd2l_rx_time-wd2l_tx_time)*1000
    | stats median(link_ms) max(link_ms) by host
```

Healthy: events for every expected host, `heartbeat_age_s` ≤ ~1, and `gap_events`,
`other_packets`, `kernel_drops`, `hec_spool_files` all 0. Link delay of a few milliseconds, and
`clock_offset_s` in the health record within a few milliseconds of 0.
