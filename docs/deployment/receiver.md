# Enclave 2: receiver host and SIEM

Linux host with Python 3.9+, `tcpdump`, `nftables`, `ethtool`, and a NIC for the one-strand fiber
(examples use `ens256`). It also needs normal Enclave 2 network access to the SIEM's HTTP event collector port.

## 1. Install

From a release ([how to bring one into the enclave and verify it](../releasing.md#bringing-a-release-into-an-enclave)),
on RHEL 9 or RHEL 10 (use the `el9` or `el10` files). The receiver package brings in
`tcpdump`, `nftables`, `ethtool` and `iproute`.

```bash
sudo dnf install ./wd2l-<version>-1.el10.noarch.rpm ./wd2l-receiver-<version>-1.el10.noarch.rpm
sudo vi /etc/wd2l/receiver.env /etc/wd2l/capture.env   # SIEM URL and indexes; IFACE if it isn't ens256
echo '<HEC token>' | sudo tee /etc/wd2l/hec.token >/dev/null
sudo chown root:wd2l /etc/wd2l/hec.token && sudo chmod 640 /etc/wd2l/hec.token
echo '<HEC audit token>' | sudo tee /etc/wd2l/hec-audit.token >/dev/null
sudo chown root:wd2l /etc/wd2l/hec-audit.token && sudo chmod 640 /etc/wd2l/hec-audit.token
sudo cp <SIEM CA bundle> /etc/wd2l/siem-ca.pem
rpm -V wd2l wd2l-receiver       # prints nothing while every file is as packaged
```

The packages create:

* the `wd2l` user, and the `wd2l-audit` group (who may read the audit files);
* `/etc/wd2l` (0750 root:wd2l); `/var/lib/wd2l` with `spool/` and `pcap/` (0750 wd2l:wd2l);
  `/var/log/wd2l` (2750 wd2l:wd2l-audit, setgid so the files get the group).

They install the units in `/usr/lib/systemd/system`, the scripts in `/usr/libexec/wd2l`, the
kernel receive buffer setting, and templates (auditd rules, the Quadlet unit, the Splunk files)
in `/usr/share/wd2l`. They enable nothing. `dnf upgrade` doesn't restart wd2l: restart it as
[planned-downtime.md](../planned-downtime.md) says.

On a host with `localpkg_gpgcheck=1` (the RHEL STIG sets it), `dnf install` needs
`--nogpgcheck`, after the release is verified: see
[releasing.md](../releasing.md#bringing-a-release-into-an-enclave).

To run the receiver as a container instead, see [containers.md](containers.md). Without the
RPMs, see [Appendix: manual install](#appendix-manual-install). On a host installed by hand
before, see [Moving a manual install to the RPMs](#moving-a-manual-install-to-the-rpms).

## 2. Capture NIC

```bash
sudo systemctl enable --now wd2l-capture-nic     # the NIC named in /etc/wd2l/capture.env
ip -d link show ens256        # UP, PROMISC, NOARP, no inet address
```

`capture-nic.sh`: no IP, ARP off, IPv6 off, promiscuous, GRO/LRO off (so the capture matches the
wire), largest RX ring, and on kernel 5.16+ an nftables rule dropping anything the host tries to
send on that NIC.

### Kernel receive buffer

The `wd2l-receiver` package installs `/usr/lib/sysctl.d/90-wd2l.conf` and applies it at
install time. Check it:

```bash
sysctl net.core.rmem_max        # 67108864
```

The receiver asks for a 64 MiB capture buffer, but it runs without `CAP_NET_ADMIN`, so the
kernel caps the buffer at `net.core.rmem_max` (about 208 KiB by default). Without this file,
bursts are dropped by the kernel (`kernel_drops`), and the receiver logs a warning at start.

## 3. Capture archive

```bash
sudo systemctl enable --now wd2l-capture wd2l-pcap-prune.timer
ls -l /var/lib/wd2l/pcap/
```

The receiver package gives `/var/lib/wd2l/pcap` the SELinux type `netutils_tmp_t`, the only one
tcpdump (started by systemd) may write. Check with `ls -dZ /var/lib/wd2l/pcap`. Without it every
write is denied and no archive is kept.

One pcap file per hour, kept 7 days. At 1,000 events/s × ~1 KB that's about 3.6 GB/hour, 600 GB
per week. Size the disk, or shorten the retention in a drop-in for `wd2l-pcap-prune.service`
(`sudo systemctl edit wd2l-pcap-prune.service`: an empty `ExecStart=`, then the `find` line
with a smaller `-mmin`).

## 4. Receiver

The options are in `/etc/wd2l/receiver.env` (section 1); the unit reads them from there.

```bash
sudo systemctl enable --now wd2l-receiver
journalctl -u wd2l-receiver -f
```

It runs as `wd2l` with only `CAP_NET_RAW`. Options (`python3 -m wd2l.receiver --help`):

| Option | Default | Notes |
|---|---|---|
| `--live IFACE` / `--pcap FILES` | | Live capture, or read pcap files (replay) |
| `--dst-ip`, `--dst-port`, `--src-ip`, `--src-port` | `10.255.255.2`, `5514`, any, any | Which packets are the log flow. `receiver.env` sets all four (source `10.255.255.1:5514`). Everything else is counted as `other_packets` |
| `--state` | none | Gap tracking that survives restarts, including which events the SIEM has not confirmed yet. Always set it in production |
| `--hec-url`, `--hec-token-file`, `--hec-ca` | | SIEM HTTP event collector. `--hec-insecure` is for labs only |
| `--spool-dir` | `/var/lib/wd2l/spool` | Where batches wait while the SIEM is unreachable |
| `--default-index` | none | For events that arrive without an index |
| `--force-index` | none | Put every event in this one index |
| `--health-index` | default index | Index for `wd2l:health` |
| `--out-dir` | none | Also (or instead) write `events.jsonl` + `health.jsonl`. For the lab and tests; see [ADR-0003](../decisions/0003-receiver-to-siem-delivery.md) before using it in production |
| `--gap-window` | `2` s | How long a missing event may be late before it's a gap |
| `--reasm-timeout` | `5` s | How long to hold part of a split event |
| `--hb-timeout` | `5` s | No heartbeat for this long → `heartbeat_stale` |
| `--health-interval` | `60` s | Summary record interval |
| `--max-event`, `--max-buffer` | 256 KB, 64 MB | Input caps |
| `--hec-queue` | `100000` | Events held in memory for the SIEM. Overflow is reported as `reason=output_dropped` gaps (replay recovers them) |
| `--stream-retention` | 7 days | How long finished sender runs with nothing open stay fully tracked. Keep it at least as long as the pcap archive |
| `--audit-dir` | none | `receiver.env` uses `/var/log/wd2l`. Hash-chained audit records, see [the audit design](../audit-and-health.md) and **Audit files** below |
| `--audit-min-free-mb` | `256` | Free space the audit directory must keep. Below it, nothing more goes in the audit files: records are still forwarded, counted as missed, and `audit_ok` is false until there is space again |
| `--hec-audit-token-file` | none | Token for the audit index. `receiver.env` uses `/etc/wd2l/hec-audit.token`. Required when `--audit-dir` and `--hec-url` are both given; if the site uses one token for both, name the `--hec-token-file` file again |
| `--audit-index` | `wd2l_audit` | Index that receives audit records |
| `--pcap-dir` | none | Capture archive directory, to check that tcpdump is writing it. `receiver.env` uses `/var/lib/wd2l/pcap` |
| `--capture-iface` | the `--live` NIC | NIC whose carrier and receive counters go into the health record |
| `--capture-rcvbuf` | `67108864` | Receive buffer of the capture socket, in bytes. Needs `net.core.rmem_max` at least this big ([above](#kernel-receive-buffer)); the receiver warns at start when it got less |
| `--fault-interval`, `--fault-window` | `5`, `60` s | How often the fault-location checks run, and over what window counter growth counts as new |
| `--input-flat-after` | `300` s | No new events from the aggregator for this long is reported as flat input |
| `--time-check-interval` | `60` s | Time between chrony reads |
| `--chronyc` | `chronyc` | The command that reports time quality (synced, stratum, offset) |
| `--chrony-addr` | none | Ask chronyd over UDP (`HOST[:PORT]`, port 323) instead of running `chronyc`. The env file uses `127.0.0.1:323`, for the native and the container unit alike: nothing to run, and no SELinux denial (chronyc can't enter its domain under `NoNewPrivileges`). chronyd's default configuration answers it; `cmdport 0` turns it off |
| `--max-stratum` | 3 | Time alarm above this chrony stratum. 3 suits a site with its own GPS time; a host on a public NTP pool may need 4 or 5. It applies to the sender's reading too |
| `--log-format` | text | `receiver.env` uses `json`: one JSON object per log line |
| `--no-rx-time` | stamping on | Stop stamping each event's arrival time (`wd2l_rx_time`). Leave it on: it's how delays are measured ([operations.md](../operations.md#measuring-delays)) |

### Audit files

The receiver writes audit records to `/var/log/wd2l/audit-*.jsonl` and sends them to the
`wd2l_audit` index. Each record carries the hash of the one before it, so a removed or changed
record breaks the chain.

**Disk space.** Put `/var/log/wd2l` on a filesystem of its own (a partition or logical volume),
so audit files can never fill the disk that holds the capture archive, the spool and the state
file. If it must share one, size it for them all. The audit files stay under 2 GB a year, even
with heavy loss, because gaps are summarised once a minute ([audit design, section
12](../audit-and-health.md#12-storage)). The receiver
keeps `--audit-min-free-mb` free on that filesystem: below it, it writes nothing more to the
audit files until there is space again, and keeps transferring. Audit records waiting for the
SIEM have their own spool, `<spool-dir>/audit` (`/var/lib/wd2l/spool/audit`), capped at 10 GiB
like the data spool. It fills only while the SIEM is unreachable.

A timer makes the files append-only and deletes them after a year:

```bash
sudo systemctl enable --now wd2l-audit-seal.timer
```

auditd rules record who changes wd2l's programs, settings, units and files:

```bash
sudo cp /usr/share/wd2l/audit/receiver.rules /etc/audit/rules.d/wd2l.rules && sudo augenrules --load
```

Check the chain:

```bash
sudo -u wd2l python3 -m wd2l.audit verify /var/log/wd2l
sudo -u wd2l wd2l-audit-report verify --dir /var/log/wd2l
```

To turn debug logging on or off so that the audit record names you, signal the receiver from your
own session (not `systemctl kill`: systemd becomes the sender of the signal):

```bash
sudo kill -USR1 "$(systemctl show -p MainPID --value wd2l-receiver)"
```

An archive replay writes to the same directory, so stop the live receiver first. The replay
refuses to start otherwise.

## 5. SIEM

The receiver sends events over HTTPS to an HTTP event collector interface in the format Splunk
calls HEC (`POST /services/collector/event`, one JSON object per event, `Authorization: Splunk
<token>` header). Splunk accepts it natively. For another SIEM, put a log pipeline that can
receive this format in front of it (e.g. Vector, Fluent Bit or Cribl). No log forwarder or
second aggregator is needed, and the receiver writes no event files, so there is nothing to
rotate. Why, and why the `--out-dir` file output isn't for production yet:
[ADR-0003](../decisions/0003-receiver-to-siem-delivery.md). The SIEM needs:

* **Indexes** (or the SIEM's equivalent): one for the imported events (`enclave1`), one for
  `wd2l` health records, and `wd2l_audit` for audit records, kept 1 year and readable by an
  auditor role only. **Every index name Enclave 1 uses must exist**, and the token must be
  allowed to write to it. Otherwise the collector rejects the batch with HTTP 400; the receiver re-sends it
  one event at a time, moves only the refused events to `<spool>/rejected/` and counts
  `hec_rejected_events`. Or run with `--force-index` and put everything in one index.
* **Two tokens**, over TLS: the main one for events and health records, and one for
  `wd2l_audit`. The main token must not be allowed to write `wd2l_audit`, so that nobody holding
  it can add to the audit trail.
* **Indexed (searchable) fields**, sent in each event's `fields` object: `wd2l_stream`,
  `wd2l_seq`, `wd2l_truncated`, `wd2l_src_seq` (with the sender's `--source-seq`), the send
  and arrival times `wd2l_tx_time` and `wd2l_rx_time`, and, on events with a blob that can't be
  inspected, `wd2l_opaque` and `wd2l_opaque_bytes`.
* **JSON parsing** for the four sourcetypes: `wd2l:health`, `wd2l:sender:health`,
  `wd2l:audit` and `wd2l:sender:audit`.
* **Alerts**: ten, on lost events, stale heartbeat, a missing sender run, silent receiver,
  unexpected traffic or damage, opaque content, fault segment, reconciliation, audit trail and
  time quality, plus a daily report of audit events for the security owner (see
  [operations.md](../operations.md)).
* **The dashboard**, which shows where a fault is. It is described in
  [state-of-health.md](../state-of-health.md).
* **The same parsing add-ons** you use in Enclave 1 for each log source. Events keep their source
  type, so parsed fields come out the same.

### Example: Splunk

Ready-made files for Splunk are in `/usr/share/wd2l/splunk/` (in this repo,
[`deploy/receiver/splunk/`](../../deploy/receiver/splunk/)). Copy them to the Splunk host and
put them in an app, e.g. `$SPLUNK_HOME/etc/apps/wd2l/local/`:

* `indexes.conf`: `enclave1`, `wd2l` and `wd2l_audit` (1 year).
* `inputs.conf`: HEC on 8088 with TLS, and two tokens: `wd2l`, and `wd2l_audit` for audit
  records only.
* `authorize.conf`: the `wd2l_auditor` role, the only one that can search `wd2l_audit`.
* `fields.conf`: marks `wd2l_stream`, `wd2l_seq`, `wd2l_truncated`, `wd2l_src_seq`,
  `wd2l_tx_time`, `wd2l_rx_time`, `wd2l_opaque` and `wd2l_opaque_bytes` as indexed fields.
* `props.conf`: JSON field extraction for the four wd2l sourcetypes.
* `savedsearches.conf`: the ten alerts (lost events, stale heartbeat, missing sender run, silent
  receiver, unexpected traffic or damage, opaque content, fault segment, reconciliation not
  balanced, audit trail, time quality) and the daily audit review. Add your alert actions.
* `wd2l-health-dashboard.json`: the state-of-health dashboard (Dashboard Studio). Import it, then
  read [state-of-health.md](../state-of-health.md) for what each panel means.

## 6. Check end to end

In the SIEM (Splunk search syntax shown):

```
index=enclave1 earliest=-15m | stats count by host, sourcetype
index=wd2l sourcetype=wd2l:health type=health | head 1
    | table _time events_delivered gap_events open_gap_events heartbeat_age_s other_packets kernel_drops hec_spool_files
index=wd2l sourcetype=wd2l:health type!=health earliest=-24h | table _time type stream first_seq last_seq count
index=wd2l sourcetype=wd2l:health type=health | head 1
    | table fault_status time_status audit_ok audit_verify reconcile_unbalanced
index=wd2l sourcetype=wd2l:sender:health | head 1
index=enclave1 earliest=-15m | eval link_ms=(wd2l_rx_time-wd2l_tx_time)*1000
    | stats median(link_ms) max(link_ms) by host
```

Healthy: events for every expected host, `heartbeat_age_s` ≤ ~1, and `gap_events`,
`other_packets`, `kernel_drops`, `hec_spool_files` all 0. `fault_status` is `ok`, `time_status` is
`ok`, `audit_ok` is `true`, `audit_verify` is `ok` (empty until the first daily check) and
`reconcile_unbalanced` is 0. The sender's health record shows that Enclave 1's records arrive too. Link delay of a few milliseconds, and
`clock_offset_s` in the health record within a few milliseconds of 0.

## Moving a manual install to the RPMs

After `dnf install`, a host installed by hand keeps running its old copies: units in
`/etc/systemd/system` win over the packaged ones in `/usr/lib/systemd/system`, and `rpm -V`
doesn't see them. So, in a planned window:

1. Stop the receiver as [planned-downtime.md](../planned-downtime.md) says. Leave the capture
   archive running until step 4, so nothing is missed.
2. Install the packages as in section 1. Edited files in `/etc/wd2l` stay; the packaged ones
   are put beside them as `.rpmnew`.
3. Units from before 0.3 carry the receiver's options in `ExecStart=`. Put them in
   `WD2L_RECEIVER_ARGS` in `/etc/wd2l/receiver.env`, and compare with `receiver.env.rpmnew`
   and `capture.env.rpmnew`.
4. Swap the old copies for the packaged units, rules and sysctl file:

   ```bash
   U="wd2l-receiver wd2l-capture wd2l-capture-nic wd2l-pcap-prune.timer wd2l-audit-seal.timer"
   sudo systemctl disable $U
   sudo rm /etc/systemd/system/wd2l-receiver.service /etc/systemd/system/wd2l-capture.service \
     /etc/systemd/system/wd2l-capture-nic.service /etc/systemd/system/wd2l-pcap-prune.service \
     /etc/systemd/system/wd2l-pcap-prune.timer /etc/systemd/system/wd2l-audit-seal.service \
     /etc/systemd/system/wd2l-audit-seal.timer /etc/sysctl.d/90-wd2l.conf
   sudo rm -rf /opt/wd2l
   sudo cp /usr/share/wd2l/audit/receiver.rules /etc/audit/rules.d/wd2l.rules && sudo augenrules --load
   sudo systemctl daemon-reload
   sudo systemctl enable $U
   sudo systemctl restart wd2l-capture-nic wd2l-capture    # now from the packaged units
   systemctl cat wd2l-receiver | head -1    # /usr/lib/systemd/system/wd2l-receiver.service
   ```

5. Start the receiver as planned-downtime.md says. `rpm -V wd2l wd2l-receiver` prints only the
   `/etc/wd2l` files you edited.

## Appendix: manual install

Without the RPMs (any Linux with Python 3.9 or newer, `tcpdump`, `nftables` and `ethtool`),
from a checkout of this repo. It puts the code in `/opt/wd2l`, and the units and their scripts
run from there.

```bash
sudo useradd --system --no-create-home --shell /sbin/nologin wd2l
sudo mkdir -p /opt/wd2l /etc/wd2l /var/lib/wd2l/pcap /var/lib/wd2l/spool
sudo chown -R wd2l:wd2l /var/lib/wd2l
sudo cp -r wd2l deploy /opt/wd2l/                      # from this repo
echo '<HEC token>' | sudo tee /etc/wd2l/hec.token >/dev/null
sudo chown root:wd2l /etc/wd2l/hec.token && sudo chmod 640 /etc/wd2l/hec.token
echo '<HEC audit token>' | sudo tee /etc/wd2l/hec-audit.token >/dev/null
sudo chown root:wd2l /etc/wd2l/hec-audit.token && sudo chmod 640 /etc/wd2l/hec-audit.token
sudo groupadd --system wd2l-audit                                # who may read audit files
sudo install -d -o wd2l -g wd2l-audit -m 2750 /var/log/wd2l      # setgid: files get the group
git rev-parse HEAD | sudo tee /opt/wd2l/wd2l/BUILD >/dev/null    # the build audit records name
sudo cp <SIEM CA bundle> /etc/wd2l/siem-ca.pem
```

The settings, units, kernel receive buffer and auditd rules, in place of the commands in
sections 2 to 4:

```bash
sudo cp deploy/receiver/capture.env deploy/receiver/receiver.env /etc/wd2l/   # edit them
sudo cp deploy/receiver/wd2l-capture-nic.service deploy/receiver/wd2l-capture.service   deploy/receiver/wd2l-pcap-prune.* deploy/receiver/wd2l-receiver.service   deploy/common/wd2l-audit-seal.service deploy/common/wd2l-audit-seal.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo cp deploy/receiver/90-wd2l.conf /etc/sysctl.d/ && sudo sysctl --system
sudo systemctl enable --now wd2l-capture-nic wd2l-capture wd2l-pcap-prune.timer wd2l-receiver wd2l-audit-seal.timer
sudo cp deploy/receiver/wd2l.rules /etc/audit/rules.d/ && sudo augenrules --load
```

`wd2l-audit-report` isn't on the path in a manual install: run
`sudo -u wd2l env PYTHONPATH=/opt/wd2l python3 -m wd2l.audit_report`, or `pip install` the
wheel from a release. Likewise `python3 -m wd2l.audit` and `python3 -m wd2l.receiver` need
`env PYTHONPATH=/opt/wd2l`.
