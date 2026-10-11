# Enclave 1: central log server (log aggregator + wd2l-sender)

Assumes a Linux host running a log aggregator (a single node) with a **second, dedicated NIC** for the
one-way link. Examples use `ens224` for that NIC. Replace it with yours.

The log aggregator also sends a copy of every event to the **log retention server**, a separate
Enclave 1 host reached over the normal NIC. See [retention-server.md](retention-server.md).

Addresses used throughout (any unused /30 works; keep them consistent everywhere):

| | |
|---|---|
| Log server egress IP | `10.255.255.1/30` |
| Black-hole IP | `10.255.255.2` |
| Black-hole MAC (made up) | `02:00:00:00:00:02` |
| UDP port | `5514` (source and destination) |

## 1. Install wd2l

From a release ([how to bring one into the enclave and verify it](../releasing.md#bringing-a-release-into-an-enclave)),
on RHEL 9 or RHEL 10 (use the `el9` or `el10` files):

```bash
sudo dnf install ./wd2l-<version>-1.el10.noarch.rpm ./wd2l-sender-<version>-1.el10.noarch.rpm
sudo vi /etc/wd2l/sender.env /etc/wd2l/egress.env      # the sender's options; the egress NIC
uuidgen | sudo tee /etc/wd2l/aggregator.token >/dev/null
sudo chown root:wd2l /etc/wd2l/aggregator.token && sudo chmod 640 /etc/wd2l/aggregator.token
sudo usermod -aG wd2l-audit <aggregator service account>         # it copies the audit files (section 5)
rpm -V wd2l wd2l-sender         # prints nothing while every file is as packaged
```

The packages create:

* the `wd2l` user, and the `wd2l-audit` group (who may read the audit files);
* `/etc/wd2l` (0750 root:wd2l), `/var/lib/wd2l`, and `/var/log/wd2l` (2750 wd2l:wd2l-audit,
  setgid so the files get the group).

They install the units in `/usr/lib/systemd/system`, the scripts in `/usr/libexec/wd2l`, and
templates (nftables, auditd rules, the Quadlet unit) in `/usr/share/wd2l`. They enable nothing.
`dnf upgrade` doesn't restart wd2l: restart it as [planned-downtime.md](../planned-downtime.md)
says.

On a host with `localpkg_gpgcheck=1` (the RHEL STIG sets it), `dnf install` needs
`--nogpgcheck`, after the release is verified: see
[releasing.md](../releasing.md#bringing-a-release-into-an-enclave).

To run the sender as a container instead, see [containers.md](containers.md). Without the RPMs,
see [Appendix: manual install](#appendix-manual-install). On a host installed by hand before,
see [Moving a manual install to the RPMs](#moving-a-manual-install-to-the-rpms).

The log aggregator copies the audit files to the log retention server, so its service account
needs to be in `wd2l-audit`. Restart the aggregator afterwards so it picks up the new group.

## 2. Egress NIC

```bash
sudo systemctl enable --now wd2l-egress-nic
```

`egress-nic.sh` sets the /30 address, pins the black-hole IP to the made-up MAC (**static ARP**),
turns IPv6 off on that NIC, and tells NetworkManager and lldpd to leave it alone. No gateway: the
/30 route is all it needs.

`wd2l-egress-arp`, started with it, puts the static ARP entry back if the NIC is taken down and
up (or the driver resets it), which flushes even permanent entries. It logs each time it does.

Check:

```bash
ip -br addr show ens224          # 10.255.255.1/30, UP
ip neigh show dev ens224         # 10.255.255.2 lladdr 02:00:00:00:00:02 PERMANENT
```

## 3. Firewall

`wd2l-egress-nic` (step 2) also loads the egress firewall, from the settings in `egress.env`. It:

* drops everything arriving on the egress NIC,
* lets only processes running as `wd2l` send UDP from `10.255.255.1:5514` to `10.255.255.2:5514`
  (`PORT` in `egress.env`),
* blocks ARP in and out on that NIC,
* on kernel 5.16+, also drops any other frame at the NIC (LLDP, IPv6, ...). Without the egress
  hook the unit's log says why, and the rest still loads.

```bash
sudo nft list table inet wd2l     # the rules, with their drop counters
```

Don't load these tables from `nftables.service` as well: its stop and reload flush every table,
firewalld's included.

## 4. Sender service

The options are in `/etc/wd2l/sender.env`; the unit reads them from there.

```bash
sudo systemctl enable --now wd2l-sender
journalctl -u wd2l-sender -f
```

**Upgrading an install from before the fixed source port:** the new sender options (`--bind 10.255.255.1:5514` in `sender.env`) and the new
nftables file go together (the firewall now only passes source port 5514). Change both, reload
nftables, then restart the sender the clean way ([planned-downtime.md](../planned-downtime.md)).
Only after that, add `--src-port 5514` to `/etc/wd2l/receiver.env` in Enclave 2. In the other order the
receiver counts every packet as `other_packets` until the sender is changed.

Every minute it logs its stream id, last sequence number and counters. Options
(`python3 -m wd2l.sender --help`):

| Option | Default | Notes |
|---|---|---|
| `--listen` | `127.0.0.1:10070` | Where the log aggregator connects. Keep it on localhost |
| `--bind` | none | Egress NIC's IP, optionally with a fixed UDP source port. `sender.env` uses `10.255.255.1:5514`, so the flow is the same after every restart (firewall, tap filter, ICD). Without a port the kernel picks a new one at each start |
| `--dst` | `10.255.255.2:5514` | Black-hole IP:port |
| `--max-datagram` | `1472` | `8972` if MTU 9000 end to end |
| `--max-event` | `262144` | Bigger events are truncated and flagged |
| `--rate-pps` | `20000` | Packet rate cap, smooths bursts. 0 = off |
| `--auth-token-file` | none | Must match the token set in the log aggregator |
| `--extra-field` | none | Extra aggregator field to carry as an indexed field in the SIEM (repeatable) |
| `--source-seq` | off | Number events per file (`wd2l_src_seq`) so Enclave 2 can rebuild interleaved files and name lost lines. See [multiple-files.md](../multiple-files.md) |
| `--no-tx-time` | stamping on | Stop stamping each event's send time (`wd2l_tx_time`). Leave it on: Enclave 2 uses it to split delays by segment ([operations.md](../operations.md#measuring-delays)) |
| `--no-opaque-check` | check on | Stop flagging long encrypted, compressed or random-looking blobs (`wd2l_opaque`). Leave it on: see [ADR-0002](../decisions/0002-opaque-content.md) |
| `--state` | none | Restart count and previous stream, so the receiver can link runs and report a missed one. `sender.env` uses `/var/lib/wd2l/sender.json` |
| `--drain-timeout` | `2` s | On shutdown, how long to keep reading input that is already arriving |
| `--input-rcvbuf` | `262144` | TCP receive buffer for the aggregator connection. Bounds input that is acknowledged but not yet read |
| `--audit-dir` | none | `sender.env` uses `/var/log/wd2l`. Hash-chained audit records, see [the audit plan](../audit-and-health-plan.md) and **Audit files** below |
| `--audit-min-free-mb` | `256` | Free space the audit directory must keep. Below it, nothing more goes in the audit files: records are still forwarded, counted as missed, and `audit_ok` is false until there is space again |
| `--egress-iface` | none | `sender.env` uses `ens224`. NIC carrier and transmit counters go into every heartbeat |
| `--chronyc` | `chronyc` | The command that reports time quality (synced, stratum, offset) |
| `--chrony-addr` | none | Ask chronyd over UDP (`HOST[:PORT]`, port 323) instead of running `chronyc`. The env file and the container unit use `127.0.0.1:323`: nothing to run, and no SELinux denial (chronyc can't enter its domain under `NoNewPrivileges`). chronyd's default configuration answers it; `cmdport 0` turns it off |
| `--log-format` | text | `sender.env` uses `json`: one JSON object per log line |

### Audit files

The sender writes audit records to `/var/log/wd2l/audit-*.jsonl`. Each record carries the hash of
the one before it, so a removed or changed record breaks the chain.

**Disk space.** Put `/var/log/wd2l` on a filesystem of its own (a partition or logical volume),
so audit files can never fill the disk that holds the sender's state file and the aggregator's
data. If it must share one, size it for them all. The audit files stay under 2 GB a year
([audit plan, section 15](../audit-and-health-plan.md#15-storage-estimate-storage-capacity-retention)).
The sender keeps `--audit-min-free-mb` free on that filesystem: below it, it writes nothing more
to the audit files until there is space again, and keeps sending. The records still cross
in-band.

A timer makes the files append-only and deletes them after a year:

```bash
sudo systemctl enable --now wd2l-audit-seal.timer
```

auditd rules record who changes wd2l's programs, settings, units and files:

```bash
sudo cp /usr/share/wd2l/audit/log-server.rules /etc/audit/rules.d/wd2l.rules && sudo augenrules --load
```

Check the chain:

```bash
sudo -u wd2l python3 -m wd2l.audit verify /var/log/wd2l
wd2l-audit-report verify --dir /var/log/wd2l
```

The aggregator copies these files to the log retention server
([retention-server.md](retention-server.md#6-wd2l-audit-files)).

To turn debug logging on or off so that the audit record names you, signal the sender from your
own session:

```bash
sudo kill -USR1 "$(systemctl show -p MainPID --value wd2l-sender)"
```

Don't use `systemctl kill`: systemd becomes the sender of the signal, and the record can't name
you.

## 5. Log aggregator

Any log aggregator works if it can do the following. (Examples of products in this role: Cribl
Stream, Fluentd/Fluent Bit, Logstash, Vector, rsyslog/syslog-ng with a JSON template.)

**Inputs**

* Receive from the hosts' log forwarding agents and on syslog (UDP/TCP 514) for firewalls,
  switches and hypervisor hosts.
* Break the incoming data into one event per log record (Windows event logs already are).
* Make sure every event ends up with `host`, `sourcetype` and `index` set, the way you want them
  to appear in the Enclave 2 SIEM, and `_time` set to the event time.

**Output to the sender**

| Requirement | Value |
|---|---|
| Transport | TCP to `127.0.0.1:10070` (no load balancing, no TLS: it's localhost) |
| Format | One JSON object per line with `_raw` (the log text), `_time` (epoch seconds), `host`, `source`, `sourcetype`, `index`. Other fields are ignored unless named with `--extra-field` |
| Optional first line | `{"authToken": "<contents of /etc/wd2l/aggregator.token>"}`. Required if the sender was started with `--auth-token-file` |
| Compression | **None**. The sender refuses gzip and logs why |
| Backpressure | **Persistent queue** (recommended) or block. On a clean sender restart, anything that couldn't be read in time is counted in `shutdown_unread_bytes`; on a crash, up to one receive buffer of input can be lost (see accreditation notes) |

Send everything that should cross (usually all of it) to that output. Anything you *don't* want
in Enclave 2 should be filtered here, in Enclave 1.

**Output to the log retention server**

A second output keeps the 1-year Enclave 1 copy ([retention-server.md](retention-server.md)):

* Send **every** event the aggregator collects, before any filter that decides what crosses,
  with at least `_time`, `host`, `source`, `sourcetype`, `index` and `_raw`.
* Send it over the log server's normal Enclave 1 NIC, never the egress NIC. The egress firewall
  allows only the one wd2l flow.
* Give it **its own persistent queue**, so a retention-server outage never holds up the output to
  the sender.
* The aggregator must be able to read a time window back from the retention server and route it
  to the sender output. Route replayed events to the sender output only, not back to the
  retention server.
* Also read `/var/log/wd2l/audit-*.jsonl` and route those lines to the retention server only,
  with each line unchanged ([retention-server.md](retention-server.md#6-wd2l-audit-files)). The
  aggregator's service account must be in group `wd2l-audit` to read them (section 1).

### Example: Cribl Stream

This is the setup the proof of concept was designed against. Menu names follow Cribl's
documentation; check them against your version.

* **Source: Splunk TCP** on port 9997 for Splunk Universal Forwarders. On each forwarder,
  `outputs.conf`:
  ```ini
  [tcpout]
  defaultGroup = aggregator
  [tcpout:aggregator]
  server = <aggregator-host>:9997
  ```
  Set the source's event breaking so each event is one record.
* **Source: Syslog** on UDP/TCP 514. Set `host`, `sourcetype` and `index` with fields on the source,
  or an Eval function or lookup keyed on host.
* **Destination: TCP JSON**. It already produces the format above. Address `127.0.0.1`, port
  `10070`, load balancing off, TLS off, **Compression: None**, auth token from
  `/etc/wd2l/aggregator.token`, **Backpressure behavior: Persistent Queue**.
* **Destination for the retention server**: Filesystem (on an NFS mount from the retention
  server) or S3 (S3-compatible storage), JSON format, gzip compression, partitioned by date and
  host, **Backpressure behavior: Persistent Queue**.
* **Routes**, in this order:
  1. everything to the retention destination, with **Final** turned off so each event also
     continues to the next route;
  2. everything that should cross, through a passthru pipeline, to the TCP JSON destination.
* **Replay**: a Filesystem or S3 collector over the retention data, run for the time window you
  need, routed to the TCP JSON destination only.

## 6. Check Enclave 1 end to end

```bash
# events flowing into the sender:
journalctl -u wd2l-sender --since -5min | grep last_seq
# packets leaving on the egress NIC (only UDP .1:5514 > .2:5514 should appear, nothing else):
sudo tcpdump -i ens224 -nn -c 20
# nftables drop counters on that NIC should stay at 0 unless something is misbehaving:
sudo nft list table inet wd2l
```

On the log retention server, new data should keep arriving. See the checks in
[retention-server.md](retention-server.md#7-checks).

## Moving a manual install to the RPMs

After `dnf install`, a host installed by hand keeps running its old copies: units in
`/etc/systemd/system` win over the packaged ones in `/usr/lib/systemd/system`, and `rpm -V`
doesn't see them. So, in a planned window:

1. Stop the sender as [planned-downtime.md](../planned-downtime.md) says.
2. Install the packages as in section 1. Edited files in `/etc/wd2l` stay; the packaged ones
   are put beside them as `.rpmnew`.
3. Units from before 0.3 carry the sender's options in `ExecStart=`. Put them in
   `WD2L_SENDER_ARGS` in `/etc/wd2l/sender.env`, and compare with `sender.env.rpmnew`.
4. Swap the old copies for the packaged units and rules:

   ```bash
   sudo systemctl disable wd2l-sender wd2l-egress-nic wd2l-audit-seal.timer
   sudo rm /etc/systemd/system/wd2l-sender.service /etc/systemd/system/wd2l-egress-nic.service \
     /etc/systemd/system/wd2l-audit-seal.service /etc/systemd/system/wd2l-audit-seal.timer
   sudo rm -rf /opt/wd2l
   sudo cp /usr/share/wd2l/audit/log-server.rules /etc/audit/rules.d/wd2l.rules && sudo augenrules --load
   sudo systemctl daemon-reload
   sudo systemctl enable wd2l-sender wd2l-egress-nic wd2l-audit-seal.timer
   systemctl cat wd2l-sender | head -1      # /usr/lib/systemd/system/wd2l-sender.service
   ```

5. Start it as planned-downtime.md says. `rpm -V wd2l wd2l-sender` prints only the `/etc/wd2l`
   files you edited.

## Appendix: manual install

Without the RPMs (any Linux with Python 3.9 or newer; standard library only), from a checkout
of this repo. It puts the code in `/opt/wd2l`, and the units and their scripts run from there.

```bash
sudo useradd --system --no-create-home --shell /sbin/nologin wd2l
sudo mkdir -p /opt/wd2l /etc/wd2l
sudo cp -r wd2l deploy /opt/wd2l/          # from this repo
sudo cp deploy/log-server/egress.env.example /etc/wd2l/egress.env   # edit IFACE etc.
sudo cp deploy/log-server/sender.env /etc/wd2l/                     # edit the options here
uuidgen | sudo tee /etc/wd2l/aggregator.token >/dev/null
sudo chown root:wd2l /etc/wd2l/aggregator.token && sudo chmod 640 /etc/wd2l/aggregator.token
sudo groupadd --system wd2l-audit                                # who may read audit files
sudo install -d -o wd2l -g wd2l-audit -m 2750 /var/log/wd2l      # setgid: files get the group
sudo usermod -aG wd2l-audit <aggregator service account>         # it copies them (section 5)
git rev-parse HEAD | sudo tee /opt/wd2l/wd2l/BUILD >/dev/null    # the build audit records name
```

The units and the auditd rules, in place of sections 2 to 4:

```bash
sudo cp deploy/log-server/wd2l-egress-nic.service deploy/log-server/wd2l-egress-arp.service \
  deploy/log-server/wd2l-sender.service \
  deploy/common/wd2l-audit-seal.service deploy/common/wd2l-audit-seal.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wd2l-egress-nic wd2l-sender wd2l-audit-seal.timer
sudo cp deploy/log-server/wd2l.rules /etc/audit/rules.d/ && sudo augenrules --load
```

`wd2l-audit-report` isn't on the path in a manual install: run
`sudo -u wd2l env PYTHONPATH=/opt/wd2l python3 -m wd2l.audit_report`, or `pip install` the
wheel from a release. Likewise `python3 -m wd2l.audit` needs `env PYTHONPATH=/opt/wd2l`.
