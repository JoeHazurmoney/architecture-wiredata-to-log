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
| UDP port | `5514` |

## 1. Install wd2l

Python 3.9 or newer, standard library only.

```bash
sudo useradd --system --no-create-home --shell /sbin/nologin wd2l
sudo mkdir -p /opt/wd2l /etc/wd2l
sudo cp -r wd2l deploy /opt/wd2l/          # from this repo
sudo cp deploy/log-server/egress.env.example /etc/wd2l/egress.env   # edit IFACE etc.
uuidgen | sudo tee /etc/wd2l/aggregator.token >/dev/null
sudo chown root:wd2l /etc/wd2l/aggregator.token && sudo chmod 640 /etc/wd2l/aggregator.token
```

## 2. Egress NIC

```bash
sudo cp deploy/log-server/wd2l-egress-nic.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wd2l-egress-nic
```

`egress-nic.sh` sets the /30 address, pins the black-hole IP to the made-up MAC (**static ARP**),
turns IPv6 off on that NIC, and tells NetworkManager and lldpd to leave it alone. No gateway: the
/30 route is all it needs.

Check:

```bash
ip -br addr show ens224          # 10.255.255.1/30, UP
ip neigh show dev ens224         # 10.255.255.2 lladdr 02:00:00:00:00:02 PERMANENT
```

## 3. Firewall

Load `deploy/log-server/nftables-wd2l.nft` (edit the interface name at the top). It:

* drops everything arriving on the egress NIC,
* lets only processes running as `wd2l` send UDP from `10.255.255.1` to `10.255.255.2:5514`,
* blocks ARP in and out on that NIC,
* on kernel 5.16+, also drops any other frame at the NIC (LLDP, IPv6, ...). Delete that last table
  if your kernel rejects it.

```bash
sudo cp deploy/log-server/nftables-wd2l.nft /etc/nftables.d/ 2>/dev/null || sudo cp deploy/log-server/nftables-wd2l.nft /etc/
# include it from /etc/sysconfig/nftables.conf (RHEL) or /etc/nftables.conf (Debian/Ubuntu)
sudo nft -f /etc/nftables.d/nftables-wd2l.nft
```

## 4. Sender service

```bash
sudo cp deploy/log-server/wd2l-sender.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wd2l-sender
journalctl -u wd2l-sender -f
```

Every minute it logs its stream id, last sequence number and counters. Options
(`python3 -m wd2l.sender --help`):

| Option | Default | Notes |
|---|---|---|
| `--listen` | `127.0.0.1:10070` | Where the log aggregator connects. Keep it on localhost |
| `--bind` | none | Egress NIC's IP |
| `--dst` | `10.255.255.2:5514` | Black-hole IP:port |
| `--max-datagram` | `1472` | `8972` if MTU 9000 end to end |
| `--max-event` | `262144` | Bigger events are truncated and flagged |
| `--rate-pps` | `20000` | Packet rate cap, smooths bursts. 0 = off |
| `--auth-token-file` | none | Must match the token set in the log aggregator |
| `--extra-field` | none | Extra aggregator field to carry as an indexed field in the SIEM (repeatable) |
| `--source-seq` | off | Number events per file (`wd2l_src_seq`) so Enclave 2 can rebuild interleaved files and name lost lines. See [multiple-files.md](../multiple-files.md) |
| `--state` | none | Restart count and previous stream, so the receiver can link runs and report a missed one. The unit uses `/var/lib/wd2l/sender.json` |
| `--drain-timeout` | `2` s | On shutdown, how long to keep reading input that is already arriving |
| `--input-rcvbuf` | `262144` | TCP receive buffer for the aggregator connection. Bounds input that is acknowledged but not yet read |

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
* Once wd2l writes audit files (audit plan, phase 1), also read `/var/log/wd2l/audit.jsonl` and
  route it to the retention server only, with each line unchanged.

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
# packets leaving on the egress NIC (only UDP to .2:5514 should appear, nothing else):
sudo tcpdump -i ens224 -nn -c 20
# nftables drop counters on that NIC should stay at 0 unless something is misbehaving:
sudo nft list table inet wd2l
```

On the log retention server, new data should keep arriving. See the checks in
[retention-server.md](retention-server.md#7-checks).
