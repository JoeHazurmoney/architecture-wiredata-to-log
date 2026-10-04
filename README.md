# architecture-wiredata-to-log

Architecture and proof of concept for moving logs **one way** from Enclave 1 to
Enclave 2 by tapping a cable and rebuilding the logs from the raw packets.

```mermaid
flowchart TB
  subgraph E1["Enclave 1"]
    H["Hosts<br/>firewalls, switches, servers,<br/>workstations, hypervisors"]
    A["Log aggregator"]
    RS["Log retention server<br/>1-year copy"]
    S["wd2l-sender<br/>numbers, splits, checksums"]
    T{{"Network tap"}}
    B["Black-hole switch port<br/>drops everything"]
    H -- "agents / syslog" --> A
    A -- "copy of every event" --> RS
    RS -. "replay<br/>if needed" .-> A
    A -- "JSON lines over TCP" --> S
    S -- "UDP to an IP<br/>nothing answers" --> T
    T --> B
  end

  subgraph E2["Enclave 2"]
    N["Capture NIC<br/>receive only, no IP"]
    R["wd2l-receiver<br/>rebuild, verify, report gaps"]
    P[("pcap archive")]
    SIEM["SIEM"]
    N --> R
    N --> P
    P -. "replay after<br/>an outage" .-> R
    R -- "events +<br/>health records" --> SIEM
  end

  T == "one fiber strand, TX only<br/>(the one-way guarantee)" ==> N

  classDef oneway stroke-width:3px
  class T,N oneway
```

* The log server sends every event as numbered UDP packets to an IP that nothing answers. The
  switch port drops them.
* A network tap copies that cable to Enclave 2 over one fiber strand. That's the one-way guarantee.
* The receiver rebuilds each event and checks it (CRC + SHA-256). It sends events to the SIEM with
  their original host, source, sourcetype, index and time, and **reports every lost event by
  sequence number**.
* A rolling pcap archive lets you replay after a receiver outage without duplicates.
* Events that never reached Enclave 2 can't be asked for again across a one-way link. A log
  retention server in Enclave 1 keeps a copy of every event for 1 year, and the aggregator
  replays the lost time window from it.

The design is product-neutral: any log aggregator, network tap and SIEM that fill the roles
work. The proof of concept was built against Cribl Stream (aggregator) and Splunk (SIEM) as
examples.

Start with [docs/architecture.md](docs/architecture.md).

## Repo map

| Path | What |
|---|---|
| `wd2l/` | Python package, standard library only (Python ≥ 3.9) |
| `wd2l/sender.py` | Enclave 1: JSON lines in from the log aggregator, framed UDP out, heartbeats |
| `wd2l/receiver.py` | Enclave 2: live capture or pcap replay → rebuild → gap tracking → outputs |
| `wd2l/wire.py` | Packet format shared by both sides ([docs/wire-format.md](docs/wire-format.md)) |
| `wd2l/opaque.py` | Enclave 1: spots long encrypted, compressed or random-looking blobs in log text so the sender can flag them ([ADR-0002](docs/decisions/0002-opaque-content.md)) |
| `wd2l/packets.py` | Ethernet/IPv4/UDP parsing, pcap files, raw-socket capture |
| `wd2l/outputs.py` | SIEM output over an HTTP event collector (HEC format, with disk spool) and JSONL file output |
| `deploy/log-server/` | Egress NIC script, nftables, systemd units |
| `deploy/switch/` | Black-hole port config (example for one switch platform) |
| `deploy/receiver/` | Capture NIC script, tcpdump archive, receiver unit, example SIEM configs (Splunk) |
| `docs/` | Architecture, wire format, deployment guides, operations runbook, accreditation notes, decision records (`docs/decisions/`) |
| `lab/` | Whole path simulated with Linux network namespaces |
| `samples/` | Real `messages`, `secure` and `audit.log` sample logs, and the script that generated them |
| `tests/` | Unit, fuzz and end-to-end tests |

## Try it

```bash
pip install pytest && python3 -m pytest          # 138 tests, no root needed

sudo lab/run-lab.sh                               # full path in network namespaces
sudo lab/run-lab.sh --loss 1                      # 1% wire loss: every loss reported exactly
sudo lab/run-lab.sh --receiver-outage             # receiver stopped mid-run, archive replay fills it
sudo lab/run-lab.sh --receiver-crash              # receiver killed mid-run: nothing lost
sudo lab/run-lab.sh --files samples/logs/messages samples/logs/secure samples/logs/audit.log
                                                  # real logs: rebuilt files must hash the same
sudo lab/run-lab.sh --interleave --files samples/logs/messages samples/logs/secure samples/logs/audit.log
                                                  # same, interleaved as if written at the same time
```

The lab needs root, `iproute2`, `nftables` (kernel ≥ 5.16), `tcpdump` and `python3`.

**Want to run the POC yourself and see the results?** Follow the step-by-step guide in
[docs/running-the-lab.md](docs/running-the-lab.md).

## Deploying

1. [Network](docs/deployment/network.md): black-hole switch port, network tap, one-strand fiber
2. [Log server](docs/deployment/log-server.md): egress NIC, firewall, `wd2l-sender`, log aggregator
3. [Log retention server](docs/deployment/retention-server.md): 1-year copy in Enclave 1, replay
   source, wd2l audit files
4. [Receiver](docs/deployment/receiver.md): capture NIC, archive, `wd2l-receiver`, SIEM
5. [Operations](docs/operations.md): health records, alerts, replay, re-send

## Status

Proof of concept. Verified in the namespace lab (see the end of
[architecture.md](docs/architecture.md)). Not yet verified: the physical tap, switch and fiber
behavior, and a real log aggregator, log retention server and SIEM (the lab has no retention
server). The deployment guides list the checks for each.

Next: audit records (NIST SP 800-53 Rev 5, Moderate) and a fault-location health dashboard.
Proposal for review: [docs/audit-and-health-plan.md](docs/audit-and-health-plan.md).

How several live log files are tracked and rebuilt from one stream:
[docs/multiple-files.md](docs/multiple-files.md).
