# Running the proof of concept yourself

The lab builds the whole one-way path on one Linux machine, with separate network namespaces for
Enclave 1, the black-hole switch port and Enclave 2. It pushes a known set of logs through and
checks what comes out the other side. No network gear is needed. Commands are for the RHEL family
(RHEL, Rocky, AlmaLinux, Fedora); Ubuntu/Debian differences follow each step.

## 1. Get a Linux machine

* **A VM is fine**, with 2 CPUs and 2 GB of RAM. On a Mac or Windows machine, use a Linux VM; a
  plain container works only with `--privileged`.
* **Kernel 5.16 or newer** (`uname -r`): the lab uses the nftables "egress" hook on a NIC.
  RHEL 10 and its rebuilds (kernel 6.12) and current Fedora work. RHEL 9 and its rebuilds ship
  5.14 and may not; if step 5 fails with an nftables error mentioning "egress", use a 10.x
  release or Fedora. Ubuntu 24.04, Debian 12 and Ubuntu 22.04 with the HWE kernel work; the stock
  Ubuntu 22.04 kernel (5.15) doesn't.
* **Root** (`sudo`), to create the namespaces.

## 2. Install the tools

```bash
sudo dnf install -y git python3 iproute iproute-tc nftables tcpdump
```

Ubuntu/Debian: `sudo apt update && sudo apt install -y git python3 python3-venv iproute2 nftables tcpdump`.

## 3. Get the code

```bash
git clone https://github.com/JoeHazurmoney/architecture-wiredata-to-log.git
cd architecture-wiredata-to-log
```

## 4. Optional: run the unit tests first

In a virtual environment, which works where `pip install` is refused (Ubuntu 24.04, Debian 12).
`requirements.txt` is hash-pinned, so it's an install of its own:

```bash
python3 -m venv ~/wd2l-venv && . ~/wd2l-venv/bin/activate
pip install pytest
pip install --require-hashes -r packaging/release/requirements.txt
python3 -m pytest
```

It runs without root in under a minute; every test should pass, none skipped.

## 5. Run the lab

Each run takes 15–25 seconds and cleans up after itself. The header of `lab/run-lab.sh` lists
every option; the ones below show the main results.

```bash
sudo lab/run-lab.sh                             # clean run
sudo lab/run-lab.sh --loss 1                    # drop 1% of packets on the "cable"
sudo lab/run-lab.sh --receiver-outage           # stop the receiver mid-run, then replay the archive
sudo lab/run-lab.sh --receiver-crash            # kill the receiver mid-run, then replay the archive
sudo lab/run-lab.sh --maintenance               # planned downtime: stop and restart both sides
sudo lab/run-lab.sh --events 25000 --eps 5000   # more logs, faster
```

A successful run ends like this:

```
sent:            5001
received:        5001
gaps (reported): 0
truncated:       1 (seq [5001])
opaque content:  3 (seq [1002, 2003, 3004])
...
link delay (wd2l_rx_time - wd2l_tx_time): median 0.0 ms, p99 4.0 ms, max 11.0 ms
clock offset (lowest of the last 10 heartbeats): 0.0 s
PASS: every event arrived intact or is accounted for in a reported gap
```

Both namespaces share one clock, so the offset is about 0. The three opaque events are blobs
planted on purpose (random, gzip, PGP), which the sender must flag
([ADR-0002](decisions/0002-opaque-content.md)).

| Run | What should happen |
|---|---|
| Clean | Every log arrives byte for byte. One 300 KB log arrives cut down and flagged; three with planted blobs arrive flagged `wd2l_opaque` |
| `--loss 1` | Some logs are lost, and every one is reported by number. PASS means nothing went missing unreported and nothing was falsely reported |
| `--receiver-outage` | The receiver misses about 2 seconds; the archive replay fills them with no duplicates |
| `--receiver-crash` | The same, with the receiver killed. Nothing is lost; some logs arrive twice (the `duplicates` line), allowed because they are identical and carry the same number |
| `--maintenance` | The [planned-downtime](planned-downtime.md) order: half the logs, everything stopped, everything started in reverse, the rest. Two sender runs, each with `input unread at stop: 0`; no gaps, no replay |

Every run also checks that Enclave 2 sent nothing: "frames Enclave 2 tried to send" counts what
the lab's drop rule on the capture NIC stopped, and "frames sent back toward Enclave 1 from
Enclave 2" what got past it; both must read 0. And it checks that only log traffic crossed
("other packets on the tapped cable: 0"). Without `--fault`, it also checks that no fault or
time alarm was raised (rule 9 is allowed after loss or an outage).

## 6. Look at the results

Everything is in `lab/out/`: `sent.jsonl` (what went in), `received/events.jsonl` and
`received/health.jsonl` (what the SIEM would get), `pcap/*.pcap` (the raw archive; open it in
Wireshark or `tcpdump -nn -r`), the programs' logs, and with `--files` the rebuilt files and their
hashes.

## 7. Poke around while it's running (optional)

```bash
sudo lab/run-lab.sh --keep
sudo ip netns list                                   # wd2l-enc1, wd2l-bh, wd2l-enc2
sudo ip netns exec wd2l-enc1 ip neigh                # the static ARP entry for the black hole
sudo ip netns exec wd2l-enc2 ip -d link show cap0    # capture NIC: no IP, NOARP, PROMISC
sudo lab/teardown.sh                                 # remove everything when done
```

## 8. Run real log files through and verify byte for byte

`--files` sends whole log files, one event per line. Enclave 2 puts the files back together and
the lab compares SHA-256 hashes of the originals and the rebuilt copies. `--files` must be the
last option.

**The sample logs** (`samples/logs/`: `messages`, `secure`, `audit.log` from a disposable cloud
VM; see [samples/logs/README.md](../samples/logs/README.md)):

```bash
sudo lab/run-lab.sh --files samples/logs/messages samples/logs/secure samples/logs/audit.log
(cd lab/out/rebuilt && sha256sum -c ../../../samples/logs/SHA256SUMS)    # each file: OK
```

The lab's own table ends `PASS: every file rebuilt byte for byte`. With `--loss 1` before
`--files`, damaged files are reported `INCOMPLETE` with the number of missing lines, never a false
`MATCH`.

**As if the files were written at the same time:** a forwarder tailing several logs interleaves
their lines. `--interleave` merges the files by each line's timestamp; the sender numbers lines
per file (`--source-seq`) and Enclave 2 separates them again. With `--loss 1`, each damaged file
is listed with its missing line numbers. How it works, and what the real pipeline needs, is in
[multiple-files.md](multiple-files.md).

**Your own logs:** copy them first (live logs keep growing), hash the copies, send them, and check
the rebuilt files against your hashes. Then delete both copies: they hold real user names, host
names and addresses (`lab/out/` is ignored by git).

```bash
mkdir -p ~/wd2l-logs && sudo cp /var/log/messages /var/log/secure /var/log/audit/audit.log ~/wd2l-logs/
sudo chown "$USER": ~/wd2l-logs/* && (cd ~/wd2l-logs && sha256sum messages secure audit.log > SHA256SUMS)
sudo lab/run-lab.sh --eps 5000 --files ~/wd2l-logs/messages ~/wd2l-logs/secure ~/wd2l-logs/audit.log
(cd lab/out/rebuilt && sha256sum -c ~/wd2l-logs/SHA256SUMS)
sudo rm -rf lab/out ~/wd2l-logs
```

On Ubuntu/Debian use `/var/log/syslog` and `/var/log/auth.log` (`audit.log` needs auditd). Any
text log works, rotated files too; two files with the same name can't go in one run. A line over
256 KB is refused up front, and lines that aren't valid UTF-8 cross base64-encoded and are
restored exactly.

## 9. Inject faults and see where the receiver places them

Each `--fault` run injects one fault, checks that the first fault the receiver reports names the
right segment and rule ([the rules](audit-and-health.md#10-where-is-the-fault-the-rules)), then
that the report clears.
It ends with `PASS: fault reported where expected, then cleared`, and the usual `PASS` too.

| `--fault` | What the lab does | The receiver should say |
|---|---|---|
| `aggregator-stop` | The stand-in aggregator pauses for 12 s | `e1-input`, amber, rule 5 |
| `sender-stop` | Half the logs, a clean sender stop for 10 s, the other half | `e1-sender`, amber, rule 2 |
| `sender-hang` | The sender frozen (`kill -STOP`) for 10 s | `e1-sender/boundary`, red, rule 3 |
| `tap-down` | The tap's monitor port down for 10 s | `boundary`, red, rule 1 |
| `foreign-only` | The sender frozen, other UDP traffic on the cable for 10 s | `boundary`, red, rule 4 |
| `wire-loss` | 20% of packets lost for 10 s | `boundary`, amber, rule 9 |
| `receiver-slow` | A small capture buffer, the receiver frozen 4 s at 5,000 events/s | `e2-capture`, red, rule 8 |
| `siem-down` | The stand-in SIEM down for 12 s | `e2-siem`, amber, rule 10 |
| `clock` | The stand-in `chronyc` says "not synchronised" for 10 s | a time alarm (`receiver: unsynced`) |

```bash
sudo lab/run-lab.sh --fault tap-down
grep '"type": "fault"' lab/out/received/health.jsonl
```

A fault run sends 20,000 events and can't be combined with `--loss`, `--receiver-outage`,
`--maintenance` or `--files`. `--chrony-udp` has both sides ask a chronyd stand-in over UDP, as
the containers do (`--fault clock --chrony-udp` checks the receiver's time check that way; the
sender asks chrony once a minute, so a 10 s fault doesn't reach its heartbeat).

## 10. Run the container image through the lab

The same runs, with `wd2l-sender` and `wd2l-receiver` in the container image as the Quadlet units
run them (user 65532, no capabilities but `NET_RAW` for the receiver, read-only). It needs Podman:

```bash
python3 -m pip install --user build && git rev-parse HEAD > wd2l/BUILD && python3 -m build
packaging/container/build.sh dist localhost/wd2l:dev
podman save localhost/wd2l:dev | sudo podman load
sudo lab/run-lab.sh --image localhost/wd2l:dev
```

Both sides use `--chrony-addr`, and the run raises `net.core.rmem_max` as production does
([receiver guide](deployment/receiver.md#kernel-receive-buffer)). `--receiver-outage` works with
`--image`; the fault runs and `--receiver-crash` don't (they would freeze or kill the podman
client, not wd2l).

## If something goes wrong

* **"run as root"**: add `sudo`. **"missing tcpdump"** (or `ip`, `tc`, `nft`): step 2.
* **An nftables error mentioning "egress"**: the kernel is older than 5.16 (step 1).
* **Leftover networks from an interrupted run**: `sudo lab/teardown.sh`, then run again.
* **No files in `lab/out/pcap/` and "Permission denied" in `lab/out/tcpdump.log`**: SELinux can
  stop tcpdump writing into a home directory. Confirm with `sudo grep AVC /var/log/audit/audit.log`
  (`ausearch -ts recent` can miss them), then put the output elsewhere:
  `sudo env OUT=/var/tmp/wd2l-lab lab/run-lab.sh`.
