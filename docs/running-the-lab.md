# Running the proof of concept yourself

The lab builds the whole one-way path on one Linux machine, using separate virtual networks
(network namespaces) for Enclave 1, the black-hole switch port and Enclave 2. It pushes a known set
of logs through, then checks what comes out the other side. No real network gear is needed.

The commands below are for the RHEL family (RHEL, Rocky, AlmaLinux, Fedora). Ubuntu/Debian
equivalents are in a note after each step where they differ.

## 1. Get a Linux machine

* **A VM is fine** (VMware, KVM, Hyper-V, VirtualBox, a cloud instance). 2 CPUs and 2 GB of RAM is
  plenty.
* **Kernel 5.16 or newer.** The lab uses a firewall feature (the nftables "egress" hook on a
  network card) that older kernels don't have. Check with:

  ```bash
  uname -r
  ```

  RHEL 10 / Rocky 10 / AlmaLinux 10 (kernel 6.12) and current Fedora work. **RHEL 9 and its
  rebuilds ship a 5.14 kernel and may not have this feature**. If step 5 fails with an nftables
  error mentioning "egress", use a 10.x release or Fedora.
* **You need root** (`sudo`). Creating virtual networks requires it.
* A plain container won't work unless it runs `--privileged`. On a Mac or Windows machine, use a
  Linux VM.

> **Ubuntu/Debian:** Ubuntu 24.04 (kernel 6.8), Debian 12 (6.1) and Ubuntu 22.04 with its newer
> "HWE" kernel work. The stock Ubuntu 22.04 kernel (5.15) is too old.

## 2. Install the tools

```bash
sudo dnf install -y git python3 python3-pip iproute nftables tcpdump
python3 -m pip install --user pytest
```

> **Ubuntu/Debian:**
> ```bash
> sudo apt update
> sudo apt install -y git python3 python3-pytest iproute2 nftables tcpdump
> ```
> Use the `python3-pytest` package. On Ubuntu 24.04, `pip install pytest` is blocked by default.

## 3. Get the code

```bash
git clone -b architecture-wd2l https://github.com/JoeHazurmoney/architecture-wiredata-to-log.git
cd architecture-wiredata-to-log
```

If the repository is private, git will ask you to sign in to GitHub.

## 4. Optional: run the unit tests first

```bash
python3 -m pytest
```

These run without root and take about 25 seconds. You should see `141 passed`.

## 5. Run the lab

Each run takes about 15–20 seconds and cleans up after itself.

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
clock offset (last heartbeat): 0.0 s
PASS: every event arrived intact or is accounted for in a reported gap
```

The link delay compares each event's send time (sender's clock) with its arrival time
(receiver's clock). Both namespaces share one clock in the lab, so the clock offset is about 0.
The three opaque-content events are blobs planted on purpose (random, gzip, PGP): the sender
must flag each one ([ADR-0002](decisions/0002-opaque-content.md)).

What each run proves:

| Run | What should happen |
|---|---|
| Clean | Every log arrives byte-for-byte identical. One 300 KB log arrives cut down and flagged. Three logs with planted encrypted or compressed blobs arrive flagged `wd2l_opaque`. |
| `--loss 1` | Some logs are lost, and every one is reported by number. PASS means nothing went missing unreported and nothing was falsely reported as missing. |
| `--receiver-outage` | The receiver misses about 2 seconds of logs, then replay from the packet archive fills them in with no duplicates. |
| `--receiver-crash` | Same, but the receiver is killed with no chance to clean up. Nothing is lost; some logs arrive twice (the `duplicates` line), which is allowed here because they are identical and carry the same sequence number. |
| `--maintenance` | Planned downtime, in the order of [planned-downtime.md](planned-downtime.md). Half the logs are sent. The stand-in aggregator stops, the sender stops, then the receiver and the capture stop as if the receiver host were going down. Everything starts again in reverse order and the rest is sent. The `sender runs` line shows two runs, each with `input unread at stop: 0`. No gaps, no replay. |

Every run also checks two things:

* **Nothing came back:** the line "frames sent back toward Enclave 1 from Enclave 2" must read 0.
* **The cable was clean:** only log traffic crossed ("other packets on the tapped cable: 0").

## 6. Look at the results

Everything is written to `lab/out/`:

| File | What it is |
|---|---|
| `sent.jsonl` | The logs that went in |
| `received/events.jsonl` | The logs rebuilt in Enclave 2, each with its sequence number |
| `received/health.jsonl` | The receiver's health, gap and heartbeat records (what the SIEM would get) |
| `pcap/*.pcap` | The raw packet archive |
| `sender.log`, `receiver.log`, `tcpdump.log` | Program logs |
| `manifest.json`, `rebuilt/`, `hashes.txt` | Only with `--files`: what was sent, the files rebuilt in Enclave 2, and the hash comparison (section 8) |

To look at the raw packets:

```bash
tcpdump -nn -r lab/out/pcap/*.pcap | head
```

Or open the pcap file in Wireshark.

## 7. Poke around while it's running (optional)

`--keep` leaves the virtual networks up after the run so you can inspect them:

```bash
sudo lab/run-lab.sh --keep
sudo ip netns list                                   # wd2l-enc1, wd2l-bh, wd2l-enc2
sudo ip netns exec wd2l-enc1 ip neigh                # the static ARP entry for the black hole
sudo ip netns exec wd2l-enc2 ip -d link show cap0    # capture NIC: no IP, NOARP, PROMISC
sudo lab/teardown.sh                                 # remove everything when done
```

## 8. Run real log files through and verify byte for byte

`--files` sends whole log files instead of generated events. Each line becomes one event.
Enclave 2 puts the files back together, and the lab compares SHA-256 hashes of the originals
and the rebuilt copies. If any byte differed, the hash would differ.

### With the sample logs in this repo

`samples/logs/` holds three real logs (`messages`, `secure`, `audit.log`) captured from a
disposable cloud VM. See [samples/logs/README.md](../samples/logs/README.md).

```bash
sudo lab/run-lab.sh --files samples/logs/messages samples/logs/secure samples/logs/audit.log
```

It takes about 25 seconds and ends with:

```
file         result     sha256 original                                                  sha256 rebuilt
messages     MATCH      b40e6d0aa8c8e1ea44aea988e5acb10db9b2dd3c7ff178b2ecd2c1c11ce784b5 b40e6d0aa8c8e1ea...
secure       MATCH      a1889c62064889fde80f6724bd31cd022e41fd30a9ab05541cb3f9a7f4cdaab0 a1889c62064889fd...
audit.log    MATCH      45667f63a67123549f835a3233d20605b2dec26ac2574571475b3eddef4fa9c6 45667f63a67123549...
PASS: every file rebuilt byte for byte
```

To check the rebuilt copies yourself with the standard tool, against the hashes shipped in the
repo:

```bash
(cd lab/out/rebuilt && sha256sum -c ../../../samples/logs/SHA256SUMS)
```

Each file should print `OK`.

With `--loss 1` added before `--files`, some lines are lost on the "cable". The affected files are
then reported as `INCOMPLETE`, with the number of missing lines, never as a false `MATCH`.

### As if the files were being written at the same time

In production a forwarder tails several logs at once, so their lines arrive interleaved. Add
`--interleave` to merge the files by each line's timestamp before sending:

```bash
sudo lab/run-lab.sh --interleave --files samples/logs/messages samples/logs/secure samples/logs/audit.log
```

The sender then numbers lines per file (`--source-seq`), and Enclave 2 separates the stream back
into three files and hashes them. With `--loss 1` added, each damaged file is listed with its
missing line numbers. How the tracking works, and what the real pipeline needs for byte-for-byte
files, is explained in [multiple-files.md](multiple-files.md).

### With your own computer's logs

1. Copy the logs and hash the copies **before** they go in. Copy first: live logs keep growing,
   so a hash of the live file won't stay the same.

   ```bash
   mkdir -p ~/wd2l-logs
   sudo cp /var/log/messages /var/log/secure /var/log/audit/audit.log ~/wd2l-logs/
   sudo chown "$USER": ~/wd2l-logs/*
   (cd ~/wd2l-logs && sha256sum messages secure audit.log | tee SHA256SUMS)
   ```

2. Send them through the lab:

   ```bash
   sudo lab/run-lab.sh --files ~/wd2l-logs/messages ~/wd2l-logs/secure ~/wd2l-logs/audit.log
   ```

   `--files` must be the last option. The lab sends 1,000 lines a second by default, so for big
   files put `--eps 5000` before it.

3. Hash the rebuilt copies **after**, against your own "before" hashes:

   ```bash
   (cd lab/out/rebuilt && sha256sum -c ~/wd2l-logs/SHA256SUMS)
   ```

   Every file should print `OK`. The lab's own table (`lab/out/hashes.txt`) shows the same
   comparison.

4. Clean up. `lab/out/` and `~/wd2l-logs/` now hold copies of your real logs:

   ```bash
   sudo rm -rf lab/out ~/wd2l-logs
   ```

> **Ubuntu/Debian:** the files are named differently. Use `/var/log/syslog` (instead of
> `messages`) and `/var/log/auth.log` (instead of `secure`), and change the names in the
> `sha256sum` and `--files` lines to match. `audit.log` only exists if auditd is installed
> (`sudo apt install auditd`).

Things to know:

* **Don't commit your own logs.** They contain real usernames, hostnames and IP addresses.
  `lab/out/` is already ignored by git; `~/wd2l-logs/` is outside the repo.
* Any text log works, not just these three: rotated files like `messages-20261001` too. Two files
  with the same name (from different folders) can't go in the same run.
* A single line longer than 256 KB would arrive truncated, so the lab refuses such a file up
  front instead of reporting a false mismatch.
* Lines that aren't valid UTF-8 (rare, but some logs have them) are carried base64-encoded and
  restored exactly.

## If something goes wrong

* **"run as root"**: add `sudo`.
* **"missing tcpdump"** (or `ip`, `tc`, `nft`): install the package from step 2.
* **An nftables error mentioning "egress"**: the kernel is older than 5.16. See step 1.
* **Leftover networks from an interrupted run**: `sudo lab/teardown.sh`, then run again.
* **No files in `lab/out/pcap/` and "Permission denied" in `lab/out/tcpdump.log`**: SELinux (on by
  default in the RHEL family) can stop tcpdump from writing into a home directory. Confirm with
  `sudo ausearch -m avc -ts recent`. Put the output somewhere else:

  ```bash
  sudo env OUT=/var/tmp/wd2l-lab lab/run-lab.sh
  ```

  Or, on a throwaway lab VM only, set SELinux to permissive for the run (`sudo setenforce 0`, then
  `sudo setenforce 1` afterward).
