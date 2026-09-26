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

These run without root and take about 25 seconds. You should see `90 passed`.

## 5. Run the lab

Each run takes about 15–20 seconds and cleans up after itself.

```bash
sudo lab/run-lab.sh                             # clean run
sudo lab/run-lab.sh --loss 1                    # drop 1% of packets on the "cable"
sudo lab/run-lab.sh --receiver-outage           # stop the receiver mid-run, then replay the archive
sudo lab/run-lab.sh --receiver-crash            # kill the receiver mid-run, then replay the archive
sudo lab/run-lab.sh --events 25000 --eps 5000   # more logs, faster
```

A successful run ends like this:

```
sent:            5001
received:        5001
gaps (reported): 0
...
PASS: every event arrived intact or is accounted for in a reported gap
```

What each run proves:

| Run | What should happen |
|---|---|
| Clean | Every log arrives byte-for-byte identical. One 300 KB log arrives cut down and flagged. |
| `--loss 1` | Some logs are lost, and every one is reported by number. PASS means nothing went missing unreported and nothing was falsely reported as missing. |
| `--receiver-outage` | The receiver misses about 2 seconds of logs, then replay from the packet archive fills them in with no duplicates. |
| `--receiver-crash` | Same, but the receiver is killed with no chance to clean up. Nothing is lost; some logs arrive twice (the `duplicates` line), which is allowed here because they are identical and carry the same sequence number. |

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
