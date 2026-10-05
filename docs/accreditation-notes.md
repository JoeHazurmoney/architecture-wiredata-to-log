# Notes for the accreditation package

Material for a security review of this transfer: the one-way argument, what each side trusts, and
the risks that remain. This is an engineering write-up, not a formal assessment.

## The transfer

* **Direction:** Enclave 1 → Enclave 2 only. Content: log events (text) and heartbeat counters.
* **Sensitivity levels:** see the [README](../README.md).
* **Enclave 1:** central log server (log aggregator + `wd2l-sender`), black-hole switch port, network tap.
  Also in Enclave 1, but off the transfer path: the log retention server, which keeps a 1-year
  copy of everything the aggregator collects and is the source for replaying lost events.
* **Enclave 2:** receiver host (tcpdump + `wd2l-receiver`), SIEM.
* **Link between them:** one fiber strand from the network tap's monitor port TX to the receiver NIC's
  RX. The other strand is not connected.

## Why data can't flow from Enclave 2 to Enclave 1

1. **Physical (the control that matters).** There is no transmit path from Enclave 2. The
   receiver NIC's TX is not connected to anything. This is the same method already accepted for
   another enclave.
2. **Even if the strand were connected**, anything sent from Enclave 2 would reach the tap's **monitor port**.
   A monitor port is an output and isn't bridged to the tap's inline ports. Confirm this for your model
   and configuration.
3. **Receiver host configuration:** capture NIC has no IP address, ARP is off, IPv6 is off,
   nftables drops all egress on that NIC (kernel 5.16+). The receiver process opens a raw socket
   and only reads from it.
4. **Enclave 1** also drops everything arriving on the black-hole port (switch ACLs) and on the log
   server's egress NIC (nftables).

Items 2–4 are defense in depth. The one-way property doesn't depend on them.

**Suggested physical check:** with the fiber disconnected at the tap end, put a light meter on
the strand from the receiver. There should be no light (or better, no strand).

## What Enclave 2 trusts

Nothing that arrives on the wire. The receiver:

* accepts only IPv4/UDP frames to the configured IP and port. Everything else is counted and dropped;
* checks every packet (CRC-32, header fields, size limits) and every rebuilt event (length and
  SHA-256) and parses one fixed JSON shape. Anything else is counted and dropped;
* caps event size (256 KB), memory for part-built events (64 MB), number of tracked streams and gap
  ranges;
* has been fuzz-tested with thousands of random and mutated packets (`tests/`);
* uses only the Python standard library (no third-party packages to review or patch);
* runs as an unprivileged user with only `CAP_NET_RAW`, under systemd sandboxing
  (`ProtectSystem=strict`, `NoNewPrivileges`, restricted address families).

## Integrity and authenticity

* CRC-32 per packet and SHA-256 per event detect **accidental** corruption.
* They don't prove **who** sent the data. Anyone who can put frames on the Enclave 1 cable could
  inject fake log events. Enclave 1 physical and administrative controls on the log server, the
  cable and the network tap cover this today.
* If reviewers want authenticity, add an HMAC-SHA256 per event with a key shared by the sender and
  the receiver. It's a small change to `wd2l/wire.py`. The key would need a managed, one-way
  distribution process.

## Completeness

Every event the sender numbers is either delivered or reported as lost. It's never silently
missing. Shown in the lab with 1% injected loss: every lost event was reported by exact sequence
number, with no false reports. Loss isn't recovered automatically (nothing can come back). The
operator replays the lost time window from the Enclave 1 log retention server
(`docs/operations.md`).

This holds across a receiver crash: an event counts as delivered only once the SIEM accepted it
or it is on disk, so anything in memory at a crash is reported (`reason=receiver_restart`) and
recovered from the pcap archive. The cost is occasional duplicates, which carry the same
`wd2l_stream` / `wd2l_seq` and are removed in searches.

Sender restarts are chained (`boot`, `prev_stream`, `prev_last_seq` in the heartbeat), so a
sender run that never reached Enclave 2 at all is reported as `stream_missing` rather than going
unnoticed.

The one exception: input the log aggregator handed to the sender that the sender had not
numbered yet when it stopped. On a clean stop the sender first reads what is already arriving
(up to 2 seconds) and reports anything left as `shutdown_unread_bytes`. On a crash, up to one TCP
receive buffer (256 KB by default) can be lost without a report. The aggregator's persistent
queue reduces this but can't fully close it, because TCP acknowledges data before the sender
reads it. Those events are still on the log retention server, which gets its own copy from the
aggregator, but no gap record points to them.

## Encrypted or opaque content

Given the direction rule in the [README](../README.md), encrypted content in a log is mainly a
visibility question. [ADR-0002](decisions/0002-opaque-content.md) has the full reasoning.

* **What is detected:** `wd2l-sender` flags events whose text carries a long blob that can't be
  inspected. Blobs are base64, base64url or hex of 256 decoded bytes or more, or a PGP or age
  armor block. Each flagged event is classed by marker or randomness as `encrypted`,
  `compressed` or `high-entropy`.
* **What happens:** flagged events cross unchanged with indexed fields `wd2l_opaque` and
  `wd2l_opaque_bytes`, are counted in heartbeats and health records, and raise a SIEM alert.
  Nothing is dropped.
* **What is not detected:** short random strings (hashes, GUIDs and tokens are normal in logs),
  other encodings (base32, base85), and data hidden in ordinary-looking text (word choice,
  spacing, splitting across events, timing). It's a tripwire for blobs, not proof that nothing
  is hidden.
* **Evidence:** no flags across 17,624 real log lines. All three planted blobs are flagged in the
  lab.
* **Controls:** a content filter in the sense of AC-4(8), with detection for AC-4(15).
  AC-4(4) (Flow Control of Encrypted Information) is High-baseline. If the ISSO tailors it in,
  the ADR's path is to redact the blob or hold the event in Enclave 1.

## Residual risks

| Risk | Notes / mitigation |
|---|---|
| Malicious content inside log text (e.g. strings aimed at analyst tools, log injection) | Same as any log ingest. The SIEM stores it as data. Keep the Enclave 2 SIEM patched. Content filtering beyond the opaque-content flag is out of scope |
| Data hidden inside log text (encrypted, compressed or encoded) | Long blobs are flagged (`wd2l_opaque`) and alerted on, but still cross. Data hidden in normal-looking text isn't detected. Enclave 1 controls on who can write logs, plus per-source volume monitoring |
| Enclave 1 compromise injects fake events | Enclave 1 controls today. Optional HMAC (above) |
| Loss is detected but not recovered | By design (requirement was detect and report). The operator replays the window from the log retention server |
| Log retention server down, full or lost | Not on the transfer path, so the transfer continues. A window missing there can't be replayed later. Its own persistent queue in the aggregator; Enclave 1 monitoring and backups |
| Misconfigured tap filter forwards other Enclave 1 traffic | Enclave 2 still only accepts the log flow and counts everything else (`other_packets` alert). The switch-port isolation means little else is on that cable to begin with |
| Receiver host compromise | It has no path back to Enclave 1. Treat it like any other Enclave 2 server |
| Parser bugs | Small code base, standard library only, fuzz tests. Runs unprivileged and sandboxed |

## If a listed cross-domain solution is required

This design relies on your organization's existing acceptance of the one-strand fiber method. If
approvers require an evaluated or listed cross-domain product for this data flow, a commercial data
diode with a syslog/UDP proxy can replace the tap-to-receiver segment. The sender's wire format
and the receiver's gap reporting still work over such a diode.
