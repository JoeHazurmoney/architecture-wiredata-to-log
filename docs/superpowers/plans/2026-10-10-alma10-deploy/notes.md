# AlmaLinux 10 deployment notes (v0.3.0rc3, single box)

Notes kept while deploying the signed v0.3.0rc3 release on a Raspberry Pi 5 running AlmaLinux 10,
with Splunk on the user's PC. Each entry says what happened and what to change. They feed three
pieces of work: the Ansible roles, the bug fixes, and the docs rewrite (see [README.md](README.md)).

Types: `doc-wrong` · `doc-unclear` · `doc-redundant` · `missing-automation` · `bug` · `works`

The **Ansible** column says what a role has to do about each entry (empty = nothing).

## Found while planning (before touching the box)

| # | Where | Type | What | Proposed fix | Ansible |
|---|---|---|---|---|---|
| P1 | running-the-lab.md §3 | doc-wrong | Clones `-b architecture-wd2l`, a branch that no longer exists | Clone `main` (or the release tag) | |
| P2 | running-the-lab.md §4 | doc-wrong | Says `143 passed`; README says 381 | Drop the exact number, or keep one in README only | |
| P3 | running-the-lab.md §3 | doc-wrong | "If the repository is private…": it's public now | Delete | |
| P4 | releasing.md, containers.md, release notes (`notes.py`) | doc-redundant | Verify commands appear three times | One home (releasing.md); others link | |
| P5 | log-server.md, receiver.md | doc-redundant | Full options tables duplicate `--help` | Keep only options a site changes | Role variables = exactly those options |
| P6 | log-server.md, receiver.md | doc-redundant | "Audit files" sections near-identical | One shared section | One shared task file |
| P7 | log-server.md, receiver.md | doc-redundant | "Moving a manual install to the RPMs" + "manual install" appendix: only pre-0.3 hosts | Drop; wheel/pip covers no-RPM installs | RPM only |
| P8 | log-server.md §4 | doc-redundant | "Upgrading from before the fixed source port": pre-0.3 only | Drop | |
| P9 | receiver.md §5 (×2), operations.md, state-of-health.md | doc-redundant | Ten alerts listed 4 times | List once (operations.md) | |
| P10 | wd2l/audit.py:362 | bug / doc-unclear | Sender + receiver on one host can't share `/var/log/wd2l`: exclusive `flock` on `.lock` | Single-box profile: separate audit dir for the sender + second seal instance | Single-box mode: sender `--audit-dir /var/log/wd2l/sender` + seal drop-in |
| P11 | log-server.md §5 | missing-automation | rsyslog named as a possible aggregator, but no template given; it can't send the `authToken` header line | Ship an rsyslog JSON-lines example (done: `pi5-config/etc_rsyslog.d_90-wd2l.conf`); say `--auth-token-file` is optional | Optional rsyslog aggregator task |
| P12 | receiver.md §5 | doc-unclear | Receiver checks the HEC cert's hostname (`wd2l/outputs.py:283`); Splunk's default self-signed cert won't pass | Say so; show how to make a cert whose SAN matches `--hec-url` (recipe in `splunk-on-docker-desktop.sh`) | CA file is a required variable |

## On the box

Box: Raspberry Pi 5, AlmaLinux 10.2, kernel 6.12.96 (RPi build), **aarch64**, 4 CPU, 7.8 GB,
SELinux enforcing, firewalld on, `nftables.service` off. Splunk runs on the PC (Docker Desktop),
192.168.1.27; the Pi is 192.168.1.120.

| # | Step | Type | What happened | Proposed fix | Ansible |
|---|---|---|---|---|---|
| A0-1 | preflight | missing-automation | Pi is aarch64. The wd2l image (`ghcr.io/joehazurmoney/wd2l`) is amd64 only, and so is `splunk/splunk`. The RPMs are noarch and fine; the Hardened Images bases and `hi/cosign` are multi-arch | Build the image for arm64 too (GitHub's `ubuntu-24.04-arm` runners are free for public repos). Until then, say "amd64 only" in containers.md | Container mode: assert `ansible_architecture == x86_64` until arm64 ships |
| A0-2 | preflight | doc-unclear | No FIPS on the Raspberry Pi kernel (`/proc/sys/crypto/fips_enabled` absent); EL10 also dropped `fips-mode-setup` | No change beyond not naming `fips-mode-setup` | Report FIPS state; don't fail on it |
| A0-3 | preflight | doc-unclear | `tcpdump` not installed by default; `gh` happened to be present | Fine: the receiver RPM pulls tcpdump in. List prerequisites in one place | Preflight: kernel ≥ 5.16, SELinux, chronyd on :323 |
| A1-1 | bring in | doc-unclear | releasing.md says "carry in the release's assets" but gives no download command | `gh release download v<version> -R JoeHazurmoney/architecture-wiredata-to-log` (or a curl loop) | Fetch on the controller (or a "transfer host"), verify there, copy only verified files to targets |
| A1-2 | bring in | doc-unclear | "cosign.pub from a trusted channel": no command | `curl -fsSLO https://raw.githubusercontent.com/<repo>/v<version>/cosign.pub`, then `cmp` with the attached copy | `cosign.pub` comes from the role's own files (pinned), never from the release |
| A1-3 | bring in | doc-wrong | Running cosign from `hi/cosign` with a plain `podman run -v $PWD:/w:Z` fails: `permission denied` on `wd2l-oci/blobs` (rootless podman, image runs as 65532) | Give the working function: `cosign() { podman run --rm --network none --userns=keep-id --user "$(id -u):$(id -g)" --security-opt label=disable --tmpfs /tmp:rw,mode=1777 -e HOME=/tmp -v "$PWD":/w -w /w registry.access.redhat.com/hi/cosign@sha256:9d892a27d5ecc4235ce101798ea6d9f5f46221eb7447e309793db1c2450e384e "$@"; }` (same flags as `packaging/ci/tool`; that digest is a multi-arch index) | Same flags |
| A1-4 | bring in | doc-unclear | `cosign verify --insecure-ignore-tlog` prints "Existence of the claims in the transparency log was verified offline", which reads like a contradiction | One sentence: cosign prints that line regardless; the key check is the one that counts | |
| A1-5 | bring in | doc-unclear | `gh release verify v0.3.0rc3` → "no attestations": rc3 was published before immutable releases were on | releasing.md: "from 0.3.0 on" | Run it only for versions ≥ 0.3.0 |
| A1-6 | bring in | works | All checks pass: `verify-blob`, `sha256sum -c` 17/17, image signature, provenance (commit `ba343f2`, wheel and both bases by digest), `gh attestation verify` offline 17/17 | — | |
| A1-7 | bring in | doc (why it matters) | Negative test: one byte changed in an RPM copy → `sha256sum` FAILED, `gh attestation verify` refused, `rpm -K` "DIGESTS NOT OK" | Put this 3-line demonstration in releasing.md; it shows *why* in seconds | Molecule/verify test: a tampered file must fail the play |
| A1-8 | bring in | missing-automation | ~10 commands across two doc sections to verify a release | One `verify-release.sh` (taken from the repo at the tag, like cosign.pub, never from the release itself) that runs every check offline and prints a table | The role can call it, or do the same checks itself |
| A3-1 | RPM install | works | `dnf install` of the three el10 RPMs: clean; tcpdump pulled in; `rmem_max` set to 64 MiB; nothing enabled | — | |
| A3-2 | RPM install | doc-wrong | `rpm -V wd2l wd2l-sender` "prints nothing" — only with `sudo`; as a user it prints `missing … (Permission denied)` for `/etc/wd2l/*` | `sudo rpm -V …` in both guides | Verify step runs `rpm -V` as root |
| A3-3 | RPM install | works (harmless) | `%sysctl_apply` printed "Couldn't write '0' to kernel/yama/ptrace_scope" — RPi kernel has no Yama | No change | |
| A2-1 | single box | doc-unclear | Both roles' auditd rules install as `/etc/audit/rules.d/wd2l.rules`; on one box they collide, and duplicate watches make auditctl stop | Single-box profile: merge with `awk '/^#/ \|\| !seen[$0]++'` | Single-box mode: merged rules file |
| A2-2 | firewall | doc-wrong / missing-automation | log-server.md §3 says include the nft file from `/etc/sysconfig/nftables.conf`, i.e. enable `nftables.service`, whose stop/reload run `nft flush ruleset` and wipe firewalld's tables too (firewalld is on by default). Also a manual copy + edit of the interface name | `egress-nic.sh` loads the table itself, like `capture-nic.sh` does: template with the NIC from `egress.env`, `destroy table …` first so it is idempotent. Removes the whole manual step | Until fixed: template `/etc/wd2l/nftables-wd2l.nft` + `ExecStartPost=` drop-in (`pi5-config/…nftables.conf`). Never enable `nftables.service` |
| A2-3 | capture NIC | **bug** | `capture-nic.sh` exits 1 silently under `set -euo pipefail` when the NIC doesn't support `ethtool -g` (veth, many USB/virtual NICs): `max=$(ethtool -g … \| awk …)` | `… ) \|\| true`; add a test | Until fixed: fixed copy + drop-in (`pi5-config/…ring-probe-fix.conf`) |
| A2-4 | capture NIC | **bug (security)** | The egress-hook probe is a one-line nft table (`… policy drop; } }`), a syntax error on nft 1.1.x. So on RHEL 10 the script always says "kernel has no netdev egress hook" and silently skips the capture NIC's egress drop | Probe with `}; }` (or the same multi-line text it loads); print nft's error instead of guessing the cause; add a test that runs `nft -c` on the generated text when nft is present | Until fixed: same fixed copy. Verify task: `nft list table netdev wd2l_notx` must succeed |
| A2-5 | capture archive | **bug (major)** | SELinux (enforcing) denies tcpdump, which systemd starts in `netutils_t`, writing `/var/lib/wd2l/pcap` (`var_lib_t`): `avc: denied { write } … tclass=dir`. The archive is never written on an enforcing RHEL host, so "replay after an outage" can't work. The lab misses it: it runs tcpdump from a shell (no domain transition). `netutils_t` can only write `netutils_tmp_t` | Receiver RPM labels the archive: `semanage fcontext -a -t netutils_tmp_t '/var/lib/wd2l/pcap(/.*)?'` + `restorecon` (or a CIL `filecon` module loaded with `semodule`, which needs no extra tools). Gives tcpdump no new rights. Applied on the Pi; works | `community.general.sefcontext` + restorecon, until the RPM does it |
| A2-6 | capture archive / containers | bug (containers) | The Quadlet unit mounts `/var/lib/wd2l:z`, which would relabel `pcap/` to `container_file_t` and break host tcpdump again (the open "`:z` vs tcpdump" item in containers.md) | Mount `pcap/` separately (read-only, no relabel) or keep the archive outside `/var/lib/wd2l`; the receiver only needs to read it | Container mode blocked on this |
| A2-7 | troubleshooting | doc-unclear | `ausearch -m avc -ts recent` found nothing; `sudo grep AVC /var/log/audit/audit.log` showed 73 denials | Troubleshooting tip: grep the audit log directly | Verify task: no new `AVC` lines after the play |
| A4-1 | aggregator | works / missing-automation | rsyslog 8.2510 as the aggregator stand-in: JSON-lines template, disk-assisted queue, `omfwd` TCP to 127.0.0.1:10070. Needs `semanage port -a -t syslogd_port_t -p tcp 10070` (rsyslogd may only connect to syslog ports). The box's own syslog crosses into `index=enclave1` with host, source, time, `wd2l_stream`, `wd2l_seq` | Ship the config as an example | Optional `wd2l_rsyslog` task: template + port label |
| A4-2 | aggregator | works | `systemctl stop rsyslog` is a correct "hold the aggregator" for planned downtime: the queue is saved on shutdown and imjournal resumes from its saved position. 94 held events drained, none lost | One line in planned-downtime.md for rsyslog | Handler order: stop rsyslog → sender → receiver; start receiver → sender → rsyslog |
| A5-1 | SIEM | doc-unclear | HEC TLS: the cert must have a SAN matching `--hec-url` (IP or name). Docs only say "SIEM CA bundle" | openssl recipe (see `splunk-on-docker-desktop.sh`) | |
| A5-2 | SIEM | doc-unclear | The repo's Splunk files work, but: `inputs.conf` needs a `serverCert` line; the token placeholders need replacing; without `app.conf` and `metadata/local.meta` (`export = system`) the JSON field extraction only works inside the app | Ship `default/app.conf` and `metadata/default.meta` in `deploy/receiver/splunk/`, as a real app | Optional `wd2l_splunk_app` role |
| A5-3 | SIEM | doc-unclear | Splunk Free turns off alerts and roles, which wd2l's alerts and `wd2l_auditor` need. Used the Enterprise trial (60 days) | One line in receiver.md | |
| A5-4 | SIEM | works | Token separation: the audit token is refused for `index=enclave1` ("Incorrect index"); the main token can't write `wd2l_audit` | — | Verify task |
| A5-5 | SIEM | doc-unclear | Dashboard import: Dashboard Studio JSON must be wrapped as `<dashboard version="2"><definition><![CDATA[…]]></definition></dashboard>` (REST `data/ui/views`) | One line, or ship the wrapped XML | |
| A6-1 | time quality | **bug (audit noise)** | Native units run `chronyc` under `NoNewPrivileges=yes`; SELinux denies the move into `chronyc_t` (`nnp_transition`), so chronyc runs in the caller's domain and every check writes an AVC denial to the audit log (works, but noisy, and SIEMs alert on AVCs) | Native `sender.env`/`receiver.env` default to `--chrony-addr 127.0.0.1:323`, like the containers: no exec, no transition, one method for both. Verified: 0 AVCs after the change | Template both env files with `--chrony-addr` |
| A6-2 | planned downtime | works | Full procedure, both sides: `stream_end` (last_seq 45, `shutdown_unread_bytes` 0), no gap, `boot 2 after stream …`, `stream_start`, backlog drained, `state_loaded` + `config_changed` in the audit index | — | The handlers should follow it |
| A6-3 | planned downtime | doc-unclear | (a) the JSON-escaped grep for the `final:` line is awkward; (b) `state_reset` is normal on the very first start (doc only says "state file lost"); (c) rule 11 (archive not written) flashes amber while the receiver is up and the sender stopped | Small doc fixes; consider not raising rule 11 while there is no heartbeat | |
| A6-4 | SIEM | bug (cosmetic) | In `index=wd2l_audit` searches `host` is multivalue (`pi5 pi5`): the JSON body's `host` plus Splunk's indexed host | Check the HEC payload / props (e.g. drop `host` from the event body, or a field alias) | |
| A6-5 | fault: carrier | works | Carrier loss on the capture NIC → "red in boundary (rule 1): capture NIC has no carrier" within ~1 s; after recovery an exact `GAP … seq 298-316 (19 events, not_received)`; sender unaffected (`send_errors` 0) | — | |
| A6-6 | fault: NIC admin down | **bug** | Receiver crashes when the capture NIC goes admin-down: unhandled `OSError: [Errno 100] Network is down` at `wd2l/packets.py:180` (`recvfrom`). systemd restarts it every ~3 s; rule 1 never fires; a flapping NIC could hit the start limit and leave it dead | Catch `ENETDOWN` in the capture loop, report the capture NIC down, keep going (the AF_PACKET socket resumes on NETDEV_UP). Unit test with a socket that raises it | |
| A6-7 | fault: egress admin down | **bug (robustness)** | Admin down/up of the egress NIC (or a driver reset) **flushes the PERMANENT static ARP entry** and nothing puts it back; the sender then can't reach the black hole (ARP is blocked by design) until `systemctl restart wd2l-egress-nic`. Carrier loss keeps the entry (tested on a dummy NIC). Detected (heartbeat stale, rule 3) but not self-healing | Re-assert the neighbor (idempotent `ip neigh replace`) on link-up or from a 1-minute timer, and/or the sender reports a missing neighbor entry in its heartbeat | A timer or `nmcli`-free udev hook until fixed |
| A6-8 | units | doc-unclear | Restarting `wd2l-egress-nic` restarts the sender (`Requires=`) | One line in log-server.md | Handler ordering |
| A6-9 | audit | works | `wd2l.audit verify` and `wd2l-audit-report verify`: both directories `result ok` (19 and 13 records). Seal: both files `+a`; root's truncate refused. Single-box needs the seal drop-in for the second directory | — | Verify task |

## Reboot test (2026-10-11)

A clean stop before a reboot, the full both-sides procedure in planned-downtime.md. The baseline
after about 12 h: `last_seq` 1878, health ok, **no new AVCs overnight** (A6-1's fix holds).

| # | Step | Type | What happened | Proposed fix | Ansible |
|---|---|---|---|---|---|
| R-1 | before you start | doc-unclear / missing-automation | Muting the three alerts is UI-only in the runbook. Over REST it is one call each: `POST /servicesNS/nobody/wd2l/saved/searches/<name> -d disabled=1` (and `0` afterwards) | Give the REST call (or a 5-line script) next to the UI steps | Optional `wd2l_siem_mute` / `wd2l_siem_unmute` tasks, run by the stop/start tags |
| R-2 | step 1 | doc-wrong | The runbook says the egress NIC shows "only ~1 packet per second: heartbeats". It shows **2 per second**: one heartbeat per stream (the events stream, and the sender's records stream; 688 and 172 bytes) | "about 2 packets per second (one heartbeat per stream)" | Verify task: no packet bigger than a heartbeat for 5 s |
| R-3 | step 1 | works | Holding rsyslog = `systemctl stop rsyslog`; `ss` shows no connection on :10070. On a reboot rsyslog starts again at boot and still holds: the sender is disabled, so its disk-assisted queue fills until the sender is back | One line in the runbook for rsyslog | The hold/release is a per-aggregator hook (rsyslog: stop/start the service) |
| R-4 | step 2 | doc-unclear | The `final:` line in JSON logs comes out escaped (`\"shutdown_unread_bytes\": 0`) and gets cut off on narrow terminals. `journalctl -o json` and a short JSON decode prints it readably | Have the sender also log the final counters as plain `key=value`, or give the decode one-liner | Parse `shutdown_unread_bytes` and fail the stop if it isn't 0 |
| R-5 | steps 2–4 | works | `final: last_seq=1896`, `events_in` = `events_sent` = 1896, `shutdown_unread_bytes` 0. Splunk: `stream_end` for both streams, no `gap`. The receiver logged amber `e1-sender` rule 2 at stop, as documented. Spool 0, state files saved, `wd2l-sender` disabled for the reboot | — | These are the stop tag's checks |
| R-6 | step 6, after the reboot | works | Everything came back on its own: all units active, nothing failed; the veth pair; the capture NIC `UP,PROMISC,NOARP`, no address, `wd2l_notx` loaded (fixed-script drop-in); the egress address, the `PERMANENT` ARP entry, `inet wd2l` (nft drop-in); NetworkManager leaves both NICs `unmanaged`; the pcap label `netutils_tmp_t` kept, a new pcap written; the receiver `loaded state for 6 streams`, no "not confirmed" warning, and it still knew the sender had stopped cleanly (amber rule 2, not red). **No AVCs since boot** | — | The start tag's checks |
| R-7 | step 9 | doc-unclear | With rsyslog, the hold ends by itself at boot: rsyslog starts and retries every 5 s, so the drain begins the moment the sender listens, before step 8's "heartbeats arrive" check. I stopped rsyslog again before starting the sender to keep the order | Runbook: "if the aggregator came back at boot, hold it again before step 7" | Start tag: make sure the aggregator is held before the sender starts; release it only after the heartbeat check |
| R-8 | step 6 | **bug (alert noise)** | A **time alarm at every boot**: the receiver started at 13:09:07, read chrony at 13:09:08 (not synced yet) → `time_status=alarm`; chrony picked a source at 13:09:11; next check 13:10:08 → `ok`. "WD2L - Time quality" would fire after every patch reboot | Order the units after `time-sync.target` (`Wants=`/`After=`) and enable `chrony-wait.service` (ships with chrony), or give chrony a grace period after boot before alarming | Enable `chrony-wait.service`; check `time_status=ok` before unmuting |
| R-9 | step 10 | works | Run linked across the reboot: `boot 4 after stream 007c… (last seq 1896)`. No `gap`, `stream_lost`, `stream_missing` or `sender_boot_reset`. The held boot logs crossed: new run seq 1–1787 contiguous, first event 13:08:54 (kernel boot), longest backlog delay 1048 s. **Every journal entry crossed exactly once** (journal: 1836 entries to 13:27:28; stream at seq 1835 for the 13:27:27 line). Lines that repeat in the SIEM repeat in the kernel log too (e.g. "xHCI Host Controller" ×2, checked against `journalctl`). Audit index: stop, stop, start + `state_loaded`, start + `state_loaded`; no `state_reset` | — | The start tag's checks |
| R-10 | step 9 | works (harmless) | rsyslog left its disk-queue files (`wd2l_fwd.00000003`, `.qi`) after the drain until its next restart, which removed them **without** re-sending anything | — | |

## Requirement from the user: start/stop/restart tags

The Ansible roles need **tags for clean start, stop and restart**, so downtime and patching are
one command. They follow planned-downtime.md, across hosts and in order:

* **Stop** (`wd2l_stop`):
  1. Optionally mute the three SIEM alerts (R-1).
  2. Hold the aggregator (a hook; rsyslog = stop the service).
  3. Check the sender's input is quiet.
  4. Stop the sender, and check `shutdown_unread_bytes` is 0 (R-4). Disable it if the receiver
     side is going down too.
  5. Optionally check `stream_end` with no `gap` in the SIEM.
  6. Stop the receiver, and the capture if the host is going down.
* **Start** (`wd2l_start`), the other way round:
  1. The capture NIC, the capture and the receiver, then check them: `wd2l_notx` loaded, a new
     pcap file, `loaded state`, no "not confirmed" warning.
  2. Check the egress NIC: the `PERMANENT` ARP entry and `inet wd2l`.
  3. Enable and start the sender, and check `boot N after stream …`.
  4. Wait for heartbeats.
  5. Release the aggregator.
  6. Check: no `gap`, `stream_lost`, `stream_missing` or `sender_boot_reset`.
  7. Unmute the alerts.
* **Restart** (`wd2l_restart`): stop, then start.
* **Patching** (e.g. `wd2l_patch`): stop, `dnf upgrade`, reboot if needed, start. The variants in
  the runbook's "Shorter variants" table (log server only, receiver host only, link work) become
  variables or separate tags.

Use `tags: [never, wd2l_stop]` and so on, so a normal run never stops anything. Cross-host order
comes from separate plays: sender hosts first for a stop, receiver hosts first for a start.

## Not done yet

* **Container mode (Quadlet)**: blocked on the Pi by A0-1 (no arm64 image) and A2-6.
* **Re-send from Enclave 1** for the 110 events lost in the fault tests: optional demo of
  operations.md "Re-sending from Enclave 1" (no retention server here; the journal is the source).
