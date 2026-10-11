# Handoff: AlmaLinux 10 deployment → Ansible roles → bug fixes → docs rewrite

Branch `alma10-deploy-notes`. Written 2026-10-10 at the end of a session that deployed the signed
v0.3.0rc3 release on the user's Raspberry Pi 5 (AlmaLinux 10.2) and noted everything that got in
the way. Start a new session here.

## What is on this branch

| File | What |
|---|---|
| [notes.md](notes.md) | Every finding, with a proposed fix and what an Ansible role has to do about it. **Read this first** |
| [pi5-config/](pi5-config/) | The exact files now deployed on the Pi, named by path (`etc_wd2l_sender.env` = `/etc/wd2l/sender.env`), plus `selinux-local-changes.txt` |
| [splunk-on-docker-desktop.sh](splunk-on-docker-desktop.sh) | How the demo SIEM was set up on the PC, step by step (no secrets) |
| [plan.md](plan.md) | The approved plan from that session. Parts A–C: deployment, notes, docs rewrite |

## State of the world

**The Pi** (`ssh pi5`, user `taylorb`, passwordless sudo, 192.168.1.120): all of these are
active and healthy:

* the three el10 RPMs, 0.3.0~rc3;
* sender and receiver on the same box, with a veth pair `wd2l-tx` ↔ `wd2l-cap` standing in for
  the tap and fiber;
* rsyslog feeding the sender (the box's own syslog crosses);
* the receiver sending to Splunk on the PC.

Workarounds in place, all in `pi5-config/`:

* the egress nft drop-in;
* a fixed copy of `capture-nic.sh` with a drop-in;
* the sender's own audit directory, plus a seal drop-in;
* `--chrony-addr` in both env files;
* the SELinux fcontext for `/var/lib/wd2l/pcap` and the port label for 10070;
* merged auditd rules.

**SSH needs the key in an agent first.** The user runs this in Git Bash; it asks for the
passphrase:

```bash
eval "$(ssh-agent -a ~/.ssh/pi5-agent.sock)"; ssh-add -t 8h ~/.ssh/id_ed25519
```

`~/.ssh/config` has `Host pi5` with `IdentityAgent ~/.ssh/pi5-agent.sock`. Use
`ssh -o BatchMode=yes pi5 '…'`. Don't nest heredocs inside the ssh string; pipe files in on
stdin instead.

**Splunk** (the user's PC, Docker Desktop):

* the container is `wd2l-splunk` (10.6.0.5, Enterprise trial from 2026-10-10, so it expires about
  2026-12-09);
* the UI is http://127.0.0.1:8000 (`admin`; the password is in
  `~/wd2l-splunk/secrets/splunk-admin-password`);
* HEC is `https://192.168.1.27:8088`;
* `~/wd2l-splunk/` also holds the local CA, the tokens and the app;
* `~/wd2l-splunk/q.sh '<SPL>'` runs a search and prints CSV.

**Release checks done on the Pi** (`~/wd2l-rc3/`): all passed (notes A1-6), and a tampered file
was refused three ways (A1-7).

## To do, in order

1. **Ansible roles for the sender and receiver (next).** See below.
2. **Bug fixes in the package** (notes: A2-2, A2-3, A2-4, A2-5, A6-1, A6-6, A6-7, then A2-6 and
   A0-1 for containers). Each one gets a test, aimed at 0.3.0 (or rc4).
   * These can go first, as step 0 of the Ansible session, so the roles carry no workarounds.
     Otherwise the roles carry the workarounds behind a version check. Ask the user.
3. **Finish the deployment checks.**
   * The reboot test: the clean-stop half was done on 2026-10-11 ([notes.md](notes.md#reboot-test-2026-10-11)).
   * If the start half isn't recorded there, the Pi may still have `wd2l-sender` **disabled**, and
     the three alerts **muted** in Splunk: "WD2L - Heartbeat stale", "WD2L - Receiver silent" and
     "WD2L - Fault segment".
   * Then container mode, once there is an arm64 image.
4. **Docs rewrite** (the user's original goals, [plan.md](plan.md) Part C):
   * streamline the install;
   * the README shows the supply chain (two vulnerability scanners, SBOMs, signing, SLSA L3
     provenance, reproducible builds, verified base images, immutable releases, weekly rescan,
     rulesets) as a secondary example, below the main purpose, with *why each matters*;
   * cut the user docs by ≥ 30%: 58,439 words → ≤ 40,900, counted with
     `git ls-files '*.md' | grep -v '^docs/superpowers/' | xargs wc -w`;
   * delete `docs/superpowers/plans/`, this directory included, once the roles and fixes have
     used it.
5. **Housekeeping, with the user's OK:**
   * delete the stale draft releases v0.3.0rc1 and rc2;
   * the repo is public, rc3 is published, and immutable releases are on.

## Brief for the Ansible roles

Every row of [notes.md](notes.md) has an **Ansible** column; together they are the requirements.
In short:

* **Roles.**
  * `wd2l_release`: fetch and verify on the controller or a transfer host, and copy only verified
    files to the targets. `cosign.pub` is pinned in the role, never taken from the release.
  * `wd2l_sender`, `wd2l_receiver`: the RPM, the env files from variables, the units, the auditd
    rules, the seal timer, and the SELinux pieces.
  * Optional: `wd2l_rsyslog` (the aggregator stand-in) and `wd2l_splunk_app` (the app, the tokens,
    the dashboard).
* **A single-box mode,** like the Pi:
  * the veth pair;
  * the sender's audit directory and its seal drop-in;
  * merged audit rules.
* **Variables** are only the options a site changes:
  * the NICs, addresses and port;
  * the HEC URL;
  * the token sources (Ansible Vault);
  * the CA file;
  * the release version;
  * the `hi/cosign` digest.
* **Restarts follow planned-downtime.md.**
  * Stop: the aggregator, then the sender, then the receiver.
  * Start: the capture and receiver, then the sender, then the aggregator.
  * Restarting `wd2l-egress-nic` restarts the sender.
* **Tags for clean stop, start, restart and patching (a requirement from the user).** The tags
  are `wd2l_stop`, `wd2l_start`, `wd2l_restart` and `wd2l_patch`. They're tagged `never`, so a
  normal run doesn't touch running services, and they run the runbook's checks as they go. The
  steps are in [notes.md](notes.md#requirement-from-the-user-startstoprestart-tags).
* **Verify tasks**, as the session did by hand:
  * `rpm -V` as root;
  * `nft list table netdev wd2l_notx` (the capture NIC's egress drop) and `inet wd2l`;
  * the static ARP entry is `PERMANENT`;
  * a pcap file is being written;
  * no new `AVC` lines in `/var/log/audit/audit.log`;
  * HEC `/services/collector/health` with the CA;
  * `wd2l.audit verify` on each audit directory;
  * in the SIEM: `fault_status=ok`, `gap_events=0`.
* **Decisions for the user:**
  * where the roles live (`deploy/ansible/` in this repo keeps them in step with releases);
  * which Ansible version, and which collections (`ansible.posix`, `community.general` for
    `sefcontext`/`seport`);
  * how to test: Molecule, or the Pi itself;
  * whether the bug fixes go first (to-do 2).
