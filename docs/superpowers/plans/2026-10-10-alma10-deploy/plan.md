# Plan: deploy wd2l on AlmaLinux 10, take notes, then streamline the docs

## Context

The user wants to run wd2l for real on their AlmaLinux 10 box. The repo's install path is spread
across `releasing.md` → `deployment/{network,log-server,retention-server,receiver,containers}.md`
→ `operations.md`, with a lot of cross-linking, so it is hard to follow. While deploying we keep notes
on every point of friction, and those notes drive a docs rewrite with three goals:

1. **Streamline install and configuration**, informed by what actually happened on the box.
2. **The README shows the supply-chain work as a secondary example**, below the main purpose
   (one-way log transfer). That work covers two vulnerability scanners, SBOMs, signing, SLSA L3
   provenance, reproducible builds, verified base images, immutable releases and a weekly rescan.
   For each one, say *why it matters*.
3. **Cut user-facing docs by ≥30%** with nothing lost from what each doc is for.

Decisions made (by the user):

* **Single-box install.** The release is real, and a veth pair stands in for the tap and fiber.
* **I drive the box over SSH** from this PC, with approval for each command.
* **The SIEM is a Splunk container** on the box.
* **Delete `docs/superpowers/plans/`** (90k words, finished plans that stay in git history), and
  separately cut the user docs by 30%.

Facts gathered:

* The repo is now **public**. `v0.3.0rc3` is a published pre-release (immutable releases were
  switched on after it). Stale drafts rc1 and rc2 are still there.
* The version is `0.3.0rc3` on `main`; the `.container` files pin `ghcr.io/joehazurmoney/wd2l:0.3.0rc3`.
* Baseline for user docs (`git ls-files '*.md' | grep -v '^docs/superpowers/' | xargs wc -w`):
  **58,439 words → target ≤ 40,900.**

## Part A: Deploy v0.3.0rc3 on AlmaLinux 10 (one box)

Work runs over `ssh alma10 …`. Before each step I post a short note on what it does and why.
Every surprise goes into the notes file (Part B).

**A0. Access and preflight.** The user gives me the host, the user, and a sudo-capable account.
I add `Host alma10` to `~/.ssh/config`. One read-only preflight follows:

* `/etc/os-release`, `uname -r` (expect 6.12), `nproc`, `free -g`, `df -h`;
* `getenforce`, `fips-mode-setup --check`;
* `ip -br link`, `systemctl is-active firewalld chronyd auditd`, the `podman --version`.

Splunk needs about 4 GB RAM and 20 GB of disk.

**A1. Bring the release in "as an enclave would"** (the supply-chain demo, step by step):

* Install the tools: `dnf install jq skopeo podman`, `gh` from the cli.github.com repo, and
  cosign (a `podman save` of `registry.access.redhat.com/hi/cosign`, or the release binary).
* `gh release download v0.3.0rc3` into `~/wd2l-rc3/`, plus
  `gh attestation trusted-root > trusted_root.jsonl`.
* Run the checks in `docs/releasing.md`:
  * `cosign verify-blob`, `sha256sum -c`;
  * `cosign verify` and `verify-attestation` on the OCI tar;
  * the `gh attestation verify` loop over SHA256SUMS, offline (`--bundle`,
    `--custom-trusted-root`).
* Try `gh release verify v0.3.0rc3`. It is expected to fail, because rc3 predates immutable
  releases. Note it.
* Run one **negative test**: change one byte in a copy of an RPM and show that `sha256sum -c` and
  `gh attestation verify` refuse it. This is the "why it matters" in action.

**A2. Single-box topology.** Two stand-ins replace the physical parts:

* A veth pair `wd2l-tx` ↔ `wd2l-cap` replaces the tap and fiber. It comes from a small oneshot
  unit, `/etc/systemd/system/wd2l-veth.service`, ordered before `wd2l-egress-nic` and
  `wd2l-capture-nic`.
* The env files name those NICs:
  * `egress.env`: `IFACE=wd2l-tx`;
  * `capture.env`: `IFACE=wd2l-cap`;
  * `--egress-iface` and `--live` follow.

Known conflict, found while planning: the audit log takes an exclusive `flock` on
`<audit-dir>/.lock` (`wd2l/audit.py:362`), so the sender and receiver can't share
`/var/log/wd2l`. So:

* the sender gets `--audit-dir /var/log/wd2l/sender` (2750 wd2l:wd2l-audit);
* a second seal timer covers that directory: a drop-in with `WD2L_AUDIT_DIR`, or a templated
  instance (`deploy/common/wd2l-audit-seal.sh` uses `maxdepth 1`).

**A3. Native install from the RPMs** (`log-server.md` §1–4, `receiver.md` §1–4):

* `dnf install` wd2l, wd2l-sender and wd2l-receiver (el10).
* Edit `sender.env`, `receiver.env`, `egress.env` and `capture.env`.
* Enable these units: `wd2l-egress-nic`, `wd2l-capture-nic`, `wd2l-capture`,
  `wd2l-pcap-prune.timer` and `wd2l-audit-seal.timer`.
* Load the auditd rules for both roles and the nftables file (check how it coexists with
  firewalld).

**A4. Aggregator stand-in.** rsyslog, already on the box, sends the box's own logs to
`127.0.0.1:10070`:

* `omfwd` over TCP with a JSON-lines template: `_raw`, `_time` (unix seconds), `host`, `source`,
  `sourcetype`, `index=enclave1`.
* rsyslog can't send the `authToken` header line, so drop `--auth-token-file` from `sender.env`
  for this setup (note it).
* `lab/gen_events.py` is optional, for extra load.

**A5. Splunk container (SIEM).**

* `podman run` with `docker.io/splunk/splunk` (pinned version), using the **Enterprise trial**.
  Splunk Free turns off alerting and roles, which the wd2l alerts and the `wd2l_auditor` role
  need.
* The repo's app files are mounted into `etc/apps/wd2l/local` (`deploy/receiver/splunk/*.conf`),
  with real HEC tokens.
* HEC TLS: the receiver checks the hostname (`wd2l/outputs.py:283`), so make a small local CA and
  a server cert (SAN `127.0.0.1`, `localhost`). Splunk uses it as `[http] serverCert`, and the CA
  goes to `/etc/wd2l/siem-ca.pem`.
* Write the tokens to `/etc/wd2l/hec.token` and `/etc/wd2l/hec-audit.token`.
* Import `wd2l-health-dashboard.json`.
* Run it as a Quadlet unit too, so it survives a reboot.

**A6. Start and verify.**

* Start the capture, the receiver and the sender, in the order of `planned-downtime.md`.
* Run the end-to-end checks in `receiver.md` §6 in Splunk:
  * events for the host;
  * `gap_events` 0 and `fault_status` ok;
  * `audit_ok` true;
  * the sender's health records arrive.
* Run `wd2l-audit-report verify` on both audit directories.
* Inject one fault (`ip link set wd2l-cap down` for 10 s) and watch the dashboard name
  `boundary`, rule 1.

**A7. Switch to the signed container image (Quadlet)**, following `containers.md`:

* Load it from the verified OCI tar with `skopeo copy`.
* Name it by digest in the `.container` files.
* Install the `*-quadlet.rules` files.
* Run the "host that ran natively first" path (`chattr -a`, start, then seal again).

This confirms the open items in its "Still to confirm on RHEL 10" list on a RHEL 10 rebuild:

* the user name resolves;
* `:z` doesn't stop tcpdump writing the archive;
* the env options reach wd2l;
* sealed audit files;
* whether Podman's `sigstoreSigned` policy accepts the cosign 3 bundles.

Run A6's checks again.

## Part B: Notes, kept as we go

**The file:** `.superpowers/notes/2026-10-10-alma10-deploy.md`. It is local and not committed,
and it feeds Part C.

**Each entry:**

* the step;
* what happened;
* the type: `doc-wrong`, `doc-unclear`, `doc-redundant`, `missing-automation` or `bug`;
* the proposed fix.

**Seeded now with what planning found:**

* `running-the-lab.md` is stale:
  * it clones `-b architecture-wd2l`, a branch that is gone;
  * it says "143 passed", but there are 381 tests;
  * it still says "If the repository is private".
* The verify commands appear three times: in `releasing.md`, in `containers.md`, and in the
  release notes generated by `packaging/release/notes.py`.
* `log-server.md` and `receiver.md` each have:
  * a full options table (which duplicates `--help`);
  * an "Audit files" section (the two are near-identical);
  * a "Moving a manual install to the RPMs" section;
  * a "manual install" appendix.

  The last two only apply to pre-0.3 hosts.
* The "fixed source port" upgrade note in `log-server.md` §4 applies to pre-0.3 hosts only.
* The list of ten alerts is repeated in `receiver.md` §5 (twice), in `operations.md` and in
  `state-of-health.md`.
* A sender and a receiver on one host clash on the audit `.lock`.

## Part C: Docs rewrite (branch `docs-streamline` off `main`, one PR)

### C1. Delete `docs/superpowers/plans/`

Fix any links to it. `tests/test_siem_config.py` already skips `superpowers`.

### C2. README: the main purpose stays first

Add one new section after "Deploying": **"Also here: a worked example of a secured software
supply chain."** It is a short intro plus a table with these columns: *practice*, *what this repo
does*, *why it matters*, *where*.

The rows:

* **Two vulnerability scanners** (Grype + Trivy) behind a gate with expiring exceptions. Why: each
  scanner's database and matching miss things the other catches, and exceptions that expire stop
  "accepted forever".
* **SBOMs** (SPDX + CycloneDX), plus an SBOM diff against the base. Why: you can answer "are we
  affected?" without rebuilding, and you can show that nothing slipped in.
* **Verified, pinned, hardened FIPS base.** Its signature, provenance and SBOM are checked
  ([ADR-0004](docs/decisions/0004-container-base-image.md)). Why: you inherit someone else's
  supply chain, so verify it, and keep the attack surface small.
* **Reproducible build.** Why: anyone can rebuild and get the same bits, so a tampered build shows.
* **Signing**: an offline cosign key, plus a keyless signature
  ([ADR-0006](docs/decisions/0006-release-artifacts-and-signing.md)). Why: the enclaves verify
  with no network, and the public verifies against a public log.
* **SLSA Build L3 provenance**, from an isolated `attest.yml`
  ([ADR-0007](docs/decisions/0007-slsa-build-l3.md)). Why: it proves which source, which workflow
  and which runner made each file, and the build steps can't forge it.
* **Immutable releases.** Why: a published tag and its assets can't be swapped later.
* **Weekly rescan, and Dependabot pins.** Why: new CVEs appear after a release ships.
* **Branch and tag rulesets, plus the `release` environment approval.** Why: no single
  compromised account or branch can cause a signature.

The rows point into `docs/releasing.md`, which becomes the detailed home for the topic. The
"why" lives in the README table only (one place per fact).

Also:

* fix the repo map (`docs/` row, `packaging/` row);
* "Deploying" becomes one link to the streamlined guide;
* refresh the test count in "Try it".

### C3. Cut the user docs to ≤ 40,900 words

ADR bodies stay as records (only links are fixed), so the rest shrinks about 36%. The rule is
**one place per fact**.

| Doc (words now) | Change | Rough saving |
|---|---|---|
| `audit-and-health-plan.md` (11.4k) | Becomes the as-built reference: drop §3 (gaps before), §16 (phases) and §17 (open items, which go to `accreditation-notes` if any are still open). Tighten the rest. Rename to `audit-and-health.md`, and update every reference, including section numbers in the code comments (`wd2l/*.py`, `deploy/common/wd2l-audit-seal.sh`, units) | ~6k |
| `wire-format.md` (1.3k) + `interface-description.md` (6.1k) | Merge into `interface-description.md` (the ICD is the superset). Repoint `wd2l/wire.py` and the others | ~2.5k |
| `deployment/*` (7.4k) + `releasing.md` "bringing in" | A streamlined path shaped by the Part B notes. Verify once (`releasing.md`), then each host guide is install → three settings → enable → check. Options tables give way to `--help`, plus only the options a site changes. The two pre-0.3 migration sections and the manual-install appendices are dropped (the wheel covers it). "Audit files" moves to one shared place | ~4k |
| `state-of-health.md` (5.2k) | The 15 scenarios become a compact table. Keep the panel table rows `\| N \| **Title** \|` (`tests/test_dashboard.py`) | ~2k |
| `operations.md` (4.2k), `planned-downtime.md` (2k) | Dedupe the alert list and the replay steps (`containers.md` has a replay copy too) | ~1.5k |
| `running-the-lab.md` (2.2k), `architecture.md` (2.8k), `multiple-files.md`, `accreditation-notes.md` | Fix the stale facts and trim the overlap with the README | ~1.5k |

**Tests that pin doc content (keep them green):**

* `tests/test_dashboard.py`: the panel titles in `state-of-health.md`.
* `tests/test_deploy.py:138`: `containers.md` names both `*-quadlet.rules` paths.
* `tests/test_release_tools.py:176`: `releasing.md` keeps its "GitHub build provenance,
  offline" heading and the pinned strings.
* `tests/test_siem_config.py`: every `"WD2L - …"` alert named in the docs exists.

`packaging/release/notes.py` links to `docs/deployment/{log-server,receiver,containers}.md` and
`releasing.md`: update it (and its tests) if any path moves.

### C4. Repo and code fixes from the notes

Only the ones the deployment proves worthwhile. For example:

* an rsyslog JSON-lines template for the aggregator;
* a `deploy/single-host/` demo profile (the veth unit, plus separate audit directories).

Each goes in its own commit, aimed at 0.3.0 final.

**Housekeeping, with the user's OK at the time:**

* delete the stale draft releases rc1 and rc2;
* update the memory files `slsa-l3-plan-status` and `release-packaging-plan` (the repo is public,
  rc3 is published, immutable releases are on).

## Verification

* **Deployment:**
  * A1's verify commands all pass, and the tampered-file negative test is refused.
  * In Splunk, `index=enclave1` has the box's own syslog.
  * The `wd2l:health` summary shows `gap_events=0`, `fault_status=ok` and `audit_ok=true`.
  * `wd2l-audit-report verify` passes on both audit directories.
  * The injected link-down fault shows as `boundary`/rule 1 on the dashboard, then clears.
  * All of the above repeats after switching to Quadlet, and after a reboot.
* **Docs:**
  * The word count script shows ≤ 40,900.
  * The unit tests pass: the `wd2l-test` and `wd2l-test-312` Docker images, per memory
    `local-docker-testing`.
  * A link check finds no broken links: a grep for `](…md` targets and anchors across the
    markdown.
  * `git grep -n "audit-and-health-plan\|wire-format.md\|superpowers/plans"` finds nothing.
  * The README read top to bottom still leads with the one-way transfer, and the supply-chain
    section reads as a secondary example.
* The CI on the PR (`tests.yml`, `ci-ok`) is green before merge.
