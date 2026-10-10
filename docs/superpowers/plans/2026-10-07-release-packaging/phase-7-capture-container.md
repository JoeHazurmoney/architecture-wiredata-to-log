# Phase 7: the receiver's capture archive in a container (tracked; decided after Phase 0)

Part of the [release packaging plan](README.md). Spec: [spec.md](spec.md) "Phase 7", and
ADR-0004's Action item 1.

**Why this is its own phase:**

* **The archive is the recovery source.** It fills a receiver outage
  ([operations.md](../../../operations.md#replay-from-the-capture-archive)). So it must keep
  running, and stay correct, independently of `wd2l-receiver`.
* **The base has no tcpdump.** Red Hat Hardened Images has no tcpdump or libpcap, so the
  capture image can't be on the same base as wd2l.
* **The decision is your partner's.** That's why it comes after Phase 0, and isn't built by
  default.

**Delivers:**

* Task 7.1 records the decision.
* If it is option (a), Task 7.2 gives the design for its own implementation plan. Write that
  plan with superpowers:writing-plans; it isn't written here, because which packages and
  allowances it needs depends on the first build.

---

### Task 7.1: The decision

**Files:**
- Modify: `docs/decisions/0004-container-base-image.md` (Action item 1), the plan README's
  As-built log

**Interfaces:**
- Consumes: P0-1, which shows whether a non-root user with only `NET_RAW` can capture. If it
  can't, (a) needs a root container with every other capability dropped.
- Produces: the decision row `P7`, and ADR-0004's action item updated.

- [ ] **Step 1: Ask your partner**, with the options exactly as ADR-0004 states them:

  "The capture archive (tcpdump) still runs on the receiver host. Do you want it in a container
  too?
  * **(a)** a tcpdump image on UBI 10 micro (tcpdump and libpcap from UBI 10, RHEL-built), run
    under Quadlet as non-root with `NET_RAW`, through the same signing and image checks.
  * **(b)** ask Project Hummingbird to package libpcap and tcpdump (an upstream contribution;
    their timeline).
  * **(c)** a standard-library archiver inside wd2l. I don't recommend it: if one bug hit both
    the live path and the recovery path, recovery would fail exactly when it's needed.
  * **(d)** leave it on the host for now.

  (a) and (b) can go together."

- [ ] **Step 2: Record the answer.**
  * Add a row `P7` to the As-built log: the choice and the reason.
  * In ADR-0004, tick or reword the action item.
  * If (b) is chosen, also add a line saying who files the request with the Hummingbird
    project, and where (`https://gitlab.com/redhat/hummingbird/containers`, "Contributing a
    rpm" / "Contributing to a container image").

```bash
git add docs/decisions/0004-container-base-image.md docs/superpowers/plans/2026-10-07-release-packaging/README.md
git commit -m "Capture archive in a container: decision recorded"
```

---

### Task 7.2: If (a): the design for the capture image's plan

This design is what the separate plan must turn into tasks with tests, in the style of
Phases 3–5.

**The image.** `packaging/container/capture.Containerfile`:

```dockerfile
# tcpdump for the receiver's capture archive (docs/decisions/0004-container-base-image.md,
# action item 1). UBI 10 micro plus tcpdump and libpcap from the UBI 10 repositories.
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:<pinned> AS build
RUN dnf install -y --installroot /rootfs --releasever 10 --setopt=reposdir=/etc/yum.repos.d \
      --setopt=install_weak_deps=0 --nodocs tcpdump \
 && dnf --installroot /rootfs clean all
FROM registry.access.redhat.com/ubi10/ubi-micro:latest@sha256:<pinned>
COPY --from=build /rootfs/ /
USER 65532
ENTRYPOINT ["/usr/sbin/tcpdump"]
```

* Pin it with `pin-images.sh`.
* `build.sh` gains a `CONTAINERFILE=` override, so the capture image is built the same way,
  with its own labels.

**Its checks.** Generalize the image pipeline by one input: a policy file per image,
`packaging/container/<image>.policy.json`, holding:

* the allowed registries: `["registry.access.redhat.com/hi/"]` for wd2l,
  `["registry.access.redhat.com/ubi10/"]` for capture;
* `fips_required`: true for wd2l, false for capture (tcpdump does no cryptography);
* `shell_allowed`: the measured answer for UBI micro, as an accepted difference recorded in
  ADR-0004;
* `rpmdb_identical`: true for wd2l. For capture it is false, replaced by an allow-list of the
  packages added over UBI micro (`tcpdump`, `libpcap` and what the first build's SBOM diff
  shows). Each package is listed, and reviewed by the security owner.

Then:

* `check_containerfile.py`, `check_image.py` and `sbom_diff.py` take `--policy FILE`;
* `image.yml`'s `build`, `hardening`, `vuln-scan`, `sbom`, `publish` and `verify-published`
  become a matrix over `[wd2l, wd2l-capture]`;
* `base-verify` for UBI: Red Hat's signature, with the same key. Record whether UBI images on
  `registry.access.redhat.com` carry SBOM and provenance referrers. If they don't, the record
  says so.

**Running it.** `deploy/receiver/wd2l-capture.container` replaces `wd2l-capture.service` on a
container host:

```ini
[Unit]
Description=wd2l: raw packet archive of the tapped log stream (container)
After=wd2l-capture-nic.service
Requires=wd2l-capture-nic.service

[Container]
ContainerName=wd2l-capture
Image=ghcr.io/joehazurmoney/wd2l-capture:<version>
Pull=never
Network=host
User=wd2l
Group=wd2l
Volume=/var/lib/wd2l/pcap:/var/lib/wd2l/pcap:z
DropCapability=all
AddCapability=NET_RAW
NoNewPrivileges=true
ReadOnly=true
# Archive everything that arrives, not just the log flow. -U writes each packet as it arrives,
# so a replay can read the current hour's file. As non-root there is no -Z privilege drop.
Exec=-i ${IFACE} -p -n -U -s 0 -G 3600 -w /var/lib/wd2l/pcap/cap-%%Y%%m%%d%%H%%M%%S.pcap

[Service]
EnvironmentFile=/etc/wd2l/capture.env
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
```

* The user lines and the `:z` follow P0-4 and P0-3, as for the receiver.
* `wd2l-pcap-prune.timer` stays on the host.

**Proving it.**

* `lab/run-lab.sh --image IMAGE --capture-image CAPTURE` runs `start_capture` through the same
  `podman run` pattern as `wd2l_run`: `NET_RAW` only, as 65532, writing `$OUT/pcap`.
* The image job adds functional runs with both images: the plain run, and `--receiver-outage`.
  In the outage run the receiver container stops while the capture container keeps going, then
  the replay fills the gap. That is the property that matters for the archive.

**Release.** The rc and v-tag flow of Task 6.5 carries the second image: its OCI layout
tarball, its SBOM, and its lines in `SHA256SUMS` and the notes.
