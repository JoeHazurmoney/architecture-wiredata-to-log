# Plan: GitHub releases as RPMs (+ wheel) and a hardened, FIPS container image

## Context

wd2l has no releases yet. Hosts install it by hand (`cp -r wd2l deploy /opt/wd2l`, `useradd`,
`install -d`, `git rev-parse HEAD > BUILD`). Two release forms are wanted from a version tag:

1. **Package install**: noarch RPMs for EL9 and EL10. They replace the manual steps: code, CLIs,
   systemd units, the `wd2l` user and `wd2l-audit` group, and the directories with the right
   modes. The wheel and sdist are built first and attached to the release too.
2. **Container**: `wd2l-sender` and `wd2l-receiver` as an image on the FIPS variant of Red Hat
   Hardened Images, run by systemd through Quadlet. Host-level pieces stay on the host for now:
   NIC scripts, nftables, the tcpdump archive, the audit seal timer, auditd rules and chrony.
   A capture image for the receiver is kept as Phase 7.

The repo is private during the proof of concept. It will go public later under the **MIT**
license. The enclaves are probably offline. So signing uses a cosign key pair and every artifact
can be verified offline; the GitHub-native extras are added when the repo goes public (end of
this plan).

Work on a new branch `release-packaging` off `main`, after `audit-and-health` merges. First
release: **v0.3.0**. The minor bump is for the new `--chrony-addr` option.

## Research findings that drive the design

* **Red Hat Hardened Images.** Project Hummingbird went GA under this name on 2026-05-12. It's
  free, at `registry.access.redhat.com/hi/`, under the UBI EULA.
  * Distroless: no shell or dnf. The image runs as UID 65532.
  * Rebuilt under the same tag when fixes land; pin by digest.
  * Its RPMs are rebuilt from Fedora spec files, not RHEL packages.
  * Python 3.12 matches the CI matrix and RHEL 10's python3.
* **Where the base image's records live.** The Red Hat signature is an OCI referrer (a Sigstore
  bundle) on `registry.access.redhat.com`. The SPDX SBOM (`.sbom`), SLSA provenance (`.att`, a
  DSSE envelope) and a Konflux signature (`.sig`) sit beside the **same digests** on the
  `quay.io/hummingbird` mirror. Red Hat also publishes `<build>-source` images, which hold the
  SRPMs (90 layers for python). All of these can be copied into our ghcr.
* **The FIPS variant (`hi/python:3.12-fips`, `3.12-fips-builder`) differs materially:**
  * Packages: adds `crypto-policies-config-fips` and `openssl-config-fips`. OpenSSL loads only
    the frozen `openssl-fips-provider` 3.0.7 module, while `openssl-libs` stays at 3.5.x. That's
    the RHEL 10 design.
  * Drops the `ca-certificates` bundle.
  * Is checked against the STIG profile at build time.
  * Behavior: only FIPS-approved algorithms work. MD5 is refused, and TLS is limited to approved
    ciphers and groups.
  * Red Hat says validation **applies only on RHEL hosts installed in FIPS mode**. On other hosts
    the image is FIPS-configured, not validated.
  * wd2l only uses SHA-256 (`hashlib`) and a default TLS context (`outputs.py:283`). CRC32 is
    zlib's and isn't a security function. So no code change is expected. Without the CA bundle,
    the receiver **must** be given `--hec-ca`; the unit already sets it.
* **Hummingbird's RPM repo has no tcpdump, libpcap or chrony**, and its image catalog has no
  tcpdump image. **UBI 10** has tcpdump and libpcap, but not chrony.
* The **UBI 9/10 repos** carry everything the RPM build and install test need: `rpm-build`,
  `python3-devel`, `python3-pip`, `systemd-rpm-macros`, `tcpdump`, `nftables`, `ethtool`,
  `iproute`, `findutils`. UBI 9's setuptools is 53, too old for this pyproject. So the wheel is
  built once and the spec installs it.
* **chronyd answers `tracking` over UDP from 127.0.0.1:323** (cmdmon v6, request 33, reply 5,
  108-byte reply; loopback is always allowed). A container on the host network can ask it
  directly.
* **`podman generate systemd` is deprecated in favor of Quadlet.** Quadlet ships with Podman 4.4
  and later (RHEL 9.2+, RHEL 10).

## Phase 0: checks that could change the design

Run these on a RHEL 10 VM (SELinux enforcing, then installed in FIPS mode) and on a GitHub
runner. Each check has a fallback.

1. A non-root container user with `--cap-drop=all --cap-add=NET_RAW` can open the AF_PACKET
   socket. Fallback: root inside the container with every other capability dropped.
2. Quadlet `Exec=$WD2L_RECEIVER_ARGS` with `EnvironmentFile=` expands and word-splits.
   Fallback: write the options in `Exec=`.
3. SELinux with shared bind mounts (`/var/lib/wd2l`, `/var/log/wd2l`), which host tcpdump and
   the seal timer also use. Try `:z`, not `:Z`. Fallback: a small policy module.
4. With `/etc/passwd` and `/etc/group` mounted read-only, `User=wd2l` resolves, and audit
   `actor` names `wd2l`.
5. `/sys/class/net/<nic>/statistics` is readable with `Network=host`.
6. The **FIPS image** runs the test suite and the lab:
   * `_hashlib.get_fips_mode()` is 1 and `hashlib.md5()` is refused, on a non-FIPS runner and on
     RHEL in FIPS mode;
   * HEC TLS to a FIPS-mode endpoint works with `--hec-ca`.
7. Cosign, in the version used:
   * key signing with no tlog, then offline verify;
   * `cosign save` to an OCI layout with signatures and attestations, then
     `cosign verify --local-image` offline;
   * it verifies Red Hat's referrer-bundle signature.
8. ghcr accepts `oras copy -r`, so referrers are copied, and `cosign copy`, so the
   `.att`/`.sbom`/`.sig` tags are copied.

## Phase 1: decisions on record, license, build artifacts

* **ADRs**, status Proposed, become Accepted after Phase 0. Same format as
  [ADR-0003](docs/decisions/0003-receiver-to-siem-delivery.md). Name controls generically, with
  NIST SP 800-53 IDs only as examples.
  * **ADR-0004: Container base image: Red Hat Hardened Images (FIPS variant).** Framed as defense
    in depth.
    * **Options:**
      * A. `hi/python:3.12-fips` (chosen);
      * B. UBI 10 micro plus python3 via `dnf --installroot`;
      * C. UBI 10 `python-312-minimal`, which has microdnf and a shell;
      * D. UBI 9 micro plus python3 3.9;
      * E. Non-RPM minimal images (Google distroless, Wolfi/Chainguard, `python:3.12-slim`).
    * **Criteria, each tied to a control:**
      * attack surface / least functionality: package count, shell, package manager, setuid
        files;
      * least privilege: default non-root user; with Quadlet, one capability and a read-only
        rootfs;
      * flaw remediation: known and fixable CVEs today, and how fast fixes ship;
      * supply-chain integrity: signature, SBOM, SLSA provenance, reproducible builds, source
        images;
      * cryptographic protection: FIPS provider and its validation scope;
      * operational fit: RPM-based, so the rpmdb can be scanned and Red Hat security data
        applies, the same ecosystem as the RHEL hosts;
      * cost and redistribution;
      * lifecycle risk: new product, Fedora-derived, floating tags, LTS later as a paid option.
    * **A measured comparison table.** `packaging/container/compare-bases.sh` pulls each
      candidate by digest and records size, package count (Syft), shell and package-manager
      presence, default user, and Grype totals and fixable High/Critical. The ADR quotes that
      output with its date.
    * **Consequences:** chronyc isn't available, hence the built-in query. tcpdump isn't
      available, hence Phase 7. There's no CA bundle, so `--hec-ca` is needed. The base's
      records are mirrored.
  * **ADR-0005: Run the containers under systemd with Quadlet.**
    * **Options:**
      * A. Quadlet (chosen);
      * B. a hand-written unit calling `podman run`;
      * C. `podman generate systemd` (deprecated);
      * D. Docker Engine with restart policies or compose (a root daemon, not shipped by RHEL);
      * E. Kubernetes, MicroShift or `podman kube play` (more components to accredit, for one
        process per host).
    * **Value:**
      * declarative units that a systemd generator turns into real services;
      * the existing dependencies and ordering keep working (`Requires=wd2l-capture-nic.service`,
        `network-online`);
      * the same `systemctl`, journald and auditd workflow as native installs;
      * no daemon: Podman runs under systemd through conmon;
      * the hardening is declared in the file (`DropCapability`, `AddCapability=NET_RAW`,
        `NoNewPrivileges`, `ReadOnly`, `User`), with SELinux `container_t` on top;
      * change control: the image is pinned by digest, `AutoUpdate` is off, and `Pull=never`
        works offline with a locally loaded image;
      * rollback is the previous digest plus a restart;
      * `StopTimeout` keeps the clean-stop guarantees.
    * **Consequences:**
      * systemd's own sandbox options (`ProtectSystem` and the rest) now confine Podman, not the
        workload; namespaces, capabilities and SELinux confine the workload;
      * a signal sent by an operator shows as pid 0 inside the container, and the host's auditd
        records the operator;
      * it needs Podman 4.4 or later.
  * **ADR-0006: Release artifacts and signing.**
    * Artifacts: RPMs plus the wheel, built from one wheel, and the image in ghcr plus a
      `cosign save` OCI layout for offline enclaves.
    * Signing: a key pair with no public log, while the repo is private; the switch to add
      keyless and GitHub attestations once public.
    * The base-image records are mirrored, so every released image's base can be verified and
      its source obtained for as long as the release is supported.
* **`LICENSE`: MIT.** The copyright holder is the name you give; the default comes from git
  config. Add `license = "MIT"` (SPDX) and `license-files` to `pyproject.toml`; that needs
  `setuptools>=77` in `[build-system]`. The spec's `License: MIT`, and the OCI label
  `org.opencontainers.image.licenses=MIT`, which covers wd2l only. Base packages keep their own
  licenses, and their source is in the mirrored `-source` image.
* `pyproject.toml`: `dynamic = ["version"]` from `wd2l.__version__`; package-data `BUILD`.
  `MANIFEST.in` grafts `deploy/` and `packaging/`, so the sdist is the RPM's Source0.
  `.gitignore` gets `wd2l/BUILD` and `dist/`.
* Build step: `git rev-parse HEAD > wd2l/BUILD; python -m build`. `hostinfo.build_id()`
  ([wd2l/hostinfo.py:90](wd2l/hostinfo.py#L90)) works unchanged everywhere. `code_sha256()`
  hashes `.py` files only.
* Bump `wd2l/__init__.py` to `0.3.0`.

## Phase 2: built-in chrony query (`--chrony-addr`)

* [wd2l/hostinfo.py](wd2l/hostinfo.py): `chrony_tracking(addr, timeout)`, standard library only.
  * It sends the 20-byte header, zero-padded to 108 bytes.
  * It checks version, type, command, status and sequence, decodes chrony's Float (7-bit
    exponent, 25-bit coefficient), and returns the **same dict** as `parse_chronyc_tracking`:
    * `offset_ms` comes from `current_correction`;
    * `synced` is `leap != 3`, stratum between 1 and 15, and a nonzero refid;
    * `source` is the IP, or the refid text.
  * `TimeQuality` takes a query callable, and the chronyc subprocess is one implementation of it.
    Failures give `"unavailable"`, and nothing raises.
* Sender and receiver: `--chrony-addr HOST:PORT`, unset by default, which keeps `--chronyc`.
* Tests in [tests/test_hostinfo.py](tests/test_hostinfo.py): a fake chronyd on UDP in a thread,
  covering synced, unsynced, a reference clock, a wrong sequence, garbage and timeout. Also
  Float vectors and the request layout.
* `lab/fake_chronyd.py`: honours the clock-bad flag file, like
  [lab/fake_chronyc.py](lab/fake_chronyc.py).
* Docs: option rows in both deployment guides, and an as-built note in
  [docs/audit-and-health-plan.md](docs/audit-and-health-plan.md) §11. Requirement: chronyd's
  cmdport isn't 0, and `tracking` is open over UDP.

## Phase 3: container image, Quadlet units, lab image mode

* `packaging/container/Containerfile`. Both bases are pinned by digest; the build context is
  `dist/`.
  * Stage `build` (`hi/python:3.12-fips-builder`):
    `python3 -m pip install --no-deps --no-index --root /out --prefix /usr dist/wd2l-*.whl`.
  * Final stage (`hi/python:3.12-fips`): `COPY --from=build /out/ /`, `USER 65532`.
  * Annotations: `org.opencontainers.image.{version,revision,source,licenses}`, and
    `org.opencontainers.image.base.{name,digest}`.
  * No ENTRYPOINT; the unit names the command.
* Quadlet files `deploy/log-server/wd2l-sender.container` and
  `deploy/receiver/wd2l-receiver.container`:
  * `Network=host`, `DropCapability=all`, `AddCapability=NET_RAW` (receiver only),
    `NoNewPrivileges=true`, `ReadOnly=true`, `Pull=never`.
  * Volumes: `/var/lib/wd2l`, `/var/log/wd2l`, `/etc/wd2l:ro`, `/etc/passwd:ro`,
    `/etc/group:ro`.
  * `--chrony-addr 127.0.0.1:323`.
  * **`StopTimeout` matching `TimeoutStopSec`** (30 s sender, 60 s receiver).
  * The same `[Unit]` dependencies as the `.service` files, and `Restart=always`.
* `lab/run-lab.sh --image IMAGE`:
  * the sender and receiver start through `podman run --rm --network ns:/run/netns/wd2l-encN
    --user 65532 --cap-drop all [--cap-add NET_RAW] -v "$OUT:$OUT"`, with fake chronyd in each
    namespace;
  * supported with the plain run, `--loss`, `--files` and `--maintenance`;
  * it refuses fault, outage and crash modes, because STOP and KILL would hit the podman client.
* New `docs/deployment/containers.md` covers:
  * verifying and importing the image offline;
  * the host steps that still apply;
  * installing the Quadlet units;
  * Podman's signature policy for ghcr pulls (`sigstoreSigned` with `cosign.pub`);
  * signals and audit;
  * FIPS: the host must be RHEL installed in FIPS mode for validation, and `--hec-ca` is needed.

## Phase 4: image assurance CI (the series of jobs)

* `.github/workflows/image.yml`, a reusable `workflow_call` with input `publish`:
  * `tests.yml` calls it with `publish: false` on every push and PR;
  * `release.yml` calls it with `publish: true`.
* Scanner and signing tools run from pinned Hardened Images where they exist (`hi/cosign`,
  `hi/grype`, `hi/oras`). Others come as release binaries with verified checksums. Actions are
  pinned by commit SHA.

| # | Job | What it does | Fails when |
|---|---|---|---|
| 1 | `lint` | hadolint and `trivy config` on the Containerfile. A script checks that every `FROM` is pinned by digest and is a `-fips` tag | lint errors, an unpinned or non-FIPS base |
| 2 | `base-verify` | Verifies the Red Hat signature on `registry.access.redhat.com/hi/python@<digest>`, using committed `packaging/container/keys/redhat.pub` (with its fingerprint and source URL). Verifies the SLSA provenance on `quay.io/hummingbird/python@<digest>` with the committed Hummingbird key. Downloads the base SBOM. Checks the label `io.hummingbird-project.variant.fips=true`. Writes `base-image-record.json`: refs, index and per-arch digests, key fingerprints, results, time | any signature or provenance check fails, or the digests differ between registries |
| 3 | `build` | Wheel, then `podman build --timestamp $SOURCE_DATE_EPOCH`. Saves an OCI archive artifact and records the digest | build error |
| 4 | `reproducible` | Rebuilds on a fresh runner from the same inputs and compares digests; `diffoci` shows any difference. Non-blocking until it's stable | (later) the digests differ |
| 5 | `hardening` | `packaging/container/check-image.sh` on the image config and its exported rootfs:<br>• runs as non-root (65532); no `/bin/sh` or bash; no dnf, microdnf, yum or rpm binaries<br>• no setuid or setgid files; no world-writable files outside `/tmp`<br>• the crypto policy is `FIPS`; `get_fips_mode()` is 1; `md5` is refused<br>• **the RPM set equals the base's**, so we add zero packages<br>• the wd2l files match the wheel's RECORD hashes; `BUILD` equals the commit; the annotations are present | any rule broken |
| 6 | `vuln-scan` | Grype and Trivy (vulnerabilities and secrets): two scanners, two databases, both gated on **fixable High/Critical**. Accepted findings live in `packaging/container/vuln-exceptions.yaml`, each with a reason and an expiry date. SARIF and JSON are kept as artifacts | a gated finding, or an expired exception |
| 7 | `sbom` | Syft SPDX and CycloneDX for our image. Diffs it against the base SBOM, so only wd2l appears as added | anything else added |
| 8 | `functional` | The CLIs' `--help`; `python -m wd2l.audit verify`; `sudo lab/run-lab.sh --image` for the plain run and `--loss 1` | the lab doesn't PASS |
| 9 | `fips-tests` | The full pytest suite inside `hi/python:3.12-fips-builder` | any test fails under the FIPS provider |
| 10 | `publish` (release only) | Push by digest. Copy the base into `ghcr.io/joehazurmoney/wd2l-base/python` with `oras copy -r` (Red Hat signature referrer) and `cosign copy` (`.att`/`.sbom`/`.sig`), and copy the matching `-source` image. `cosign sign --key --tlog-upload=false`. `cosign attest` with: SPDX SBOM, SLSA v1 provenance that we generate (repo, commit, workflow, runner, wheel sha256, `resolvedDependencies` = base digest and mirror ref), the Grype results, and `base-image-record.json`. `cosign save` to an OCI layout, tarred as a release asset | any push, sign or attest step fails |
| 11 | `verify-published` | A fresh job pulls by digest. `cosign verify` and `cosign verify-attestation` for every predicate type with `cosign.pub`, plus `cosign tree`. Then the same against the saved OCI layout with networking turned off | anything can't be verified |

* **Ongoing:** `.github/workflows/image-rescan.yml` runs weekly and on demand. It rescans every
  supported released digest with fresh databases. On a new fixable High/Critical it opens an
  issue. Dependabot proposes base digest bumps, and those PRs run the whole pipeline.
* What our own provenance is worth: until the repo is public it's self-asserted, generated and
  signed in our workflow, so roughly SLSA Build L1–L2. Going public raises it; see the end of
  this plan.

## Phase 5: RPMs (`packaging/rpm/`)

* `wd2l.spec`, one noarch source package with three binary packages:
  * **`wd2l`**: the Python package and CLIs, `wd2l.sysusers` (`%sysusers_create_compat` on EL9),
    `wd2l.tmpfiles` (`/var/log/wd2l` **2750 wd2l:wd2l-audit**), `/etc/wd2l` 0750 root:wd2l, and
    the seal script in `/usr/libexec/wd2l/` with its timer.
  * **`wd2l-sender`**: Requires nftables and iproute. The units, `egress-nic.sh`,
    `/etc/wd2l/{egress,sender}.env` as `%config(noreplace)`, the nft template and auditd rules in
    `/usr/share/wd2l/`, and the Quadlet example.
  * **`wd2l-receiver`**: Requires tcpdump, nftables, ethtool, iproute and findutils. The units,
    `capture-nic.sh`, `receiver.env`, the Splunk examples, auditd rules, and the Quadlet example.
* `%install` pip-installs the wheel (`--root %{buildroot} --prefix %{_prefix}`), sets
  `INSTALLER` to `rpm` and removes `direct_url.json`.
* Paths are rewritten at build time: the seal script moves to `/usr/libexec/wd2l/`; in the
  auditd rules, `/opt/wd2l/` becomes `%{python3_sitelib}/wd2l/` and `/usr/libexec/wd2l/`, and
  the rules also watch `/usr/lib/systemd/system/wd2l-*` and the drop-in directories.
* Nothing is enabled automatically.
* **Unit change, which also applies to the manual install:** the site options move to
  `EnvironmentFile=/etc/wd2l/{sender,receiver}.env`. The new line is
  `ExecStart=/usr/bin/python3 -m wd2l.sender $WD2L_SENDER_ARGS`, and the Quadlet files read the
  same env file.
  * [tests/test_deploy.py](tests/test_deploy.py) `args()` reads the env file.
  * New `tests/test_packaging.py`: `deploy/` matches the spec's `%files`, the env files parse
    with `build_parser()`, and the Quadlet stop timeouts match the units.
* FIPS: no packaging change. On RHEL hosts in FIPS mode, Python already uses RHEL's validated
  OpenSSL. The docs say so.
* Docs: the install sections of the two deployment guides become `dnf install` plus `rpm -V`.
  The manual install stays as a short appendix.

## Phase 6: release workflow and docs

* `.github/workflows/release.yml`: runs on tag `v*.*.*`, plus `workflow_dispatch` as a dry run.
  Steps:
  * `tests.yml` (which now has `workflow_call`, and calls `image.yml`);
  * `dist`: the tag must equal `__version__`;
  * `rpm`: a `ubi9/ubi` and `ubi10/ubi` matrix with `rpmbuild` and rpmlint, then an install test
    in a fresh UBI container. It checks the CLIs, `getent passwd wd2l`, the `/var/log/wd2l`
    mode, a clean `rpm -V`, and `systemd-analyze verify`;
  * `image.yml` with `publish: true`;
  * `release`: `SHA256SUMS` over every asset (wheel, sdist, 6 RPMs, the OCI layout tarball,
    SBOMs, `base-image-record.json`), `cosign sign-blob` on it, then `gh release create --draft
    --verify-tag`. The notes give the image digest and the offline verify steps. You publish it.
* One-time setup by you: `cosign generate-key-pair`; `gh secret set COSIGN_PRIVATE_KEY` and
  `COSIGN_PASSWORD`; commit `cosign.pub`.
* `.github/dependabot.yml` for the `docker` ecosystem (`packaging/container`) and
  `github-actions`.
* `docs/releasing.md`: covers cutting a release and the enclave import: `cosign verify-blob` on
  `SHA256SUMS`, then `sha256sum -c`, `cosign verify --local-image`, `skopeo copy` or
  `podman load`, and `dnf install`.
* README: the license section, and links to ADR-0004–0006 and the containers guide.

## Phase 7: receiver capture container (tracked, decided after Phase 0 check 1)

The tcpdump archive is what fills a receiver outage, so it has to stay independent of the
receiver. Options, to record in ADR-0004's action items:

* **(a) tcpdump on UBI 10 micro.** tcpdump and libpcap come from the UBI 10 repos (RHEL
  lineage). Non-root with `NET_RAW` replaces `-Z wd2l`. It's a `wd2l-capture.container` and goes
  through the same Phase 4 pipeline. **Recommended** if you want the capture in a container now.
* **(b) Contribute libpcap, tcpdump and a tcpdump image to Project Hummingbird.** They take RPM
  and image contributions. This is the best attack-surface story, but the timeline isn't ours.
  Pursue it alongside (a).
* **(c) A stdlib archiver in wd2l.** `packets.py` already writes pcap. It would add no packages,
  but if one bug hit both the live path and the recovery path, recovery would fail exactly when
  it's needed. Recorded, not recommended.

The prune timer and the capture-NIC script stay on the host whichever option is chosen.

## When the repo goes public (later)

* Add `actions/attest-build-provenance` (SLSA Build L3) and keyless cosign signatures alongside
  the key signatures. Enclaves keep verifying offline with `cosign.pub`.
* Upload the scanners' SARIF to code scanning.
* Make the ghcr packages public, and turn on immutable releases.

## Not in this plan

RPM-native GPG signing and a dnf repository; the signed `SHA256SUMS` covers the RPMs. Also out:
arm64 RPM testing.

## Verification

1. `python -m pytest -q` on 3.9 and 3.12 (the Docker images `wd2l-test` / `wd2l-test-312`), and
   inside the FIPS builder image.
2. The lab in host mode is unchanged. The lab in image mode (plain, `--loss 1`, `--files`)
   PASSes with byte-identical rebuilds and the audit chain OK.
3. Dry run of `image.yml` and `release.yml` on the branch: all 11 jobs are green, the RPMs
   install on UBI 9 and 10, and every asset is produced.
4. Tag `v0.3.0-rc.1`. On a machine with no network, verify `SHA256SUMS`, the OCI layout's
   signatures and attestations, and the base-image record. Import the image.
5. RHEL 10 VM, SELinux enforcing and installed in FIPS mode; repeat on RHEL 9 for the RPM:
   * native run and Quadlet run;
   * NIC counters and `time_quality` match `chronyc -c tracking`;
   * clean `stream_end` on stop;
   * the seal timer makes the container-written audit files append-only;
   * HEC TLS works in FIPS mode.
