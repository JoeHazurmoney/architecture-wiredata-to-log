# Releases as RPMs and a hardened FIPS container image: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish every version tag as a GitHub release that holds:

* noarch RPMs for EL9 and EL10, plus the wheel and sdist;
* a container image on Red Hat Hardened Images (FIPS variant), run under Quadlet.

Everything is signed with a cosign key pair, and an offline enclave can verify all of it. Every
image is checked by a pipeline of image-assurance jobs.

**Architecture:**

* **One build feeds everything.** One wheel, built once with `wd2l/BUILD` (the commit) inside
  it, feeds the RPM spec and the container. The spec pip-installs the wheel; the container's
  builder stage does the same.
* **Code changes are small.** wd2l gains a stdlib chrony query (`--chrony-addr`), because the
  image has no `chronyc`. The receiver also says when the kernel gave its capture socket less
  buffer than it asked for.
* **Units read their options from files.** The site options move from the units into
  `/etc/wd2l/*.env`. The native units and the Quadlet units read the same files.
* **CI is reusable workflows.** `image.yml` builds and checks the image on every push, and
  publishes on a release. `release.yml` adds the RPMs, `SHA256SUMS` and a draft release.
* **Small stdlib Python scripts** under `packaging/` do the checking, so each check has unit
  tests.

**Tech Stack:**

* Python ≥ 3.9, standard library only, for wd2l and every script under `packaging/`.
* pytest.
* Podman 4.9+ (GitHub runners) and 5.x (RHEL 10).
* Red Hat Hardened Images: `hi/python:3.12-fips` and `-fips-builder`, plus `hi/cosign`,
  `hi/grype` and `hi/oras` as CI tools.
* Syft, Trivy, hadolint and diffoci as pinned tool images.
* RPM: `rpm-build`, `python3-rpm-macros` and `systemd-rpm-macros` in UBI 9/10 containers.
* GitHub Actions, and Dependabot.

**Spec:** [spec.md](spec.md), the approved design, copied here verbatim. Executors read it
together with this plan. "Spec Phase n" below refers to its sections.

## Phases

| Phase | File | Delivers | Tasks |
|---|---|---|---|
| 0 | [phase-0-checks.md](phase-0-checks.md) | The eight design checks (CI runner and RHEL 10 VM), each result recorded, a fallback chosen where needed | 0.1–0.3 |
| 1 | [phase-1-decisions-license-build.md](phase-1-decisions-license-build.md) | MIT license, one version source, the wheel carries BUILD, dist checks; pinned CI tools; ADR-0004 (base image, measured), ADR-0005 (Quadlet), ADR-0006 (artifacts and signing) | 1.1–1.5 |
| 2 | [phase-2-chrony-query.md](phase-2-chrony-query.md) | `chrony_tracking()` and `--chrony-addr` on both sides; the lab's fake chronyd and `--chrony-udp` | 2.1–2.3 |
| 3 | [phase-3-container-and-quadlet.md](phase-3-container-and-quadlet.md) | The capture buffer the kernel actually gave, and its sysctl; the Containerfile and `build.sh`; lab `--image`; options moved into env files; Quadlet units; the containers guide | 3.1–3.5 |
| 4 | [phase-4-image-assurance-ci.md](phase-4-image-assurance-ci.md) | `image.yml`'s 11 jobs (with `versions.py` and `provenance.py`), the weekly rescan, Dependabot | 4.1–4.8 |
| 5 | [phase-5-rpms.md](phase-5-rpms.md) | `rpmify.py`, `wd2l.spec` (3 packages), `rpm.yml` (build and install test on UBI 9/10), the deployment guides | 5.1–5.4 |
| 6 | [phase-6-release.md](phase-6-release.md) | `notes.py`, the signing key, `release.yml`, `docs/releasing.md`, README, an rc release, then v0.3.0 | 6.1–6.5 |
| 7 | [phase-7-capture-container.md](phase-7-capture-container.md) | The receiver capture-container decision, and the design for option (a) if it's chosen | 7.1–7.2 |

* **Order and dependencies:** Phase 0 runs first; its results can change Phase 3 and Phase 4
  details (each task says which check it depends on). Phases 1–3 each end with the full test
  suite green and could merge on their own. Phase 4 needs Phase 3's Containerfile, Phase 5
  needs Phase 3's env files, and Phase 6 needs 4 and 5. Phase 7 waits for your decision.
* **Inside a phase,** tasks are in order; each task's **Interfaces** block names what it uses
  from earlier tasks and what it produces.

## Global constraints

Every task's requirements include these. Values are copied from the spec or the repo.

* **Python ≥ 3.9, standard library only** for `wd2l/` and for every script under `packaging/`
  (`rpmify.py` runs on EL9's Python 3.9 inside `rpmbuild`). No 3.10+ syntax: no `match`, and no
  `X | Y` outside annotations. CI byte-compiles with 3.9:
  `python -m compileall -q wd2l lab tests packaging`.
* **Never add `__init__.py` under `packaging/`.** A regular package called `packaging` would
  shadow the `packaging` library that pytest and pip import. Tests load the scripts by path with
  `helpers.load_script("packaging/…/x.py")` (Task 1.1).
* **Defaults don't change behavior.** Without `--chrony-addr`, time quality is read exactly as
  today. Moving the unit options into env files leaves every option parsing to the same value;
  a test checks that.
* **One version source:** `wd2l/__init__.py` `__version__`, in PEP 440 form: `X.Y.Z` or
  `X.Y.Z{a|b|rc}N`. The derived names:
  * the tag is `v` + version;
  * the RPM `Version` is `X.Y.Z~rcN` for a pre-release;
  * the image tags are `X.Y.Z` and `X.Y` for a final release, or just the version for a
    pre-release (`packaging/release/versions.py`, Task 4.7).
  * The `Image=` tag in both `.container` files equals the version; a test keeps them equal.
* **License:** MIT, written as SPDX `MIT` (pyproject, spec, image label). The copyright line
  names the holder your partner confirms (Task 1.1).
* **Image:**
  * built `FROM registry.access.redhat.com/hi/python:3.12-fips-builder` and
    `…/hi/python:3.12-fips`, each pinned as `NAME:TAG@sha256:DIGEST`;
  * runs as UID 65532, with no ENTRYPOINT;
  * **adds zero RPMs to its base** (the rpmdb is byte-identical to the base's).
* **Registry names:** `ghcr.io/joehazurmoney/wd2l` and
  `ghcr.io/joehazurmoney/wd2l-base/python`, all lowercase. Only `release.yml`, on a version tag,
  publishes.
* **Signing:**
  * cosign key pair: the private key exists only in the Actions secrets `COSIGN_PRIVATE_KEY` and
    `COSIGN_PASSWORD`, and `cosign.pub` is committed at the repo root;
  * `--tlog-upload=false` on every sign and attest while the repo is private. Verification uses
    `--insecure-ignore-tlog`, which only means "don't look in the public log";
  * signing flags are as confirmed by Phase 0 check 7 (cosign 3.x).
* **Pinning:** GitHub Actions are pinned by full commit SHA with a `# vX.Y.Z` comment. Tool
  images are pinned by digest in `packaging/ci/tools.Containerfile`. Bases are pinned in the
  Containerfile. Dependabot proposes updates to all three.
* **Outward actions need your partner's OK each time:** pushing a branch, starting a workflow,
  creating a tag or release, setting secrets, pushing to ghcr. Never use force-push.
* **RPMs:**
  * noarch, built for EL9 (Python 3.9) and EL10 (Python 3.12);
  * nothing is enabled or restarted by `dnf install`/`upgrade` (upgrades follow
    [planned-downtime.md](../../../planned-downtime.md));
  * config files are `%config(noreplace)`.
* **Direction:** link the README's direction rule; don't restate it.
* **Docs:**
  * framework-neutral: controls in plain words, with NIST SP 800-53 or SOC 2 IDs only as
    examples ("e.g. NIST CM-7");
  * ADRs follow [ADR-0003](../../../decisions/0003-receiver-to-siem-delivery.md)'s layout;
  * product-neutral, in plain short sentences like the existing docs;
  * say "security owner".

## Review focus

The inputs and failure modes the spec implies but is quiet about, most likely to bite first.
Each one has a test in the task that owns the code.

1. **chronyd refuses, answers late, or isn't there.**
   * Situations: `tracking` not allowed over UDP, `cmdport 0`, a stale reply to an earlier
     request arriving first, nothing listening.
   * Expected: `time_quality` says `unavailable` within the timeout and never uses the stale
     reply; the next read recovers.
   * Tests: Task 2.1 `test_refused_request_is_unavailable_with_the_status`,
     `test_stale_reply_is_skipped`, `test_nothing_listening_is_unavailable_quickly`.
2. **The capture buffer is silently smaller than asked.** Without `CAP_NET_ADMIN` (native unit
   and container alike), `SO_RCVBUFFORCE` fails and the kernel caps the buffer at
   `net.core.rmem_max`, about 208 KiB by default. The receiver must say so at start, and the
   deploy steps must fix it. Tests: Task 3.1 `test_rcvbuf_falls_back_and_reports_the_cap`,
   `test_rcvbuf_warning`.
3. **An RPM installed over a manual install, or upgraded.**
   * Situations: an existing `wd2l` user and group, an edited `/etc/wd2l/sender.env`, a running
     service.
   * Expected: `%pre` succeeds; the edited file is kept (`.rpmnew` beside it); nothing restarts.
   * Test: Task 5.3 `install-test.sh` (the pre-existing user and env-file leg, and the upgrade
     leg).
4. **A base digest moves or is missing.**
   * Situations: Red Hat rebuilds the tag between pin and check, the quay mirror doesn't have
     the digest yet, or the provenance names a different digest.
   * Expected: base-verify fails closed and names the digest; it never verifies a different
     image.
   * Tests: Task 4.2 `test_record_refuses_a_signature_for_another_digest`,
     `test_record_refuses_provenance_for_another_digest`.
5. **Vulnerability exceptions go stale or reach too far.**
   * Situations: an expired exception; one that matches the CVE but a different package.
   * Expected: an expired exception fails the gate even if nothing matches it; an exception
     only covers its own CVE in its own package.
   * Tests: Task 4.4 `test_expired_exception_fails_even_unused`,
     `test_exception_only_covers_its_package`.

Also covered:

* pre-release RPM ordering, `0.3.0~rc1 < 0.3.0` (Task 4.7);
* tag and version mismatch (Task 4.7);
* a non-FIPS or unpinned base sneaking into the Containerfile (Task 3.2);
* a setuid file or a shell appearing in the image (Task 4.3);
* the image claiming to be the base, through inherited Red Hat labels (Tasks 3.2 and 4.3);
* a test that only passes outside FIPS mode (Task 4.1 `fips-tests`).

## File map

| File | Status | Responsibility |
|---|---|---|
| `LICENSE`, `MANIFEST.in` | new | MIT; the sdist carries `deploy/`, `packaging/` and `wd2l/BUILD` |
| `pyproject.toml`, `wd2l/__init__.py` | modify | SPDX license, version from `__version__`, BUILD as package data; 0.3.0 |
| `wd2l/hostinfo.py` | modify | `chrony_float`, `chrony_request`, `parse_chrony_tracking`, `chrony_tracking`, `chrony_hostport`, `chrony_address`; `TimeQuality(query=)`; `time_quality()` |
| `wd2l/packets.py` | modify | `set_rcvbuf()`, and `LiveCapture.rcvbuf` (what the kernel gave) |
| `wd2l/sender.py`, `wd2l/receiver.py` | modify | `--chrony-addr`; the receiver's buffer warning (`rcvbuf_warning`) |
| `lab/fake_chronyd.py` | new | cmdmon stand-in for `--chrony-addr`, honours the clock-bad flag |
| `lab/run-lab.sh` | modify | `--image IMAGE`: sender and receiver run from the image as UID 65532 |
| `deploy/log-server/sender.env`, `deploy/receiver/receiver.env`, `deploy/receiver/capture.env` | new | Site options the units and the Quadlet files read |
| `deploy/**/*.service` | modify | `EnvironmentFile=` + `$WD2L_*_ARGS`; tcpdump `-i ${IFACE}`; sender `StateDirectoryMode=0750` |
| `deploy/log-server/wd2l-sender.container`, `deploy/receiver/wd2l-receiver.container` | new | Quadlet units |
| `deploy/receiver/90-wd2l.conf` | new | sysctl: `net.core.rmem_max = 67108864` |
| `packaging/check_dist.py` | new | Wheel and sdist checks |
| `packaging/container/Containerfile`, `packaging/container/build.sh` | new | Two-stage build on the FIPS Hardened Images; the one build command (labels, time, removed base labels) |
| `packaging/container/check_containerfile.py` | new | Every FROM pinned, a Hardened Image, a FIPS variant; prints the refs |
| `packaging/container/check_image.py`, `fips_check.py` | new | Hardening rules on the image's filesystem and config; FIPS in force at run time |
| `packaging/container/vuln_gate.py`, `vuln-exceptions.json` | new | One gate over Grype and Trivy; exceptions with expiry |
| `packaging/container/sbom_diff.py` | new | Only wd2l added to the base |
| `packaging/container/base_record.py`, `keys/` | new | Cross-checks the base evidence; writes `base-image-record.json`; Red Hat and Hummingbird public keys |
| `packaging/container/compare-bases.sh`, `candidates/*.Containerfile` | new | ADR-0004's measured table |
| `packaging/ci/tools.Containerfile`, `packaging/ci/tool`, `packaging/ci/pin-images.sh` | new | Pinned tool images, the wrapper that runs them, and re-pinning |
| `packaging/rpm/rpmify.py`, `wd2l.spec`, `wd2l.sysusers`, `wd2l.tmpfiles`, `wd2l-receiver.tmpfiles`, `build-rpms.sh`, `install-test.sh` | new | RPM sources, the deploy-tree rewrite, the build and install test |
| `packaging/selinux/wd2l.te` | new, only if P0-3 failed | The SELinux allowances the shared mounts need |
| `packaging/release/versions.py`, `provenance.py`, `notes.py` | new | Version names, the SLSA predicate, release notes |
| `tests/helpers.py` | modify | `load_script()` |
| `tests/test_hostinfo.py`, `tests/test_deploy.py` | modify | Chrony tests; env-file parsing |
| `tests/test_packaging.py`, `tests/test_container_checks.py`, `tests/test_release_tools.py`, `tests/test_capture_buffer.py` | new | Tests for the scripts above |
| `.github/workflows/tests.yml` | modify | `workflow_call`; calls `image.yml`; compiles `packaging` |
| `.github/workflows/image.yml`, `rpm.yml`, `image-rescan.yml`, `compare-bases.yml`, `release.yml` | new | The pipelines |
| `.github/dependabot.yml` | new | docker (the Containerfile, the tools file) and github-actions |
| `cosign.pub` | new | The release public key (your partner generates the pair) |
| `docs/decisions/0004-container-base-image.md`, `0005-quadlet.md`, `0006-release-artifacts-and-signing.md` | new | ADRs |
| `docs/deployment/containers.md`, `docs/releasing.md` | new | Container deployment; cutting and importing a release |
| `docs/deployment/log-server.md`, `receiver.md`, `docs/operations.md`, `docs/running-the-lab.md`, `docs/audit-and-health-plan.md`, `README.md` | modify | In the task whose change needs them |

## Running tests on this machine

There is no Python on the Windows host. CI runs pytest on Ubuntu with 3.9 and 3.12; the
namespace lab, the image jobs and the RPM jobs also run in CI. Locally, use Docker Desktop
(start it first). From Git Bash at the repo root:

```bash
# once: small images with pytest (they may already exist: docker images | grep wd2l-test)
printf 'FROM python:3.9-slim\nRUN pip install -q pytest\n' | docker build -q -t wd2l-test -
printf 'FROM python:3.12-slim\nRUN pip install -q pytest\n' | docker build -q -t wd2l-test-312 -

# T runs pytest on 3.9; T312 on 3.12. Extra arguments go to pytest.
T() { MSYS_NO_PATHCONV=1 docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
      -v "$(pwd -W)":/src -w /src wd2l-test python -m pytest -p no:cacheprovider "$@"; }
T312() { MSYS_NO_PATHCONV=1 docker run --rm -e PYTHONDONTWRITEBYTECODE=1 \
      -v "$(pwd -W)":/src -w /src wd2l-test-312 python -m pytest -p no:cacheprovider "$@"; }

T -q                                    # whole suite
T tests/test_hostinfo.py::test_name -v  # one test
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src wd2l-test \
    python -m compileall -q wd2l lab tests packaging     # what CI's 3.9 byte-compile step checks

# B builds the wheel and sdist into dist/ (with BUILD = the current commit)
B() { git rev-parse HEAD > wd2l/BUILD && MSYS_NO_PATHCONV=1 docker run --rm \
      -v "$(pwd -W)":/src -w /src python:3.12-slim \
      sh -c "pip install -q build && rm -rf dist && python -m build -q"; }
```

Every "Run:" line in the tasks uses these. For the image:

```bash
B && MSYS_NO_PATHCONV=1 docker build -f packaging/container/Containerfile -t wd2l:dev dist/
docker run --rm wd2l:dev wd2l-receiver --help
```

The lab, the image pipeline and the RPM jobs need Linux root, Podman and network namespaces.
**CI is their check.** Pushing the branch and starting workflows are outward actions; ask your
partner first (Global constraints).

## As-built log

**Whenever an implementation differs from the spec, add a line here in the same commit:** the
task, the spec section, what was built instead, and why. Task 6.5 turns this list into notes in
the ADRs and guides. These rows are already decided by this plan:

| Task | Spec | Built | Why |
|---|---|---|---|
| 1.1 | Phase 1 license | `[build-system] requires = ["setuptools>=77"]`, `license = "MIT"`, `license-files = ["LICENSE"]` | SPDX license expressions need setuptools 77; the build runs in CI with build isolation, so hosts are unaffected |
| 2.2 | Phase 2 | The first start after the upgrade writes one `config_changed` audit record | `--chrony-addr` is a new key in the settings that are hashed. It is true: the set of settings changed |
| 3.1 | (new) | `set_rcvbuf()` reports the buffer the kernel gave; the receiver warns when it's under `--capture-rcvbuf`. `deploy/receiver/90-wd2l.conf` raises `net.core.rmem_max` | Found while planning the container: with only `CAP_NET_RAW`, the 64 MiB the docs promise was never granted, natively or in a container |
| 3.4 | Phase 5 unit change | Done in Phase 3, before the Quadlet files; `wd2l-capture.service` also reads `IFACE` from `capture.env`; the sender gets `StateDirectoryMode=0750` | The Quadlet units read the same env files; with the RPM there's no editing of `/usr/lib` units; `StateDirectory` would otherwise make `/var/lib/wd2l` 0755 and fail `rpm -V` |
| 4.4 | Phase 4 job 6 | Exceptions are `vuln-exceptions.json` (JSON, not YAML), keyed by CVE and package, with `expires` and `approved_by` | Standard library only |
| 4.7 | Phase 4 job 10 | Scan results and the base record are attested with our own predicate types (`…/attestations/vuln-scan/v1`, `…/attestations/base-image-record/v1`) | cosign's built-in `vuln` type has a fixed schema |
| 5.2 | Phase 5 sysusers | `%pre` runs `groupadd`/`useradd` when the names are missing; `wd2l.sysusers` is shipped for systemd too | It's the same on EL9 and EL10, and idempotent over a manual install |
| 5.2 | Phase 5 | `%systemd_postun` without restart | An upgrade must not bounce the sender or receiver outside the planned-downtime runbook |
| 5.2 | Phase 5 | The RPM owns empty drop-in dirs `/etc/systemd/system/wd2l-*.{service,timer}.d/`, so the auditd rules can watch them | An auditd directory watch needs the directory to exist |
| 1.2 | Phase 4 | The tool images are pinned in `packaging/ci/tools.Containerfile` and run by `packaging/ci/tool`, from Phase 1 on | ADR-0004's measurement (Task 1.3) already needs Syft and Grype |
| 2.3 | (new) | Lab `--chrony-udp`, and CI runs `--fault clock --chrony-udp` | Proves the UDP time path end to end, clock alarm included, before any image exists |
| 3.2 | (new) | `build.sh` removes the base's product labels (`cpe`, `com.redhat.component`, `io.hummingbird-project.*`, …) and sets `name=wd2l`, `vendor=wd2l project` | The image must not claim to be `hi/python` or a Red Hat product; the base is named in `org.opencontainers.image.base.*` |
| 3.3 | Phase 3 lab | `--image` also allows `--receiver-outage`; it refuses `--fault` and `--receiver-crash` | An outage stops wd2l with SIGTERM, which podman passes on; SIGSTOP and SIGKILL would reach the podman client |
| 4.1 | Phase 4 job 8 | `functional` runs the plain run, `--loss 1`, `--maintenance`, `--receiver-outage` and `--files` (spec: plain and `--loss 1`) | Cheap, and it covers the stop/start and replay paths in the container |
| 4.6 | Phase 4 job 4 | Compares image IDs, then diffs the config and file listings; no diffoci | One tool fewer to pin; the diff is enough to find the cause |
| Final | Phase 2 | chronyd's tracking reply is **104 bytes** (28 + 76): it stops before the EOR marker, so the spec's "108-byte reply" was wrong, and the fake chronyd shared the mistake. Fixed in `hostinfo.py` and `lab/fake_chronyd.py`; a reply captured from chronyd 4.8 is a unit test, and `packaging/ci/chrony-smoke.sh` asks a real chronyd in CI (lab job) | Found by the whole-branch review: `--chrony-addr` returned "unavailable" against every real chronyd |
| 4.4 | Phase 4 job 6 | The image removes the base's pip (`/usr/local/bin/pip*` and its `site-packages`, installed by `ensurepip`, not an RPM) with an exec-form `python3` `RUN`; `hardening` refuses pip, and `sbom` allows `pkg:pypi/pip@` to be removed | On 2026-10-08 Trivy gated fixable High CVEs in pip's vendored msgpack, setuptools and urllib3. wd2l installs nothing at run time; the RPM set is unchanged |
| 5.2 | Phase 5 | The spec's defines are `wd2l_pyversion`, `wd2l_rpmversion` and `wd2l_date`, and it has a one-entry `%changelog` | rpm reserves `%rpmversion`; the changelog dates the build and rpmlint expects one |
| 5.3 | Phase 5 rpmlint | rpmlint (EL9) findings left as they are: `non-readable` 0640 env files and `non-standard-dir-perm` 0750/2750 dirs (the modes the design sets); `systemd-unit-in-etc` (the owned drop-in dirs); `specfile-error` on the SRPM (the spec needs its version defines); `non-executable-script` for `/usr/share/wd2l/nftables-wd2l.nft` (a template to copy); `log-files-without-logrotate` (the seal timer keeps a year); `invalid-url` (private repo); no man pages; summaries start with the lowercase name. Fixed: description lines over 79 columns | Advisory only; the CI build runs it every push |
| 4.7 | Phase 6 | `versions.py` comes in Task 4.7, not Phase 6 | `publish` needs the tags first |
| 4.7 | Phase 6 rc tag | Pre-release tags are `vX.Y.ZrcN` (for example `v0.3.0rc1`), not `v0.3.0-rc.1` | The tag is `v` + the PEP 440 version, from one source |
| 5.3 | Phase 6 rpm | The RPMs are built and install-tested by a reusable `rpm.yml` on every push, and `release.yml` calls it | A broken spec shows on the PR, not at release time |
| 6.3 | Phase 6 | Assets include both SRPMs | Source for what's shipped, next to the binaries |
| P0-1 | Phase 0 check 1 | Runner (Ubuntu 24.04, Podman 4.9.3): user 65532 with `--cap-drop all --cap-add NET_RAW` opens and binds AF_PACKET; without `NET_RAW` it gets EPERM. **RHEL with SELinux enforcing: not run yet** (no VM), so it moves to Task 6.5 step 4 | Podman gives an added capability to a non-root user (ambient), so the receiver needs no root inside the container |
| P0-2 | Phase 0 check 2 | **Not run yet** (no RHEL VM). Task 3.5 uses `Exec=… $WD2L_*_ARGS` with `EnvironmentFile=`, as planned; Task 6.5 step 4 checks it; the fallback (options in `Exec=`) stays ready | Your partner chose to go on without the VM |
| P0-3 | Phase 0 check 3 | **Not run yet.** `:z` on the shared mounts, as planned; checked in Task 6.5 step 4 | Same |
| P0-4 | Phase 0 check 4 | **Not run yet.** Option (a): `User=wd2l` with `/etc/passwd` and `/etc/group` mounted read-only, as planned; checked in Task 6.5 step 4 | Same |
| P0-5 | Phase 0 check 5 | Runner: `/sys/class/net/*/statistics` readable as user 65532 with `--network host`. RHEL in Task 6.5 | `hostinfo.nic_stats` works in the container |
| P0-6 | Phase 0 check 6 | Runner: `hi/python:3.12-fips` has `get_fips_mode() == 1` (OpenSSL 3.5.9); MD5 is refused (`[digital envelope routines] unsupported`); SHA-256 works; the whole suite (381 tests then) passes in `3.12-fips-builder`. RHEL in FIPS mode and HEC TLS: Task 6.5 | wd2l needs no change for FIPS |
| P0-7 | Phase 0 check 7 | cosign **v3.1.3** (`hi/cosign`) refuses `--tlog-upload=false` by default. So sign, attest and sign-blob use `--signing-config packaging/release/signing-config.json`, a config with no log and no timestamp service (`{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json","rekorTlogConfig":{},"tsaConfig":{}}`). Verify with `--insecure-ignore-tlog`. Signatures and attestations are OCI referrers (on ghcr, the referrers-tag fallback), and `cosign save` carries them. `verify --local-image`, `verify-attestation --local-image` and `verify-blob --bundle` work with `--network none`. `skopeo copy oci:… containers-storage:…` then `podman run --pull=never IMAGE@DIGEST` works. Tool containers run as the caller (`--user`) with a writable `/tmp` | cosign 3 moved to signing configs; tested end to end in run 37775702487 |
| P0-8 | Phase 0 check 8 | `oras copy -r` (oras 1.3: `--from-registry-config`/`--to-registry-config`; other commands `--registry-config`) copies the index, both platforms and Red Hat's signature referrer into ghcr (oras writes the `sha256-<digest>` referrers tag, since ghcr has no referrers API). The quay `.att`, `.sbom` and `.sig` tags (index and amd64 digests) are copied one by one with plain `oras copy`; `cosign copy` is deprecated in v3 and collides with the referrers tag. The `<release>-source` image copies | Tested in run 37775702487. Also: the runner's `net.core.rmem_max` is 1048576 |
| P7 | Phase 7 | Decision (2026-10-09): **(a)**, a tcpdump image on UBI 10 micro, under Quadlet as non-root with `NET_RAW`, through the same image checks. It is built in a follow-up plan from Task 7.2's design; until then the capture stays on the host. (b) is not pursued for now, (c) is declined | Your partner's choice; ADR-0004 action item 1 says the same |
