# ADR-0006: Release artifacts and how they are signed

**Status:** Proposed
**Date:** 2026-10-08
**Deciders:** System owner. The security owner, who holds the signing key.

## Context

A version tag must produce everything a site needs, verifiable in an enclave that has no
internet:

* RPMs for RHEL 9 and RHEL 10;
* the container image ([ADR-0004](0004-container-base-image.md));
* the wheel and sdist they are made from.

An assessor must be able to show, for any running copy, where it came from: the commit, the
build, the base image and its sources.

Constraints:

* **The repository is private for the proof of concept.** It will go public under the MIT license
  afterwards.
* **Private-repository limits.** GitHub's artifact attestations need GitHub Enterprise Cloud in a
  private repository. Keyless Sigstore signing writes the repository's identity to the public
  Rekor log.
* **Offline verification.** Enclaves verify from files: no Rekor, no Fulcio, no GitHub.

## Decision

* **Artifacts:**
  * **From one wheel,** built once with `wd2l/BUILD` (the commit): the RPMs (three noarch
    packages each for EL9 and EL10, plus the two SRPMs) and the image.
  * **The image goes out twice:** pushed to `ghcr.io/joehazurmoney/wd2l`, and saved with
    `cosign save` as an OCI layout that carries its signature and attestations.
  * **SBOMs** (SPDX and CycloneDX) and `base-image-record.json`.
  * **`SHA256SUMS`** over all of the above.
* **Signing:**
  * **A cosign key pair.** The private key is only in the Actions secrets. The public key is
    `cosign.pub` in the repo and in every release.
  * **No transparency log.** cosign 3 signs with a signing config that names no log and no
    timestamp service (`packaging/release/signing-config.json`). Every verification is offline
    with `--insecure-ignore-tlog`, which only means "don't look in the public log".
  * **What gets signed:** the image, by digest, and `SHA256SUMS`, which covers every asset.
  * **Attestations on the image:** the SBOM, SLSA provenance (commit, workflow, wheel digest,
    base digests), the vulnerability scan results and the base-image record.
* **The base's records.** Every release copies its base images into
  `ghcr.io/joehazurmoney/wd2l-base/python`, by digest:
  * Red Hat's signature, which `oras copy -r` brings along as an OCI referrer;
  * the SLSA provenance, SBOM and Konflux signature, which quay publishes as `.att`, `.sbom` and
    `.sig` tags; each tag is copied as it is;
  * the matching source image (`<release>-source`, the SRPMs).

  They are kept as long as the release is supported.
* **A person publishes.** The workflow creates a **draft** release, and a maintainer reviews and
  publishes it.

## Options considered

### Option A: cosign key pair, no transparency log (chosen while private)

| Dimension | Assessment |
|---|---|
| Works offline | Yes: one public key file. Tested: `verify --local-image`, `verify-attestation --local-image` and `verify-blob --bundle` pass with no network |
| Private repo | Nothing is published outside GitHub |
| Key management | We hold one key: generation, storage, rotation and compromise response below |
| Strength of provenance | Self-asserted, signed by our key: about SLSA Build L1–L2 |

### Option B: keyless Sigstore and GitHub artifact attestations

| Dimension | Assessment |
|---|---|
| Works offline | Only with a copied trust root and a bundle that includes the log proof |
| Private repo | Needs a public repository (or Enterprise Cloud); writes the identity to the public log |
| Key management | None: short-lived certificates from GitHub's OIDC identity |
| Strength of provenance | SLSA Build L3 from GitHub's isolated builder |

Added **alongside** A once the repository is public.

### Option C: GPG-signed RPMs and a dnf repository

| Dimension | Assessment |
|---|---|
| Works offline | Yes, with the key imported into rpm |
| Private repo | Fine |
| Key management | One more key, and a repository to host in each enclave |
| Strength of provenance | Signs the packages only |

Deferred; the signed `SHA256SUMS` covers the RPMs today.

### Option D: checksums only

| Dimension | Assessment |
|---|---|
| Works offline | Yes |
| Strength of provenance | None: shows the files match each other, not who made them |

Rejected.

## Key management

* **Generation:** `cosign generate-key-pair` by the security owner, on a trusted machine.
  * The password goes in the secret `COSIGN_PASSWORD`, the private key in `COSIGN_PRIVATE_KEY`.
  * `cosign.pub` is committed.
  * The local private key is then stored offline, or destroyed.
* **Who can cause a signature:** only a `v*` tag on a commit already on `main`, and only once
  the owner approves the run. The signing secrets live in the `release` environment, which only
  `v*` tags may use and whose runs the owner approves; a ruleset lets only the admin role create
  `v*` tags; `main` takes changes only through PRs with green CI, with no bypass
  ([releasing.md](../releasing.md#one-time-setup)).
* **Rotation:** a new pair, a new `cosign.pub` committed, and the old one moved to
  `keys/retired/cosign-<from>-<to>.pub`. Releases signed with the old key stay verifiable with
  it.
* **Compromise:**
  1. Remove the secrets.
  2. Publish a notice that names the window.
  3. Rotate the key.
  4. Re-sign the supported releases' `SHA256SUMS` and images with the new key.

## Trade-off analysis

* **Integrity of what's installed** (e.g. NIST SI-7, CM-14). Verifying `SHA256SUMS` and the image
  signature before anything is installed proves the files are the ones this repository's workflow
  built.
* **Provenance** (e.g. NIST SR-4, SR-11). The provenance names the commit, and the base-image
  record names the exact Red Hat image. That record carries the base's own signature, provenance,
  SBOM and sources.
* **Offline first.** Everything an enclave needs to verify is in the release: the files, the
  signatures and `cosign.pub`.

## Consequences

* **Easier:** one key, one command per artifact, and it works the same online and offline.
* **Harder:**
  * The key is ours to protect.
  * Our provenance is self-asserted until the repository is public. It is still bound to the
    commit, and it is signed.
  * cosign 3 prefers signing configs; a later version may change these flags again. The release
    plan's Phase 0 check 7 is the test to rerun after a cosign upgrade.
* **Revisit** when the repository goes public:
  * add GitHub artifact attestations (`actions/attest-build-provenance`) and keyless signatures
    **alongside** the key, and keep the key for offline enclaves;
  * upload the scanners' SARIF to code scanning;
  * make the packages public, and turn on immutable releases.

## Update: the repository is public (2026-10-09)

* **Done:** the scanners' SARIF goes to code scanning from `main`; the packages are public; the
  signing jobs run in the `release` environment (owner approval, `v*` tags only), whose secrets
  replace the repository's; rulesets
  protect `main` (PRs with green CI, no bypass) and `v*` tags (admin only); actions must be
  pinned by SHA; secret scanning, push protection and Dependabot security updates are on.
* **Still to do:** immutable releases (a setting).
* **GitHub artifact attestations and keyless signatures** alongside the key: done,
  [ADR-0007](0007-slsa-build-l3.md) (from 0.3.0rc3).
* **Unchanged:** the key pair and offline verification. Enclaves still verify with
  `cosign.pub` and no network.
