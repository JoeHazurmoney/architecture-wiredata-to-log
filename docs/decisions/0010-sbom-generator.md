# ADR-0010: Syft makes the SBOMs

**Status:** Proposed (to be accepted once proven on 1.2.0rc1)
**Date:** 2026-10-17
**Deciders:** System owner. The security owner.

## Context

* **Syft came in with the image (#10, 2026-10-09)** with no recorded reason. This ADR records one,
  tested against the alternatives on a real release.
* **What the tool must do** ([ADR-0009](0009-sbom-content.md)):
  * read the image from an OCI archive, offline, with no container daemon;
  * catalog the base's RPM database (sqlite), whether or not a scanner supports the base's
    operating system, and Python's `dist-info`;
  * list every file with its SHA-256, which wd2l's file links and the readable page rely on;
  * write SPDX 2.3 and CycloneDX 1.7;
  * be pinned by digest, and moved by Dependabot, like every other tool.
* **The evidence: each tool's SBOM of 1.1.0's amd64 image** (`ghcr.io/joehazurmoney/wd2l@sha256:5fd02bb6…`),
  made on 2026-10-17:

  | Tool | The 64 RPMs | Files listed | Suppliers | Package hashes |
  |---|---|---|---|---|
  | Syft 1.54.1 | 64, each with a package ID (`pkg:rpm/redhat/…`) | 4,752, each with SHA-1 and SHA-256 | none (ADR-0009 adds them) | SPDX's verification code, on 57 of 66 |
  | Trivy 0.75.0 (upstream) | named, but **none has a package ID**: Trivy doesn't recognize the operating system | 1 (wd2l's `METADATA`, SHA-1 only) | none | MD5, on 62 |
  | Trivy 0.75.0 (Red Hat's build) | 64, each with a package ID (`pkg:rpm/hummingbird/…`) | 1 | none | MD5, on 62 |

  * **A package ID is what a scanner matches.** Upstream Trivy's SBOM names the RPMs, but no
    scanner could match them against advisories.
  * **Red Hat makes its own base SBOM with Syft** (1.51.1), with its build tools hermeto and
    Mobster, by its `creators` (`base-evidence/sbom-0-amd64.spdx.json`, run 39034618013).
  * **Both Trivy builds warn about the SBOM inside the image.** Reading the SBOM Red Hat ships in
    the base, they log "Third-party SBOM may lead to inaccurate vulnerability detection" and
    recommend Trivy-made SBOMs. Their own SBOMs, above, list no files.

## Decision

* **Syft makes every SBOM wd2l ships,** run by digest from `packaging/ci/tools.Containerfile`.
  It meets each need above:
  * it reads `oci-archive:` offline;
  * it reads the RPM database on Hummingbird, an operating system upstream Trivy doesn't
    recognize;
  * it lists every file with its SHA-256;
  * it writes both formats;
  * it's licensed under Apache-2.0.
* **`sbom_enrich.py` fills what Syft leaves out** (ADR-0009). Its tests pin the shape Syft 1.54
  writes, and a release fails on any gap. So a Syft update that changes that shape is caught, not
  shipped.
* **The SBOM isn't the scanners' input.** Grype and Trivy each read the image itself. A gap in the
  SBOM can't hide a vulnerability from them, and a scanner's blind spot can't empty the SBOM.

## Options considered

### Option A: Syft (chosen)

| Dimension | Assessment |
|---|---|
| The RPMs | All 64, each with a package ID, on a base upstream Trivy doesn't recognize |
| Files | Every one, with SHA-256 |
| Formats | SPDX 2.3 and CycloneDX 1.7 |
| What Red Hat uses | The same tool, for the base's own SBOM |
| Gaps | Suppliers, wd2l's files and the author, filled by `sbom_enrich.py` |

### Option B: Trivy (upstream)

Its SBOM gives the RPMs no package ID, because it doesn't recognize Hummingbird. It lists no
files.

### Option C: Trivy (Red Hat's build)

It gives the RPMs package IDs, but lists no files and no file hashes, which ADR-0009's file links
and the readable page need. Red Hat ships it only as an RPM, with no image, so wd2l would also
have to build a tool image to run it.

### Option D: cdxgen

Not run against the image. By its documentation, it reads an image's operating-system packages
through a bundled build of Trivy (`cdxgen-plugins-bin`), so it would carry the coverage measured
in Option B.

### Option E: Microsoft's sbom-tool

Not run against the image. It finds an image's components through Microsoft's Component
Detection, which, by its documentation, runs Syft for containers. It would add a layer around the
same tool.

### Option F: Red Hat's SBOM of the base, alone

It leaves out wd2l, its files, and what the build changes (the base's pip is removed).

## Consequences

* **Easier:**
  * the SBOM's RPMs are those Red Hat's own SBOM lists, found the same way;
  * one tool and one pin make the SBOM of every platform, and of the comparison image (#192).
* **Harder:**
  * Syft's gaps are wd2l's to fill, and its tests have to follow Syft's output across updates;
  * Syft runs with `-q`, which hides its own warnings, until #191 raises every tool's warnings
    on the run.

## Action items

1. [x] Measured against the Trivy builds on 1.1.0's image (2026-10-17).
2. [ ] Proven on 1.2.0rc1, then this ADR becomes Accepted.
