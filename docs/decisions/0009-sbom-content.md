# ADR-0009: What the image's SBOMs say, and a page a person can read

**Status:** Proposed (to be accepted once proven on 1.2.0rc1)
**Date:** 2026-10-17
**Deciders:** System owner. The security owner.

## Context

* **What the SBOMs are for.** Each release ships an SPDX and a CycloneDX bill of materials for
  each platform's image. A customer uses them to answer "are we affected?" when a flaw is
  announced, and a reviewer checks them against the fields an SBOM is widely expected to carry:
  supplier, name, version, a unique ID, relationships, author, timestamp, hashes and how it
  was made.
* **What Syft wrote on its own, measured on 1.1.0's amd64 SBOM:**
  * **No supplier** on any of its 66 packages: every one said `NOASSERTION`.
  * **wd2l's own files weren't linked to wd2l.** Syft read wd2l's `RECORD` but linked only the
    3 launchers in `/usr/bin`, out of wd2l's 41 files.
  * **The image was named by where CI kept it,** `/work/image/image.oci.tar`, with its digest
    as the version.
  * **The author was the tool's maker** (`Organization: Anchore, Inc`). Nothing said when in the
    life cycle the SBOM was made.
  * **The namespace was random:** `anchore.com/syft/...` plus a UUID, so two SBOMs of the same
    image never matched.
  * **Not every file was listed.** By default Syft lists only files that belong to a package
    (4,702). Listing every file also lists each directory and symlink: 1,407 entries on amd64,
    with no SHA-256 and no relationships.
* **Its own options don't close the gaps.** `--source-name` and `--source-version` name the image
  properly. `--source-supplier` stamps one supplier on every component, which is wrong for Red
  Hat's RPMs, and writes `Organization:` twice.
* **Who reads them.** The JSON is for tools. A customer's security owner needs to see what is in
  the image, without a JSON viewer, a network connection, or a tool to install.

## Decision

* **Syft makes the SBOMs** ([ADR-0010](0010-sbom-generator.md)), listing every file
  (`SYFT_FILE_METADATA_SELECTION=all`), with the image named as it's published:
  `--source-name ghcr.io/joehazurmoney/wd2l --source-version <version>`.
* **[`sbom_enrich.py`](../../packaging/container/sbom_enrich.py) completes them** in the `sbom` job,
  before anything reads them. **Any gap fails the run**, so a weaker SBOM never ships quietly.
  * **Suppliers, by rule, failing closed.** Each component's supplier comes from its package ID:
    * `pkg:rpm/redhat/` and `pkg:rpm/hummingbird/`: Red Hat, Inc.;
    * `pkg:pypi/wd2l@`, and the image itself: wd2l project;
    * CycloneDX's operating-system entry, by distribution (`hummingbird`, `rhel`): Red Hat, Inc.;
    * a language package that an OS package installed, such as UBI 9's Python packages from
      Red Hat's RPMs: that package's supplier. The files Syft found it by must be that one
      package's, and only one supplier's.

    A component that no rule covers fails the run, so a new dependency can't arrive
    unattributed. The rules match the start of the package ID, so a look-alike name doesn't match.
  * **wd2l's files,** in the SPDX SBOM, which records the component that installed each file
    (Syft's CycloneDX lists the files, each with its hashes, but not their component). wd2l is
    given:
    * every file in the wheel's `RECORD`, each with its SHA-256 checked against it;
    * the files the installer writes in its `dist-info` directory;
    * the compiled `.pyc` of its own modules.

    A file in wd2l's directory that `RECORD` doesn't list, a listed file that's missing, or a
    file whose hash differs fails the run. wd2l's package verification code is recomputed over
    its files.
  * **Directories and links are dropped.** They have no SHA-256 and no relationships. One that
    has a relationship is kept, and fails the run.
  * **The author and the generation context.** The author is the project
    (`Organization: wd2l project`), and Syft stays named as the tool. When it was made is
    recorded as CycloneDX's `post-build` lifecycle, and as SPDX's creation comment.
  * **An SPDX namespace of our own:** `<repository>/sbom/<image>-<version>-<platform>-<digest>`.
    The same image always gets the same namespace, and no two images share one. (CycloneDX's
    serial number stays the random one Syft gives each document, as that format intends.)
  * **A hash on each component (#190), in both formats.**
    * Each RPM gets its header's SHA-256: the digest rpm records for that exact build, read
      from the image's own RPM database (`rpm -q --qf '%{SHA256HEADER}'` gives the same on a
      host). An RPM missing from the database is a gap.
    * wd2l gets the SHA-256 of the wheel it was installed from.
    * Red Hat's own SBOM of the base hashes 2 of its 224 packages, so there was none to reuse.
* **SBOMs of the release's own packages (#190):** `wd2l-<version>-rpms-el9`, `-rpms-el10` and
  `-python`, each in SPDX and CycloneDX, made at release by
  [`package_sbom.py`](../../packaging/release/package_sbom.py) from the packages' own metadata
  ([ADR-0010](0010-sbom-generator.md)).
  * **Each RPM:**
    * its file's SHA-256 and SHA-1, and its payload's and header's digests;
    * its license;
    * every file it installs, with its SHA-1 and SHA-256. The files are hashed from its payload
      and checked against the header's digests, so a mismatch fails the release.
  * **What an RPM needs from the host:** its `Requires`, less rpm's internal `rpmlib()` entries
    and what the set provides itself. Each need is a package of its own, marked "required from
    the host, not shipped", with its version range: SPDX `DEPENDS_ON`, and CycloneDX `isExternal`
    with a `versionRange`. The set's own RPMs depend on each other.
  * **The Python package:** the wheel and the sdist, each with its files (the wheel's checked
    against its RECORD). The hash-pinned tools that built them are recorded as build
    dependencies (CycloneDX scope `excluded`), never as runtime ones. wd2l itself needs nothing
    at run time.
  * **Determinism:** the supplier and author are the wd2l project, and the generation context
    is `build`. The time is the commit's, and the namespace and serial number follow from the
    files. So the same files give the same SBOMs.
* **A readable page with every release: `wd2l-<version>-sbom.html`**
  ([`sbom_report.py`](../../packaging/release/sbom_report.py)).
  * **What it shows:**
    * one tab per image, and per package set (each RPM's host needs, and the Python package's
      build tools, listed under it), with a table comparing them at the top;
    * the components by default, each expanding to the files it installed, with their SHA-256;
    * "Show every entry", and a search box;
    * each component's known vulnerabilities, merged across the scanners, with which scanner
      found each one;
    * the fields an SBOM is expected to carry, and whether this one carries each.
  * **It loads nothing.** There is no external stylesheet, script, font or image, and a
    Content-Security-Policy forbids them, so it opens offline inside an enclave. Without
    JavaScript it shows every image in turn.
  * **The JSON stays the authority,** and the page says so. The page is a release file like the
    rest: it's in the release manifest (kind `sbom-report`), in the signed `SHA256SUMS`, and
    covered by the provenance.
  * **It takes views and named scans** (`--view ID LABEL SPDX CDX`, `--scan ID NAME=FILE`). So
    another image, another scanner, or a page about some other system needs no new code.

## Options considered

### The SBOM's gaps

#### Option A: complete Syft's output with a script that fails closed (chosen)

| Dimension | Assessment |
|---|---|
| Suppliers | Every component, by a rule anyone can read; a new origin stops the run until it has a rule |
| wd2l's files | Every file, each checked against the wheel the release ships |
| Cost | A script and its tests (`tests/test_sbom.py`), which pin the shape Syft writes |

#### Option B: Syft's own options only

`--source-name` and `--source-version` are used. `--source-supplier` would name one supplier
for all 66 components, so it isn't used.

#### Option C: ship Syft's output as it is

The gaps above are the first things a reviewer finds.

#### Option D: a hand-kept supplier for each package

It would go stale with every base update. A rule by package ID covers a new package from the
same origin, and stops the run when a new origin arrives.

### The readable form

#### Option A: a static HTML page, made in the release (chosen)

It opens in any browser, offline, and stays a release file with a checksum.

#### Option B: send reviewers to an SBOM viewer

A hosted viewer needs a network, and a desktop viewer needs installing. Neither is in every
enclave.

#### Option C: a PDF

A PDF can't expand a component to its files, and 4,752 files make it very long. It would also
need a renderer in the pipeline.

## Consequences

* **Easier:**
  * every component names its supplier, and every file has a SHA-256;
  * wd2l's own files are tied to the wheel the customer also receives;
  * a security owner reads one page, offline.
* **Harder:**
  * a new base or a new kind of package needs a supplier rule before the run passes. That's the
    intent;
  * a Syft update that changes its output's shape fails the enrichment. It's caught there, by a
    gap, instead of shipping a weaker SBOM.
* **The sizes:** about 3.7 MB of SPDX and 1.5 MB of CycloneDX per platform, about what 1.1.0
  shipped. The page is about 1.7 MB for both platforms.
* **Component hashes, measured on 1.1.0's images:**
  * the Hardened image has a SHA-256 on all 65 of its components;
  * UBI 9 has one on 189 of 207. Its Python packages that RPMs installed have none of their
    own; their RPMs' hashes cover them.
* **The package SBOMs, on 1.1.0's files:** each RPM set has 3 RPMs and 91 files. It needs, for
  example, `python3 >= 3.9`, systemd, nftables and tcpdump from the host.

## Action items

1. [x] The enrichment, the page, their tests, and both in the release (#188, #189).
2. [ ] Proven on 1.2.0rc1, then this ADR becomes Accepted.
3. [x] The UBI 9 image's tab (#192).
4. [x] The RPMs', wheel's and sdist's SBOMs, and package hashes (#190).
