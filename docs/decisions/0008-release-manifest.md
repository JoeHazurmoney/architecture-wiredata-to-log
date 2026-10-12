# ADR-0008: A release manifest with every release

**Status:** Proposed (2026-10-12)
**Date:** 2026-10-12
**Deciders:** System owner. The security owner.

## Context

* A customer receiving a release needs one document that says, officially:
  * what was delivered, file by file;
  * which issues it resolves;
  * how to check that what they hold is what was built.

  The same document has to work years later, as reference, without the forge (e.g. GitLab,
  GitHub) that produced it.
* Most of the evidence already exists, spread across the release:
  * `SHA256SUMS` and its key signature;
  * SLSA provenance for every file and the image ([ADR-0007](0007-slsa-build-l3.md));
  * the base-image record, an SBOM and a scan summary per platform;
  * the immutable release, which the forge attests at publication
    ([ADR-0006](0006-release-artifacts-and-signing.md)).
* Two things are missing:
  * **Nothing ties the evidence together.** No single file names it all for one release.
  * **The changes.** Until 2026-10-12, work was tracked in pull requests only. There were no
    issues, so nothing listed what a release resolves.
* The goal is to **retrieve** a release, not rebuild it. Fetching exactly what shipped, and
  showing it's unchanged, is achievable. A byte-identical rebuild years later depends on too
  many inputs outside our control. The reproducible builds stay a verification exercise, not a
  promise.
* Two releases showed gaps in the process:
  * **0.3.0rc5's run stalled** at an approval gate during a forge outage. The run was deleted,
    and a new run couldn't recover the version.
  * **0.3.0rc6 was published by hand** instead of from the workflow's draft. The result was an
    immutable release with no files (#27).

## Decision

* **The manifest.** Each release has `wd2l-<version>-release-manifest.json`.
  * It's validated against a committed JSON Schema (`packaging/release/release-manifest.schema.json`),
    and the release fails on an invalid one. A malformed manifest is worse than none, because it
    still looks authoritative.
  * A generated markdown view, `wd2l-<version>-release-manifest.md`, is the customer's version
    description. The JSON is the source of truth, and the markdown is only a view.
* **What it records:**
  * **Identity and source:** the version, the tag, the full 40-character commit, the previous
    final release, and the run that made it.
  * **Changes:**
    * every pull request merged since the previous final release;
    * the issues each one closes, as the union of `Closes #N` in the commit message and the
      links the forge records;
    * the first release that contained each change;
    * any pull request with no issue, listed separately so gaps show.
  * **Known issues:** open bugs at release time.
  * **Deliverables:** every release file, with its SHA-256 and size.
  * **The image:** the index and per-platform digests, and the base images.
  * **The build environment, as pinned at the commit:** actions by SHA, and tool images by
    digest.
  * **The changelog,** with the tool and configuration that made it.
  * **Approvals:** those given before the manifest was sealed.
  * **How to verify it.**
* **Issue categories.** Customer-facing issues are grouped by category label: `enhancement`,
  `bug`, `security`, `documentation`, `dependencies`, `release`. Issues recorded after the work
  merged carry `retroactive` and are dated by their pull request's merge, since the forge can't
  backdate a closing date.
* **The convention behind the changes** (`docs/releasing.md`, "Conventions"):
  * the pull request (merge request) title is a Conventional Commit, enforced in three layers;
  * the squash commit lands the title and description unchanged, so the issue links are in git
    history;
  * the changelog is generated from that history by git-cliff, grouped by commit type.
* **It's a release file, made before `SHA256SUMS`,** in the `assets` job, which holds no
  secrets and no OIDC token. Three existing protections then cover it, with no new signing
  path:
  * the key signature on `SHA256SUMS`;
  * SLSA provenance from `attest.yml`;
  * the forge's release attestation at publication.
* **Retrieval offline.** Each release also has a full-history `git bundle` of the source and
  `verify-release`, a standard-library Python script that checks a directory of release files
  with no network:
  * the `SHA256SUMS` signature, and every checksum;
  * the manifest against both;
  * the bundle's commit.

  A timed retrieval drill on a clean host proves it.
* **Release notes are generated.** They come from the manifest and `docs/releases/<version>.md`.
  The person publishing opens the workflow's draft and publishes it, and never makes a release
  by hand.

## Options considered

### Option A: a release file made in the `assets` job (chosen)

| Dimension | Assessment |
|---|---|
| Integrity | Covered by the key signature, SLSA provenance and the release attestation, like every other file |
| Secrets near forge data | None: the job has read permissions only |
| Dry runs | Made on every dry run too, so a branch shows a real manifest |
| Limits | Can't name the attestations made after it, or the final approval |

### Option B: made in the `release` job, after `attest`

It could name the attestation IDs and the final approval. But it would hold the signing secrets
while it reads untrusted forge data, it would need a signature of its own, and it would have no
SLSA provenance. Attestations can be found by digest anyway, and the final approval is *of* the
manifest, so it belongs outside it.

### Option C: the release notes alone

The notes are markdown on a forge page. They have no schema and aren't covered by
`SHA256SUMS`, and they're gone if the forge is.

### Option D: an attestation attached to the image

It would travel inside the OCI tars. But the manifest describes the whole release, not the
image, and `publish` runs before the files it lists are final.

## Consequences

* **Easier:**
  * a customer gets one signed document listing what was delivered and why;
  * a reviewer approving the `release` gate reads the manifest first, in the run summary;
  * years later, the release files alone are enough to check and restore a release.
* **Harder:**
  * every change needs an issue and a conventional title;
  * the `assets` job reads the forge's API, so an outage there fails the job. The fix is to
    re-run the failed jobs (`docs/releasing.md`).
* **The spec's items, and where each landed:**

  | Item | In wd2l |
  |---|---|
  | Identity, previous release, generated by | Adopted |
  | Components keyed on immutable IDs; full SHAs; digests, never tags | Adopted (one repository: the commit; the image by digest) |
  | Pipeline provenance: pinned templates, job images, tools | Already covered by SLSA provenance and the pins at the commit; the manifest lists the pins |
  | Deployed artifacts with digests | Already covered by `SHA256SUMS` and the image index; the manifest lists them |
  | Integrity: signature, certificate chain, timestamp | Already covered. The raw signing key has no certificate to expire; keyless signatures carry transparency-log timestamps |
  | Approvals | Those before sealing are in the manifest. The final one signs it, and the forge attests publication |
  | Cross-references (issues) | Adopted |
  | Schema validation that fails the pipeline; markdown view | Adopted |
  | Offline bundle and retrieval script | Adopted, alongside the existing OCI tars, RPMs and checksums |
  | Retrieval drill | Adopted (#38) |
  | Deployment binding | Out of scope: deployment records belong to the customer's site |
  | Code-size metrics | Deferred |
  | A separate manifest repository | Not needed: the manifest is a file of the release it describes |
* **Retention:**
  * Release files are permanent. Nothing relies on workflow artifacts, which expire after
    90 days, once a release is published.
  * The container registry has no cleanup policy, and none may ever match version tags.

## Action items

1. [ ] The schema, the generator and the markdown view (#32, #33).
2. [ ] The git-cliff changelog (#34).
3. [ ] The source bundle and `verify-release` (#35).
4. [ ] Proven end to end on 1.0.0rc1 (#36), then this ADR becomes Accepted.
5. [ ] The retrieval drill on a clean host (#38).
