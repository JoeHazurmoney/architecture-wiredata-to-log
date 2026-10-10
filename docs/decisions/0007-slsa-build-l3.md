# ADR-0007: SLSA Build Level 3 provenance, alongside the key

**Status:** Proposed
**Date:** 2026-10-10
**Deciders:** System owner. The security owner.

## Context

* The repository is public (2026-10-09). [ADR-0006](0006-release-artifacts-and-signing.md)
  planned GitHub attestations and keyless signatures alongside the key once it was.
* Our provenance (`provenance.py`) is self-asserted: generated and signed in our workflow with
  our key, about SLSA Build Level 2.
* SLSA v1.1 Build L3 adds, on the build platform: runs can't influence one another, and the
  material that signs provenance isn't reachable from the user-defined build steps.
* GitHub documents L3 as: build with reusable workflows, generate attestations there, and
  verify with `--signer-workflow`.
* A run on a throwaway branch (2026-10-10) confirmed four things:
  * the certificate names the reusable workflow at the caller's ref, and the caller's own
    workflow is refused as signer;
  * the bundles verify with no network and no GitHub login (gh 2.102.0);
  * the image's attestation can be pushed to ghcr next to the image;
  * cosign 3.1.3 enforces the repository pin on a keyless signature.

## Decision

* **`attest.yml`, a reusable workflow, is the only place an OIDC token exists.**
  * It makes GitHub build provenance (`actions/attest`) for every line of `SHA256SUMS` and for
    the image in ghcr, and a keyless cosign signature on the image.
  * The build jobs never get `id-token: write`; `tests/test_workflow_policy.py` fails if one does.
* **Runs share nothing** on the release path: no cache and no other run's artifacts. They run
  on GitHub-hosted, ephemeral runners. The same test checks both.
* **Tags only:** a `v*` tag on `main`, created by the admin. `attest` runs only after the
  owner approved `publish`, and its job checks for itself that the run is for a `v*` tag in
  this repository.
* **Verification is pinned** to `--repo`, `--signer-workflow …/attest.yml`, `--source-ref
  refs/tags/v<version>` and `--deny-self-hosted-runners`. The keyless signature's check pins
  the identity and also `--certificate-github-workflow-repository`.
* **The key stays.** Enclaves verify with `cosign.pub` and no network, as before. GitHub's
  provenance can be checked offline too, with the release's bundles and Sigstore's trusted root.

## Options considered

### Option A: `actions/attest` in a reusable workflow (chosen)

| Dimension | Assessment |
|---|---|
| SLSA level | Build L3, as GitHub documents it, with the signer workflow pinned |
| Offline | Yes: `gh attestation verify --bundle --custom-trusted-root` |
| Tools for consumers | `gh` (or cosign) |
| Moving parts | One action, one workflow file |

### Option B: `slsa-framework/slsa-github-generator`

| Dimension | Assessment |
|---|---|
| SLSA level | Build L3, by design (isolated generator workflows) |
| Offline | Yes, with `slsa-verifier` |
| Tools for consumers | `slsa-verifier` |
| Moving parts | Separate generator workflows per artifact type; container and generic flows differ |

Not chosen: it adds a verifier and a generator flow per artifact type for the same level.
Option A uses `gh`, which consumers already have.

### Option C: the key only

Stays as the offline base, but it tops out at about L2: our workflow signs its own claims.

## Consequences

* **Easier:** consumers can check who built a file, from which tag, on which runner, without
  trusting our key.
* **Harder:**
  * Sigstore's public instance is in the trust chain for this path.
  * An offline check needs a trusted root fetched with the release.
  * Keyless signing writes the workflow's identity to the public transparency log, which is
    fine for a public repository.
* **A public reusable workflow can be called by anyone.** In such a call, the certificate
  names our `attest.yml` and tag, but the source repository is the caller's. So:
  * `attest.yml` refuses to run for another repository;
  * every documented check pins our repository (`--repo` for `gh`, and
    `--certificate-github-workflow-repository` for cosign).
* **The claim's limits:** L3 holds as long as `attest.yml` is the only OIDC holder and changes
  only through `main`'s rules. Both are enforced (the policy test, the rulesets).

## Action items

1. [ ] The rc proves it end to end (the plan's Phase 4), then this ADR becomes Accepted.
