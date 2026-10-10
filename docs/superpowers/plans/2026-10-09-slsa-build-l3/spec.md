# Spec: SLSA Build Level 3 provenance for wd2l releases

Approved direction, 2026-10-09. The repository went public that day.
[ADR-0006](../../../decisions/0006-release-artifacts-and-signing.md) said that once public, we
add "GitHub artifact attestations (`actions/attest-build-provenance`) and keyless signatures
**alongside** the key, and keep the key for offline enclaves". This plan does that.

## What SLSA Build L3 requires (SLSA v1.1, "Build levels")

* **L2:** a hosted build platform generates provenance and signs it.
* **L3 adds two things on the platform:**
  * it must "prevent runs from influencing one another, even within the same project";
  * it must "prevent secret material used to sign the provenance from being accessible to the
    user-defined build steps".

## GitHub's route to L3

From "Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3":

1. Build with a reusable workflow.
2. Generate the attestations in that reusable workflow.
3. Grant `attestations: write`, `contents: read`, `id-token: write` (and `packages: write` for
   images) to the caller and the reusable workflow.
4. Verify with `gh attestation verify … --signer-workflow
   <owner>/<repo>/.github/workflows/<reusable>.yml`.

`actions/attest@v4` generates SLSA build provenance by default. `actions/attest-build-provenance`
v4 is a wrapper on it. It needs `id-token: write`, `attestations: write` and
`artifact-metadata: write`. It can push an image's attestation to the registry
(`push-to-registry`). Storage records are for organization-owned repositories only.

## Requirements

1. **Every release file gets GitHub build provenance:** the wheel, sdist, RPMs, SRPMs, image
   tarball, SBOMs, base record and vulnerability summary. The image in ghcr gets provenance too,
   pushed next to it.
2. **One place holds the signing material.** A reusable workflow, `attest.yml`, is the only
   workflow that may get an OIDC token (`id-token: write`). The jobs that build (pip, Podman,
   rpmbuild) never get one, and a test keeps it that way.
3. **Runs can't influence one another:** GitHub-hosted, ephemeral runners, and no cache shared
   between runs anywhere on the release path. A test keeps it that way.
4. **A keyless cosign signature on the image**, made in `attest.yml`, alongside the key
   signature. It's for consumers who pull from ghcr and check signatures with Sigstore's public
   instance (Podman, Kubernetes admission).
5. **The key stays.**
   * `cosign.pub`, the key signatures, the key-signed attestations and `SHA256SUMS.sigstore.json`
     are unchanged.
   * An enclave can still verify everything with `cosign.pub` and no network.
6. **GitHub attestations can be checked offline too.**
   * The release carries every bundle as `wd2l-<version>-attestations.jsonl`.
   * `docs/releasing.md` says how to bring `gh` and Sigstore's trusted root into an enclave, and
     how to verify with `--bundle` and `--custom-trusted-root`.
7. **Only for a `v*` tag on `main`,** as the signing is today. A dry run makes no attestation and
   asks for no OIDC token.
8. **Verification is pinned:**
   * `--repo JoeHazurmoney/architecture-wiredata-to-log`;
   * `--signer-workflow JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml`;
   * `--source-ref refs/tags/v<version>`;
   * `--deny-self-hosted-runners`.

   The release notes print these commands.
9. **A decision record:** ADR-0007. It states the level claimed, and why.
10. **Same proof as before:** Phase 0 checks the things that could change the design on a
    throwaway branch, and an rc proves it end to end, online and offline.

## Not in scope

* Hermetic or reproducible builds as an L3 requirement. The `reproducible` job stays as it is.
* Replacing `provenance.py`'s key-signed predicate. It stays for offline enclaves; GitHub's
  provenance is the L3 one.
* GPG-signed RPMs or a dnf repository.
