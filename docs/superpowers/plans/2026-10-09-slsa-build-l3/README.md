# SLSA Build Level 3 provenance: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every wd2l release GitHub build provenance that meets SLSA v1 Build Level 3:
every file and the image, plus a keyless signature on the image. All of it sits alongside the
existing cosign key signing, and all of it can be verified offline.

**Architecture:**

* **One reusable workflow, `attest.yml`, is the only place an OIDC token exists.**
  * It runs `actions/attest@v4` over every line of `SHA256SUMS` and over the image digest, and
    signs the image keylessly with cosign.
  * The jobs that build (`image.yml`, `rpm.yml`, the asset assembly) never hold `id-token: write`,
    so their steps can't reach the signing material.
  * Consumers pin `--signer-workflow …/attest.yml`.
* **`release.yml` changes shape:**
  * a new `assets` job assembles the files and `SHA256SUMS` (the old `release` job's first half);
  * `attest` calls `attest.yml` on tags only;
  * `release` key-signs `SHA256SUMS`, writes the notes and drafts the release, now with
    `wd2l-<version>-attestations.jsonl` attached.
* **Policy is tested.** A new `tests/test_workflow_policy.py` reads the workflow files. It fails
  if:
  * any other job asks for `id-token: write`;
  * anything is shared between runs on the release path, or a job there runs on a runner that
    isn't GitHub-hosted;
  * attestation could run off a tag, or for another repository.

**Tech Stack:**

* GitHub Actions: `actions/attest` v4.2.2 (pinned by SHA), `gh attestation verify`.
* cosign v3.1.3 (`hi/cosign`), keyless with GitHub's OIDC, through `packaging/ci/tool`.
* Python ≥ 3.9 stdlib and pytest for `notes.py` and the policy tests.

**Spec:** [spec.md](spec.md). Executors read it with this plan.

## Phases

| Phase | File | Delivers | Tasks |
|---|---|---|---|
| 0 | [phase-0-checks.md](phase-0-checks.md) | The five checks that could change the design, run on a throwaway branch, results recorded | 0.1–0.2 |
| 1 | [phase-1-attest-workflow.md](phase-1-attest-workflow.md) | Policy tests; `attest.yml` (file and image provenance); `release.yml` reshaped; bundles in the release | 1.1–1.2 |
| 2 | [phase-2-keyless-image-signature.md](phase-2-keyless-image-signature.md) | The keyless cosign signature on the image, checked right after signing | 2.1 |
| 3 | [phase-3-verification-docs.md](phase-3-verification-docs.md) | Release notes with the `gh attestation verify` commands; `releasing.md` online and offline; ADR-0007 | 3.1–3.3 |
| 4 | [phase-4-rc-and-close.md](phase-4-rc-and-close.md) | An rc proves it end to end, online and offline; ADR-0007 Accepted | 4.1–4.2 |

**Order:** Phase 0 runs first. Its results can change Phases 1 and 2; each task names the
check it depends on. Phases 1 to 3 merge as one PR. Phase 4 runs on `main` after the merge.

## Global constraints

* **The key path is unchanged.** These all stay exactly as they are:
  * `cosign.pub`;
  * `publish.yml`'s key signature and key-signed attestations;
  * `cosign save`;
  * `SHA256SUMS.sigstore.json`;
  * `verify-published`.
* **An enclave can verify a release with `cosign.pub` and no network,** as `docs/releasing.md`
  says today.
* **Only `attest.yml` may hold `id-token: write`.** A caller job may grant it only to a job
  that `uses: ./.github/workflows/attest.yml`. No workflow may use `write-all`.
* **`attest.yml` runs only for this repository and a `v*` tag.** Its job's own `if:` says so.
  The repository is public, so any other repository can call `attest.yml` at one of our tags.
  In that call, `actions/checkout` fetches the *caller's* code, which would then run next to
  the OIDC token and get a certificate naming our `attest.yml@refs/tags/v…`.
* **Keyless verification pins the source repository:**
  `--certificate-github-workflow-repository JoeHazurmoney/architecture-wiredata-to-log`, on
  top of `--certificate-identity`. `gh attestation verify` already pins it, through `--repo`.
* **Nothing shared between runs in `tests.yml`, `image.yml`, `rpm.yml`, `publish.yml`,
  `release.yml` or `attest.yml`:**
  * no `actions/cache`, no `cache:` input (setup-python) and no `type=gha`;
  * no `run-id:` on download-artifact, so no artifacts from another run;
  * only GitHub-hosted runners (`ubuntu-24.04`, `ubuntu-latest`).
* **Attestation and keyless signing run only when `startsWith(github.ref, 'refs/tags/v')`.**
  `release.yml` already refuses a tag that isn't on `main`.
* **Every `uses:` is pinned to a full commit SHA**, with the version in a comment. The repository
  setting `sha_pinning_required` enforces it.
* **The signer workflow** is `JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml`,
  and the source ref is `refs/tags/v<version>`.
* **Names:** the image is `ghcr.io/joehazurmoney/wd2l`; the attestations asset is
  `wd2l-<version>-attestations.jsonl`.
* **Repository rules apply:**
  * `main` takes changes only through a PR whose `ci-ok` check passed;
  * `v*` tags are admin-only;
  * the `release` environment needs the owner's approval for each tag run.
* **Docs name controls generically,** with NIST SP 800-53 or SOC 2 only as examples. ADRs may
  name NIST controls.
* **Outward actions need your partner's OK:** pushing a branch other than the plan's, tags,
  releases, and repository settings.

## Review focus

1. **A dry run, on `main` or a branch, must not ask for an OIDC token or an approval, and must
   not attest.** Tests: `test_attestation_runs_only_for_a_tag` (Task 1.2) and
   `test_attest_yml_runs_only_for_this_repo_and_a_tag` (Task 1.1).
2. **A release built from a branch, or rebuilt from another ref, must not verify as the tag.**
   The documented commands pin `--source-ref refs/tags/v<version>`. Test:
   `test_notes_show_how_to_verify_the_github_attestations` (Task 3.1).
3. **Enclaves with a stale Sigstore trusted root.** Offline verification with an old
   `trusted_root.jsonl` may fail after Sigstore rotates keys. `releasing.md` says to carry the
   trusted root fetched with that release, and how to refresh it (Task 3.2).
4. **The attestations bundle must cover what is downloaded.** Its subjects come from
   `SHA256SUMS`, after the `~` → `.` rename. Test: `test_attest_reads_the_checksums_the_release_lists`
   (Task 1.1).
5. **A failure after `publish` must leave no half-made release.** If `attest` fails, `release`
   must not draft. Test: `test_release_waits_for_attest_on_a_tag` (Task 1.2).
6. **Another repository calling `attest.yml`** must get no OIDC token, and a signature made
   that way must not verify. Tests: `test_attest_yml_runs_only_for_this_repo_and_a_tag`
   (Task 1.1), `test_attest_signs_the_image_keylessly_and_checks_the_identity` (Task 2.1),
   `test_releasing_md_pins_the_signer_workflow_and_the_tag` (Task 3.2).

## File map

| File | Change |
|---|---|
| `.github/workflows/attest.yml` | **New.** The reusable workflow that attests and signs keylessly |
| `.github/workflows/release.yml` | New `assets` and `attest` jobs; `release` downloads both and attaches the bundles |
| `tests/test_workflow_policy.py` | **New.** OIDC, cache and tag-only policy over the workflow files |
| `packaging/release/notes.py`, `tests/test_release_tools.py` | The `gh attestation verify` commands in the notes |
| `docs/releasing.md` | Verifying GitHub attestations, online and offline; the keyless signature |
| `docs/decisions/0007-slsa-build-l3.md` | **New.** ADR |
| `docs/decisions/0006-release-artifacts-and-signing.md` | Its update section points to ADR-0007 |

## Running tests on this machine

As in the [release plan](../2026-10-07-release-packaging/README.md#running-tests-on-this-machine):
`T -q` (Python 3.9) and `T312 -q` (3.12) in Docker, and `actionlint` for workflows:

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/repo -w /repo rhysd/actionlint:latest -color=false

# L FILE: every relative markdown link in FILE resolves; prints "missing: <link>" for each that doesn't
L() { f="$1"; d="$(dirname "$f")"; for l in $(grep -oE '\]\([^)#:]+(#[^)]*)?\)' "$f" \
      | sed -E 's/^\]\(//; s/\)$//; s/#.*//' | sort -u); do [ -e "$d/$l" ] || echo "missing: $l"; done; }
```

The workflows themselves are checked in CI: Phase 0's branch, the PR's runs, a release dry run,
and the rc.

## As-built log

| Task | Spec | As built | Why |
|---|---|---|---|
| Review (2026-10-10) | Req. 2, 3, 7, 8 | Before Phase 0, the plan was checked against the code and amended. `attest.yml`'s job checks its own repository and tag. Keyless `cosign verify` pins `--certificate-github-workflow-repository`. The policy tests also cover `write-all`, `cache:`, `type=gha`, `run-id:` and GitHub-hosted runners. Phase 0's `verify` logs in to ghcr for P0-3 and runs every check even when one fails. The docs' offline loop reads `SHA256SUMS`. Task references are fixed | A public reusable workflow can be called from any repository, and it then checks out the caller's code next to the OIDC token. Req. 3 asks for a runner test. The globs missed the SBOMs and records that req. 1 covers |
| Review (2026-10-10) | Req. 4 | The docs present the keyless signature as being for cosign and for admission controllers that read Sigstore bundles. They don't promise Podman | `containers.md`: it isn't confirmed that Podman's `sigstoreSigned` reads cosign 3 referrer bundles, and the keyless signature is stored the same way |
| P0-1 | Req. 1, 2, 8 | Run [38064386319](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/actions/runs/38064386319): `actions/attest@v4.2.2` in a reusable workflow, in this user-owned repo, made one attestation for both lines of `SHA256SUMS` ("Attestation created for 2 subjects"). It needed no `artifact-metadata: write`. `--signer-workflow …/slsa-phase0-attest.yml` passes, and the caller's `slsa-phase0.yml` is refused. The certificate's SAN and Build Signer URI are `https://github.com/JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/slsa-phase0-attest.yml@refs/heads/slsa-phase0`: the reusable workflow, at the caller's ref. Source Repository URI is this repo, `runnerEnvironment` is `github-hosted`. No fallback | The design holds: `attest.yml@refs/tags/v<version>` is the identity Phases 1–3 pin |
| P0-2 | Req. 6 | Same run: `gh attestation verify --bundle … --custom-trusted-root …` passes under `sudo unshare --net` with `GH_TOKEN` empty: no network, no login. gh 2.102.0. No fallback | The offline path documented in Task 3.2 works as written |
| P0-3 | Req. 1 | Same run: with `docker login` and `create-storage-record: false`, the image attestation is pushed to ghcr as an OCI referrer (`https://slsa.dev/provenance/v1`, in `cosign tree`), and `gh attestation verify oci://… --bundle-from-oci` passes. No fallback | — |
| P0-4 | Req. 4, 8 | Same run: a keyless `cosign sign --yes` through `packaging/ci/tool`, with `TOOL_ENV` set to the two `ACTIONS_ID_TOKEN_REQUEST_*` variables, works. cosign v3.1.3. `cosign verify --certificate-identity https://github.com/<repo>/.github/workflows/slsa-phase0-attest.yml@refs/heads/slsa-phase0 --certificate-oidc-issuer … --certificate-github-workflow-repository <repo>` passes. With `someone-else/…` it fails ("expected GithubWorkflowRepository to be …"). The key signature on the same image still verifies. `cosign tree` lists both signatures and the provenance as referrers. The bundle file has 2 lines. No fallback | The repository pin is enforced, so it goes in every documented keyless check |
| P0-5 | Req. 2 | Same run: with `sha_pinning_required` on, `actions/attest` (a `node24` action) runs | — |
| P0 cleanup | — | Branch `slsa-phase0` and the ghcr package `wd2l-slsa-phase0` deleted (2026-10-10) | Throwaway |
| 4.1 rc3 | Req. 10 | Tag `v0.3.0rc3` on `ba343f2`, run [38072299782](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/actions/runs/38072299782): every job green, with two approvals. `attest` made one attestation for the 17 subjects in `SHA256SUMS` ([54651398](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations/54651398)) and one for the image `sha256:44f86d9e…`, pushed to ghcr ([54651401](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations/54651401)). It logged `keyless signature: ok`, and the bundle file has 2 lines. The draft pre-release has 20 assets, `wd2l-0.3.0rc3-attestations.jsonl` among them | — |
| 4.1 online | Req. 1, 4, 5, 8 | `sha256sum -c`: 17 OK. With the pinned flags, `gh attestation verify` passes for 17 of 17 files and for the image with `--bundle-from-oci`. Keyless `cosign verify` with the repository pin passes. The key signature passes, and the attached `cosign.pub` matches the repository's. Negative checks: `--source-ref refs/heads/main` is refused ("expected SourceRepositoryRef to be refs/heads/main, got refs/tags/v0.3.0rc3"), and `--certificate-github-workflow-repository someone-else/…` is refused | gh 2.96.0 on this machine; cosign v3.1.3 from the pinned `hi/cosign` image |
| 4.1 offline | Req. 5, 6 | In containers with `--network none`, no GitHub login. The `releasing.md` loop with gh 2.102.0 (the Linux build, checked against cli/cli's checksums), the release's bundle file and the trusted root fetched with it: 17 of 17. The key path: `verify-blob` of `SHA256SUMS`, `verify --local-image` and `verify-attestation --type slsaprovenance1`: all pass | On this Windows machine, Docker's `--network none` stands in for `unshare --net` |

**Closed (2026-10-10).** 0.3.0rc3 proved it end to end, online and offline. ADR-0007 is Accepted.
