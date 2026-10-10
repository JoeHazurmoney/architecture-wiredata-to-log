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
* **Policy is tested.** A new `tests/test_workflow_policy.py` reads the workflow files and fails
  if any other job asks for `id-token: write`, if a cache appears on the release path, or if
  attestation could run off a tag.

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
  that `uses: ./.github/workflows/attest.yml`.
* **No `actions/cache` in `tests.yml`, `image.yml`, `rpm.yml`, `publish.yml`, `release.yml` or
  `attest.yml`.**
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
   not attest.** Test: `test_attestation_runs_only_for_a_tag` (Task 1.1).
2. **A release built from a branch, or rebuilt from another ref, must not verify as the tag.**
   The documented commands pin `--source-ref refs/tags/v<version>`. Test:
   `test_notes_show_how_to_verify_the_github_attestations` (Task 3.1).
3. **Enclaves with a stale Sigstore trusted root.** Offline verification with an old
   `trusted_root.jsonl` may fail after Sigstore rotates keys. `releasing.md` says to carry the
   trusted root fetched with that release, and how to refresh it (Task 3.2).
4. **The attestations bundle must cover what is downloaded.** Its subjects come from
   `SHA256SUMS`, after the `~` → `.` rename. Test: `test_attest_reads_the_checksums_the_release_lists`
   (Task 1.2).
5. **A failure after `publish` must leave no half-made release.** If `attest` fails, `release`
   must not draft. Test: `test_release_waits_for_attest_on_a_tag` (Task 1.3).

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
