# Phase 3: how to verify it, and the decision record

Part of the [SLSA Build L3 plan](README.md). Spec requirements 6, 8 and 9.

---

### Task 3.1: The release notes print the pinned `gh attestation verify` commands

**Files:**
- Modify: `packaging/release/notes.py`, `tests/test_release_tools.py`

**Interfaces:**
- Consumes: `notes.notes(names, image, digest, sums_text, base_record, repo_url, run_url, commit)`
  (unchanged signature); `ARGS` in `tests/test_release_tools.py`
  (`repo_url="https://github.com/o/r"`, `digest="sha256:" + "d" * 64`).
- Produces: a "Build provenance (SLSA Build Level 3)" section in the notes.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_release_tools.py`)

```python
def test_notes_show_how_to_verify_the_github_attestations():
    text = notes.notes(versions.names("0.4.0"), **ARGS)
    pin = ("--repo o/r --signer-workflow o/r/.github/workflows/attest.yml "
           "--source-ref refs/tags/v0.4.0 --deny-self-hosted-runners")
    assert "gh attestation verify wd2l-0.4.0-py3-none-any.whl " + pin in text
    assert "gh attestation verify oci://ghcr.io/joehazurmoney/wd2l@sha256:%s %s --bundle-from-oci" % (
        "d" * 64, pin) in text
    assert "--bundle wd2l-0.4.0-attestations.jsonl --custom-trusted-root trusted_root.jsonl" in text


def test_dry_run_notes_have_no_image_attestation_line():
    text = notes.notes(versions.names("0.4.0"), **dict(ARGS, digest=""))
    assert "gh attestation verify wd2l-0.4.0-py3-none-any.whl" in text
    assert "gh attestation verify oci://" not in text
```

- [ ] **Step 2: Run them**

Run: `T -q tests/test_release_tools.py -k attestation`
Expected: both FAIL (no "gh attestation verify" in the notes).

- [ ] **Step 3: Add the section** in `packaging/release/notes.py`. In `notes()`, replace

```python
            "cosign verify --key cosign.pub --insecure-ignore-tlog --local-image wd2l-oci",
            "```", "",
            "## Image", ""]
```

with

```python
            "cosign verify --key cosign.pub --insecure-ignore-tlog --local-image wd2l-oci",
            "```", ""]
    slug = repo_url.rstrip("/").split("github.com/", 1)[-1]
    pin = ("--repo %s --signer-workflow %s/.github/workflows/attest.yml --source-ref refs/tags/%s "
           "--deny-self-hosted-runners" % (slug, slug, tag))
    out += ["## Build provenance (SLSA Build Level 3)", "",
            "Every asset below and the image have GitHub build provenance, made only by "
            "`attest.yml`. With the GitHub CLI:", "",
            "```bash",
            "gh attestation verify wd2l-%s-py3-none-any.whl %s" % (v, pin)]
    if digest:
        out.append("gh attestation verify oci://%s@%s %s --bundle-from-oci" % (image, digest, pin))
    out += ["# offline: add --bundle wd2l-%s-attestations.jsonl --custom-trusted-root "
            "trusted_root.jsonl (docs/releasing.md)" % v,
            "```", "",
            "## Image", ""]
```

- [ ] **Step 4: Run the tests**

Run: `T -q tests/test_release_tools.py && T -q`
Expected: all PASS, including the existing notes tests.

- [ ] **Step 5: Commit**

```bash
git add packaging/release/notes.py tests/test_release_tools.py
git commit -m "Release notes: the pinned gh attestation verify commands, online and offline"
```

---

### Task 3.2: `docs/releasing.md`: build provenance, online and offline

**Files:**
- Modify: `docs/releasing.md`, `tests/test_release_tools.py`

**Interfaces:**
- Consumes: the asset name `wd2l-<version>-attestations.jsonl` (Task 1.2), the signer
  workflow, and the keyless identity (Task 2.1).
- Produces: the anchor `#github-build-provenance-offline`.

- [ ] **Step 1: Write the failing test** (append to `tests/test_release_tools.py`)

```python
def test_releasing_md_pins_the_signer_workflow_and_the_tag():
    with open(os.path.join(REPO, "docs", "releasing.md"), encoding="utf-8") as f:
        doc = f.read()
    assert "## GitHub build provenance, offline" in doc
    assert "--signer-workflow JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml" in doc
    assert "--source-ref refs/tags/v<version>" in doc
    assert "gh attestation trusted-root > trusted_root.jsonl" in doc
    assert "done < SHA256SUMS" in doc          # every listed file, not a few globs
    assert ("--certificate-identity https://github.com/JoeHazurmoney/architecture-wiredata-to-log"
            "/.github/workflows/attest.yml@refs/tags/v<version>") in doc
    assert "--certificate-github-workflow-repository JoeHazurmoney/architecture-wiredata-to-log" in doc
```

- [ ] **Step 2: Run it.** `T -q tests/test_release_tools.py -k signer` → FAIL.

- [ ] **Step 3: Edit `docs/releasing.md`:**
  * **"How a release is built":**
    * add `attest` to the flowchart, between `publish` and `assets, SHA256SUMS…`;
    * add a bullet: "**attest** ([`attest.yml`](../.github/workflows/attest.yml), tags only):
      GitHub build provenance (SLSA Build Level 3) for every file and the image, and a keyless
      signature on the image. It is the only workflow that gets an OIDC token, so the build
      steps can't reach what signs the provenance ([ADR-0007](decisions/0007-slsa-build-l3.md))."
    * the **release** bullet adds: "and `wd2l-<version>-attestations.jsonl`, the GitHub
      attestations for offline checks".
  * **"Who can cause a signature":** the `release` environment bullet adds: "`attest.yml`
    has no gate of its own. It runs only after `publish` was approved, and only for a `v*` tag
    in this repository."
  * **A new section, after "Bringing a release into an enclave":**

````markdown
## GitHub build provenance, offline

Optional, on top of the checks above. It shows the files were built by this repository's
`attest.yml`, from the release tag, on GitHub's hosted runners (SLSA Build Level 3,
[ADR-0007](decisions/0007-slsa-build-l3.md)).

**What to carry in, besides the release:**

* the GitHub CLI (`gh`), from your approved software source (tested with `gh` <the version
  P0 recorded> or later);
* Sigstore's trusted root, fetched on a connected machine when you fetch the release:
  `gh attestation trusted-root > trusted_root.jsonl`. Sigstore rotates its keys from time to
  time, so carry the one fetched with the release you're bringing in.

After `sha256sum -c SHA256SUMS` passes, check every file it lists:

```bash
while read -r _ f; do
  gh attestation verify "$f" --bundle wd2l-<version>-attestations.jsonl \
    --custom-trusted-root trusted_root.jsonl \
    --repo JoeHazurmoney/architecture-wiredata-to-log \
    --signer-workflow JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml \
    --source-ref refs/tags/v<version> --deny-self-hosted-runners > /dev/null && echo "ok $f"
done < SHA256SUMS
```

Online, drop `--bundle` and `--custom-trusted-root`. For the image in ghcr, use
`gh attestation verify oci://ghcr.io/joehazurmoney/wd2l@sha256:<digest> --bundle-from-oci` with the
same `--repo`, `--signer-workflow` and `--source-ref`.

**The keyless signature on the image.** This is for cosign, and for admission controllers that
read Sigstore bundles and trust Sigstore's public instance. Podman's own policy is still open
([containers.md](deployment/containers.md)). Pin the repository as well as the identity: any
repository can call a public reusable workflow.

```bash
cosign verify ghcr.io/joehazurmoney/wd2l@sha256:<digest> \
  --certificate-identity https://github.com/JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml@refs/tags/v<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository JoeHazurmoney/architecture-wiredata-to-log
```
````

  * **"Seeing the scan results and attestations":** add a bullet: "**GitHub's attestations
    page:** `https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations` lists
    every attestation `attest.yml` made, with its subjects."

- [ ] **Step 4: Run the test and the link check**

```bash
T -q tests/test_release_tools.py
L docs/releasing.md        # L: README, "Running tests on this machine"
```

Expected: the tests PASS, and `L` prints only `missing: decisions/0007-slsa-build-l3.md`,
which Task 3.3 creates.

- [ ] **Step 5: Commit**

```bash
git add docs/releasing.md tests/test_release_tools.py
git commit -m "releasing.md: verifying GitHub build provenance online and offline; the keyless signature"
```

---

### Task 3.3: ADR-0007

**Files:**
- Create: `docs/decisions/0007-slsa-build-l3.md`
- Modify: `docs/decisions/0006-release-artifacts-and-signing.md` (its 2026-10-09 update)

- [ ] **Step 1: Write the ADR**, in the format of ADR-0006:

```markdown
# ADR-0007: SLSA Build Level 3 provenance, alongside the key

**Status:** Proposed
**Date:** <the day it's written>
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

## Decision

* **`attest.yml`, a reusable workflow, is the only place an OIDC token exists.**
  * It makes GitHub build provenance (`actions/attest`) for every line of `SHA256SUMS` and for
    the image in ghcr, and a keyless cosign signature on the image.
  * The build jobs never get `id-token: write`; `tests/test_workflow_policy.py` fails if one does.
* **Runs don't share caches** on the release path (same test), and run on GitHub-hosted,
  ephemeral runners.
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

Not chosen: GitHub now recommends its own attestations, and consumers already use `gh`.

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
```

- [ ] **Step 2: In ADR-0006's "Update: the repository is public" section,** change the "Still
  to do" bullet's second half to: "GitHub artifact attestations and keyless signatures alongside
  the key: [ADR-0007](0007-slsa-build-l3.md)."

- [ ] **Step 3: Check the links, run the suite, commit**

```bash
L docs/decisions/0007-slsa-build-l3.md; L docs/decisions/0006-release-artifacts-and-signing.md; L docs/releasing.md
T -q
git add docs/decisions/0007-slsa-build-l3.md docs/decisions/0006-release-artifacts-and-signing.md
git commit -m "ADR-0007: SLSA Build Level 3 provenance alongside the key"
```

Then open the PR for Phases 1 to 3 (with OK). Its CI must be green, including `ci-ok` and a
release dry run.
