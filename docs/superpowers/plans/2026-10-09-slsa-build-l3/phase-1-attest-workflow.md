# Phase 1: `attest.yml`, and the release built around it

Part of the [SLSA Build L3 plan](README.md). Spec requirements 1–3, 6 (the bundle file) and 7.

---

### Task 1.1: `attest.yml` and the policy tests

**Files:**
- Create: `.github/workflows/attest.yml`, `tests/test_workflow_policy.py`

**Interfaces:**
- Consumes: P0-1, P0-3 and P0-5 (Phase 0). Use the fallback the As-built log names, if any.
- Produces:
  * `attest.yml`: `workflow_call` with input `image-digest` (string, `sha256:…`). It reads the
    artifact `assets` (the release files and `SHA256SUMS`) and uploads the artifact
    `attestations`, which holds `attestations.jsonl` (one Sigstore bundle per line).
  * `tests/test_workflow_policy.py`: `jobs(text) -> Dict[str, str]`, which Task 1.2 and
    Phase 2 reuse.

- [ ] **Step 1: Write the tests**

```python
"""Policy over the workflow files (docs/decisions/0007-slsa-build-l3.md):

* only attest.yml may get an OIDC token, so build steps can't reach what signs the provenance;
* no cache shared between runs on the release path;
* attestation runs only for a v* tag."""

import glob
import os
import re
from typing import Dict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
WORKFLOWS = os.path.join(REPO, ".github", "workflows")
RELEASE_PATH = ("tests.yml", "image.yml", "rpm.yml", "publish.yml", "release.yml", "attest.yml")


def read(name: str) -> str:
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return f.read()


def jobs(text: str) -> Dict[str, str]:
    """Each job's name -> its lines, from a workflow file (two-space job keys under jobs:)."""
    body = text.split("\njobs:\n", 1)[1]
    out, name, lines = {}, None, []
    for line in body.splitlines():
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            if name:
                out[name] = "\n".join(lines)
            name, lines = m.group(1), []
        elif name:
            lines.append(line)
    if name:
        out[name] = "\n".join(lines)
    return out


def test_only_attest_yml_can_get_an_oidc_token():
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        assert "id-token" not in text.split("\njobs:\n", 1)[0], name
        if name == "attest.yml":
            continue
        for job, body in jobs(text).items():
            if "uses: ./.github/workflows/attest.yml" in body:
                continue                      # a caller grants it to attest.yml only
            assert "id-token: write" not in body, (name, job)


def test_no_cache_shared_between_runs_on_the_release_path():
    for name in RELEASE_PATH:
        assert "actions/cache" not in read(name), name


def test_attest_reads_the_checksums_the_release_lists():
    att = read("attest.yml")
    assert "subject-checksums: assets/SHA256SUMS" in att
    assert "push-to-registry: true" in att and "subject-name: ghcr.io/joehazurmoney/wd2l\n" in att
    assert "create-storage-record: false" in att
    assert "name: attestations" in att
```

- [ ] **Step 2: Run them**

Run: `T -q tests/test_workflow_policy.py`
Expected: `test_attest_reads_the_checksums_the_release_lists` FAILS (`FileNotFoundError` for
`attest.yml`). The other two already pass: they pin today's state, since no workflow asks for
`id-token` and none uses a cache.

- [ ] **Step 3: Write `.github/workflows/attest.yml`**

```yaml
name: attest
# SLSA Build Level 3 provenance for a release (docs/decisions/0007-slsa-build-l3.md). This is
# the only workflow that gets an OIDC token (tests/test_workflow_policy.py): the jobs that build
# never hold one, so their steps can't reach what signs the provenance. Consumers pin it:
#   gh attestation verify FILE --repo JoeHazurmoney/architecture-wiredata-to-log \
#     --signer-workflow JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml
# release.yml calls it for a v* tag, after publish pushed the image and assets made SHA256SUMS.
on:
  workflow_call:
    inputs:
      image-digest:
        description: the image publish.yml pushed (sha256:...)
        type: string
        required: true
defaults:
  run:
    shell: bash
permissions:
  contents: read
jobs:
  attest:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write
      attestations: write
      packages: write
    env:
      IMAGE: ghcr.io/joehazurmoney/wd2l
      TOKEN: ${{ secrets.GITHUB_TOKEN }}
      ACTOR: ${{ github.actor }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: assets
          path: assets
      - name: Provenance for every release file (each line of SHA256SUMS is a subject)
        id: files
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with:
          subject-checksums: assets/SHA256SUMS
      - name: Log in to ghcr.io (actions/attest uses Docker's login)
        run: echo "$TOKEN" | docker login ghcr.io -u "$ACTOR" --password-stdin
      - name: Provenance for the image, pushed next to it in ghcr
        id: image
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with:
          subject-name: ghcr.io/joehazurmoney/wd2l
          subject-digest: ${{ inputs.image-digest }}
          push-to-registry: true
          # Storage records are for organization-owned repositories only.
          create-storage-record: false
      - name: The bundles, one per line, for offline verification
        env:
          FILES_BUNDLE: ${{ steps.files.outputs.bundle-path }}
          IMAGE_BUNDLE: ${{ steps.image.outputs.bundle-path }}
        run: |
          mkdir attestations
          jq -c . "$FILES_BUNDLE" "$IMAGE_BUNDLE" > attestations/attestations.jsonl
          wc -l attestations/attestations.jsonl
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: attestations
          path: attestations/
```

- [ ] **Step 4: Run the tests, the whole suite, and actionlint**

Run: `T -q tests/test_workflow_policy.py && T -q`, then the actionlint command from the README.
Expected: all PASS; actionlint prints nothing.

- [ ] **Step 5: Commit** (with the As-built rows from Phase 0)

```bash
git add .github/workflows/attest.yml tests/test_workflow_policy.py docs/superpowers/plans/2026-10-09-slsa-build-l3/README.md
git commit -m "attest.yml: GitHub build provenance for the release files and the image; the OIDC token stays there"
```

---

### Task 1.2: `release.yml`: assets, attest, release

**Files:**
- Modify: `.github/workflows/release.yml`, `tests/test_workflow_policy.py`

**Interfaces:**
- Consumes: `attest.yml` (Task 1.1); `jobs()` from `tests/test_workflow_policy.py`; the
  existing `release` job's steps.
- Produces: in `release.yml`, the jobs `assets` (uploads artifact `assets`), `attest` (tags
  only) and `release` (attaches `wd2l-<version>-attestations.jsonl` on a tag). The dry run's
  `release-assets` artifact is unchanged.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_workflow_policy.py`)

```python
def test_attestation_runs_only_for_a_tag():
    att = jobs(read("release.yml"))["attest"]
    assert "if: ${{ startsWith(github.ref, 'refs/tags/v') }}" in att
    assert "uses: ./.github/workflows/attest.yml" in att
    assert "image-digest: ${{ needs.publish.outputs.digest }}" in att
    for p in ("id-token: write", "attestations: write", "packages: write"):
        assert p in att, p


def test_release_waits_for_attest_on_a_tag():
    rel = jobs(read("release.yml"))["release"]
    assert "needs: [version, publish, assets, attest]" in rel
    assert "needs.attest.result == 'success'" in rel
    assert "(needs.attest.result == 'skipped' && !startsWith(github.ref, 'refs/tags/v'))" in rel
    assert '"assets/wd2l-$V-attestations.jsonl"' in rel


def test_assets_are_made_once_without_secrets_or_a_token():
    a = jobs(read("release.yml"))["assets"]
    assert "- name: Assemble the assets" in a and "name: assets" in a
    assert "secrets." not in a and "id-token" not in a and "environment:" not in a
```

- [ ] **Step 2: Run them**

Run: `T -q tests/test_workflow_policy.py`
Expected: the three new tests FAIL with `KeyError: 'attest'` or `'assets'`.

- [ ] **Step 3: Reshape `release.yml`.** Keep `version`, `tests`, `image`, `rpm` and `publish`
  as they are, and replace the `release` job with these three jobs:

```yaml
  assets:
    # The release files and SHA256SUMS, made once, for attest and release. No secrets and no
    # OIDC token here.
    if: >-
      ${{ !cancelled() && needs.tests.result == 'success' && needs.image.result == 'success'
      && needs.rpm.result == 'success'
      && (needs.publish.result == 'success'
          || (needs.publish.result == 'skipped' && !startsWith(github.ref, 'refs/tags/v'))) }}
    needs: [version, tests, image, rpm, publish]
    runs-on: ubuntu-24.04
    env:
      V: ${{ needs.version.outputs.pep440 }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          pattern: "{dist,rpms-el9,rpms-el10,sbom,base-evidence,vuln,image-release}"
      # (move the existing "Assemble the assets" step here unchanged, the "~" rename included)
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: assets
          path: assets/

  attest:
    # SLSA Build L3 provenance and the keyless signature (docs/decisions/0007-slsa-build-l3.md):
    # only attest.yml gets an OIDC token, and only for a tag.
    if: ${{ startsWith(github.ref, 'refs/tags/v') }}
    needs: [publish, assets]
    uses: ./.github/workflows/attest.yml
    with:
      image-digest: ${{ needs.publish.outputs.digest }}
    permissions:
      contents: read
      id-token: write
      attestations: write
      packages: write

  release:
    # attest is skipped on a dry run; on a tag it must have succeeded.
    if: >-
      ${{ !cancelled() && needs.assets.result == 'success'
      && (needs.attest.result == 'success'
          || (needs.attest.result == 'skipped' && !startsWith(github.ref, 'refs/tags/v'))) }}
    needs: [version, publish, assets, attest]
    runs-on: ubuntu-24.04
    # The signing secrets and the approval gate live in the `release` environment, which only a
    # v* tag may use; a dry run needs neither.
    environment: ${{ startsWith(github.ref, 'refs/tags/v') && 'release' || '' }}
    permissions:
      contents: write
    env:
      V: ${{ needs.version.outputs.pep440 }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: assets
          path: assets
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        if: ${{ needs.attest.result == 'success' }}
        with:
          name: attestations
          path: attestations
      # (keep "Sign SHA256SUMS (our key, no public log)" unchanged)
      - name: Attach the GitHub attestations (one bundle per line)
        if: ${{ needs.attest.result == 'success' }}
        run: cp attestations/attestations.jsonl "assets/wd2l-$V-attestations.jsonl"
      # (keep "Notes", "Draft release (a person reviews and publishes it)" and the
      #  release-assets upload-artifact step unchanged)
```

  The `~` rename test in `tests/test_release_tools.py`
  (`test_asset_names_are_what_github_serves_before_sha256sums_lists_them`) finds the step by its
  name, so it keeps passing after the move.

- [ ] **Step 4: Run the tests, the suite and actionlint**

Run: `T -q tests/test_workflow_policy.py tests/test_release_tools.py && T -q`, then actionlint.
Expected: all PASS.

- [ ] **Step 5: Commit, push the branch (with OK), and check the dry run**

```bash
git add .github/workflows/release.yml tests/test_workflow_policy.py
git commit -m "release.yml: assets once, attest on tags (only it holds an OIDC token), bundles in the release"
git push
gh run watch "$(gh run list --branch "$(git branch --show-current)" --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: every job is green, and `publish` and `attest` are skipped. The `release-assets`
artifact holds the same files as before, with no attestations file (dry run).
