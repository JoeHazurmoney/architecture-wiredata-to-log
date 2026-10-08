# Phase 6: the release workflow, the release guide, and the first release

Part of the [release packaging plan](README.md). Read its **Global constraints** first. Spec:
[spec.md](spec.md) "Phase 6" and "Verification".

**Delivers:**

* `release.yml`. A version tag runs the tests, the image pipeline (which publishes and signs)
  and the RPM builds, then assembles every asset and `SHA256SUMS`, signs it, and creates a
  **draft** release.
* The signing key, which your partner sets up.
* `docs/releasing.md`.
* The README's license and release sections.
* An rc release, verified offline and on RHEL, then **v0.3.0**.

Run tests with `T` from the plan README.

---

### Task 6.1: Release notes (`notes.py`)

**Files:**
- Create: `packaging/release/notes.py`
- Modify: `tests/test_release_tools.py`

**Interfaces:**
- Consumes: `versions.names()` (Task 4.7), `SHA256SUMS`, and `base-image-record.json`
  (Task 4.2).
- Produces: `notes.notes(names, image, digest, sums_text, base_record, repo_url, run_url,
  commit) -> str` (Markdown), with a CLI.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_release_tools.py`)

```python
notes = load_script("packaging/release/notes.py")
SUMS = ("%s  wd2l-0.3.0-py3-none-any.whl\n%s  wd2l-0.3.0-1.el10.noarch.rpm\n"
        "%s  wd2l-0.3.0-image-oci.tar\n" % ("a" * 64, "b" * 64, "c" * 64))
RECORD = {"images": [
    {"ref": "r/hi/python:3.12-fips-builder@sha256:" + "1" * 64, "stage": "build",
     "index_digest": "sha256:" + "1" * 64, "source_image": "r/hi/python:111-source"},
    {"ref": "r/hi/python:3.12-fips@sha256:" + "2" * 64, "stage": "runtime",
     "index_digest": "sha256:" + "2" * 64, "source_image": "r/hi/python:222-source"}]}
ARGS = dict(image="ghcr.io/joehazurmoney/wd2l", digest="sha256:" + "d" * 64, sums_text=SUMS,
            base_record=RECORD, repo_url="https://github.com/o/r",
            run_url="https://github.com/o/r/actions/runs/7", commit="e" * 40)


def test_notes_name_every_asset_the_image_and_its_bases():
    text = notes.notes(versions.names("0.3.0"), **ARGS)
    for part in ("wd2l-0.3.0-py3-none-any.whl", "b" * 64, "ghcr.io/joehazurmoney/wd2l@sha256:" + "d" * 64,
                 "r/hi/python:3.12-fips@sha256:" + "2" * 64, "r/hi/python:222-source",
                 "cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
                 "sha256sum -c SHA256SUMS", "--local-image wd2l-oci", "e" * 40,
                 "https://github.com/o/r/blob/v0.3.0/docs/releasing.md"):
        assert part in text, part
    assert "Pre-release" not in text


def test_prerelease_notes_say_so_and_dry_runs_have_no_digest():
    text = notes.notes(versions.names("0.3.0rc1"), **dict(ARGS, digest=""))
    assert text.startswith("> **Pre-release**") and "not published (dry run)" in text
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_release_tools.py -k notes -v`
Expected: FAIL (`FileNotFoundError` for `notes.py`).

- [ ] **Step 3: Write `packaging/release/notes.py`**

```python
#!/usr/bin/env python3
"""Release notes for the draft GitHub release (release.yml): what is in it, how to verify it
offline, the exact image and the bases it stands on, and every asset with its SHA-256.

    notes.py --image-digest sha256:... --sums SHA256SUMS --base-record base-image-record.json
             --repo-url URL --run-url URL --commit SHA > notes.md"""

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import versions  # noqa: E402  (a sibling script, not a package)

IMAGE = "ghcr.io/joehazurmoney/wd2l"


def notes(names: Dict[str, Any], image: str, digest: str, sums_text: str,
          base_record: Dict[str, Any], repo_url: str, run_url: str, commit: str) -> str:
    v, tag = names["pep440"], names["tag"]
    doc = "%s/blob/%s/docs" % (repo_url, tag)
    out = []
    if names["prerelease"]:
        out += ["> **Pre-release** for testing. Not for production.", ""]
    out += ["wd2l %s, built from commit `%s` by [this workflow run](%s)." % (v, commit, run_url), "",
            "## Install", "",
            "* **RPMs** for RHEL 9 (`el9`) and RHEL 10 (`el10`): `wd2l` plus `wd2l-sender` on the "
            "log server ([guide](%s/deployment/log-server.md)), or `wd2l` plus `wd2l-receiver` on "
            "the receiver host ([guide](%s/deployment/receiver.md))." % (doc, doc),
            "* **Container** (FIPS, Red Hat Hardened Images): `%s:%s` "
            "([guide](%s/deployment/containers.md)); `wd2l-%s-image-oci.tar` is the same image, "
            "with its signature and attestations, for enclaves without a registry."
            % (image, " / ".join(names["image_tags"]), doc, v),
            "* Bringing a release into an enclave: [releasing.md](%s/releasing.md#bringing-a-release-into-an-enclave)."
            % doc, "",
            "## Verify (works offline)", "",
            "Use a `cosign.pub` you got from a trusted channel (the repository at `%s`, or the "
            "security owner). The copy attached here is for convenience." % tag, "",
            "```bash",
            "cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
            "sha256sum -c SHA256SUMS",
            "tar -xf wd2l-%s-image-oci.tar" % v,
            "cosign verify --key cosign.pub --insecure-ignore-tlog --local-image wd2l-oci",
            "```", "",
            "## Image", ""]
    out.append("`%s@%s`" % (image, digest) if digest else "Image not published (dry run).")
    out += ["", "| Stage | Base image | Source (SRPMs) |", "|---|---|---|"]
    for b in base_record.get("images", []):
        out.append("| %s | `%s` | `%s` |" % (b.get("stage"), b.get("ref"), b.get("source_image")))
    out += ["", "The bases, their Red Hat signatures, SBOMs, provenance and sources are mirrored "
            "in `ghcr.io/joehazurmoney/wd2l-base/python` ([why](%s/decisions/0006-release-artifacts-and-signing.md))."
            % doc, "", "## Assets", "", "| File | SHA-256 |", "|---|---|"]
    for line in sums_text.splitlines():
        if line.strip():
            h, name = line.split(None, 1)
            out.append("| `%s` | `%s` |" % (name.lstrip("*"), h))
    return "\n".join(out) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Release notes for the draft release.")
    p.add_argument("--image", default=IMAGE)
    p.add_argument("--image-digest", default="")
    p.add_argument("--sums", required=True)
    p.add_argument("--base-record", required=True)
    p.add_argument("--repo-url", required=True)
    p.add_argument("--run-url", required=True)
    p.add_argument("--commit", required=True)
    a = p.parse_args(argv)
    with open(a.sums) as f:
        sums = f.read()
    with open(a.base_record) as f:
        rec = json.load(f)
    sys.stdout.write(notes(versions.names(versions.read_version()), a.image, a.image_digest, sums,
                           rec, a.repo_url, a.run_url, a.commit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T tests/test_release_tools.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packaging/release/notes.py tests/test_release_tools.py
git commit -m "Release notes: install, offline verification, the image and its bases, every asset"
```

---

### Task 6.2: The signing key (your partner)

**Files:**
- Create: `cosign.pub` (from your partner)
- Modify: `tests/test_release_tools.py`

**Interfaces:**
- Consumes: nothing.
- Produces: the Actions secrets `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`, and `cosign.pub`
  at the repo root. `image.yml`'s `verify-published` job and every enclave use it.

- [ ] **Step 1: Ask your partner to do this themselves.** The private key must never pass
  through this session. Give them this, from ADR-0006's key management:

```bash
# On a trusted machine, as the security owner. Choose a strong password when asked.
podman run --rm -it --userns=keep-id -v "$PWD:/work" -w /work registry.access.redhat.com/hi/cosign:latest generate-key-pair
gh secret set COSIGN_PRIVATE_KEY < cosign.key
gh secret set COSIGN_PASSWORD           # paste the password
# Keep cosign.key offline (or destroy it: the secret is now the only copy). Give back cosign.pub.
```

Wait for them to say it's done, and to hand over `cosign.pub`.

- [ ] **Step 2: Write the failing test** (append to `tests/test_release_tools.py`)

```python
def test_cosign_pub_is_a_public_key_and_never_a_private_one():
    with open(os.path.join(REPO, "cosign.pub")) as f:
        text = f.read()
    assert text.startswith("-----BEGIN PUBLIC KEY-----") and "PRIVATE" not in text
    assert not os.path.exists(os.path.join(REPO, "cosign.key"))
```

Run: `T tests/test_release_tools.py -k cosign -v`
Expected: FAIL (no `cosign.pub`) until the file is in place, then PASS.

- [ ] **Step 3: Commit.** First add `cosign.key` to `.gitignore`, so it can never be added by
  mistake.

```bash
echo "cosign.key" >> .gitignore
git add cosign.pub .gitignore tests/test_release_tools.py
git commit -m "cosign.pub: the release signing public key"
```

---

### Task 6.3: `release.yml`

**Files:**
- Create: `.github/workflows/release.yml`

**Interfaces:**
- Consumes: `tests.yml` (with `image: false`), `image.yml` (`publish` and `outputs.digest`),
  `rpm.yml`, `versions.py`, `notes.py` and the secrets.
- Produces:
  * on a tag push: a draft GitHub release holding the assets and the notes;
  * on `workflow_dispatch`: the same assets and notes as the artifact `release-assets`, with
    nothing pushed, signed or published.

- [ ] **Step 1: Write the workflow** (pin every `uses:` as in Task 4.1; the cosign flags as in
  P0-7):

```yaml
name: release
# A version tag (vX.Y.Z or vX.Y.ZrcN) builds, checks, signs and publishes everything, then makes
# a DRAFT GitHub release for a person to review and publish (docs/releasing.md).
# workflow_dispatch is a dry run: the same builds and checks, nothing pushed, signed or released.
on:
  push:
    tags: ["v*"]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  version:
    runs-on: ubuntu-24.04
    outputs:
      pep440: ${{ steps.v.outputs.pep440 }}
      tag: ${{ steps.v.outputs.tag }}
      prerelease: ${{ steps.v.outputs.prerelease }}
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - id: v
        run: |
          python3 packaging/release/versions.py --github-output "$GITHUB_OUTPUT"
          if [ "${{ github.event_name }}" = push ]; then
            python3 packaging/release/versions.py --check-tag "${{ github.ref_name }}"
          fi

  tests:
    needs: [version]
    uses: ./.github/workflows/tests.yml
    with:
      image: false

  image:
    needs: [version]
    uses: ./.github/workflows/image.yml
    with:
      publish: ${{ github.event_name == 'push' }}
    secrets: inherit
    permissions:
      contents: read
      packages: write

  rpm:
    needs: [image]
    uses: ./.github/workflows/rpm.yml

  release:
    needs: [version, tests, image, rpm]
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    env:
      V: ${{ needs.version.outputs.pep440 }}
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          pattern: "{dist,rpms-el9,rpms-el10,sbom,base-evidence,vuln,image-release}"
      - name: Assemble the assets
        run: |
          mkdir assets
          cp "dist/wd2l-$V-py3-none-any.whl" "dist/wd2l-$V.tar.gz" assets/
          cp rpms-el9/rel1/*.rpm rpms-el10/rel1/*.rpm assets/
          cp sbom/wd2l.spdx.json "assets/wd2l-$V-image.spdx.json"
          cp sbom/wd2l.cdx.json "assets/wd2l-$V-image.cdx.json"
          cp base-evidence/base-image-record.json assets/
          cp vuln/vuln-summary.md "assets/wd2l-$V-vuln-summary.md"
          cp cosign.pub assets/
          if [ -d image-release ]; then
            cp "image-release/wd2l-$V-image-oci.tar" assets/
            cp image-release/provenance.json "assets/wd2l-$V-provenance.json"
          fi
          (cd assets && sha256sum -- * > SHA256SUMS && cat SHA256SUMS)
      - name: Sign SHA256SUMS (our key, no public log)
        if: github.event_name == 'push'
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
          TOOL_ENV: COSIGN_PRIVATE_KEY COSIGN_PASSWORD
        run: |
          packaging/ci/tool cosign sign-blob --key env://COSIGN_PRIVATE_KEY --tlog-upload=false --yes \
            --bundle /work/assets/SHA256SUMS.sigstore.json /work/assets/SHA256SUMS
          packaging/ci/tool cosign verify-blob --key /work/cosign.pub --insecure-ignore-tlog \
            --bundle /work/assets/SHA256SUMS.sigstore.json /work/assets/SHA256SUMS
      - name: Notes
        run: |
          python3 packaging/release/notes.py --image-digest "${{ needs.image.outputs.digest }}" \
            --sums assets/SHA256SUMS --base-record assets/base-image-record.json \
            --repo-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
            --run-url "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID" \
            --commit "$GITHUB_SHA" > notes.md
          cat notes.md >> "$GITHUB_STEP_SUMMARY"
      - name: Draft release (a person reviews and publishes it)
        if: github.event_name == 'push'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          pre=(); [ "${{ needs.version.outputs.prerelease }}" != true ] || pre=(--prerelease)
          gh release create "${{ needs.version.outputs.tag }}" --draft --verify-tag \
            --title "wd2l $V" --notes-file notes.md "${pre[@]}" assets/*
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: release-assets
          path: |
            assets/
            notes.md
```

- [ ] **Step 2: Dry run** (ask your partner first: it runs the whole pipeline once)

```bash
git add .github/workflows/release.yml
git commit -m "Release workflow: tag -> tests, image (signed), RPMs -> SHA256SUMS, notes, draft release"
git push
gh workflow run release.yml --ref release-packaging
gh run watch "$(gh run list --workflow release.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run download --name release-assets --dir /tmp/assets && ls -l /tmp/assets/assets && head -40 /tmp/assets/notes.md
```

Expected:

* every job is green; `publish`, `verify-published` and the signing and draft steps show as
  skipped;
* `assets/` has the wheel, the sdist, 6 noarch RPMs plus 2 SRPMs, two SBOMs,
  `base-image-record.json`, the vulnerability summary, `cosign.pub` and `SHA256SUMS`;
* the notes say "Image not published (dry run)".

---

### Task 6.4: `docs/releasing.md` and the README

**Files:**
- Create: `docs/releasing.md`
- Modify: `README.md`, `docs/architecture.md` (one link)

**Interfaces:**
- Consumes: the workflows, the scripts and the ADRs.
- Produces: the anchors other pages link to: `#how-a-release-is-built` (the provenance
  `buildType`), `#bringing-a-release-into-an-enclave` (the guides and the release notes), and
  `#cutting-a-release`.

- [ ] **Step 1: Write `docs/releasing.md`.** Plain, short sentences. Sections:

  1. **"How a release is built."** A Mermaid flowchart:

     ```text
     tag vX.Y.Z → tests (pytest 3.9/3.12, lab) → image.yml (lint, base-verify, build, hardening,
     vuln-scan, sbom, functional, fips-tests, reproducible, publish, verify-published) → rpm.yml
     (EL9, EL10 build; 6 install tests) → assets, SHA256SUMS, signature, notes → draft release →
     a person publishes
     ```

     One sentence per job, saying what it proves, with a link to the script that does it.
     "One wheel, built once, is in every package (`wd2l/BUILD` names the commit)."
  2. **"Cutting a release."** A checklist:
     * set `__version__` in `wd2l/__init__.py`, and the `Image=` tag in both `.container`
       files (`tests/test_deploy.py` keeps them equal);
     * merge to `main` through a PR with CI green;
     * `git tag -a vX.Y.Z -m "wd2l X.Y.Z"` on main, then `git push origin vX.Y.Z`;
     * watch `release.yml`;
     * review the draft:
       * the assets list, and the notes;
       * the `vuln-scan` gate summary, the `hardening` result and the `reproducible` result;
     * edit the notes if needed (a short "What changed" section on top), then publish.

     Pre-releases are `X.Y.ZrcN` (tag `vX.Y.ZrcN`); their RPMs sort before the release
     (`X.Y.Z~rcN`).
  3. **"One-time setup."**
     * The key, per Task 6.2 and [ADR-0006](decisions/0006-release-artifacts-and-signing.md#key-management).
     * Turn on immutable releases if the repository's settings offer it.
     * Package permissions: `wd2l` and `wd2l-base` live in the repository's packages and are
       private while the repository is. Enclaves use the release assets, not the registry.
  4. **"Bringing a release into an enclave"** (anchor `bringing-a-release-into-an-enclave`):
     * **What to carry:** the release's assets, `cosign.pub` (from a trusted channel), and
       cosign itself: `registry.access.redhat.com/hi/cosign` saved with `podman save`, or the
       binary from your approved software source.
     * **The commands:**

       ```bash
       cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS
       sha256sum -c SHA256SUMS
       tar -xf wd2l-<version>-image-oci.tar
       cosign verify --key cosign.pub --insecure-ignore-tlog --local-image wd2l-oci
       cosign verify-attestation --key cosign.pub --insecure-ignore-tlog --type slsaprovenance1 --local-image wd2l-oci | jq -r .payload | base64 -d | jq .predicate.buildDefinition.resolvedDependencies
       sudo skopeo copy oci:wd2l-oci containers-storage:ghcr.io/joehazurmoney/wd2l:<version>
       sudo dnf install ./wd2l-<version>-1.el10.noarch.rpm ./wd2l-receiver-<version>-1.el10.noarch.rpm
       ```

     * **What each command proves:** the files are the ones the workflow built; the image is
       signed; the provenance names the commit and the exact Red Hat bases.
     * The RPMs aren't GPG-signed: `SHA256SUMS`, signed, covers them
       ([ADR-0006](decisions/0006-release-artifacts-and-signing.md)).
  5. **"After a release."**
     * The weekly rescan (`image-rescan.yml`) opens an issue for a new fixable High/Critical.
       Then rebuild on a newer base, as a patch release.
     * Dependabot PRs move the base, tool and action pins; merge them when the pipeline is
       green.
     * Vulnerability exceptions: only the security owner approves them, each for at most
       90 days (`packaging/container/vuln-exceptions.json`).
  6. **"Keys."** Rotation and compromise: link ADR-0006's key management.

- [ ] **Step 2: README.**
  * **Repo map:** add the rows `| \`packaging/\` | How releases are built: the RPM spec,
    the Containerfile, and the CI checks (\`packaging/container/\`, \`packaging/rpm/\`,
    \`packaging/release/\`, \`packaging/ci/\`) |` and
    `| \`docs/releasing.md\` | Cutting a release, and bringing one into an enclave |`.
  * **"Try it":** add the line
    `sudo lab/run-lab.sh --image localhost/wd2l:dev    # the same path, from the container image (docs/running-the-lab.md §10)`.
  * **"Deploying":** add at the end: "Releases (RPMs and the signed container image), and how
    to verify one offline: [docs/releasing.md](docs/releasing.md)."
  * **New section "License"** at the end: "MIT, see [LICENSE](LICENSE). The container image
    also contains Red Hat Hardened Images packages under their own licenses (the UBI EULA);
    their sources are mirrored with every release
    ([ADR-0006](docs/decisions/0006-release-artifacts-and-signing.md))."
- [ ] **Step 3: `docs/architecture.md`.** Where it lists the components or the deployment, add one
  sentence: "The sender and receiver ship as RPMs and as a FIPS container image on Red Hat
  Hardened Images ([ADR-0004](decisions/0004-container-base-image.md),
  [releasing.md](releasing.md))."
- [ ] **Step 4: Check links and commit**

```bash
grep -o '](releasing[^)]*\|](docs/releasing[^)]*\|](decisions/000[456][^)]*' README.md docs/*.md docs/deployment/*.md | sort -u
git add docs/releasing.md README.md docs/architecture.md
git commit -m "Docs: cutting a release and bringing one into an enclave; license"
```

---

### Task 6.5: The rc release, the checks around it, and v0.3.0

**Files:**
- Modify: `wd2l/__init__.py`, `deploy/log-server/wd2l-sender.container`,
  `deploy/receiver/wd2l-receiver.container`, the ADRs (status and as-built notes), the
  plan README's As-built log

**Interfaces:**
- Consumes: everything above. Your partner merges the branch, pushes tags, publishes
  releases, and runs the RHEL VM checks.
- Produces: the published `v0.3.0`; ADR-0004, ADR-0005 and ADR-0006 Accepted; the As-built
  rows carried into the docs.

- [ ] **Step 1: Whole-branch review.** Use superpowers:requesting-code-review on the branch
  against `main`, fix what it finds, and get CI green. Then ask your partner to review and merge
  the PR:

```bash
gh pr create --base main --head release-packaging --title "Releases: RPMs (EL9/EL10) and a FIPS container image on Red Hat Hardened Images" \
  --body-file - <<'EOF'
<summary of the phases, the ADRs, the Phase 0 results, and the As-built log>

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
```

- [ ] **Step 2: rc1.** On `main`, after the merge, through a small PR:
  * set `__version__ = "0.3.0rc1"`;
  * set both `.container` files to `Image=ghcr.io/joehazurmoney/wd2l:0.3.0rc1`.

  Then, with your partner's OK:
  `git tag -a v0.3.0rc1 -m "wd2l 0.3.0rc1" && git push origin v0.3.0rc1`.

  Expected:
  * `release.yml` is green, including `publish` and `verify-published`;
  * a draft **pre-release** `v0.3.0rc1` holds every asset, including
    `wd2l-0.3.0rc1-image-oci.tar` and `SHA256SUMS.sigstore.json`.

- [ ] **Step 3: The offline drill.** On a machine with no network (a VM with networking
  removed), with the downloaded assets and cosign:
  * run the commands from `docs/releasing.md` §4, one at a time;
  * each must succeed: verify-blob, `sha256sum -c` (all OK), the image verify, the provenance
    showing the commit and both base digests, and the import;
  * change one byte of an RPM and confirm that `sha256sum -c` fails.

- [ ] **Step 4: The RHEL checks** (spec Verification 5). On RHEL 10, SELinux enforcing and
  installed in FIPS mode, and on RHEL 9 for the RPMs. Your partner runs them; you list them and
  record the results:
  1. Install the RPMs from the rc. `rpm -V wd2l wd2l-sender wd2l-receiver` prints nothing.
  2. The native receiver and sender run, and a lab-like flow arrives. The health records carry
     NIC counters, and `time_quality` from `chronyc`.
  3. Switch to the Quadlet units:
     * `time_quality` from `--chrony-addr` matches `chronyc -c tracking` field for field
       (stratum, offset to 3 decimals, synced, source);
     * the receiver log has no `capture receive buffer` warning (the sysctl applied);
     * `systemctl stop wd2l-sender` gives a clean `stream_end`;
     * after the next hourly run of the seal timer, `lsattr /var/log/wd2l/audit-*.jsonl` shows
       `a` on the files the container wrote.
  4. HEC TLS to a FIPS-mode endpoint works with `--hec-ca`.
  5. `rpm -V` is still clean after the services ran (`StateDirectoryMode=0750` kept
     `/var/lib/wd2l`'s mode).

  Each failure is a finding: fix it in a PR, then cut `0.3.0rc2` (steps 2–4 again).

- [ ] **Step 5: Publish rc1** (your partner), so the weekly rescan has something to scan. Then
  run `gh workflow run image-rescan.yml`, and expect "passed" for `0.3.0rc1`.

- [ ] **Step 6: Close the plan's records**, in one PR:
  * **The As-built rows.** Each row goes into the doc it changes, as a short **As built** note:
    * Phase 0 results go into ADR-0005 and the containers guide;
    * cosign flags go into ADR-0006;
    * everything else goes into the doc its Spec column names.
  * **The ADRs.** ADR-0004, ADR-0005 and ADR-0006 go from **Proposed** to **Accepted**, with
    the date.
  * At the end of the plan README's As-built log, add
    "**Closed by Task 6.5 (<date>).** Every row has a matching note in the doc it changed."

- [ ] **Step 7: v0.3.0.**
  * Through a PR: `__version__ = "0.3.0"`, and both `Image=` tags `0.3.0`.
  * After the merge, with your partner's OK: `git tag -a v0.3.0 -m "wd2l 0.3.0" && git push origin v0.3.0`.

  Expected: `release.yml` is green. Your partner reviews the draft (assets, notes, gate summary)
  and publishes it. The images are tagged `0.3.0` and `0.3`.

- [ ] **Step 8: Tell your partner what's left for "when the repo goes public".** That's the
  spec's last section, and ADR-0006's Revisit:
  * add `actions/attest-build-provenance` and keyless signing **alongside** the key;
  * upload the SARIF files that `vuln-scan` already produces to code scanning;
  * make the packages public;
  * turn on immutable releases.
