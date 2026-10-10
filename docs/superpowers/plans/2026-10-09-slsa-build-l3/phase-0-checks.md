# Phase 0: checks that could change the design

Part of the [SLSA Build L3 plan](README.md). Five things the design assumes, checked for real on a
throwaway branch before anything lands on `main`:

| Check | What could go wrong | Fallback |
|---|---|---|
| **P0-1** `actions/attest@v4` in a **reusable** workflow, in a **user-owned** public repo: one attestation over every line of a checksums file; `gh attestation verify --signer-workflow` passes for that workflow, and fails for another | Storage records refused on a user-owned repo; `actions/attest` asks for `artifact-metadata: write` even with storage records off (the checks run without it); signer identity names the caller | `create-storage-record: false` (already planned); if `attest` asks for it, add `artifact-metadata: write` to the reusable job and its caller (Phase 1 too); pin `--signer-workflow` to what the certificate shows, and record it |
| **P0-2** Offline: `gh attestation verify --bundle … --custom-trusted-root …` with **no network** | gh still reaches the network | Verify bundles with `cosign verify-blob-attestation --bundle --trusted-root` instead, and document that |
| **P0-3** The image's attestation, pushed to ghcr (`push-to-registry`), verifies with `--bundle-from-oci` | The push needs Docker's login, not Podman's | Log in with `docker login` before `actions/attest` (already planned) |
| **P0-4** A keyless `cosign sign` through `packaging/ci/tool` (the OIDC request variables passed in), then `cosign verify --certificate-identity …/<reusable>.yml@<ref>`; a key signature on the same image still verifies | The container can't reach the token; the identity is the caller's workflow | Run cosign on the runner from the pinned image's binary; pin the identity the certificate shows |
| **P0-5** `sha_pinning_required` (on for this repository) lets `actions/attest` run | A nested action isn't SHA-pinned | None needed if it runs: `actions/attest` is a `node24` action, not a composite one |

---

### Task 0.1: The throwaway branch and its run

**Files (branch `slsa-phase0` only, never merged):**
- Create: `.github/workflows/slsa-phase0.yml`, `.github/workflows/slsa-phase0-attest.yml`

**Interfaces:**
- Consumes: `packaging/ci/tool` (cosign), `packaging/container/check_containerfile.py --base`.
- Produces: results P0-1 to P0-5 in the README's As-built log.

- [ ] **Step 1: Ask your partner** to push `slsa-phase0` and to create the ghcr package
  `wd2l-slsa-phase0`, which will be deleted in Task 0.2.

- [ ] **Step 2: Write the caller** `.github/workflows/slsa-phase0.yml`:

```yaml
name: slsa-phase0
# Throwaway checks for docs/superpowers/plans/2026-10-09-slsa-build-l3/phase-0-checks.md.
# Delete this branch and the ghcr package wd2l-slsa-phase0 afterwards.
on:
  push:
    branches: [slsa-phase0]
permissions:
  contents: read
defaults:
  run:
    shell: bash
jobs:
  build:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write
    outputs:
      digest: ${{ steps.push.outputs.digest }}
    env:
      TOKEN: ${{ secrets.GITHUB_TOKEN }}
      ACTOR: ${{ github.actor }}
      IMAGE: ghcr.io/joehazurmoney/wd2l-slsa-phase0
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Two files, their SHA256SUMS, and an image pushed by digest
        id: push
        run: |
          mkdir out && echo "phase0 $GITHUB_SHA" > out/file-a.txt && echo "b" > out/file-b.txt
          (cd out && sha256sum -- * > SHA256SUMS)
          echo "$TOKEN" | podman login ghcr.io -u "$ACTOR" --password-stdin
          B=$(python3 packaging/container/check_containerfile.py --base)
          podman pull -q "$B" && podman tag "$B" "$IMAGE:check"
          podman push --digestfile digest "$IMAGE:check"
          echo "digest=$(cat digest)" >> "$GITHUB_OUTPUT"
      - name: A key signature too (P0-4), with a throwaway key
        env:
          COSIGN_PASSWORD: throwaway
          TOOL_ENV: COSIGN_PASSWORD
        run: |
          packaging/ci/tool cosign generate-key-pair --output-key-prefix out/phase0
          packaging/ci/tool cosign sign --key /work/out/phase0.key \
            --signing-config /work/packaging/release/signing-config.json --yes \
            "$IMAGE@$(cat digest)"
          rm out/phase0.key
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: phase0-files
          path: out/

  attest:
    needs: [build]
    uses: ./.github/workflows/slsa-phase0-attest.yml
    with:
      digest: ${{ needs.build.outputs.digest }}
    permissions:
      contents: read
      id-token: write
      attestations: write
      packages: write

  verify:
    needs: [build, attest]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: read
      attestations: read
    env:
      GH_TOKEN: ${{ github.token }}
      ACTOR: ${{ github.actor }}
      R: JoeHazurmoney/architecture-wiredata-to-log
      W: JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/slsa-phase0-attest.yml
      I: ghcr.io/joehazurmoney/wd2l-slsa-phase0@${{ needs.build.outputs.digest }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: phase0-files
          path: out
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: phase0-bundles
          path: bundles
      - name: P0-1 files, online, pinned to the signer workflow
        run: |
          gh attestation verify out/file-a.txt --repo "$R" --signer-workflow "$W" \
            --source-ref "$GITHUB_REF" --deny-self-hosted-runners
          gh attestation verify out/file-b.txt --repo "$R" --signer-workflow "$W"
          if gh attestation verify out/file-a.txt --repo "$R" \
               --signer-workflow "$R/.github/workflows/slsa-phase0.yml"; then
            echo "P0-1: the caller's workflow passed as signer" >&2; exit 1
          fi
          echo "P0-1: ok"
      - name: P0-3 the image, from the attestation in ghcr
        run: |
          gh attestation verify "oci://$I" --repo "$R" --signer-workflow "$W" --bundle-from-oci
          echo "P0-3: ok"
      - name: P0-2 offline, with the bundles and Sigstore's trusted root
        run: |
          gh attestation trusted-root > trusted_root.jsonl
          sudo unshare --net -- env HOME="$HOME" PATH="$PATH" GH_TOKEN= \
            gh attestation verify out/file-a.txt --bundle bundles/attestations.jsonl \
            --custom-trusted-root trusted_root.jsonl --repo "$R" --signer-workflow "$W"
          echo "P0-2: ok"
      - name: P0-4 the keyless signature, and the key signature beside it
        run: |
          echo "$GH_TOKEN" | podman login ghcr.io -u "$ACTOR" --password-stdin
          packaging/ci/tool cosign verify "$I" \
            --certificate-identity "https://github.com/$W@$GITHUB_REF" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com > /dev/null
          echo "P0-4 keyless: ok"
          packaging/ci/tool cosign verify --key /work/out/phase0.pub --insecure-ignore-tlog "$I" > /dev/null
          echo "P0-4 key: ok"
          packaging/ci/tool cosign tree "$I"
```

- [ ] **Step 3: Write the reusable workflow** `.github/workflows/slsa-phase0-attest.yml`:

```yaml
name: slsa-phase0-attest
# The reusable workflow that attests in Phase 0 (P0-1 to P0-5). Throwaway.
on:
  workflow_call:
    inputs:
      digest:
        type: string
        required: true
permissions:
  contents: read
defaults:
  run:
    shell: bash
jobs:
  attest:
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      id-token: write
      attestations: write
      packages: write
    env:
      TOKEN: ${{ secrets.GITHUB_TOKEN }}
      ACTOR: ${{ github.actor }}
      IMAGE: ghcr.io/joehazurmoney/wd2l-slsa-phase0
      D: ${{ inputs.digest }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2
        with:
          name: phase0-files
          path: out
      - id: files
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with:
          subject-checksums: out/SHA256SUMS
      - run: echo "$TOKEN" | docker login ghcr.io -u "$ACTOR" --password-stdin
      - id: image
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with:
          subject-name: ghcr.io/joehazurmoney/wd2l-slsa-phase0
          subject-digest: ${{ inputs.digest }}
          push-to-registry: true
          create-storage-record: false
      - name: Keyless cosign signature (P0-4)
        env:
          TOOL_ENV: ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN
        run: |
          echo "$TOKEN" | podman login ghcr.io -u "$ACTOR" --password-stdin
          packaging/ci/tool cosign sign --yes "$IMAGE@$D"
      - name: The bundles, one per line
        env:
          FILES_BUNDLE: ${{ steps.files.outputs.bundle-path }}
          IMAGE_BUNDLE: ${{ steps.image.outputs.bundle-path }}
        run: |
          mkdir bundles
          jq -c . "$FILES_BUNDLE" "$IMAGE_BUNDLE" > bundles/attestations.jsonl
          wc -l bundles/attestations.jsonl
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: phase0-bundles
          path: bundles/
```

- [ ] **Step 4: Lint, commit on the branch, push (with OK), watch**

```bash
git checkout -b slsa-phase0 main
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/repo -w /repo rhysd/actionlint:latest -color=false
git add .github/workflows/slsa-phase0.yml .github/workflows/slsa-phase0-attest.yml
git commit -m "Phase 0 (SLSA L3): attest, keyless sign and verify, online and offline"
git push -u origin slsa-phase0
gh run watch "$(gh run list --branch slsa-phase0 --workflow slsa-phase0 --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: `build`, `attest` and `verify` are green, and the `verify` log has `P0-1: ok`,
`P0-3: ok`, `P0-2: ok`, `P0-4 keyless: ok` and `P0-4 key: ok`. P0-5 passes by the
`attest` job running at all.

For each failure, read the log, apply the check's fallback from the table above, push again,
and write down what changed.

- [ ] **Step 5: Record P0-1 to P0-5** as rows in the README's As-built log: the result, the
  run ID, and the fallback if one was used. **Also record from the `attest` job's log** the
  certificate's SubjectAlternativeName, which `cosign tree` and `gh attestation verify
  --format json` show. Phases 1 and 2 pin that identity.

```bash
git checkout main   # the README's As-built rows go in with Phase 1's first commit
```

---

### Task 0.2: Clean up

- [ ] **Step 1: With your partner's OK,** delete the branch (`git push origin --delete
  slsa-phase0; git branch -D slsa-phase0`). Ask them to delete the ghcr package
  `wd2l-slsa-phase0` (Packages, then Package settings), or do it with
  `gh api -X DELETE user/packages/container/wd2l-slsa-phase0` if they say so.
- [ ] **Step 2:** Add an As-built row "P0 cleanup: branch and package deleted".
