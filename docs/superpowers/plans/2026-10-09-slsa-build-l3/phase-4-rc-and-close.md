# Phase 4: an rc proves it, then the records close

Part of the [SLSA Build L3 plan](README.md). Spec requirement 10. Runs on `main` after the PR
for Phases 1–3 merges.

---

### Task 4.1: The rc, checked online and offline

**Files:**
- Modify: `wd2l/__init__.py`, `deploy/log-server/wd2l-sender.container`,
  `deploy/receiver/wd2l-receiver.container` (the next rc version, through a PR)

**Interfaces:**
- Consumes: everything above; `docs/releasing.md`'s commands.
- Produces: a draft pre-release holding `wd2l-<version>-attestations.jsonl`, and the results
  recorded in the As-built log.

- [ ] **Step 1: The version PR.** Set the next rc (`X.Y.ZrcN`): `__version__` and both
  `Image=` tags. Get your partner's OK to open the PR, and they merge it once `ci-ok` passes.
- [ ] **Step 2: The tag**, with your partner's OK, on the merged `main` commit, once `main`'s
  `tests` run is green:

```bash
git checkout main && git pull --ff-only
git tag -a vX.Y.ZrcN -m "wd2l X.Y.ZrcN" && git push origin vX.Y.ZrcN
```

  Your partner approves the two `release` deployments when the run asks.

- [ ] **Step 3: Check the run.** Every job is green, `attest` included. Its log shows `keyless
  signature: ok`. The draft has `wd2l-X.Y.ZrcN-attestations.jsonl` (2 lines).

- [ ] **Step 4: Verify online** (any machine with `gh` and cosign):

```bash
V=X.Y.ZrcN; R=JoeHazurmoney/architecture-wiredata-to-log
P="--repo $R --signer-workflow $R/.github/workflows/attest.yml --source-ref refs/tags/v$V --deny-self-hosted-runners"
gh release download "v$V" -R "$R" -D "rc-$V" && cd "rc-$V"
sha256sum -c SHA256SUMS
while read -r _ f; do gh attestation verify "$f" $P > /dev/null && echo "ok $f"; done < SHA256SUMS
D=$(gh release view "v$V" -R "$R" --json body --jq .body \
    | grep -o 'ghcr.io/joehazurmoney/wd2l@sha256:[0-9a-f]\{64\}' | head -1 | cut -d@ -f2)
gh attestation verify "oci://ghcr.io/joehazurmoney/wd2l@$D" $P --bundle-from-oci
cosign verify "ghcr.io/joehazurmoney/wd2l@$D" \
  --certificate-identity "https://github.com/$R/.github/workflows/attest.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-github-workflow-repository "$R" > /dev/null && echo "keyless ok"
cosign verify --key cosign.pub --insecure-ignore-tlog "ghcr.io/joehazurmoney/wd2l@$D" > /dev/null && echo "key ok"
```

  Expected: `ok` for every line of `SHA256SUMS`, the image verifies both ways, and the key
  path still passes. Then two **negative checks**, which must both fail:
  * `gh attestation verify` with `--source-ref refs/heads/main`;
  * the keyless `cosign verify` with `--certificate-github-workflow-repository
    someone-else/architecture-wiredata-to-log`.

- [ ] **Step 5: Verify offline.** Fetch the trusted root while still online
  (`gh attestation trusted-root > trusted_root.jsonl`). Then cut the network: a VM with its
  network removed, or `sudo unshare --net` on Linux. Run the loop from `docs/releasing.md`
  ("GitHub build provenance, offline") and the key-path commands from "Bringing a release into
  an enclave". Expected: everything passes with no network.

- [ ] **Step 6: Record** in the As-built log: the run ID, the draft's assets, and each check's
  result. Any failure is a finding: fix it in a PR, then cut the next rc.

---

### Task 4.2: Close the records

- [ ] **Step 1:** ADR-0007 goes from **Proposed** to **Accepted**, with the date. Its action
  item gets ticked, with the rc's version.
- [ ] **Step 2:** ADR-0006's update section: "GitHub artifact attestations and keyless
  signatures: done, [ADR-0007](0007-slsa-build-l3.md)."
- [ ] **Step 3:** At the end of this plan's As-built log, add "**Closed (<date>).**" and the rc
  that proved it.
- [ ] **Step 4:** Commit through a PR (with OK):

```bash
git add docs/decisions/0007-slsa-build-l3.md docs/decisions/0006-release-artifacts-and-signing.md docs/superpowers/plans/2026-10-09-slsa-build-l3/README.md
git commit -m "SLSA Build L3: proven on vX.Y.ZrcN; ADR-0007 Accepted"
```
