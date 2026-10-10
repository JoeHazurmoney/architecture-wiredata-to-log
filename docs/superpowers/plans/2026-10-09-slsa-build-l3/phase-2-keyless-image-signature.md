# Phase 2: a keyless signature on the image

Part of the [SLSA Build L3 plan](README.md). Spec requirement 4. The key signature stays
(Global constraints). This one is for consumers who pull from ghcr and check it against
Sigstore's public instance, with cosign or an admission controller that reads Sigstore
bundles. The docs don't promise Podman: whether its `sigstoreSigned` policy reads cosign 3
referrer bundles is still open in `docs/deployment/containers.md` (As-built, Review).

---

### Task 2.1: Sign keylessly in `attest.yml`, and check it at once

**Files:**
- Modify: `.github/workflows/attest.yml`, `tests/test_workflow_policy.py`

**Interfaces:**
- Consumes: P0-4 (the identity the certificate shows, and whether `packaging/ci/tool` passes the
  token request through); `attest.yml` from Task 1.1.
- Produces: a keyless signature on `ghcr.io/joehazurmoney/wd2l@<digest>`, whose certificate
  identity is
  `https://github.com/JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml@refs/tags/v<version>`
  and whose issuer is `https://token.actions.githubusercontent.com`. Its GitHub workflow
  repository extension is `JoeHazurmoney/architecture-wiredata-to-log`, and every verify pins it.

- [ ] **Step 1: Write the failing test** (append to `tests/test_workflow_policy.py`)

```python
def test_attest_signs_the_image_keylessly_and_checks_the_identity():
    att = jobs(read("attest.yml"))["attest"]
    assert "TOOL_ENV: ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN" in att
    assert 'packaging/ci/tool cosign sign --yes "$IMAGE@$D"' in att
    assert ('--certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/'
            'attest.yml@$GITHUB_REF"') in att
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in att
    # the identity alone also matches a run of attest.yml called from another repository
    assert '--certificate-github-workflow-repository "$GITHUB_REPOSITORY"' in att
    # keyless means Sigstore's public log: never the no-log signing config used with the key
    assert "signing-config" not in att
```

- [ ] **Step 2: Run it**

Run: `T -q tests/test_workflow_policy.py::test_attest_signs_the_image_keylessly_and_checks_the_identity`
Expected: FAIL (the `TOOL_ENV` line isn't there).

- [ ] **Step 3: Add the step** to `attest.yml`, after "Provenance for the image" and before
  "The bundles":

```yaml
      - name: Keyless cosign signature on the image (Sigstore's public instance), checked at once
        env:
          TOOL_ENV: ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN
          D: ${{ inputs.image-digest }}
        run: |
          echo "$TOKEN" | podman login ghcr.io -u "$ACTOR" --password-stdin
          packaging/ci/tool cosign sign --yes "$IMAGE@$D"
          packaging/ci/tool cosign verify "$IMAGE@$D" \
            --certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/attest.yml@$GITHUB_REF" \
            --certificate-oidc-issuer https://token.actions.githubusercontent.com \
            --certificate-github-workflow-repository "$GITHUB_REPOSITORY" > /dev/null
          echo "keyless signature: ok"
```

  If P0-4 used its fallback (cosign on the runner, outside the tool container), use the
  command form the As-built row records, keep the test's identity and issuer lines, and change
  the test's `cosign sign` line to match.

- [ ] **Step 4: Run the tests and actionlint**

Run: `T -q tests/test_workflow_policy.py && T -q`, then actionlint.
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/attest.yml tests/test_workflow_policy.py
git commit -m "attest.yml: a keyless cosign signature on the image beside the key's, checked against attest.yml's identity"
```

`verify-published` in `publish.yml` stays as it is: it checks the key signature, and runs
before `attest`. The rc (Phase 4) checks both signatures side by side.
