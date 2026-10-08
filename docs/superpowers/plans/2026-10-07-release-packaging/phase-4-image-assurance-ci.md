# Phase 4: image assurance CI (the series of jobs)

Part of the [release packaging plan](README.md). Read its **Global constraints** first. Spec:
[spec.md](spec.md) "Phase 4" (the 11-job table).

**Delivers:** `.github/workflows/image.yml`, a reusable workflow.

* `tests.yml` calls it on every push and PR with `publish: false`. `release.yml` calls it with
  `publish: true` (Phase 6).
* Each check is a small stdlib script with unit tests, so a red job always names the rule it
  broke.
* Also: the weekly rescan of released images, and Dependabot for the pins.

| # | Job | Task | Runs |
|---|---|---|---|
| 1 | `lint` | 4.1 | always |
| 2 | `base-verify` | 4.2 | always |
| 3 | `build` | 4.1 | always |
| 4 | `reproducible` | 4.6 | always (report-only at first) |
| 5 | `hardening` | 4.3 | always |
| 6 | `vuln-scan` | 4.4 | always |
| 7 | `sbom` | 4.5 | always |
| 8 | `functional` | 4.1 | always |
| 9 | `fips-tests` | 4.1 | always |
| 10 | `publish` | 4.7 | `publish: true` only |
| 11 | `verify-published` | 4.7 | `publish: true` only |

**Depends on Phase 0:**

* P0-7 (cosign flags) and P0-8 (copying the base). If a row says a flag differs, use the
  recorded form everywhere in this phase.
* Phase 0's runner log: if `skopeo` or `jq` aren't on the runner, install them in the job
  (`sudo apt-get install -y -q skopeo jq`).

**Paths for tools:** `packaging/ci/tool` mounts the work tree at `/work`. Files given to a tool
are `/work/<relative path>`, and files a tool writes go under `/work/...` too.

Run tests with `T` from the plan README.

---

### Task 4.1: `image.yml`: lint, build, functional, fips-tests; actions pinned by SHA

**Files:**
- Create: `.github/workflows/image.yml`
- Modify: `.github/workflows/tests.yml` (drop `dist` and `lab-image`, call `image.yml`),
  `.github/workflows/compare-bases.yml` (pins)

**Interfaces:**
- Consumes: `check_containerfile.py`, `build.sh`, `lab/run-lab.sh --image`, `check_dist.py`,
  `packaging/ci/tool`.
- Produces:
  * `image.yml` with `on.workflow_call.inputs.publish` (boolean) and the secrets
    `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD` (optional), plus `workflow_dispatch`;
  * `on.workflow_call.outputs.digest`, filled by Task 4.7;
  * these artifacts:
    * `dist`: the wheel and sdist;
    * `image`: `image.oci.tar`;
    * `build-info`: `build-info.json`, with `commit`, `version`, `image_id`, `epoch` and
      `started`.

- [ ] **Step 1: Resolve the action pins.** For each action, take the current major's commit:

```bash
for a in actions/checkout actions/setup-python actions/upload-artifact actions/download-artifact; do
  tag=$(gh release view -R "$a" --json tagName --jq .tagName); major=${tag%%.*}
  echo "$a $tag $(gh api "repos/$a/commits/$major" --jq .sha)"
done
```

Use them as `uses: actions/checkout@<sha> # <tag>` in every workflow in this plan, including
`tests.yml` and `compare-bases.yml`.

- [ ] **Step 2: Write `.github/workflows/image.yml`**, with the first four jobs. Tasks 4.2–4.7
  add the rest.

```yaml
name: image
# The container image's checks (docs/decisions/0004-container-base-image.md): every push and PR
# via tests.yml (publish: false); releases via release.yml (publish: true, signs and pushes).
on:
  workflow_call:
    inputs:
      publish:
        type: boolean
        default: false
    secrets:
      COSIGN_PRIVATE_KEY:
        required: false
      COSIGN_PASSWORD:
        required: false
    outputs:
      digest:
        value: ${{ jobs.publish.outputs.digest }}
  workflow_dispatch:
permissions:
  contents: read
jobs:
  lint:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - name: Every FROM pinned, a Hardened Image, a FIPS variant
        run: python3 packaging/container/check_containerfile.py
      - name: hadolint
        run: packaging/ci/tool hadolint /bin/hadolint /work/packaging/container/Containerfile
      - name: trivy config (High and Critical)
        run: packaging/ci/tool trivy config --quiet --exit-code 1 --severity HIGH,CRITICAL /work/packaging/container

  build:
    needs: [lint]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/setup-python@<sha> # <tag>
        with:
          python-version: "3.12"
      - name: Wheel and sdist (BUILD = the commit; file times = the commit's)
        run: |
          export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
          python -m pip install -q build
          git rev-parse HEAD > wd2l/BUILD
          python -m build
          python packaging/check_dist.py dist --commit "$(git rev-parse HEAD)"
      - name: Image
        run: |
          started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          packaging/container/build.sh dist localhost/wd2l:ci
          mkdir -p image build-info
          podman save --format oci-archive -o image/image.oci.tar localhost/wd2l:ci
          jq -n --arg commit "$(git rev-parse HEAD)" \
                --arg version "$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' wd2l/__init__.py)" \
                --arg image_id "$(podman image inspect --format '{{.Id}}' localhost/wd2l:ci)" \
                --arg epoch "$(git log -1 --format=%ct)" --arg started "$started" \
                '{commit: $commit, version: $version, image_id: $image_id, epoch: $epoch, started: $started}' \
                > build-info/build-info.json
          cat build-info/build-info.json
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: dist
          path: dist/
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: image
          path: image/
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: build-info
          path: build-info/

  functional:
    needs: [build]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          name: image
          path: image
      - run: sudo apt-get update -q && sudo apt-get install -y -q iproute2 nftables tcpdump
      - name: Load
        run: echo "IMG=$(sudo podman load -q -i image/image.oci.tar | awk '{print $NF}')" >> "$GITHUB_ENV"
      - name: Smoke
        run: |
          for c in wd2l-sender wd2l-receiver wd2l-audit-report; do sudo podman run --rm "$IMG" "$c" --help > /dev/null; done
          if sudo podman run --rm "$IMG" python3 -m wd2l.audit verify /tmp; then exit 1; fi
          echo "an empty audit directory is refused, as expected"
      - run: sudo lab/run-lab.sh --image "$IMG"
      - run: sudo lab/run-lab.sh --image "$IMG" --loss 1
      - run: sudo lab/run-lab.sh --image "$IMG" --maintenance
      - run: sudo lab/run-lab.sh --image "$IMG" --receiver-outage
      - run: sudo lab/run-lab.sh --image "$IMG" --files samples/logs/messages samples/logs/secure samples/logs/audit.log

  fips-tests:
    # The whole test suite under the OpenSSL FIPS provider (the builder has the same Python and
    # crypto policy as the runtime image, plus a shell and dnf for pytest).
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - run: |
          B=$(python3 packaging/container/check_containerfile.py --json | jq -r '.[] | select(.tag | endswith("-builder")) | .ref')
          podman run --rm --userns=keep-id -v "$PWD:/src" -w /src "$B" bash -c \
            'python3 -c "import _hashlib; assert _hashlib.get_fips_mode() == 1, \"not FIPS\"" &&
             python3 -m pip install -q --user pytest && python3 -m pytest -q -p no:cacheprovider'
```

- [ ] **Step 3: Change `tests.yml`**
  * Delete the `dist` job (Task 1.1) and the `lab-image` job (Task 3.3).
  * Change `push:` to `push: {branches: ["**"]}`. Then a version tag runs only `release.yml`,
    which calls this workflow itself.
  * Add `workflow_call:` under `on:`, with the input `image` (boolean, default true).
  * Add this job, and pin every `uses:` by SHA:

```yaml
  image:
    if: ${{ inputs.image != false }}
    uses: ./.github/workflows/image.yml
    with:
      publish: false
```

(`inputs.image` is empty on push and PR events, so the job runs then. `release.yml` calls
`tests.yml` with `image: false` and calls `image.yml` itself, so it isn't built twice.)

- [ ] **Step 4: Check it in CI.** Ask your partner, then push.

```bash
git add .github/workflows/image.yml .github/workflows/tests.yml .github/workflows/compare-bases.yml
git commit -m "CI: image pipeline (lint, build, functional, FIPS tests); actions pinned by SHA"
git push
gh run watch "$(gh run list --branch release-packaging --workflow tests --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: `pytest`, `lab` and `image / lint, build, functional, fips-tests` are all green.

* If hadolint flags a rule that is deliberate (for example `USER 0` in the build stage), add
  `packaging/container/.hadolint.yaml` with that rule under `ignored:` and a comment saying why.
  Then pass `--config /work/packaging/container/.hadolint.yaml`, and add an As-built row.
* If a test fails only in `fips-tests`, it uses a non-approved algorithm. Find it before going
  on: that is a finding, not noise.

---

### Task 4.2: `base-verify`: the base images' signatures, provenance and SBOMs

**Files:**
- Create: `packaging/container/base_record.py`, `packaging/container/keys/redhat-release3.pub`,
  `packaging/container/keys/hummingbird-ci.pub`, `packaging/container/keys/README.md`
- Modify: `.github/workflows/image.yml`, `tests/test_container_checks.py`

**Interfaces:**
- Consumes: `check_containerfile.py --json` and `packaging/ci/tool` (cosign, oras).
- Produces:
  * `base_record.record(froms, evidence_dir, keys_dir, now) -> (dict, List[str])`, plus the
    helpers `platform_digests(index) -> Dict[str, str]` and
    `provenance_subjects(text) -> Set[str]`;
  * the `base-evidence` artifact:
    * `froms.json`;
    * `index-<i>.json`, `config-<i>.json`, `signature-<i>.json`, `provenance-<i>.json` and
      `sbom-<i>.spdx.json` for each FROM `i`;
    * `base-image-record.json`.

- [ ] **Step 1: Fetch and commit the two public keys**

```bash
mkdir -p packaging/container/keys
curl -s https://security.access.redhat.com/data/63405576.txt -o /tmp/rh.txt
sha256sum /tmp/rh.txt                                   # 2d43fc0ec7f773a75b5d4ae70c1c0b93c6ddc4a8f2ef9fd81b2589076032e80c (2026-10-07)
sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' /tmp/rh.txt > packaging/container/keys/redhat-release3.pub
curl -s "https://gitlab.com/redhat/hummingbird/containers/-/raw/main/ci/key.pub?ref_type=heads" \
  -o packaging/container/keys/hummingbird-ci.pub
sha256sum packaging/container/keys/*.pub
```

Expected: the downloaded Red Hat file's hash matches the one above, and
`hummingbird-ci.pub`'s is `40537705f3be25019a6c0c4befb4cff9454968cfb4c984001e755a9e278f2c4c`.
If either differs, stop. Tell your partner that the key changed since the plan was written, and
confirm the new one on Red Hat's product security pages before going on.

`packaging/container/keys/README.md`:

```markdown
# Public keys for the base images

The image pipeline (`.github/workflows/image.yml`, job `base-verify`) verifies each base image
with these, before every build. They are copies, so a change upstream can't silently change what
we trust; replacing one is a reviewed commit.

| File | What it verifies | Source | SHA-256 of the file |
|---|---|---|---|
| `redhat-release3.pub` | Red Hat's signature on `registry.access.redhat.com/hi/*` | PEM block of https://security.access.redhat.com/data/63405576.txt ("Red Hat, Inc. (release key 3)", fetched 2026-10-07; that page's SHA-256 was 2d43fc0e…2e80c) | <sha256sum of the PEM file> |
| `hummingbird-ci.pub` | The SLSA provenance on `quay.io/hummingbird/*` (Red Hat's Konflux pipeline) | https://gitlab.com/redhat/hummingbird/containers/-/raw/main/ci/key.pub | 40537705…8f2c4c |
```

- [ ] **Step 2: Write the failing tests** (append to `tests/test_container_checks.py`)

```python
import base64
import hashlib

br = load_script("packaging/container/base_record.py")


def write_evidence(d, i, ref_name, tag, sign_digest=None, prov_digest=None, fips=True,
                   index_bytes=None):
    """Evidence files for FROM number i, as the base-verify job writes them. Returns the
    index digest the Containerfile must name."""
    amd = "sha256:" + hashlib.sha256(b"amd%d" % i).hexdigest()
    arm = "sha256:" + hashlib.sha256(b"arm%d" % i).hexdigest()
    index = index_bytes or json.dumps({"manifests": [
        {"digest": amd, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": arm, "platform": {"os": "linux", "architecture": "arm64"}}]}).encode()
    digest = "sha256:" + hashlib.sha256(index).hexdigest()
    (d / ("index-%d.json" % i)).write_bytes(index)
    labels = {"version": "3.12.15", "release": "1791414125"}
    if fips:
        labels["io.hummingbird-project.variant.fips"] = "true"
    (d / ("config-%d.json" % i)).write_text(json.dumps({"config": {"Labels": labels}}))
    (d / ("signature-%d.json" % i)).write_text(json.dumps([{"critical": {
        "image": {"docker-manifest-digest": sign_digest or digest}}}]))
    statement = {"_type": "https://in-toto.io/Statement/v0.1",
                 "predicateType": "https://slsa.dev/provenance/v0.2",
                 "subject": [{"name": "quay.io/hummingbird/python",
                              "digest": {"sha256": (prov_digest or amd).split(":")[1]}}]}
    (d / ("provenance-%d.json" % i)).write_text(json.dumps({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n")
    (d / ("sbom-%d.spdx.json" % i)).write_text(json.dumps({
        "spdxVersion": "SPDX-2.3", "packages": [{"name": "python3.12"}, {"name": "glibc"}]}))
    return digest


def evidence(tmp_path, **kw):
    d = tmp_path / "evidence"
    d.mkdir()
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "redhat-release3.pub").write_text("rh")
    (keys / "hummingbird-ci.pub").write_text("hb")
    d0 = write_evidence(d, 0, B, "3.12-fips-builder")
    d1 = write_evidence(d, 1, B, "3.12-fips", **kw)
    froms = [{"ref": "%s:3.12-fips-builder@%s" % (B, d0), "stage": "build", "name": B,
              "tag": "3.12-fips-builder", "digest": d0},
             {"ref": "%s:3.12-fips@%s" % (B, d1), "stage": None, "name": B,
              "tag": "3.12-fips", "digest": d1}]
    return froms, d, keys


def test_record_from_good_evidence(tmp_path):
    froms, d, keys = evidence(tmp_path)
    rec, probs = br.record(froms, str(d), str(keys), "2026-10-07T00:00:00Z")
    assert probs == []
    img = rec["images"][1]
    assert img["index_digest"] == froms[1]["digest"] and set(img["platforms"]) == {"amd64", "arm64"}
    assert img["source_image"] == B + ":1791414125-source"
    assert img["mirror"] == "quay.io/hummingbird/python@" + froms[1]["digest"]
    assert img["signature"]["verified"] and img["provenance"]["predicate_type"].endswith("v0.2")
    assert img["sbom"]["packages"] == 2
    assert rec["keys"]["redhat-release3.pub"] == hashlib.sha256(b"rh").hexdigest()


def test_record_refuses_a_signature_for_another_digest(tmp_path):
    froms, d, keys = evidence(tmp_path, sign_digest="sha256:" + "9" * 64)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("signature" in p and froms[1]["digest"] in p for p in probs)


def test_record_refuses_provenance_for_another_digest(tmp_path):
    froms, d, keys = evidence(tmp_path, prov_digest="sha256:" + "8" * 64)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("provenance" in p for p in probs)


def test_record_refuses_an_index_that_is_not_the_pinned_digest(tmp_path):
    froms, d, keys = evidence(tmp_path)
    (d / "index-1.json").write_bytes(b'{"manifests": []}')
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("index" in p and "pinned" in p for p in probs)


def test_record_refuses_a_fips_tag_without_the_fips_label(tmp_path):
    froms, d, keys = evidence(tmp_path, fips=False)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("FIPS" in p for p in probs)


def test_record_refuses_missing_evidence(tmp_path):
    froms, d, keys = evidence(tmp_path)
    (d / "sbom-1.spdx.json").unlink()
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("sbom-1.spdx.json" in p for p in probs)
```

- [ ] **Step 3: Run them to verify they fail**

Run: `T tests/test_container_checks.py -k record -v`
Expected: FAIL (`FileNotFoundError` for `base_record.py`).

- [ ] **Step 4: Write `packaging/container/base_record.py`**

```python
#!/usr/bin/env python3
"""Cross-checks what the base-verify job collected for each base image, and writes
base-image-record.json: the exact images a build stood on, and how each was checked
(docs/decisions/0006-release-artifacts-and-signing.md).

EVIDENCE holds, for FROM number i of the Containerfile (0 = the first):
  index-<i>.json       the image index, raw bytes (skopeo inspect --raw)
  config-<i>.json      the amd64 image config (skopeo inspect --config)
  signature-<i>.json   `cosign verify` output with keys/redhat-release3.pub
  provenance-<i>.json  `cosign verify-attestation --type slsaprovenance` output with
                       keys/hummingbird-ci.pub, one JSON object per line
  sbom-<i>.spdx.json   the base's SPDX SBOM, from quay.io/hummingbird
cosign has already verified the signatures (it exits non-zero otherwise). This script checks
that they are about the pinned digests, so nothing else could have been verified instead.

    base_record.py --containerfile FILE --evidence DIR --keys DIR --out FILE"""

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_containerfile  # noqa: E402  (a sibling script, not a package)

REGISTRY = "registry.access.redhat.com/hi/"
MIRROR = "quay.io/hummingbird/"
SIGNING_KEY, PROVENANCE_KEY = "redhat-release3.pub", "hummingbird-ci.pub"


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def platform_digests(index: Dict[str, Any]) -> Dict[str, str]:
    return {m["platform"]["architecture"]: m["digest"] for m in index.get("manifests", [])
            if m.get("platform", {}).get("os", "linux") == "linux"}


def provenance_subjects(text: str) -> Tuple[Set[str], Set[str]]:
    """(subject digests, predicate types) of the attestations in cosign's output."""
    digests, types = set(), set()
    for line in text.splitlines():
        if not line.strip():
            continue
        env = json.loads(line)
        st = json.loads(base64.b64decode(env["payload"]))
        types.add(st.get("predicateType", ""))
        for s in st.get("subject", []):
            if "sha256" in s.get("digest", {}):
                digests.add("sha256:" + s["digest"]["sha256"])
    return digests, types


def _entry(i: int, f: Dict[str, Any], ev: str, probs: List[str]) -> Dict[str, Any]:
    def path(name: str) -> Optional[str]:
        p = os.path.join(ev, name % i)
        if not os.path.isfile(p):
            probs.append("%s: missing %s" % (f["ref"], name % i))
            return None
        return p

    digest = f["digest"]
    out: Dict[str, Any] = {"ref": f["ref"], "stage": f["stage"] or "runtime",
                           "index_digest": digest,
                           "mirror": MIRROR + f["name"][len(REGISTRY):] + "@" + digest}
    p = path("index-%d.json")
    if p:
        got = "sha256:" + _sha256(p)
        if got != digest:
            probs.append("%s: the index fetched (%s) is not the pinned digest" % (f["ref"], got))
        with open(p) as fh:
            out["platforms"] = platform_digests(json.load(fh))
    known = {digest} | set(out.get("platforms", {}).values())
    p = path("config-%d.json")
    if p:
        with open(p) as fh:
            labels = (json.load(fh).get("config") or {}).get("Labels") or {}
        out["version"], out["release"] = labels.get("version"), labels.get("release")
        out["source_image"] = "%s:%s-source" % (f["name"], labels.get("release"))
        if str(f["tag"]).endswith(("-fips", "-fips-builder")) and \
                labels.get("io.hummingbird-project.variant.fips") != "true":
            probs.append("%s: tagged FIPS but its config has no FIPS variant label" % f["ref"])
    p = path("signature-%d.json")
    if p:
        with open(p) as fh:
            text = fh.read()
        ok = digest in text
        if not ok:
            probs.append("%s: the Red Hat signature verified is not for %s" % (f["ref"], digest))
        out["signature"] = {"key": SIGNING_KEY, "verified": ok, "evidence_sha256": _sha256(p)}
    p = path("provenance-%d.json")
    if p:
        with open(p) as fh:
            subjects, types = provenance_subjects(fh.read())
        if not subjects & known:
            probs.append("%s: the provenance is about %s, not this image" % (f["ref"], sorted(subjects)))
        out["provenance"] = {"key": PROVENANCE_KEY, "predicate_type": ",".join(sorted(types)),
                             "subjects": sorted(subjects), "evidence_sha256": _sha256(p)}
    p = path("sbom-%d.spdx.json")
    if p:
        with open(p) as fh:
            sbom = json.load(fh)
        if not str(sbom.get("spdxVersion", "")).startswith("SPDX-"):
            probs.append("%s: the SBOM is not SPDX" % f["ref"])
        out["sbom"] = {"file": os.path.basename(p), "sha256": _sha256(p),
                       "packages": len(sbom.get("packages", []))}
    return out


def record(froms: List[Dict[str, Any]], evidence: str, keys: str,
           now: str) -> Tuple[Dict[str, Any], List[str]]:
    probs: List[str] = []
    rec: Dict[str, Any] = {"created": now, "keys": {}, "images": []}
    for k in (SIGNING_KEY, PROVENANCE_KEY):
        p = os.path.join(keys, k)
        rec["keys"][k] = _sha256(p) if os.path.isfile(p) else None
        if rec["keys"][k] is None:
            probs.append("missing key %s" % p)
    for i, f in enumerate(froms):
        if not f.get("digest"):
            probs.append("%s: not pinned" % f["ref"])
            continue
        rec["images"].append(_entry(i, f, evidence, probs))
    return rec, probs


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Write base-image-record.json from the evidence.")
    p.add_argument("--containerfile", default=check_containerfile.DEFAULT)
    p.add_argument("--evidence", required=True)
    p.add_argument("--keys", default=os.path.join(HERE, "keys"))
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    with open(a.containerfile) as fh:
        froms = check_containerfile.froms(fh.read())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec, probs = record(froms, a.evidence, a.keys, now)
    for x in probs:
        print("base: " + x, file=sys.stderr)
    with open(a.out, "w") as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
    if not probs:
        print("base: ok, %d images verified and recorded in %s" % (len(rec["images"]), a.out))
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `T tests/test_container_checks.py -v`
Expected: PASS.

- [ ] **Step 6: Add the job to `image.yml`** (and add `base-verify` to `build`'s `needs`)

```yaml
  base-verify:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - name: Collect each base image's signature, provenance, SBOM, index and config
        run: |
          mkdir -p evidence
          python3 packaging/container/check_containerfile.py --json > evidence/froms.json
          for i in $(seq 0 $(( $(jq length evidence/froms.json) - 1 ))); do
            name=$(jq -r ".[$i].name" evidence/froms.json)
            digest=$(jq -r ".[$i].digest" evidence/froms.json)
            mirror="quay.io/hummingbird/${name#registry.access.redhat.com/hi/}"
            skopeo inspect --raw "docker://$name@$digest" > "evidence/index-$i.json"
            skopeo inspect --config --override-os linux --override-arch amd64 \
              "docker://$name@$digest" > "evidence/config-$i.json"
            packaging/ci/tool cosign verify --key /work/packaging/container/keys/redhat-release3.pub \
              --insecure-ignore-tlog "$name@$digest" > "evidence/signature-$i.json"
            packaging/ci/tool cosign verify-attestation --key /work/packaging/container/keys/hummingbird-ci.pub \
              --insecure-ignore-tlog --type slsaprovenance "$mirror@$digest" > "evidence/provenance-$i.json"
            amd=$(jq -r '.manifests[] | select(.platform.architecture == "amd64") | .digest' "evidence/index-$i.json")
            layer=$(packaging/ci/tool oras manifest fetch "$mirror:sha256-${amd#sha256:}.sbom" | jq -r '.layers[0].digest')
            packaging/ci/tool oras blob fetch --output "/work/evidence/sbom-$i.spdx.json" "$mirror@$layer"
          done
      - name: Cross-check and record
        run: python3 packaging/container/base_record.py --evidence evidence --out evidence/base-image-record.json
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: base-evidence
          path: evidence/
```

- [ ] **Step 7: Commit, push (with OK) and check** that `base-verify` is green and its artifact
  has a `base-image-record.json` with two images.

```bash
git add packaging/container/base_record.py packaging/container/keys tests/test_container_checks.py \
  .github/workflows/image.yml
git commit -m "Image CI: verify the base images' signatures and provenance; record them"
```

---

### Task 4.3: `hardening`: the image's filesystem and config

**Files:**
- Create: `packaging/container/check_image.py`, `packaging/container/fips_check.py`
- Modify: `.github/workflows/image.yml`, `tests/test_container_checks.py`

**Interfaces:**
- Consumes: the `image`, `dist` and `build-info` artifacts, and `check_containerfile.base()`.
- Produces:
  * `check_image.check_config(cfg, version, commit, base_ref) -> List[str]`;
  * `check_image.check_filesystem(root, base_root) -> List[str]`;
  * `check_image.check_wheel_files(root, wheel, commit) -> List[str]`;
  * the constants `SHELLS`, `PACKAGE_MANAGERS`, `RPMDB` and `REMOVED_LABELS`;
  * `fips_check.py`, which runs inside the image and exits 0 or 1.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_container_checks.py`)

```python
import stat
import zipfile

ci = load_script("packaging/container/check_image.py")
SHA = "a" * 40


def wheel_and_rootfs(tmp_path, build=SHA):
    """A wheel and a rootfs that installed it, plus a base rootfs with the same rpmdb."""
    files = {"wd2l/__init__.py": b'__version__ = "0.3.0"\n', "wd2l/BUILD": (build + "\n").encode()}
    whl = tmp_path / "wd2l-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as z:
        rec = []
        for name, data in files.items():
            z.writestr(name, data)
            h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rec.append("%s,sha256=%s,%d" % (name, h, len(data)))
        rec.append("wd2l-0.3.0.dist-info/RECORD,,")
        z.writestr("wd2l-0.3.0.dist-info/RECORD", "\n".join(rec) + "\n")
    roots = []
    for name in ("rootfs", "base"):
        root = tmp_path / name
        (root / "etc/crypto-policies").mkdir(parents=True)
        (root / "etc/crypto-policies/config").write_text("FIPS\n")
        (root / "usr/lib/sysimage/rpm").mkdir(parents=True)
        (root / ci.RPMDB).write_bytes(b"the same rpmdb")
        (root / "tmp").mkdir()
        os.chmod(str(root / "tmp"), 0o1777)
        roots.append(root)
    site = roots[0] / "usr/lib/python3.12/site-packages"
    for name, data in files.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_bytes(data)
    return str(whl), str(roots[0]), str(roots[1])


def config(**over):
    labels = {"name": "wd2l", "vendor": "wd2l project",
              "org.opencontainers.image.title": "wd2l", "org.opencontainers.image.version": "0.3.0",
              "org.opencontainers.image.revision": SHA,
              "org.opencontainers.image.source": "https://github.com/x/y",
              "org.opencontainers.image.licenses": "MIT",
              "org.opencontainers.image.base.name": B + ":3.12-fips",
              "org.opencontainers.image.base.digest": D2}
    labels.update(over.pop("labels", {}))
    c = {"User": "65532", "Cmd": ["wd2l-receiver", "--help"], "Labels": labels}
    c.update(over)
    return [{"Config": c}]


BASE_REF = "%s:3.12-fips@%s" % (B, D2)


def test_good_image_passes(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    assert ci.check_config(config(), "0.3.0", SHA, BASE_REF) == []
    assert ci.check_filesystem(root, base) == []
    assert ci.check_wheel_files(root, whl, SHA) == []


def test_config_problems(tmp_path):
    probs = ci.check_config(config(User="0", Entrypoint=["/bin/sh", "-c"],
                                   labels={"cpe": "cpe:/a:redhat:hummingbird:1",
                                           "io.hummingbird-project.variant": "fips",
                                           "name": "hi/python",
                                           "org.opencontainers.image.base.digest": D1}),
                            "0.3.0", SHA, BASE_REF)
    text = "\n".join(probs)
    for word in ("65532", "shell", "cpe", "io.hummingbird-project.variant", "name", "base.digest"):
        assert word in text, word


def test_shell_and_package_manager_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    for p in ("usr/bin/bash", "usr/bin/dnf"):
        os.makedirs(os.path.join(root, os.path.dirname(p)), exist_ok=True)
        open(os.path.join(root, p), "w").close()
    text = "\n".join(ci.check_filesystem(root, base))
    assert "shell present: /usr/bin/bash" in text and "package manager present: /usr/bin/dnf" in text


def test_setuid_and_world_writable_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    os.makedirs(os.path.join(root, "usr/bin"), exist_ok=True)
    su = os.path.join(root, "usr/bin/su")
    open(su, "w").close()
    os.chmod(su, 0o4755)
    ww = os.path.join(root, "etc/open")
    open(ww, "w").close()
    os.chmod(ww, 0o666)
    text = "\n".join(ci.check_filesystem(root, base))
    assert "setuid/setgid file: /usr/bin/su" in text and "world-writable: /etc/open" in text
    assert "/tmp" not in text


def test_non_fips_policy_and_changed_rpmdb_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    with open(os.path.join(root, "etc/crypto-policies/config"), "w") as f:
        f.write("DEFAULT\n")
    with open(os.path.join(root, ci.RPMDB), "wb") as f:
        f.write(b"one more package")
    text = "\n".join(ci.check_filesystem(root, base))
    assert "not FIPS" in text and "rpm database differs" in text


def test_changed_wd2l_file_and_wrong_build_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    with open(os.path.join(root, "usr/lib/python3.12/site-packages/wd2l/__init__.py"), "a") as f:
        f.write("# changed\n")
    text = "\n".join(ci.check_wheel_files(root, whl, "b" * 40))
    assert "changed: " in text and "wd2l/__init__.py" in text and "BUILD" in text
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_container_checks.py -k "image or config or shell or setuid or fips or wd2l_file" -v`
Expected: FAIL (`FileNotFoundError` for `check_image.py`).

- [ ] **Step 3: Write `packaging/container/check_image.py`**

```python
#!/usr/bin/env python3
"""Hardening rules for the built image (docs/decisions/0004-container-base-image.md), checked on
its filesystem and its config:

* it runs as 65532, and its command isn't a shell;
* no shell and no package manager (pip comes with the base; the root filesystem is read-only
  and the user non-root, so it can't install anything);
* no setuid or setgid file, and nothing world-writable except sticky /tmp-like directories;
* the system crypto policy is FIPS;
* the RPM database is byte-identical to the base's, so the image adds no packages;
* wd2l's files match the wheel's RECORD hashes, and wd2l/BUILD names the commit;
* the labels name wd2l (not the base), the version, the commit, MIT and the exact base.

    check_image.py --rootfs DIR --base-rootfs DIR --config INSPECT.json --wheel WHL
                   --commit SHA --version V [--base-ref NAME:TAG@DIGEST]

The two rootfs directories come from `podman image mount`, inside `podman unshare`."""

import argparse
import base64
import csv
import glob
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from typing import Any, Dict, List, Optional, Sequence

SHELLS = ("bin/sh", "bin/bash", "usr/bin/sh", "usr/bin/bash", "bin/ash", "bin/dash",
          "usr/bin/dash", "bin/busybox", "usr/bin/busybox", "usr/bin/zsh")
PACKAGE_MANAGERS = ("usr/bin/dnf", "usr/bin/dnf5", "usr/bin/dnf-3", "usr/bin/microdnf",
                    "usr/bin/yum", "usr/bin/rpm", "usr/bin/apt", "usr/bin/apt-get",
                    "usr/bin/dpkg", "sbin/apk", "usr/bin/apk")
RPMDB = "usr/lib/sysimage/rpm/rpmdb.sqlite"
STICKY_OK = ("tmp", "var/tmp", "dev/shm")
REMOVED_LABELS = ("cpe", "com.redhat.component")
REQUIRED_LABELS = ("org.opencontainers.image.title", "org.opencontainers.image.version",
                   "org.opencontainers.image.revision", "org.opencontainers.image.source",
                   "org.opencontainers.image.licenses", "org.opencontainers.image.base.name",
                   "org.opencontainers.image.base.digest")


def _read(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_config(inspect: Any, version: str, commit: str, base_ref: Optional[str]) -> List[str]:
    cfg = inspect[0] if isinstance(inspect, list) else inspect
    c = cfg.get("Config") or cfg.get("config") or {}
    out = []
    if str(c.get("User", "")).split(":")[0] != "65532":
        out.append("runs as %r, not 65532" % c.get("User"))
    cmd = list(c.get("Entrypoint") or []) + list(c.get("Cmd") or [])
    if cmd and os.path.basename(cmd[0]) in ("sh", "bash", "ash", "dash"):
        out.append("its command runs a shell: %s" % cmd)
    labels = c.get("Labels") or {}
    for k in REQUIRED_LABELS:
        if not labels.get(k):
            out.append("label %s is missing" % k)
    want = {"name": "wd2l", "org.opencontainers.image.licenses": "MIT",
            "org.opencontainers.image.version": version,
            "org.opencontainers.image.revision": commit}
    if base_ref:
        want["org.opencontainers.image.base.name"] = base_ref.split("@")[0]
        want["org.opencontainers.image.base.digest"] = base_ref.split("@")[1]
    for k, v in want.items():
        if labels.get(k) != v:
            out.append("label %s is %r, expected %r" % (k, labels.get(k), v))
    for k in sorted(labels):
        if k in REMOVED_LABELS or k.startswith("io.hummingbird-project."):
            out.append("label %s from the base is still there (the image would claim to be it)" % k)
    return out


def check_filesystem(root: str, base_root: str) -> List[str]:
    out = []
    for p in SHELLS:
        if os.path.lexists(os.path.join(root, p)):
            out.append("shell present: /" + p)
    for p in PACKAGE_MANAGERS:
        if os.path.lexists(os.path.join(root, p)):
            out.append("package manager present: /" + p)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if rel.split(os.sep)[0] in ("proc", "sys"):
            dirnames[:] = []
            continue
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            relp = os.path.relpath(path, root).replace(os.sep, "/")
            if stat.S_ISLNK(st.st_mode):
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                out.append("setuid/setgid file: /" + relp)
            if st.st_mode & stat.S_IWOTH and not (
                    stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX and relp in STICKY_OK):
                out.append("world-writable: /" + relp)
    policy = (_read(os.path.join(root, "etc/crypto-policies/config")) or "").strip()
    if policy != "FIPS":
        out.append("the crypto policy is %r, not FIPS" % policy)
    a, b = os.path.join(root, RPMDB), os.path.join(base_root, RPMDB)
    if not (os.path.isfile(a) and os.path.isfile(b)):
        out.append("the rpm database is missing in the image or the base")
    elif _sha256(a) != _sha256(b):
        out.append("the rpm database differs from the base's: the image changed packages")
    return out


def check_wheel_files(root: str, wheel: str, commit: str) -> List[str]:
    sites = glob.glob(os.path.join(root, "usr/lib/python3.*/site-packages"))
    if len(sites) != 1:
        return ["expected one site-packages under /usr/lib, found %d" % len(sites)]
    site, out = sites[0], []
    with zipfile.ZipFile(wheel) as z:
        record = [n for n in z.namelist() if n.endswith(".dist-info/RECORD")][0]
        rows = csv.reader(io.StringIO(z.read(record).decode("utf-8")))
        for row in rows:
            if len(row) < 2 or not row[0].startswith("wd2l/") or not row[1]:
                continue
            algo, _, digest = row[1].partition("=")
            want = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
            path = os.path.join(site, row[0])
            shown = "/" + os.path.relpath(path, root).replace(os.sep, "/")
            if not os.path.isfile(path):
                out.append("missing: " + shown)
                continue
            with open(path, "rb") as f:
                if hashlib.new(algo, f.read()).digest() != want:
                    out.append("changed: " + shown)
    build = (_read(os.path.join(site, "wd2l", "BUILD")) or "").strip()
    if build != commit:
        out.append("wd2l/BUILD is %r, not the commit %s" % (build, commit))
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Hardening checks for the wd2l image.")
    p.add_argument("--rootfs", required=True)
    p.add_argument("--base-rootfs", required=True)
    p.add_argument("--config", required=True, help="`podman image inspect` output")
    p.add_argument("--wheel", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--base-ref", help="the runtime base, NAME:TAG@DIGEST")
    a = p.parse_args(argv)
    with open(a.config) as f:
        inspect = json.load(f)
    probs = (check_config(inspect, a.version, a.commit, a.base_ref)
             + check_filesystem(a.rootfs, a.base_rootfs)
             + check_wheel_files(a.rootfs, a.wheel, a.commit))
    for x in probs:
        print("hardening: " + x)
    if not probs:
        print("hardening: ok")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
```

`packaging/container/fips_check.py`:

```python
"""Runs inside the image: the OpenSSL FIPS provider is in force, MD5 is refused, and what wd2l
uses (SHA-256, a TLS context) works (docs/decisions/0004-container-base-image.md).
    podman run --rm -v ./packaging/container/fips_check.py:/fips_check.py:ro IMAGE python3 /fips_check.py"""
import _hashlib
import hashlib
import ssl
import sys

problems = []
if _hashlib.get_fips_mode() != 1:
    problems.append("OpenSSL is not in FIPS mode")
try:
    hashlib.md5(b"x")
    problems.append("MD5 is allowed")
except ValueError:
    pass
hashlib.sha256(b"wd2l").hexdigest()
ssl.create_default_context()
print("\n".join(problems) or "FIPS: ok (%s)" % ssl.OPENSSL_VERSION)
sys.exit(1 if problems else 0)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T tests/test_container_checks.py -v`
Expected: PASS. (The tests chmod setuid and sticky bits, which the Docker test container
allows as root.)

- [ ] **Step 5: Add the job to `image.yml`**

```yaml
  hardening:
    needs: [build]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          pattern: "{image,dist,build-info}"
          merge-multiple: false
      - name: Filesystem and config
        run: |
          IMG=$(podman load -q -i image/image.oci.tar | awk '{print $NF}')
          BASE=$(python3 packaging/container/check_containerfile.py --base)
          podman pull -q "$BASE"
          podman image inspect "$IMG" > inspect.json
          COMMIT=$(jq -r .commit build-info/build-info.json); VERSION=$(jq -r .version build-info/build-info.json)
          podman unshare bash -c 'set -e
            R=$(podman image mount "$1"); B=$(podman image mount "$2")
            python3 packaging/container/check_image.py --rootfs "$R" --base-rootfs "$B" \
              --config inspect.json --wheel dist/*.whl --commit "$3" --version "$4" --base-ref "$2"' \
            _ "$IMG" "$BASE" "$COMMIT" "$VERSION"
          echo "IMG=$IMG" >> "$GITHUB_ENV"
      - name: FIPS in force at run time
        run: podman run --rm -v "$PWD/packaging/container/fips_check.py:/fips_check.py:ro" "$IMG" python3 /fips_check.py
```

(`download-artifact` with `pattern` and `merge-multiple: false` puts each artifact in a
directory named after it: `image/`, `dist/`, `build-info/`.)

- [ ] **Step 6: Commit, push (with OK) and check** that `hardening` is green.

```bash
git add packaging/container/check_image.py packaging/container/fips_check.py \
  tests/test_container_checks.py .github/workflows/image.yml
git commit -m "Image CI: hardening rules on the image's filesystem and config; FIPS at run time"
```

If the real image fails a rule:

* a `world-writable` entry or a `setuid` file **in the base** is a finding about the base.
  Record it in the As-built log and tell your partner before adding an allowance;
* `rpm database differs` means the build changed packages. Fix the Containerfile.

---

### Task 4.4: `vuln-scan`: one gate over two scanners

**Files:**
- Create: `packaging/container/vuln_gate.py`, `packaging/container/vuln-exceptions.json`
- Modify: `.github/workflows/image.yml`, `tests/test_container_checks.py`

**Interfaces:**
- Consumes: the `image` artifact.
- Produces:
  * `vuln_gate.grype_findings(doc)` and `vuln_gate.trivy_findings(doc)`, each
    `-> List[dict]` with the keys `scanner`, `id`, `package`, `version`, `severity`,
    `fixed_in`, `fixable` and `secret`;
  * `vuln_gate.load_exceptions(doc, today) -> (List[dict], List[str])`;
  * `vuln_gate.gate(findings, exceptions) -> (gated, excepted)`;
  * the CLI flags `--summary FILE` (Markdown) and `--predicate FILE` (JSON for the attestation,
    Task 4.7);
  * the `vuln` artifact: `grype.json`, `trivy.json`, the SARIF files, `vuln-summary.md` and
    `vuln-predicate.json`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_container_checks.py`)

```python
vg = load_script("packaging/container/vuln_gate.py")
TODAY = "2026-10-07"


def grype_doc(*matches):
    return {"matches": [{"vulnerability": {"id": i, "severity": s, "fix": {"state": st, "versions": ["9"]}},
                         "artifact": {"name": p, "version": "1"}} for i, s, st, p in matches]}


def trivy_doc(vulns=(), secrets=()):
    return {"Results": [{"Target": "img", "Vulnerabilities": [
        {"VulnerabilityID": i, "PkgName": p, "InstalledVersion": "1", "Severity": s, "FixedVersion": f}
        for i, s, f, p in vulns], "Secrets": [{"RuleID": r} for r in secrets]}]}


def exc(id_, package, expires="2026-12-31", **kw):
    e = {"id": id_, "package": package, "reason": "r", "expires": expires, "approved_by": "security owner"}
    e.update(kw)
    return e


def run_gate(grype, trivy, exceptions):
    found = vg.grype_findings(grype) + vg.trivy_findings(trivy)
    valid, probs = vg.load_exceptions({"exceptions": exceptions}, TODAY)
    gated, excepted = vg.gate(found, valid)
    return gated, excepted, probs


def test_only_fixable_high_and_critical_are_gated():
    gated, _e, probs = run_gate(
        grype_doc(("CVE-1", "High", "fixed", "openssl-libs"), ("CVE-2", "High", "not-fixed", "glibc"),
                  ("CVE-3", "Medium", "fixed", "zlib")),
        trivy_doc([("CVE-4", "CRITICAL", "2.0", "python3.12"), ("CVE-5", "LOW", "1.1", "x")]), [])
    assert sorted(f["id"] for f in gated) == ["CVE-1", "CVE-4"] and probs == []


def test_secrets_are_always_gated():
    gated, _e, _p = run_gate(grype_doc(), trivy_doc(secrets=["aws-access-key-id"]), [])
    assert [f["id"] for f in gated] == ["aws-access-key-id"]


def test_an_exception_covers_its_cve_in_its_package():
    gated, excepted, probs = run_gate(grype_doc(("CVE-1", "High", "fixed", "openssl-libs")),
                                      trivy_doc(), [exc("CVE-1", "openssl-libs")])
    assert gated == [] and [f["id"] for f in excepted] == ["CVE-1"] and probs == []


def test_exception_only_covers_its_package():
    gated, _e, _p = run_gate(grype_doc(("CVE-1", "High", "fixed", "glibc")), trivy_doc(),
                             [exc("CVE-1", "openssl-libs")])
    assert [f["package"] for f in gated] == ["glibc"]


def test_expired_exception_fails_even_unused():
    gated, _e, probs = run_gate(grype_doc(), trivy_doc(), [exc("CVE-9", "x", expires="2026-10-01")])
    assert gated == [] and any("expired" in p and "CVE-9" in p for p in probs)


def test_an_expired_exception_no_longer_covers():
    gated, _e, _p = run_gate(grype_doc(("CVE-1", "High", "fixed", "openssl-libs")), trivy_doc(),
                             [exc("CVE-1", "openssl-libs", expires="2026-10-06")])
    assert [f["id"] for f in gated] == ["CVE-1"]


def test_incomplete_exception_is_a_problem():
    _g, _e, probs = run_gate(grype_doc(), trivy_doc(), [{"id": "CVE-1", "package": "x"}])
    assert any("reason" in p for p in probs)


def test_cli_exit_codes_summary_and_predicate(tmp_path):
    g, t, e = tmp_path / "g.json", tmp_path / "t.json", tmp_path / "e.json"
    g.write_text(json.dumps(grype_doc(("CVE-1", "Critical", "fixed", "openssl-libs"))))
    t.write_text(json.dumps(trivy_doc()))
    e.write_text(json.dumps({"exceptions": []}))
    s, p = tmp_path / "s.md", tmp_path / "p.json"
    args = ["--grype", str(g), "--trivy", str(t), "--exceptions", str(e), "--today", TODAY,
            "--summary", str(s), "--predicate", str(p)]
    assert vg.main(args) == 1
    assert "CVE-1" in s.read_text() and json.loads(p.read_text())["gate"]["passed"] is False
    e.write_text(json.dumps({"exceptions": [exc("CVE-1", "openssl-libs")]}))
    assert vg.main(args) == 0


def test_the_committed_exceptions_file_is_valid():
    with open(os.path.join(REPO, "packaging", "container", "vuln-exceptions.json")) as f:
        _valid, probs = vg.load_exceptions(json.load(f), TODAY)
    assert probs == []
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_container_checks.py -k "gate or exception or secret" -v`
Expected: FAIL (`FileNotFoundError` for `vuln_gate.py`).

- [ ] **Step 3: Write `packaging/container/vuln_gate.py`**

```python
#!/usr/bin/env python3
"""One gate over Grype and Trivy results (docs/decisions/0004-container-base-image.md).

Fails on any fixable High or Critical vulnerability, and on any secret Trivy finds, unless an
unexpired exception in vuln-exceptions.json names that ID in that package. Also fails on any
expired or incomplete exception, used or not, so that each one gets looked at again.

    vuln_gate.py --grype G.json --trivy T.json --exceptions E.json [--today YYYY-MM-DD]
                 [--summary OUT.md] [--predicate OUT.json]"""

import argparse
import json
import sys
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

GATED = ("HIGH", "CRITICAL")
FIELDS = ("id", "package", "reason", "expires", "approved_by")


def grype_findings(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for m in doc.get("matches") or []:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        fix = v.get("fix") or {}
        out.append({"scanner": "grype", "id": v.get("id"), "package": a.get("name"),
                    "version": a.get("version"), "severity": str(v.get("severity", "")).upper(),
                    "fixed_in": ",".join(fix.get("versions") or []),
                    "fixable": fix.get("state") == "fixed", "secret": False})
    return out


def trivy_findings(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for r in doc.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            out.append({"scanner": "trivy", "id": v.get("VulnerabilityID"),
                        "package": v.get("PkgName"), "version": v.get("InstalledVersion"),
                        "severity": str(v.get("Severity", "")).upper(),
                        "fixed_in": v.get("FixedVersion") or "",
                        "fixable": bool(v.get("FixedVersion")), "secret": False})
        for s in r.get("Secrets") or []:
            out.append({"scanner": "trivy", "id": s.get("RuleID"), "package": r.get("Target"),
                        "version": "", "severity": "SECRET", "fixed_in": "", "fixable": True,
                        "secret": True})
    return out


def load_exceptions(doc: Dict[str, Any], today: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    valid, probs = [], []
    t = date.fromisoformat(today)
    for e in doc.get("exceptions") or []:
        missing = [k for k in FIELDS if not e.get(k)]
        if missing:
            probs.append("exception %s is missing %s" % (e.get("id"), ", ".join(missing)))
            continue
        try:
            expires = date.fromisoformat(e["expires"])
        except ValueError:
            probs.append("exception %s: expires %r is not YYYY-MM-DD" % (e["id"], e["expires"]))
            continue
        if expires < t:
            probs.append("exception for %s in %s expired on %s: review it, then renew or remove it"
                         % (e["id"], e["package"], e["expires"]))
            continue
        valid.append(e)
    return valid, probs


def gate(findings: List[Dict[str, Any]],
         exceptions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    covered = {(e["id"], e["package"]) for e in exceptions}
    gated, excepted = [], []
    for f in findings:
        if not (f["secret"] or (f["severity"] in GATED and f["fixable"])):
            continue
        (excepted if (f["id"], f["package"]) in covered else gated).append(f)
    return gated, excepted


def summary(gated: List[Dict[str, Any]], excepted: List[Dict[str, Any]], probs: List[str],
            counts: Dict[str, int]) -> str:
    lines = ["### Vulnerability gate: %s" % ("FAILED" if gated or probs else "passed"), "",
             "Findings: %s." % ", ".join("%s %d" % kv for kv in sorted(counts.items())), ""]
    for title, rows in (("Gated (fixable High/Critical, or a secret)", gated),
                        ("Covered by an exception", excepted)):
        if rows:
            lines += ["**%s**" % title, "", "| Scanner | ID | Package | Version | Severity | Fixed in |",
                      "|---|---|---|---|---|---|"]
            lines += ["| %(scanner)s | %(id)s | %(package)s | %(version)s | %(severity)s | %(fixed_in)s |" % f
                      for f in rows]
            lines.append("")
    lines += ["- " + p for p in probs]
    return "\n".join(lines) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Gate Grype and Trivy results.")
    p.add_argument("--grype", required=True)
    p.add_argument("--trivy", required=True)
    p.add_argument("--exceptions", required=True)
    p.add_argument("--today", default=datetime.now(timezone.utc).date().isoformat())
    p.add_argument("--summary")
    p.add_argument("--predicate")
    a = p.parse_args(argv)
    docs = {}
    for name in ("grype", "trivy", "exceptions"):
        with open(getattr(a, name)) as f:
            docs[name] = json.load(f)
    g, t = grype_findings(docs["grype"]), trivy_findings(docs["trivy"])
    valid, probs = load_exceptions(docs["exceptions"], a.today)
    gated, excepted = gate(g + t, valid)
    text = summary(gated, excepted, probs, {"grype": len(g), "trivy": len(t)})
    print(text)
    if a.summary:
        with open(a.summary, "w") as f:
            f.write(text)
    if a.predicate:
        with open(a.predicate, "w") as f:
            json.dump({"scanned_on": a.today,
                       "scanners": {"grype": docs["grype"].get("descriptor", {}),
                                    "trivy": {"SchemaVersion": docs["trivy"].get("SchemaVersion")}},
                       "gate": {"passed": not (gated or probs), "rule": "fixable High/Critical, or a secret",
                                "gated": gated, "excepted": excepted, "problems": probs},
                       "findings": {"grype": len(g), "trivy": len(t)}}, f, indent=1)
    return 1 if gated or probs else 0


if __name__ == "__main__":
    sys.exit(main())
```

`packaging/container/vuln-exceptions.json`:

```json
{
  "_how": "An exception lets one fixable High/Critical finding through the gate: the CVE (or Trivy secret rule) ID, the package it is in, why it is acceptable, who approved it (the security owner), and when it expires (YYYY-MM-DD, at most 90 days out). Expired exceptions fail the gate until renewed or removed.",
  "exceptions": []
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T tests/test_container_checks.py -v`
Expected: PASS.

- [ ] **Step 5: Add the job to `image.yml`**

```yaml
  vuln-scan:
    needs: [build]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          name: image
          path: image
      - name: Grype and Trivy
        run: |
          mkdir -p vuln .cache
          packaging/ci/tool grype oci-archive:/work/image/image.oci.tar -q \
            -o json=/work/vuln/grype.json -o sarif=/work/vuln/grype.sarif
          packaging/ci/tool trivy image --quiet --cache-dir /work/.cache/trivy --input /work/image/image.oci.tar \
            --scanners vuln,secret --format json --output /work/vuln/trivy.json
          packaging/ci/tool trivy convert --format sarif --output /work/vuln/trivy.sarif /work/vuln/trivy.json
      - name: Gate (fixable High/Critical, or a secret)
        run: |
          python3 packaging/container/vuln_gate.py --grype vuln/grype.json --trivy vuln/trivy.json \
            --exceptions packaging/container/vuln-exceptions.json \
            --summary vuln/vuln-summary.md --predicate vuln/vuln-predicate.json \
            && rc=0 || rc=$?
          cat vuln/vuln-summary.md >> "$GITHUB_STEP_SUMMARY"
          exit $rc
      - uses: actions/upload-artifact@<sha> # <tag>
        if: always()
        with:
          name: vuln
          path: vuln/
```

- [ ] **Step 6: Commit, push (with OK) and check** that `vuln-scan` is green. The job summary
  shows the gate table.

```bash
git add packaging/container/vuln_gate.py packaging/container/vuln-exceptions.json \
  tests/test_container_checks.py .github/workflows/image.yml
git commit -m "Image CI: one vulnerability gate over Grype and Trivy, exceptions that expire"
```

If the real image is gated, that is a finding, not a pipeline problem:

* if a newer base digest fixes it, run `pin-images.sh` on the Containerfile and commit that;
* otherwise, tell your partner. Only the security owner may approve an exception.

---

### Task 4.5: `sbom`: the image adds wd2l and nothing else

**Files:**
- Create: `packaging/container/sbom_diff.py`
- Modify: `.github/workflows/image.yml`, `tests/test_container_checks.py`

**Interfaces:**
- Consumes: the `image` artifact, and `check_containerfile.base()`.
- Produces:
  * `sbom_diff.purls(doc) -> Set[str]`;
  * `sbom_diff.diff(base_doc, image_doc, allow) -> (added_not_allowed, removed)`;
  * the `sbom` artifact: `wd2l.spdx.json`, `wd2l.cdx.json` and `base.spdx.json`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_container_checks.py`)

```python
sd = load_script("packaging/container/sbom_diff.py")


def spdx(*purls):
    return {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": p.split("/")[-1], "externalRefs": [{"referenceType": "purl", "referenceLocator": p}]}
        for p in purls] + [{"name": "the image itself"}]}


BASE_PKGS = ("pkg:rpm/hummingbird/glibc@2.42-1?arch=x86_64", "pkg:rpm/hummingbird/python3.12@3.12.15-1?arch=x86_64")


def test_adding_only_wd2l_passes():
    added, removed = sd.diff(spdx(*BASE_PKGS), spdx(*BASE_PKGS + ("pkg:pypi/wd2l@0.3.0",)),
                             ["pkg:pypi/wd2l@"])
    assert added == [] and removed == []


def test_anything_else_added_or_removed_is_named():
    added, removed = sd.diff(spdx(*BASE_PKGS),
                             spdx(BASE_PKGS[0], "pkg:pypi/wd2l@0.3.0", "pkg:rpm/hummingbird/bash@5.3-1?arch=x86_64"),
                             ["pkg:pypi/wd2l@"])
    assert added == ["pkg:rpm/hummingbird/bash@5.3-1?arch=x86_64"] and removed == [BASE_PKGS[1]]


def test_cli(tmp_path):
    b, i = tmp_path / "b.json", tmp_path / "i.json"
    b.write_text(json.dumps(spdx(*BASE_PKGS)))
    i.write_text(json.dumps(spdx(*BASE_PKGS + ("pkg:pypi/requests@2.0",))))
    assert sd.main([str(b), str(i)]) == 1
    i.write_text(json.dumps(spdx(*BASE_PKGS + ("pkg:pypi/wd2l@0.3.0",))))
    assert sd.main([str(b), str(i)]) == 0
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_container_checks.py -k "wd2l_passes or added_or_removed or cli" -v`
Expected: FAIL (`FileNotFoundError` for `sbom_diff.py`).

- [ ] **Step 3: Write `packaging/container/sbom_diff.py`**

```python
#!/usr/bin/env python3
"""The image adds wd2l to its base and nothing else: compares the SPDX SBOMs Syft makes of the
base and of the image, package by package (by purl). Packages without a purl (the image itself,
files) are ignored.

    sbom_diff.py BASE.spdx.json IMAGE.spdx.json [--allow PREFIX ...]
The default --allow is pkg:pypi/wd2l@. Exit 1 when anything else was added or removed."""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def purls(doc: Dict[str, Any]) -> Set[str]:
    out = set()
    for p in doc.get("packages") or []:
        for ref in p.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                out.add(ref["referenceLocator"])
    return out


def diff(base: Dict[str, Any], image: Dict[str, Any],
         allow: Sequence[str]) -> Tuple[List[str], List[str]]:
    b, i = purls(base), purls(image)
    added = sorted(p for p in i - b if not any(p.startswith(a) for a in allow))
    return added, sorted(b - i)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Only wd2l may be added to the base.")
    p.add_argument("base")
    p.add_argument("image")
    p.add_argument("--allow", action="append", default=None)
    a = p.parse_args(argv)
    allow = a.allow or ["pkg:pypi/wd2l@"]
    with open(a.base) as f:
        base = json.load(f)
    with open(a.image) as f:
        image = json.load(f)
    added, removed = diff(base, image, allow)
    for x in added:
        print("sbom: added to the base: " + x)
    for x in removed:
        print("sbom: missing from the image: " + x)
    if not (added or removed):
        print("sbom: ok, the image is the base plus %s" % ", ".join(allow))
    return 1 if added or removed else 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T tests/test_container_checks.py -v`
Expected: PASS.

- [ ] **Step 5: Add the job to `image.yml`**

```yaml
  sbom:
    needs: [build]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          name: image
          path: image
      - name: SBOMs of the image and of its base
        run: |
          mkdir -p sbom
          packaging/ci/tool syft oci-archive:/work/image/image.oci.tar -q \
            -o spdx-json=/work/sbom/wd2l.spdx.json -o cyclonedx-json=/work/sbom/wd2l.cdx.json
          BASE=$(python3 packaging/container/check_containerfile.py --base)
          podman pull -q "$BASE" && podman save -q --format oci-archive -o base.oci.tar "$BASE"
          packaging/ci/tool syft oci-archive:/work/base.oci.tar -q -o spdx-json=/work/sbom/base.spdx.json
      - run: python3 packaging/container/sbom_diff.py sbom/base.spdx.json sbom/wd2l.spdx.json
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: sbom
          path: sbom/
```

- [ ] **Step 6: Commit, push (with OK) and check** that `sbom` is green and prints "the image
  is the base plus pkg:pypi/wd2l@".

```bash
git add packaging/container/sbom_diff.py tests/test_container_checks.py .github/workflows/image.yml
git commit -m "Image CI: the image's SBOM is the base's plus wd2l, nothing else"
```

---

### Task 4.6: `reproducible`: the same commit builds the same image

**Files:**
- Modify: `.github/workflows/image.yml`

**Interfaces:**
- Consumes: the `dist`, `image` and `build-info` artifacts, and `build.sh`.
- Produces: the job. It is report-only (`continue-on-error: true`) until it has matched on 10
  pushes in a row; then remove `continue-on-error` and add an As-built row.

- [ ] **Step 1: Add the job**

```yaml
  reproducible:
    needs: [build]
    runs-on: ubuntu-24.04
    continue-on-error: true      # report-only until it has matched on 10 pushes in a row
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/setup-python@<sha> # <tag>
        with:
          python-version: "3.12"
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          pattern: "{dist,image,build-info}"
      - name: Rebuild the wheel and the image from the same commit, on a fresh runner
        run: |
          export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
          python -m pip install -q build
          git rev-parse HEAD > wd2l/BUILD
          python -m build --wheel --outdir dist2
          if cmp -s dist/*.whl dist2/*.whl; then echo "wheel: identical"; else echo "wheel: DIFFERS"; fi
          packaging/container/build.sh dist localhost/wd2l:again
          want=$(jq -r .image_id build-info/build-info.json)
          got=$(podman image inspect --format '{{.Id}}' localhost/wd2l:again)
          echo "first build $want"; echo "rebuild     $got"
          [ "$want" = "$got" ] && { echo "image: identical"; exit 0; }
          first=$(podman load -q -i image/image.oci.tar | awk '{print $NF}')
          for i in "$first" localhost/wd2l:again; do
            c=$(podman create -q "$i"); podman export "$c" | tar -tv --full-time | sort -k6 > "list-$(echo "$i" | tr -c 'a-z0-9\n' _).txt"; podman rm -f "$c" >/dev/null
          done
          diff <(podman image inspect "$first" | jq '.[0] | {Config, RootFS, Created}') \
               <(podman image inspect localhost/wd2l:again | jq '.[0] | {Config, RootFS, Created}') || true
          diff list-*.txt || true
          exit 1
```

- [ ] **Step 2: Commit, push (with OK) and watch it.** If it reports differences, read the
  diff:
  * file times mean `--timestamp` didn't apply to that layer;
  * a `.pyc` means the checked-hash compile didn't run.

  Fix it, or record why in the As-built log. A non-identical result never blocks a release
  while the job is report-only.

```bash
git add .github/workflows/image.yml
git commit -m "Image CI: rebuild and compare (report-only for now)"
```

---

### Task 4.7: `publish` and `verify-published`, the version names and our provenance

**Files:**
- Create: `packaging/release/versions.py`, `packaging/release/provenance.py`,
  `tests/test_release_tools.py`
- Modify: `.github/workflows/image.yml`

**Interfaces:**
- Consumes: every artifact above, the secrets `COSIGN_PRIVATE_KEY` and `COSIGN_PASSWORD`,
  `cosign.pub` (Task 6.2), and P0-7 and P0-8.
- Produces:
  * `versions.names(version) -> Dict` with the keys `pep440`, `tag`, `rpm`, `image_tags` (a
    list) and `prerelease`;
  * `versions.read_version(path=…) -> str`;
  * the CLI: `--github-output FILE`, `--check-tag TAG` and `--get KEY`;
  * `provenance.predicate(env, wheel_name, wheel_sha256, froms, mirror, started, finished) ->
    Dict`, an SLSA v1 predicate;
  * the job output `publish.outputs.digest`;
  * the artifact `image-release`: `wd2l-<version>-image-oci.tar` and `provenance.json`.

- [ ] **Step 1: Write the failing tests** (`tests/test_release_tools.py`)

```python
import json
import os

import pytest

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
versions = load_script("packaging/release/versions.py")
prov = load_script("packaging/release/provenance.py")


def test_final_release_names():
    assert versions.names("0.3.0") == {"pep440": "0.3.0", "tag": "v0.3.0", "rpm": "0.3.0",
                                       "image_tags": ["0.3.0", "0.3"], "prerelease": False}


@pytest.mark.parametrize("v, rpm", [("0.3.0rc1", "0.3.0~rc1"), ("1.0.0a2", "1.0.0~a2"),
                                    ("1.0.0b1", "1.0.0~b1")])
def test_prerelease_names(v, rpm):
    n = versions.names(v)
    assert n["rpm"] == rpm and n["tag"] == "v" + v and n["image_tags"] == [v] and n["prerelease"]


@pytest.mark.parametrize("bad", ["0.3", "v0.3.0", "0.3.0-rc.1", "0.3.0.post1", "0.3.0rc"])
def test_versions_outside_the_scheme_are_refused(bad):
    with pytest.raises(ValueError):
        versions.names(bad)


def rpmvercmp(a, b):
    """RPM's version comparison, enough for X.Y.Z[~preN] (tilde sorts before anything)."""
    def key(v):
        main, _, pre = v.partition("~")
        return ([int(x) for x in main.split(".")], 0 if pre else 1, pre)
    return (key(a) > key(b)) - (key(a) < key(b))


def test_a_prerelease_rpm_sorts_before_the_release():
    assert rpmvercmp(versions.names("0.3.0rc1")["rpm"], versions.names("0.3.0")["rpm"]) < 0
    assert rpmvercmp(versions.names("0.3.0")["rpm"], versions.names("0.3.1rc1")["rpm"]) < 0


def test_check_tag_and_github_output(tmp_path):
    v = versions.read_version()
    assert versions.main(["--check-tag", "v" + v]) == 0
    assert versions.main(["--check-tag", "v9.9.9"]) == 1
    out = tmp_path / "out"
    assert versions.main(["--github-output", str(out)]) == 0
    lines = dict(x.split("=", 1) for x in out.read_text().splitlines())
    assert lines["pep440"] == v and lines["tag"] == "v" + v and lines["prerelease"] in ("true", "false")


ENV = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "JoeHazurmoney/r",
       "GITHUB_REF": "refs/tags/v0.3.0", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "77",
       "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "RUNNER_ENVIRONMENT": "github-hosted",
       "GITHUB_WORKFLOW_REF": "JoeHazurmoney/r/.github/workflows/release.yml@refs/tags/v0.3.0"}
FROMS = [{"ref": "r/hi/python:3.12-fips-builder@sha256:" + "1" * 64, "stage": "build",
          "name": "r/hi/python", "tag": "3.12-fips-builder", "digest": "sha256:" + "1" * 64},
         {"ref": "r/hi/python:3.12-fips@sha256:" + "2" * 64, "stage": None, "name": "r/hi/python",
          "tag": "3.12-fips", "digest": "sha256:" + "2" * 64}]


def test_provenance_names_the_commit_the_wheel_and_both_bases():
    p = prov.predicate(ENV, "wd2l-0.3.0-py3-none-any.whl", "c" * 64, FROMS,
                       "ghcr.io/o/wd2l-base/python", "t0", "t1")
    deps = p["buildDefinition"]["resolvedDependencies"]
    assert deps[0] == {"uri": "git+https://github.com/JoeHazurmoney/r@refs/tags/v0.3.0",
                       "digest": {"gitCommit": "a" * 40}}
    assert deps[1] == {"uri": "wd2l-0.3.0-py3-none-any.whl", "digest": {"sha256": "c" * 64}}
    assert [d["digest"]["sha256"] for d in deps[2:]] == ["1" * 64, "2" * 64]
    assert deps[3]["annotations"] == {"stage": "runtime",
                                      "mirror": "ghcr.io/o/wd2l-base/python@sha256:" + "2" * 64}
    assert p["runDetails"]["builder"]["id"] == "https://github.com/" + ENV["GITHUB_WORKFLOW_REF"]
    assert p["runDetails"]["metadata"]["invocationId"].endswith("/actions/runs/77/attempts/1")
    json.dumps(p)
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_release_tools.py -v`
Expected: FAIL (`FileNotFoundError` for `versions.py`).

- [ ] **Step 3: Write the two scripts**

`packaging/release/versions.py`:

```python
#!/usr/bin/env python3
"""Release names, all from wd2l/__init__.py's __version__ (the one place a version is written):

  pep440      0.3.0 or 0.3.0rc1          wheel, sdist, image label
  tag         v0.3.0 or v0.3.0rc1        git tag, GitHub release
  rpm         0.3.0 or 0.3.0~rc1         RPM Version (the tilde sorts before the release)
  image_tags  0.3.0 0.3, or 0.3.0rc1     ghcr tags
  prerelease  false or true

    versions.py [--github-output FILE] [--check-tag TAG] [--get KEY]"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Optional, Sequence

INIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "wd2l", "__init__.py")
SCHEME = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")


def read_version(path: str = INIT) -> str:
    with open(path) as f:
        m = re.search(r'^__version__ = "([^"]+)"$', f.read(), re.M)
    if not m:
        raise ValueError("no __version__ in %s" % path)
    return m.group(1)


def names(version: str) -> Dict[str, Any]:
    m = SCHEME.match(version)
    if not m:
        raise ValueError("version %r is not X.Y.Z or X.Y.Z{a,b,rc}N" % version)
    major, minor, patch, pre, n = m.groups()
    base = "%s.%s.%s" % (major, minor, patch)
    return {"pep440": version, "tag": "v" + version,
            "rpm": base + ("~%s%s" % (pre, n) if pre else ""),
            "image_tags": [version] if pre else [base, "%s.%s" % (major, minor)],
            "prerelease": bool(pre)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Release names from __version__.")
    p.add_argument("--github-output", help="append key=value lines (GitHub Actions outputs)")
    p.add_argument("--check-tag", help="exit 1 unless this is the version's tag")
    p.add_argument("--get", help="print one name")
    a = p.parse_args(argv)
    n = names(read_version())
    if a.check_tag is not None and a.check_tag != n["tag"]:
        print("tag %s doesn't match __version__ (expected %s)" % (a.check_tag, n["tag"]), file=sys.stderr)
        return 1
    if a.github_output:
        with open(a.github_output, "a") as f:
            for k, v in n.items():
                f.write("%s=%s\n" % (k, " ".join(v) if isinstance(v, list) else
                                     str(v).lower() if isinstance(v, bool) else v))
    if a.get:
        v = n[a.get]
        print(" ".join(v) if isinstance(v, list) else v)
    elif not a.github_output and a.check_tag is None:
        print(json.dumps(n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

`packaging/release/provenance.py`:

```python
#!/usr/bin/env python3
"""The SLSA v1 provenance predicate for a published image. `cosign attest --type slsaprovenance1`
wraps it in an in-toto statement whose subject is the image digest. It names the commit, the
workflow, the wheel and the exact base images, with their mirrored copies
(docs/decisions/0006-release-artifacts-and-signing.md). While the repository is private this
provenance is self-asserted: it is generated and signed in our own workflow.

    provenance.py --wheel WHL --froms froms.json --mirror REPO --started ISO > provenance.json"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence


def predicate(env: Mapping[str, str], wheel_name: str, wheel_sha256: str,
              froms: List[Dict[str, Any]], mirror: str, started: str,
              finished: str) -> Dict[str, Any]:
    server, repo = env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"]
    workflow = env.get("GITHUB_WORKFLOW_REF", "")
    deps: List[Dict[str, Any]] = [
        {"uri": "git+%s/%s@%s" % (server, repo, env["GITHUB_REF"]),
         "digest": {"gitCommit": env["GITHUB_SHA"]}},
        {"uri": wheel_name, "digest": {"sha256": wheel_sha256}}]
    for f in froms:
        deps.append({"uri": "%s:%s" % (f["name"], f["tag"]),
                     "digest": {"sha256": f["digest"].split(":", 1)[1]},
                     "annotations": {"stage": f["stage"] or "runtime",
                                     "mirror": "%s@%s" % (mirror, f["digest"])}})
    return {
        "buildDefinition": {
            "buildType": "%s/%s/blob/main/docs/releasing.md#how-a-release-is-built" % (server, repo),
            "externalParameters": {
                "workflow": {"ref": env["GITHUB_REF"], "repository": "%s/%s" % (server, repo),
                             "path": workflow.split("@")[0].split("/", 2)[-1] if workflow else ""},
                "containerfile": "packaging/container/Containerfile"},
            "internalParameters": {"github": {
                "event_name": env.get("GITHUB_EVENT_NAME"),
                "runner_environment": env.get("RUNNER_ENVIRONMENT"),
                "repository_id": env.get("GITHUB_REPOSITORY_ID")}},
            "resolvedDependencies": deps},
        "runDetails": {
            "builder": {"id": "%s/%s" % (server, workflow) if workflow else server},
            "metadata": {
                "invocationId": "%s/%s/actions/runs/%s/attempts/%s" % (
                    server, repo, env["GITHUB_RUN_ID"], env.get("GITHUB_RUN_ATTEMPT", "1")),
                "startedOn": started, "finishedOn": finished}}}


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="SLSA v1 predicate for the image.")
    p.add_argument("--wheel", required=True)
    p.add_argument("--froms", required=True, help="check_containerfile.py --json output")
    p.add_argument("--mirror", required=True, help="where the base images are mirrored")
    p.add_argument("--started", required=True)
    a = p.parse_args(argv)
    with open(a.wheel, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    with open(a.froms) as f:
        froms = json.load(f)
    finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    json.dump(predicate(os.environ, os.path.basename(a.wheel), sha, froms, a.mirror, a.started,
                        finished), sys.stdout, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T tests/test_release_tools.py -v`
Expected: PASS.

- [ ] **Step 5: Add the two jobs to `image.yml`.** Use the cosign flags recorded in P0-7 if
  they differ from these.

```yaml
  publish:
    if: inputs.publish
    needs: [base-verify, build, hardening, vuln-scan, sbom, functional, fips-tests]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: write
    outputs:
      digest: ${{ steps.push.outputs.digest }}
    env:
      IMAGE: ghcr.io/joehazurmoney/wd2l
      BASE_MIRROR: ghcr.io/joehazurmoney/wd2l-base/python
      ATT: https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          pattern: "{dist,image,build-info,base-evidence,sbom,vuln}"
      - id: v
        run: python3 packaging/release/versions.py --github-output "$GITHUB_OUTPUT"
      - name: Log in to ghcr.io
        run: echo "${{ secrets.GITHUB_TOKEN }}" | podman login ghcr.io -u "${{ github.actor }}" --password-stdin
      - id: push
        name: Push, with each tag
        run: |
          IMG=$(podman load -q -i image/image.oci.tar | awk '{print $NF}')
          for t in ${{ steps.v.outputs.image_tags }}; do
            podman push -q --digestfile digest.txt "$IMG" "docker://$IMAGE:$t"
          done
          echo "digest=$(cat digest.txt)" >> "$GITHUB_OUTPUT"
      - name: Mirror the base images, their records and the runtime base's sources
        run: |
          f=base-evidence/froms.json; last=$(( $(jq length $f) - 1 ))
          for i in $(seq 0 $last); do
            name=$(jq -r ".[$i].name" $f); tag=$(jq -r ".[$i].tag" $f); digest=$(jq -r ".[$i].digest" $f)
            packaging/ci/tool oras copy --registry-config /auth/config.json -r "$name@$digest" "$BASE_MIRROR:$tag-${digest:7:12}"
            packaging/ci/tool cosign copy "quay.io/hummingbird/${name#registry.access.redhat.com/hi/}@$digest" "$BASE_MIRROR"
          done
          name=$(jq -r ".[$last].name" $f)
          rel=$(jq -r '.config.Labels.release' "base-evidence/config-$last.json")
          packaging/ci/tool oras copy --registry-config /auth/config.json "$name:$rel-source" "$BASE_MIRROR:$rel-source"
      - name: Sign and attest (our key, no public log)
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
          TOOL_ENV: COSIGN_PRIVATE_KEY COSIGN_PASSWORD
        run: |
          D=${{ steps.push.outputs.digest }}
          python3 packaging/release/provenance.py --wheel dist/*.whl --froms base-evidence/froms.json \
            --mirror "$BASE_MIRROR" --started "$(jq -r .started build-info/build-info.json)" > provenance.json
          S() { packaging/ci/tool cosign "$@" --key env://COSIGN_PRIVATE_KEY --tlog-upload=false --yes; }
          S sign "$IMAGE@$D"
          S attest --type slsaprovenance1 --predicate /work/provenance.json "$IMAGE@$D"
          S attest --type spdxjson --predicate /work/sbom/wd2l.spdx.json "$IMAGE@$D"
          S attest --type "$ATT/vuln-scan/v1" --predicate /work/vuln/vuln-predicate.json "$IMAGE@$D"
          S attest --type "$ATT/base-image-record/v1" --predicate /work/base-evidence/base-image-record.json "$IMAGE@$D"
      - name: Save the image with its signature and attestations, for offline enclaves
        run: |
          packaging/ci/tool cosign save --dir /work/wd2l-oci "$IMAGE@${{ steps.push.outputs.digest }}"
          tar -cf "wd2l-${{ steps.v.outputs.pep440 }}-image-oci.tar" wd2l-oci
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: image-release
          path: |
            wd2l-*-image-oci.tar
            provenance.json

  verify-published:
    if: inputs.publish
    needs: [publish]
    runs-on: ubuntu-24.04
    permissions:
      contents: read
      packages: read
    env:
      I: ghcr.io/joehazurmoney/wd2l@${{ needs.publish.outputs.digest }}
      ATT: https://github.com/JoeHazurmoney/architecture-wiredata-to-log/attestations
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          name: image-release
      - run: echo "${{ secrets.GITHUB_TOKEN }}" | podman login ghcr.io -u "${{ github.actor }}" --password-stdin
      - name: Verify as a consumer would, online and then with no network
        run: |
          V() { packaging/ci/tool cosign "$@" --key /work/cosign.pub --insecure-ignore-tlog > /dev/null; }
          TYPES="slsaprovenance1 spdxjson $ATT/vuln-scan/v1 $ATT/base-image-record/v1"
          V verify "$I" && echo "signature: ok"
          for t in $TYPES; do V verify-attestation --type "$t" "$I" && echo "attestation $t: ok"; done
          packaging/ci/tool cosign tree "$I"
          tar -xf wd2l-*-image-oci.tar
          export TOOL_NETWORK=none
          V verify --local-image /work/wd2l-oci && echo "offline signature: ok"
          for t in $TYPES; do V verify-attestation --type "$t" --local-image /work/wd2l-oci && echo "offline $t: ok"; done
```

- [ ] **Step 6: Check what can be checked now.** `publish` and `verify-published` only run with
  `publish: true`, which means a release. Phase 0 checks 7 and 8 already exercised every command
  in them. Their first full run is the rc release in Task 6.5. Now, run the tests and confirm
  the workflow parses:

```bash
T -q
gh workflow view image.yml >/dev/null && echo "image.yml parses"   # after pushing, with OK
```

- [ ] **Step 7: Commit**

```bash
git add packaging/release/versions.py packaging/release/provenance.py tests/test_release_tools.py \
  .github/workflows/image.yml
git commit -m "Image CI: publish, sign and attest on releases; verify as a consumer, offline too"
```

---

### Task 4.8: The weekly rescan and Dependabot

**Files:**
- Create: `.github/workflows/image-rescan.yml`, `.github/dependabot.yml`

**Interfaces:**
- Consumes: `vuln_gate.py`, `packaging/ci/tool` (grype, trivy) and the published releases.
- Produces: a weekly job that opens (or comments on) an issue when a released image has a new
  fixable High/Critical; Dependabot PRs for the base digests, the tool digests and the actions.

- [ ] **Step 1: Write `.github/workflows/image-rescan.yml`**

```yaml
name: image-rescan
# Re-scans the released images with today's vulnerability data: a CVE disclosed after a release
# opens an issue (docs/decisions/0004-container-base-image.md, docs/releasing.md).
on:
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch:
permissions:
  contents: read
  packages: read
  issues: write
jobs:
  rescan:
    runs-on: ubuntu-24.04
    env:
      GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - run: echo "${{ secrets.GITHUB_TOKEN }}" | podman login ghcr.io -u "${{ github.actor }}" --password-stdin
      - name: Scan the last three releases
        run: |
          gh release list --limit 3 --exclude-drafts --exclude-pre-releases --json tagName --jq '.[].tagName' > tags.txt
          fail=0
          while read -r tag; do
            v=${tag#v}; ref="ghcr.io/joehazurmoney/wd2l:$v"
            packaging/ci/tool grype "registry:$ref" -q -o json --file "/work/grype-$v.json"
            packaging/ci/tool trivy image --quiet --scanners vuln --format json --output "/work/trivy-$v.json" "$ref"
            if ! python3 packaging/container/vuln_gate.py --grype "grype-$v.json" --trivy "trivy-$v.json" \
                 --exceptions packaging/container/vuln-exceptions.json --summary "summary-$v.md" > /dev/null; then
              fail=1
              title="Image rescan: wd2l $v has a fixable High/Critical vulnerability"
              n=$(gh issue list --state open --search "\"$title\" in:title" --json number --jq '.[0].number // empty')
              if [ -n "$n" ]; then gh issue comment "$n" --body-file "summary-$v.md"
              else gh issue create --title "$title" --body-file "summary-$v.md"; fi
            fi
            { echo "## wd2l $v"; cat "summary-$v.md"; } >> "$GITHUB_STEP_SUMMARY"
          done < tags.txt
          exit $fail
```

- [ ] **Step 2: Write `.github/dependabot.yml`**

```yaml
version: 2
updates:
  # Base image digests (packaging/container/Containerfile) and CI tool digests
  # (packaging/ci/tools.Containerfile). Each PR runs the whole image pipeline.
  - package-ecosystem: docker
    directories: ["/packaging/container", "/packaging/ci"]
    schedule:
      interval: weekly
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
```

- [ ] **Step 3: Commit, push (with OK), and check Dependabot sees both files.** On GitHub, go
  to Insights → Dependency graph → Dependabot, and confirm that `packaging/container/Containerfile`
  and `packaging/ci/tools.Containerfile` are listed. If `tools.Containerfile` isn't, Dependabot
  doesn't recognize that name:
  * rename it `tools.Dockerfile`;
  * update `packaging/ci/tool`, `pin-images.sh`'s usage line and `tests/test_packaging.py`;
  * add an As-built row.

  The rescan has nothing to scan until the first release. Run it by hand after Task 6.5:
  `gh workflow run image-rescan.yml`.

```bash
git add .github/workflows/image-rescan.yml .github/dependabot.yml
git commit -m "Weekly rescan of released images; Dependabot for base, tool and action pins"
```
