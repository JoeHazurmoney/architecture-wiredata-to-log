"""Policy over the workflow files (docs/decisions/0007-slsa-build-l3.md):

* only attest.yml may get an OIDC token, so build steps can't reach what signs the provenance;
* nothing shared between runs on the release path, and only GitHub-hosted runners;
* attestation runs only for a v* tag, and only in this repository;
* every job has a time limit, and a newer commit cancels only a PR's or a dry run's older run,
  never a run on main or a tag's (docs/releasing.md, "When CI runs");
* the wheel and the sdist are built one way, with hash-pinned tools, and a rebuild that
  differs fails the run."""

import glob
import os
import re
from typing import Dict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
WORKFLOWS = os.path.join(REPO, ".github", "workflows")
RELEASE_PATH = ("tests.yml", "image.yml", "rpm.yml", "publish.yml", "release.yml", "attest.yml")
GITHUB_HOSTED = ("ubuntu-24.04", "ubuntu-24.04-arm")
# The arm64 runner only where the image is built or run natively for arm64.
ARM_JOBS = {("image.yml", "build"), ("image.yml", "reproducible"), ("image.yml", "hardening"),
            ("image.yml", "functional"), ("image.yml", "fips-tests"), ("publish.yml", "import-check")}
BOTH_ARCHES = ARM_JOBS | {("image.yml", "vuln-scan"), ("image.yml", "sbom")}
THIS_REPO_AND_A_TAG = ("if: ${{ github.repository == 'JoeHazurmoney/architecture-wiredata-to-log'"
                       " && startsWith(github.ref, 'refs/tags/v') }}")


def read(name: str) -> str:
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as f:
        return f.read()


def header(text: str) -> str:
    """A workflow file's lines above jobs: (its name, triggers, concurrency and permissions)."""
    return text.split("\njobs:\n", 1)[0]


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
        assert "write-all" not in text, name      # grants id-token: write without naming it
        if name == "attest.yml":
            continue
        for job, body in jobs(text).items():
            if "uses: ./.github/workflows/attest.yml" in body:
                continue                      # a caller grants it to attest.yml only
            assert "id-token: write" not in body, (name, job)


def test_nothing_is_shared_between_runs_on_the_release_path():
    for name in RELEASE_PATH:
        text = read(name)
        assert "actions/cache" not in text and "type=gha" not in text, name
        assert not re.search(r"^\s+cache(-dependency-path)?:", text, re.M), name   # setup-python
        assert not re.search(r"^\s+run-id:", text, re.M), name    # another run's artifacts


def runners(body: str):
    """The runner labels a job can use: its runs-on, or each matrix entry's runner."""
    label = re.search(r"^\s+runs-on:\s*(.+?)\s*$", body, re.M).group(1)
    if "matrix.runner" in label:
        return re.findall(r"runner:\s*([\w.-]+)", body)
    return [label]


def test_release_path_runs_on_github_hosted_runners():
    for name in RELEASE_PATH:
        for job, body in jobs(read(name)).items():
            if "runs-on:" not in body:
                continue                      # a call to a reusable workflow
            for label in runners(body):
                assert label in GITHUB_HOSTED, (name, job, label)
                if label.endswith("-arm"):
                    assert (name, job) in ARM_JOBS, (name, job)


def test_no_job_runs_on_a_moving_runner_label():
    # ubuntu-latest moves to a new Ubuntu when GitHub decides, and Python 3.9, the floor, has no
    # build for 26.04 (#118). The release manifest also lists these labels as pinned.
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for label in re.findall(r"(?:runs-on|runner):\s*([^\s,}]+)", text):
            assert not label.endswith("-latest"), (os.path.basename(path), label)


def test_every_image_check_runs_for_both_architectures():
    for name, job in sorted(BOTH_ARCHES):
        body = jobs(read(name))[job]
        assert "arch: amd64" in body and "arch: arm64" in body, (name, job)
        assert "fail-fast: false" in body, (name, job)
    for name, job in sorted(ARM_JOBS):
        assert "runner: ubuntu-24.04-arm" in jobs(read(name))[job], (name, job)


def test_attest_yml_runs_only_for_this_repo_and_a_tag():
    # Any repository can call a public reusable workflow, and checkout then fetches the
    # caller's code: the job must not start, so no OIDC token exists for it.
    att = jobs(read("attest.yml"))
    assert list(att) == ["attest"]
    assert THIS_REPO_AND_A_TAG in att["attest"]


def test_attest_reads_the_checksums_the_release_lists():
    att = read("attest.yml")
    assert "subject-checksums: assets/SHA256SUMS" in att
    assert "push-to-registry: true" in att and "subject-name: ghcr.io/joehazurmoney/wd2l\n" in att
    assert "create-storage-record: false" in att
    assert "name: attestations" in att
    for d in ("inputs.image-digest }}", "inputs.image-digest-amd64 }}", "inputs.image-digest-arm64 }}"):
        assert "subject-digest: ${{ " + d in att, d


def test_attestation_runs_only_for_a_tag():
    att = jobs(read("release.yml"))["attest"]
    assert "if: ${{ startsWith(github.ref, 'refs/tags/v') }}" in att
    assert "uses: ./.github/workflows/attest.yml" in att
    assert "image-digest: ${{ needs.publish.outputs.digest }}" in att
    assert "image-digest-amd64: ${{ needs.publish.outputs.digest_amd64 }}" in att
    assert "image-digest-arm64: ${{ needs.publish.outputs.digest_arm64 }}" in att
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


def test_no_workflow_hands_its_secrets_on():
    # The signing key lives only in the `release` environment, which publish.yml's job names
    # itself (docs/releasing.md, one-time setup). Inheriting would also pass any repository
    # secret to the called workflow's jobs that run outside that environment.
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
        with open(path, encoding="utf-8") as f:
            assert "secrets: inherit" not in f.read(), os.path.basename(path)


def test_main_fails_if_the_signing_key_is_a_repository_secret():
    t = jobs(read("tests.yml"))
    job = t["signing-key-scope"]
    assert "github.event_name == 'push' && github.ref == 'refs/heads/main'" in job
    # Outside an environment, secrets.* holds only repository and organization secrets.
    assert "environment:" not in job
    assert "${{ secrets.COSIGN_PRIVATE_KEY != '' }}" in job
    assert "signing-key-scope" not in t["ci-ok"]      # on main only, like landed-title


def test_attest_signs_the_image_keylessly_and_checks_the_identity():
    att = jobs(read("attest.yml"))["attest"]
    assert "TOOL_ENV: ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_ID_TOKEN_REQUEST_TOKEN" in att
    assert 'packaging/ci/tool cosign sign --yes --recursive "$IMAGE@$D"' in att
    assert ('--certificate-identity "https://github.com/$GITHUB_REPOSITORY/.github/workflows/'
            'attest.yml@$GITHUB_REF"') in att
    assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in att
    # the identity alone also matches a run of attest.yml called from another repository
    assert '--certificate-github-workflow-repository "$GITHUB_REPOSITORY"' in att
    # keyless means Sigstore's public log: never the no-log signing config used with the key
    assert "signing-config" not in att


def test_publish_signs_the_index_and_each_platform_image():
    pub = jobs(read("publish.yml"))["publish"]
    assert 'S sign --recursive "$IMAGE@$D"' in pub
    # Podman's sigstoreSigned policy reads only cosign's older .sig format (rc5 spike S6).
    assert "--new-bundle-format=false --use-signing-config=false --tlog-upload=false" in pub
    assert "image_index.py" in pub and "base-image-record/v2" in pub
    for out in ("digest_amd64:", "digest_arm64:"):
        assert out in pub


def test_verify_published_checks_the_older_format_signature_of_each_platform_image():
    # With this flag cosign reads only the older .sig: it finds none on the index (checked
    # against rc5's images), so a missing Podman-readable signature fails here too.
    ver = jobs(read("publish.yml"))["verify-published"]
    assert "--new-bundle-format=false" in ver
    older = ver.split("--new-bundle-format=false", 1)[1].split("\n", 1)[0]
    assert '"$IMG@$c"' in older


def test_import_check_runs_the_offline_import_and_the_podman_policy_on_both_platforms():
    imp = jobs(read("publish.yml"))["import-check"]
    assert "skopeo copy -q oci:wd2l-oci" in imp and 'type: "sigstoreSigned"' in imp
    assert "--remove-signatures" in imp


def test_each_platform_tar_is_saved_before_the_older_format_signature():
    # cosign save lists an older-format .sig as a second image in the layout, and then
    # `skopeo copy oci:wd2l-oci` stops with "more than one image in oci" (final review, S9).
    pub = jobs(read("publish.yml"))["publish"]
    assert pub.index("cosign save --dir") < pub.index("--new-bundle-format=false")


def test_extra_tags_point_at_the_index_only_after_it_is_checked():
    push = read("publish.yml").split("- id: push", 1)[1].split("- name:", 1)[0]
    assert push.index("image_index.py") < push.index("oras tag")


def test_every_pushed_tag_serves_the_index():
    # Customers pull by tag, and nothing read the tags back (#161).
    push = read("publish.yml").split("- id: push", 1)[1].split("- name:", 1)[0]
    check = 'got="sha256:$(skopeo inspect --raw "docker://$IMAGE:$t" | sha256sum | cut -d\' \' -f1)"'
    assert push.index("oras tag") < push.index(check) < push.index('echo "digest=$D" >> "$GITHUB_OUTPUT"')
    loop = push[:push.index(check)].rsplit("for t in ", 1)[1].split("; do", 1)[0]
    assert loop == "${{ steps.v.outputs.image_tags }}"           # every tag, the first included
    assert '[ "$got" = "$D" ] || {' in push


def test_publish_refuses_to_sign_an_image_an_earlier_run_signed():
    # A re-run pushes the same digests (the build is reproducible), and signed them again: a
    # second set of signatures on an image customers already have (#161).
    pub = jobs(read("publish.yml"))["publish"]
    guard = pub.index("is already signed by an earlier run")
    assert pub.index("- id: push") < guard < pub.index("S sign --recursive")
    step = pub[:guard].rsplit("- name:", 1)[1]
    assert "for d in ${{ steps.push.outputs.digest }} ${{ steps.push.outputs.digest_amd64 }}" \
           " ${{ steps.push.outputs.digest_arm64 }}; do" in step
    assert 'if packaging/ci/tool cosign verify --key /work/cosign.pub --insecure-ignore-tlog "$IMAGE@$d"' in step


def test_the_comparison_image_is_published_signed_attested_and_verified_like_the_shipped_one():
    # #192: wd2l-ubi9 (amd64) is pushed by the digest that was tested, signed with the key (and
    # in the older format), attested, saved for offline use, and checked online, offline and
    # under Podman's policy. GitHub attests and signs it keylessly too.
    pub = jobs(read("publish.yml"))["publish"]
    for art in ("image-ubi9-amd64", "build-info-ubi9-amd64", "sbom-ubi9-amd64", "vuln-ubi9-amd64",
                "base-evidence-ubi9"):
        assert "name: %s" % art in pub, art
    push = pub.split("- id: push-ubi9", 1)[1].split("\n      - ", 1)[0]
    assert 'skopeo copy -q --digestfile ubi9-digest.txt "oci-archive:image-ubi9-amd64/image.oci.tar" "docker://$UBI9:$1"' in push
    assert '"sha256:$(jq -r .image_id build-info-ubi9-amd64/build-info.json)"' in push        # the tested image
    assert 'echo "digest_ubi9=$D" >> "$GITHUB_OUTPUT"' in push
    guard = pub.index('"$UBI9@${{ steps.push-ubi9.outputs.digest_ubi9 }}"')
    assert pub.index("is already signed by an earlier run") - 600 < guard < pub.index('S sign "$UBI9@$DU"')
    for att in ('--predicate /work/provenance-ubi9.json "$UBI9@$DU"',
                '--predicate /work/base-evidence-ubi9/base-image-record-ubi9.json "$UBI9@$DU"',
                '--predicate /work/sbom-ubi9-amd64/wd2l.spdx.json "$UBI9@$DU"',
                '--predicate /work/vuln-ubi9-amd64/vuln-predicate.json "$UBI9@$DU"'):
        assert att in pub, att
    assert pub.index('cosign save --dir "/work/save-ubi9/wd2l-oci" "$UBI9@$DU"') < pub.index("--new-bundle-format=false")
    assert "digest_ubi9: ${{ steps.push-ubi9.outputs.digest_ubi9 }}" in pub
    ver = jobs(read("publish.yml"))["verify-published"]
    assert 'V verify --new-bundle-format=false "$UBI9@$DU"' in ver and "off-ubi9" in ver
    imp = jobs(read("publish.yml"))["import-check"]
    assert "if: ${{ matrix.arch == 'amd64' }}" in imp and "wd2l-*-image-ubi9-amd64-oci.tar" in imp
    assert '"ghcr.io/joehazurmoney/wd2l-ubi9": [{type: "sigstoreSigned"' in imp
    att = jobs(read("attest.yml"))["attest"]
    assert "subject-name: ghcr.io/joehazurmoney/wd2l-ubi9" in att and "subject-digest: ${{ inputs.image-digest-ubi9 }}" in att
    assert 'packaging/ci/tool cosign sign --yes "$UBI9@$DU"' in att
    assert "image-digest-ubi9: ${{ needs.publish.outputs.digest_ubi9 }}" in jobs(read("release.yml"))["attest"]


def test_release_stops_before_signing_when_the_tag_already_has_a_release():
    # gh release create ran last, after everything was signed, and a leftover draft for the
    # tag broke it there (#161).
    rel = jobs(read("release.yml"))["release"]
    create = rel.index('gh release create "${{ needs.version.outputs.tag }}"')
    assert rel.index('gh release view "$TAG"') < rel.index("cosign sign-blob") < create
    step = rel[:rel.index('gh release view "$TAG"')].rsplit("- name:", 1)[1]
    assert "if: ${{ env.REAL == 'true' }}" in step and "GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}" in step


def test_assets_makes_the_manifest_with_reads_only_before_sha256sums():
    # docs/decisions/0008-release-manifest.md: the manifest is a release file, so SHA256SUMS
    # (signed), the SLSA provenance and the release attestation all cover it.
    a = jobs(read("release.yml"))["assets"]
    perms = a.split("permissions:\n", 1)[1].split("    env:\n", 1)[0]
    assert set(re.findall(r"^\s+([\w-]+): (\w+)$", perms, re.M)) == {
        ("contents", "read"), ("issues", "read"), ("pull-requests", "read"), ("actions", "read")}
    assert "GH_TOKEN: ${{ github.token }}" in a and "secrets." not in a
    assert "fetch-depth: 0" in a
    assert "--require-hashes -r packaging/release/requirements.txt" in a
    order = [a.index(s) for s in ("manifest.py generate", "manifest.py validate", "manifest.py render",
                                  "sha256sum -- * > SHA256SUMS")]
    assert order == sorted(order)
    assert '"${dry[@]}"' in a and "GITHUB_STEP_SUMMARY" in a


def test_a_tag_without_its_summary_stops_before_anything_is_built():
    v = jobs(read("release.yml"))["version"]
    assert "docs/releases/$(python3 packaging/release/versions.py --get pep440).md" in v


def test_every_job_has_a_time_limit():
    # Otherwise a hung step holds its runner for GitHub's default of 360 minutes.
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        for job, body in jobs(text).items():
            if "runs-on:" not in body:
                continue                      # a call: the called workflow's jobs set their own
            m = re.search(r"^    timeout-minutes: (\d+)(?:\s+#.*)?$", body, re.M)
            assert m and 1 <= int(m.group(1)) <= 60, (name, job)


def test_each_pr_commit_runs_the_tests_once():
    # A push to any branch and the PR each ran tests.yml for the same commit, the whole image
    # pipeline twice (#116). A branch with no PR runs it by hand, from workflow_dispatch.
    on = header(read("tests.yml"))
    assert re.search(r"^  push:\n(?:    #.*\n)*    branches: \[main\]$", on, re.M)
    assert "\n  pull_request:\n" in on and "\n  workflow_dispatch:\n" in on


def test_only_a_prs_or_a_dry_runs_older_run_is_cancelled():
    t = header(read("tests.yml"))
    # A run on main, a manual run and a run release.yml calls (its event is release.yml's)
    # each get a group of their own, so nothing cancels them.
    assert ("group: tests-${{ github.event_name == 'pull_request' && github.ref"
            " || github.run_id }}") in t
    assert "cancel-in-progress: true" in t
    rel = header(read("release.yml"))
    assert "group: release-${{ github.ref }}" in rel
    assert "cancel-in-progress: ${{ !startsWith(github.ref, 'refs/tags/') }}" in rel
    # One rescan at a time: two could both find no open issue and file the same one twice.
    resc = header(read("image-rescan.yml"))
    assert "group: image-rescan\n" in resc and "cancel-in-progress: false" in resc


def test_only_the_floors_job_keeps_a_pytest_without_the_tmpdir_fix():
    # CVE-2025-71176 is fixed in pytest 9.0.3, which needs Python 3.10 (#139). Dependabot's
    # ignore rules hold for a whole entry, so the 3.9 pins have their own, in a sibling
    # directory: the /packaging/ci entry also reads the directories below it (#145).
    def pin(path, name):
        with open(os.path.join(REPO, path), encoding="utf-8") as f:
            return tuple(map(int, re.search(r"^%s==([\d.]+)" % name, f.read(), re.M).group(1)
                                        .split(".")))
    assert pin("packaging/ci/test-requirements.txt", "pytest") >= (9, 0, 3)
    assert pin("packaging/ci-py39/test-requirements.txt", "pytest")[0] == 8
    below = [os.path.relpath(os.path.join(d, f), REPO) for d, _, fs in
             os.walk(os.path.join(REPO, "packaging", "ci")) for f in fs if "requirements" in f]
    assert below == [os.path.join("packaging", "ci", "test-requirements.txt")], below
    with open(os.path.join(REPO, ".github", "dependabot.yml"), encoding="utf-8") as f:
        cfg = f.read()
    ci = cfg.split('directory: "/packaging/ci"\n', 1)[1].split("package-ecosystem:", 1)[0]
    assert "dependency-name: pytest" not in ci
    py39 = cfg.split('directory: "/packaging/ci-py39"\n', 1)[1].split("package-ecosystem:", 1)[0]
    assert '      - dependency-name: pytest\n        versions: [">=9"]' in py39


def test_the_wheel_is_built_with_hash_pinned_tools_only():
    # The wheel is in every package. `pip install build` and an isolated build fetched whatever
    # build and setuptools PyPI served that minute, unhashed, into a signed release (#155).
    # packaging/build-dist.sh is the one way to build it: the shipped build and the rebuild
    # it's compared with take the same steps (#159).
    with open(os.path.join(REPO, "packaging", "build-dist.sh"), encoding="utf-8") as f:
        script = f.read()
    install = '-m pip install -q --require-hashes -r "$REPO/packaging/build-tools/requirements.txt"'
    builds = list(re.finditer(r"-m build\b.*", script))
    assert len(builds) == 1 and "--no-isolation" in builds[0].group(0)
    assert install in script[:builds[0].start()]
    # setuptools gives the wheel's files the builder's umask: RHEL's 002 made another wheel.
    assert re.search(r"^umask 022$", script[:builds[0].start()], re.M)
    assert "normalize_sdist.py" in script[builds[0].end():]
    for name in RELEASE_PATH:
        for job, body in jobs(read(name)).items():
            assert not re.search(r"-m build\b", body), (name, job)
            assert not re.search(r"pip install (?:-\S+ )*(?:build|setuptools)\b", body), (name, job)
    image = jobs(read("image.yml"))
    assert "packaging/build-dist.sh dist\n" in image["wheel"]
    assert "packaging/build-dist.sh dist2\n" in image["reproducible"]
    with open(os.path.join(REPO, ".github", "dependabot.yml"), encoding="utf-8") as f:
        assert 'directory: "/packaging/build-tools"' in f.read()


def test_a_build_that_does_not_reproduce_fails():
    # Report-only since it was added, and still after matching on every run, v1.0.0's
    # included; a wheel mismatch only printed "wheel: DIFFERS" (#159).
    for name in RELEASE_PATH:
        assert "continue-on-error" not in read(name), name
    rebuild = jobs(read("image.yml"))["reproducible"]
    assert 'packaging/check_dist.py dist2 --commit "$(git rev-parse HEAD)" --same-as dist || rc=1' in rebuild
    assert 'if [ "$want" = "$got" ]; then echo "image: identical"; exit $rc; fi' in rebuild
    assert rebuild.rstrip().endswith("exit 1")       # an image that differs


def test_called_workflows_set_no_concurrency_of_their_own():
    # A group matching the caller's would deadlock the run, and GitHub cancels it.
    for name in ("image.yml", "rpm.yml", "publish.yml", "attest.yml"):
        assert "concurrency:" not in read(name), name


def test_compare_bases_runs_for_branches_only():
    # GitHub doesn't apply a push: paths: filter to tags, so every release tag ran it (#116).
    on = header(read("compare-bases.yml"))
    assert re.search(r'^  push:\n(?:    #.*\n)*    branches: \["\*\*"\]\n    paths:\n', on, re.M)


def test_ci_runs_every_test_with_hash_pinned_packages():
    # A skip fails the run in CI (WD2L_NO_SKIPS, tests/conftest.py), so both test jobs install
    # what the tests need: the runner and the manifest's validator, by hash, and in fips-tests
    # git, which the builder lacks (#122). Without them, 29 tests skipped there with CI green.
    both = "--require-hashes -r packaging/ci/test-requirements.txt -r packaging/release/requirements.txt"
    pytest_job = jobs(read("tests.yml"))["pytest"]
    assert ('python -m pip install --require-hashes -r "$TEST_REQS" '
            '-r packaging/release/requirements.txt') in pytest_job
    # Only the floor's leg takes the 3.9 pins: pytest 9, which fixes CVE-2025-71176, needs 3.10.
    assert ("TEST_REQS: ${{ matrix.python-version == '3.9' && 'packaging/ci-py39/test-requirements.txt'"
            " || 'packaging/ci/test-requirements.txt' }}") in pytest_job
    assert 'WD2L_NO_SKIPS: "1"' in pytest_job
    fips = jobs(read("image.yml"))["fips-tests"]
    assert "python3 -m pip install -q --user " + both in fips
    assert "-e WD2L_NO_SKIPS=1" in fips and "dnf -y -q install git-core" in fips
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
        with open(path, encoding="utf-8") as f:
            assert not re.search(r"pip install (?:-\S+ )*pytest\b", f.read()), os.path.basename(path)


def test_notes_get_the_manifest_and_the_attestation_pages():
    rel = jobs(read("release.yml"))["release"]
    assert '--manifest "assets/wd2l-$V-release-manifest.json"' in rel
    assert "needs.attest.outputs.files-url" in rel and "needs.attest.outputs.image-url" in rel
    att = read("attest.yml")
    assert "files-url: ${{ steps.files.outputs.attestation-url }}" in att
    assert "image-url: ${{ steps.image.outputs.attestation-url }}" in att


def test_assets_adds_the_changelog_bundle_and_verify_release_before_the_manifest():
    a = jobs(read("release.yml"))["assets"]
    cliff = a.index("packaging/ci/tool git-cliff --config /work/cliff.toml")
    bundle = a.index('git bundle create "assets/wd2l-$V-source.bundle" HEAD "${tags[@]}"')
    script = a.index('cp packaging/release/verify_release.py "assets/wd2l-$V-verify-release.py"')
    assert max(cliff, bundle, script) < a.index("manifest.py generate")
    assert '--changelog "assets/wd2l-$V-changelog.md"' in a
    # ...and the release checks itself with the script it ships, after SHA256SUMS.
    assert a.index("sha256sum -- * > SHA256SUMS") < \
        a.index('python "assets/wd2l-$V-verify-release.py" --dir assets --skip-signature')


def test_scan_findings_pause_for_a_security_review_instead_of_failing():
    # The user's rule (#175): scanning measures known risk; it records the findings and, when one
    # needs a decision, waits for a person, as a release waits at its gate.
    image = jobs(read("image.yml"))
    scan = image["vuln-scan"]
    assert "vuln_gate.py" in scan and "--exit-code" not in scan and "exit $rc" not in scan
    review = image["vuln-review"]
    assert "needs: [vuln-scan]" in review and "pattern: vuln-*" in review
    assert "jq -s 'map(.gate.review_needed) | any' vuln-amd64/vuln-predicate.json vuln-arm64/vuln-predicate.json" in review
    gate = image["security-review"]
    assert "needs: [vuln-review]" in gate and "environment: security-review" in gate
    # Pull requests and releases pause; a push to main records without pausing.
    assert ("if: ${{ needs.vuln-review.outputs.needed == 'true' && "
            "!(github.event_name == 'push' && github.ref == 'refs/heads/main') }}") in gate
    # Every later step waits for the review: tests.yml's ci-ok and rpm, release.yml's publish.
    assert "needs: [pytest, lab, image, rpm]" in jobs(read("tests.yml"))["ci-ok"]
    assert "needs: [version, tests, image, rpm]" in jobs(read("release.yml"))["publish"]


def test_code_scanning_uploads_whatever_results_exist_unless_cancelled():
    # It was skipped whenever any image check failed, the functional lab included, so a finding
    # never reached Code scanning on the push where it first showed (#175).
    cs = jobs(read("tests.yml"))["code-scanning"]
    assert "if: ${{ !cancelled() && github.event_name == 'push' && github.ref == 'refs/heads/main' }}" in cs
    steps = cs.split("      - uses: ")[2:]
    downloads = [s for s in steps if s.startswith("actions/download-artifact@")]
    uploads = [s for s in steps if s.startswith("github/codeql-action/upload-sarif@")]
    # One download by pattern: a platform whose image didn't build has no results to fetch.
    assert len(downloads) == 1 and "pattern: vuln-*" in downloads[0]
    assert len(uploads) == 4
    for s in uploads:
        sarif = re.search(r"sarif_file: (\S+)", s).group(1)
        assert "if: ${{ hashFiles('%s') != '' }}" % sarif in s


def test_the_rescan_opens_issues_from_the_review_decision_and_fails_only_on_errors():
    # vuln_gate.py no longer fails on findings; --exit-code 3 marks "needs review" (#175).
    scan = jobs(read("image-rescan.yml"))["rescan"]
    assert '--summary "summary-$v-$a.md" --warnings "coverage-$v-$a.log" --exit-code 3 || rc=$?' in scan
    assert '[ "$rc" -eq 0 ] || [ "$rc" -eq 3 ] || exit "$rc"' in scan
    assert 'if [ "$rc" -eq 3 ]; then' in scan
    assert "exit $fail" not in scan


def test_the_rescan_scans_what_shipped_and_labels_its_issues():
    # It scanned wd2l:$v, which can move, and filed unlabelled issues the manifest's Known
    # issues left out (#177).
    scan = jobs(read("image-rescan.yml"))["rescan"]
    assert 'gh release download "$tag" -p "wd2l-$v-release-manifest.json" -O "manifest-$v.json"' in scan
    assert "d=$(jq -r '.image.index_digest // empty' \"manifest-$v.json\")" in scan
    assert '[[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]] || {' in scan
    assert 'ref="ghcr.io/joehazurmoney/wd2l@$d"' in scan
    assert 'wd2l:$v"' not in scan
    assert 'gh issue create --title "$title" --label security --label bug --body-file "summary-$v-$a.md"' in scan


def test_no_secret_is_pasted_into_a_script():
    # An expression in run: is pasted into the script's text; `echo "${{ secrets.GITHUB_TOKEN }}"`
    # did that for each podman login (#178). Secrets reach scripts through env, as variables.
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")):
        name = os.path.basename(path)
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                if "secrets." not in line or line.lstrip().startswith("#"):
                    continue
                # Allowed: a key whose value is the expression (env:, with:, secrets: blocks).
                env_like = r"^\s+[A-Za-z_][A-Za-z0-9_-]*: \$\{\{ secrets\.\w+( != '')? \}\}\s*$"
                assert re.match(env_like, line), "%s:%d: %s" % (name, n, line.strip())


def test_one_version_parser():
    # Four parsers could drift; the two sed copies already differed on a CR (#180).
    for path in glob.glob(os.path.join(WORKFLOWS, "*.yml")) + [
            os.path.join(REPO, "packaging", "container", "build.sh")]:
        with open(path, encoding="utf-8") as f:
            assert "__version__" not in f.read(), os.path.basename(path)
    assert ('--arg version "$(python3 packaging/release/versions.py --get pep440)"'
            in jobs(read("image.yml"))["build"])
    with open(os.path.join(REPO, "packaging", "container", "build.sh"), encoding="utf-8") as f:
        assert 'VERSION="$(python3 "$REPO/packaging/release/versions.py" --get pep440)"' in f.read()


def tool_runs(body: str):
    """Each run of a scanner or Syft in a job, its continuation lines joined."""
    joined = re.sub(r"\\\n\s*", " ", body)
    return re.findall(r"packaging/ci/tool (?:grype|trivy|syft)\b[^\n]*", joined)


SCAN_JOBS = (("image.yml", "lint"), ("image.yml", "vuln-scan"), ("image.yml", "sbom"),
             ("image.yml", "ubi9-scan"), ("image-rescan.yml", "rescan"))


def test_the_comparison_image_is_built_checked_and_scanned_but_never_pauses_a_run():
    # wd2l on UBI 9 (#192): built from the same wheel, checked by its own profile, scanned and
    # described, and published; its findings are shown, never gated (ADR-0004's amendment).
    image = jobs(read("image.yml"))
    assert "needs: [wheel, lint, base-verify-ubi9]" in image["ubi9-build"]
    assert "packaging/container/build.sh dist localhost/wd2l-ubi9:ci packaging/container/Containerfile.ubi9" in image["ubi9-build"]
    assert "--containerfile packaging/container/Containerfile.ubi9" in image["base-verify-ubi9"]
    assert "--type spdxjson" in image["base-verify-ubi9"]
    checks = image["ubi9-checks"]
    assert "packaging/container/build.sh dist localhost/wd2l-ubi9:again packaging/container/Containerfile.ubi9" in checks
    assert "--profile ubi9" in checks and "for c in wd2l-sender wd2l-receiver wd2l-audit-report" in checks
    scan = image["ubi9-scan"]
    assert "--source-name ghcr.io/joehazurmoney/wd2l-ubi9" in scan
    assert "sbom_enrich.py" in scan and "sbom_diff.py" in scan and "vuln_gate.py" in scan
    assert "name: vuln-ubi9-amd64" in scan and "name: sbom-ubi9-amd64" in scan
    assert "ubi9" not in image["vuln-review"] and "ubi9" not in image["security-review"]
    for check in ("check_containerfile.py packaging/container/Containerfile.ubi9",
                  "/work/packaging/container/Containerfile.ubi9"):
        assert check in image["lint"], check


def test_no_scanner_or_syft_runs_quietly():
    # --quiet hid upstream Trivy's "Unsupported os" on the Hardened image for every release (#191).
    for name in ("image.yml", "image-rescan.yml", "publish.yml", "release.yml", "tests.yml"):
        for job, body in jobs(read(name)).items():
            for run in tool_runs(body):
                assert not re.search(r"(^|\s)(-q|--quiet)(\s|$)", run), (name, job, run)


def test_every_scanner_and_syft_log_is_kept_and_its_warnings_raised():
    # Each tool's output goes to a log in the run's artifact, and tool_warnings.py raises every
    # warning in it on the run, never failing it, unless tool-warnings.json expects it.
    for name, job in SCAN_JOBS:
        body = jobs(read(name))[job]
        runs = tool_runs(body)
        assert runs, (name, job)
        (warn,) = [s for s in body.split("\n      - ") if "tool_warnings.py" in s]       # its step
        assert "python3 packaging/container/tool_warnings.py --known packaging/container/tool-warnings.json" in warn
        assert "if: ${{ !cancelled() }}" in warn, (name, job)
        for run in runs:
            m = re.search(r"2>&1 \| tee (?:-a )?(\S+)$", run)
            assert m, (name, job, run)
            log = m.group(1).strip('"')
            # Named outright, or (the rescan: one log per release and platform) by a glob.
            globs = re.findall(r"for f in (\S*)\*\.log; do", warn)
            assert "=%s" % log in warn or ("$" in log and any(log.startswith(g) for g in globs)), (name, job, log)


def test_the_gate_s_coverage_warnings_go_through_the_reviewed_list():
    scan = jobs(read("image.yml"))["vuln-scan"]
    assert "--warnings vuln/coverage.log" in scan and "--log vuln-gate=vuln/coverage.log" in scan
    assert scan.index("vuln_gate.py") < scan.index("tool_warnings.py")
    rescan = jobs(read("image-rescan.yml"))["rescan"]
    assert '--warnings "coverage-$v-$a.log"' in rescan
    assert 'for f in coverage-*.log; do args+=(--log "vuln-gate=$f"); done' in rescan


def test_the_rescan_reports_the_comparison_image_and_opens_no_issue_for_it():
    # #192: wd2l-ubi9, by the digest its release's manifest records, scanned weekly too; its
    # findings are shown, never an issue (ADR-0004's amendment).
    scan = jobs(read("image-rescan.yml"))["rescan"]
    assert "d9=$(jq -r '.comparison_image.digest // empty' \"manifest-$v.json\")" in scan
    block = scan.split('if [ -n "$d9" ]; then', 1)[1].split("\n            fi\n", 1)[0]
    assert '"registry:ghcr.io/joehazurmoney/wd2l-ubi9@$d9" --platform linux/amd64' in block
    assert '--warnings "coverage-ubi9-$v.log"' in block and "gh issue" not in block and "--exit-code" not in block


def test_the_weekly_pins_job_notices_when_red_hat_s_trivy_database_becomes_reachable():
    # Red Hat's Trivy was dropped because its Hummingbird database refuses anonymous access
    # (ADR-0011); when that changes, an issue says to revisit it.
    pins = jobs(read("image-rescan.yml"))["pins"]
    assert "packaging/ci/tool oras manifest fetch quay.io/hummingbird-ci/trivy-db:2" in pins
    assert 'title="Red Hat\'s Trivy database for Hummingbird is reachable: revisit ADR-0011"' in pins


def test_the_image_sbom_names_the_image_lists_every_file_and_is_completed_before_use():
    # #188: Syft's SBOM named no suppliers, didn't link wd2l's own files and had a random
    # namespace. The sbom job names the image and its version, lists every file, and completes
    # both SBOMs (sbom_enrich.py, which fails on a gap) before the diff and the upload.
    body = jobs(read("image.yml"))["sbom"]
    assert "name: dist" in body
    assert "SYFT_FILE_METADATA_SELECTION: all" in body
    image = re.search(r"TOOL_ENV=SYFT_FILE_METADATA_SELECTION packaging/ci/tool syft "
                      r"oci-archive:/work/image/image\.oci\.tar[^\n]*\\\n[^\n]*", body).group(0)
    assert '--source-name ghcr.io/joehazurmoney/wd2l --source-version "$V"' in image
    enrich = body.index('python3 packaging/container/sbom_enrich.py --spdx sbom/wd2l.spdx.json '
                        '--cdx sbom/wd2l.cdx.json --wheel "$WHEEL" --arch ${{ matrix.arch }}')
    assert body.index(image) < enrich < body.index("sbom_diff.py") < body.index("upload-artifact")


def test_the_release_has_the_readable_sbom_of_both_platforms_listed_and_summed():
    # #189: wd2l-<v>-sbom.html, made from the released SBOM files and both scanners' results,
    # before the manifest lists the assets and SHA256SUMS sums them.
    body = jobs(read("release.yml"))["assets"]
    report = body.index('python packaging/release/sbom_report.py --version "$V"')
    assert '--out "assets/wd2l-$V-sbom.html"' in body[report:report + 400]
    for part in ('--view "$a" "linux/$a" "assets/wd2l-$V-image-$a.spdx.json" "assets/wd2l-$V-image-$a.cdx.json"',
                 '--scan "$a" "grype=vuln-$a/grype.json"', '--scan "$a" "trivy=vuln-$a/trivy.json"',
                 "for a in amd64 arm64; do"):
        assert part in body[body.index("name: The SBOMs and their scans as one readable page"):report], part
    assert body.index('cp "sbom-$a/wd2l.spdx.json"') < report < body.index("manifest.py generate")


def test_the_release_carries_the_comparison_image_s_files_tab_and_record():
    # #192: its SBOMs, scan summary, base record and tar are release files, listed and summed;
    # the SBOM page has its tab; the manifest records the image by the digest publish pushed.
    body = jobs(read("release.yml"))["assets"]
    assert "sbom-ubi9-amd64,vuln-ubi9-amd64,base-evidence-ubi9" in body
    for part in ('cp sbom-ubi9-amd64/wd2l.spdx.json "assets/wd2l-$V-image-ubi9-amd64.spdx.json"',
                 'cp sbom-ubi9-amd64/wd2l.cdx.json "assets/wd2l-$V-image-ubi9-amd64.cdx.json"',
                 'cp vuln-ubi9-amd64/vuln-summary.md "assets/wd2l-$V-vuln-summary-ubi9-amd64.md"',
                 "cp base-evidence-ubi9/base-image-record-ubi9.json assets/",
                 '--view ubi9 "UBI 9 (amd64)" "assets/wd2l-$V-image-ubi9-amd64.spdx.json" "assets/wd2l-$V-image-ubi9-amd64.cdx.json"',
                 '--scan ubi9 grype=vuln-ubi9-amd64/grype.json --scan ubi9 trivy=vuln-ubi9-amd64/trivy.json',
                 '--comparison-digest "$DIGEST_UBI9" --comparison-base-record assets/base-image-record-ubi9.json',
                 "DIGEST_UBI9: ${{ needs.publish.outputs.digest_ubi9 }}"):
        assert part in body, part


def test_the_image_name_and_the_urls_agree_everywhere():
    # Written out in five files (#180): a change to one would push, sign, attest or rescan
    # under another name.
    from helpers import load_script
    manifest = load_script("packaging/release/manifest.py")
    notes = load_script("packaging/release/notes.py")
    assert notes.IMAGE == manifest.IMAGE
    texts = {os.path.basename(p): open(p, encoding="utf-8").read()
             for p in glob.glob(os.path.join(WORKFLOWS, "*.yml"))}
    for p in ("packaging/release/manifest.py", "packaging/release/notes.py"):
        texts[p] = open(os.path.join(REPO, p), encoding="utf-8").read()
    names = {"ghcr.io/%s/%s" % m for t in texts.values()
             for m in re.findall(r"ghcr\.io/([\w.-]+)/(wd2l[\w.-]*)", t)
             if not m[1].startswith("wd2l-base")}             # the base images' mirror
    assert names == {manifest.IMAGE, manifest.UBI9_IMAGE}      # and the comparison image (#192)
    atts = {m for t in texts.values()
            for m in re.findall(r"https://github\.com/[\w.-]+/[\w.-]+/attestations", t)}
    assert atts == {manifest.ATT}
    mirror = "quay.io/hummingbird/${name#registry.access.redhat.com/hi/}"
    assert mirror in texts["image.yml"] and mirror in texts["publish.yml"]
