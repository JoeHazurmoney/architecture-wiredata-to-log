"""Policy over the workflow files (docs/decisions/0007-slsa-build-l3.md):

* only attest.yml may get an OIDC token, so build steps can't reach what signs the provenance;
* nothing shared between runs on the release path, and only GitHub-hosted runners;
* attestation runs only for a v* tag, and only in this repository;
* every job has a time limit, and a newer commit cancels only a PR's or a dry run's older run,
  never a run on main or a tag's (docs/releasing.md, "When CI runs")."""

import glob
import os
import re
from typing import Dict

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
WORKFLOWS = os.path.join(REPO, ".github", "workflows")
RELEASE_PATH = ("tests.yml", "image.yml", "rpm.yml", "publish.yml", "release.yml", "attest.yml")
GITHUB_HOSTED = ("ubuntu-24.04", "ubuntu-latest", "ubuntu-24.04-arm")
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


def test_called_workflows_set_no_concurrency_of_their_own():
    # A group matching the caller's would deadlock the run, and GitHub cancels it.
    for name in ("image.yml", "rpm.yml", "publish.yml", "attest.yml"):
        assert "concurrency:" not in read(name), name


def test_compare_bases_runs_for_branches_only():
    # GitHub doesn't apply a push: paths: filter to tags, so every release tag ran it (#116).
    on = header(read("compare-bases.yml"))
    assert re.search(r'^  push:\n(?:    #.*\n)*    branches: \["\*\*"\]\n    paths:\n', on, re.M)


def test_the_tests_install_the_manifest_requirements():
    # Otherwise the schema tests would skip silently in CI.
    assert "python -m pip install --require-hashes -r packaging/release/requirements.txt" in \
        jobs(read("tests.yml"))["pytest"]


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
