"""Policy over the workflow files (docs/decisions/0007-slsa-build-l3.md):

* only attest.yml may get an OIDC token, so build steps can't reach what signs the provenance;
* nothing shared between runs on the release path, and only GitHub-hosted runners;
* attestation runs only for a v* tag, and only in this repository."""

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
