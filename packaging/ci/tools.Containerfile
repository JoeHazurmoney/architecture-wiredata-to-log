# Pinned CI tool images. Never built: packaging/ci/tool runs a stage by name, and Dependabot
# (.github/dependabot.yml) proposes new digests. Re-pin by hand with:
#   packaging/ci/pin-images.sh packaging/ci/tools.Containerfile
FROM registry.access.redhat.com/hi/cosign:3@sha256:b093a3ec46fab423d25333ca1a9466ccf21799c94008eaf1b9fdbd23e7ee25a2 AS cosign
FROM registry.access.redhat.com/hi/grype:0.121@sha256:f1d87e4157be6dc5cb7bb7da30676826e295e0f2e3e2ebba472b463e2fae0a65 AS grype
FROM registry.access.redhat.com/hi/oras:1.3@sha256:df2ad9b0dbd12b8cec46efe6977691e7894b65b5ac8ee5df66af30b06ba2783a AS oras
FROM docker.io/anchore/syft:v1.57.1@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060 AS syft
FROM docker.io/aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c AS trivy
FROM docker.io/hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d AS hadolint
# The changelog in every release (cliff.toml, docs/decisions/0008-release-manifest.md).
FROM docker.io/orhunp/git-cliff:2.14.2@sha256:1e696a381a1b0366bb6ccbb6bd4e50e73473fda88eab3a757b95e0d0d66c9531 AS git-cliff
FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:1963e00991088221a3405be7eb315a3dbc0be0f1f7440f0bd537d481cf33c83e AS ubi9
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:a75ad754aa048d808dd3260243452f8c9a665831d0493b4c9d92f0c88fe2f8c3 AS ubi10
# A real chronyd for packaging/ci/chrony-smoke.sh (UBI has no chrony): EL10's, as the hosts run.
# Not Fedora: quay.io deletes each fedora:44 digest when the daily rebuild re-tags it (#97).
FROM docker.io/library/almalinux:10@sha256:5a4b41a427c9717be8f4ac2a32aa22efbae5f9124fbcb79a6765394f312acfe8 AS alma10
