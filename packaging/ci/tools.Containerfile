# Pinned CI tool images. Never built: packaging/ci/tool runs a stage by name, and Dependabot
# (.github/dependabot.yml) proposes new digests. Re-pin by hand with:
#   packaging/ci/pin-images.sh packaging/ci/tools.Containerfile
FROM registry.access.redhat.com/hi/cosign:latest@sha256:17d443385a03b0f6592120ff4b99aa00cea043a0e9b84514070f0d2360a78fde AS cosign
FROM registry.access.redhat.com/hi/grype:0.119@sha256:1870f5513102bc232ba1e40372531119c4bc41f896e0c0a5ce3a3acbebb23a81 AS grype
FROM registry.access.redhat.com/hi/oras:1.3@sha256:244ffe118d64ac08d20aa7b632951e399387a88760cf30b254bedfddc60caca1 AS oras
FROM docker.io/anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa AS syft
FROM docker.io/aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM docker.io/hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d AS hadolint
# The changelog in every release (cliff.toml, docs/decisions/0008-release-manifest.md).
FROM docker.io/orhunp/git-cliff:2.14.2@sha256:1e696a381a1b0366bb6ccbb6bd4e50e73473fda88eab3a757b95e0d0d66c9531 AS git-cliff
FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:16e9e43d99e181463513cc84a514859b1abb9460f1c4d9e208da4b4e51cd5cc3 AS ubi9
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:ad0d8e4fcd4c83cf4a2d025de402f010fd068e43f253d0a57b5681d1ad45f044 AS ubi10
# A real chronyd for packaging/ci/chrony-smoke.sh (UBI has no chrony): EL10's, as the hosts run.
# Not Fedora: quay.io deletes each fedora:44 digest when the daily rebuild re-tags it (#97).
FROM docker.io/library/almalinux:10@sha256:838c2fafefb1a8a0d7f8cdbc3b0551c2a2b1eb0cd87aad6d62aecadb18311f1b AS alma10
