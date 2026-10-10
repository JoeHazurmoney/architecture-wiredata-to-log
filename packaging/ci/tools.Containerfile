# Pinned CI tool images. Never built: packaging/ci/tool runs a stage by name, and Dependabot
# (.github/dependabot.yml) proposes new digests. Re-pin by hand with:
#   packaging/ci/pin-images.sh packaging/ci/tools.Containerfile
FROM registry.access.redhat.com/hi/cosign:latest@sha256:ce4f2d3901e7709fadfce8b861a8e454cbcadf776d04c9d43ca933957e524e2f AS cosign
FROM registry.access.redhat.com/hi/grype:0.115@sha256:40f8d610ac61ccb6fdeca2c2049ecb00e0a3751f1ae8481a68b62614d290c9b0 AS grype
FROM registry.access.redhat.com/hi/oras:1.3@sha256:b4ae77d63b264fd151cd32717f75d77a514fab8d1784f0cfa54e11aa6db400bb AS oras
FROM docker.io/anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa AS syft
FROM docker.io/aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM docker.io/hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d AS hadolint
FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:5858f9ace07316e3b12caab62f6c2481a5030bb6bafdca5a9ea324c321ef36df AS ubi9
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:27e14f4987d7abe56664d7e1b1dddcd0226d4ca593da5726f0f65697a17d0fee AS ubi10
# A real chronyd for packaging/ci/chrony-smoke.sh (UBI has no chrony). From quay.io, the same
# image as registry.fedoraproject.org, which Dependabot can't read.
FROM quay.io/fedora/fedora:42@sha256:e78cd1a688cd079c23864f289a89a49a3f4ad66d817864e325e1d058310ee95c AS fedora
