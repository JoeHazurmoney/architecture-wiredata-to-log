# Pinned CI tool images. Never built: packaging/ci/tool runs a stage by name, and Dependabot
# (.github/dependabot.yml) proposes new digests. Re-pin by hand with:
#   packaging/ci/pin-images.sh packaging/ci/tools.Containerfile
FROM registry.access.redhat.com/hi/cosign:latest@sha256:17d443385a03b0f6592120ff4b99aa00cea043a0e9b84514070f0d2360a78fde AS cosign
FROM registry.access.redhat.com/hi/grype:0.119@sha256:a4b323580f29ae8b9f820da350a73e1d7283e52641fcbf091d735bf87bfc63f6 AS grype
FROM registry.access.redhat.com/hi/oras:1.3@sha256:b5a146743b09c88bba3b91b888ce68588b257789b53ea7f69cc62420a4841bd7 AS oras
FROM docker.io/anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa AS syft
FROM docker.io/aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM docker.io/hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d AS hadolint
FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:beba9460df08acc9f2d5a99f61b8544d5367b05e02c945ca726c6f07ca5963a7 AS ubi9
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:ad0d8e4fcd4c83cf4a2d025de402f010fd068e43f253d0a57b5681d1ad45f044 AS ubi10
# A real chronyd for packaging/ci/chrony-smoke.sh (UBI has no chrony). From quay.io, the same
# image as registry.fedoraproject.org, which Dependabot can't read.
FROM quay.io/fedora/fedora:44@sha256:1ff9eb02e4e2d7fb1175becac7139b2960c4fdcccedce81c86ec25b98ef3124d AS fedora
