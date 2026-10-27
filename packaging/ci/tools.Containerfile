# Pinned CI tool images. Never built: packaging/ci/tool runs a stage by name, and Dependabot
# (.github/dependabot.yml) proposes new digests. Re-pin by hand with:
#   packaging/ci/pin-images.sh packaging/ci/tools.Containerfile
FROM registry.access.redhat.com/hi/cosign:3@sha256:18bd54867ddcb217f045e3ff97135c373864ea5bdb0f4bb97db90f645ac0e07d AS cosign
FROM registry.access.redhat.com/hi/grype:0.119@sha256:1885fd16dbad4977a36b700d2ba55d1cc9946ed608c249833c5e45e31bd3906f AS grype
FROM registry.access.redhat.com/hi/oras:1.3@sha256:213219800a7d65604924395878e5e93d3cd568ecb99acd75dbca03356517dcd8 AS oras
FROM docker.io/anchore/syft:v1.54.1@sha256:3eb5379ba7b409c3f4069b686110527af0c47df993fa5c10d13e7cf34f49b1aa AS syft
FROM docker.io/aquasec/trivy:0.75.0@sha256:af6acf9a6b85dfe389a1941505c0ce9efef52a4719635e1a962f022a3d855daa AS trivy
FROM docker.io/hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d AS hadolint
# The changelog in every release (cliff.toml, docs/decisions/0008-release-manifest.md).
FROM docker.io/orhunp/git-cliff:2.14.2@sha256:1e696a381a1b0366bb6ccbb6bd4e50e73473fda88eab3a757b95e0d0d66c9531 AS git-cliff
FROM registry.access.redhat.com/ubi9/ubi:latest@sha256:48393e4261b2544f652c915b3e052256ddf66ee95cd04dc0362191f302c4e94a AS ubi9
FROM registry.access.redhat.com/ubi10/ubi:latest@sha256:a75ad754aa048d808dd3260243452f8c9a665831d0493b4c9d92f0c88fe2f8c3 AS ubi10
# A real chronyd for packaging/ci/chrony-smoke.sh (UBI has no chrony): EL10's, as the hosts run.
# Not Fedora: quay.io deletes each fedora:44 digest when the daily rebuild re-tags it (#97).
FROM docker.io/library/almalinux:10@sha256:838c2fafefb1a8a0d7f8cdbc3b0551c2a2b1eb0cd87aad6d62aecadb18311f1b AS alma10
