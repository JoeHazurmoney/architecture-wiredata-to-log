# Public keys for the base images

The image pipeline (`.github/workflows/image.yml`, job `base-verify`) verifies each base image
with these, before every build. They are copies, so a change upstream can't silently change what
we trust; replacing one is a reviewed commit.

| File | What it verifies | Source | SHA-256 of the file |
|---|---|---|---|
| `redhat-release3.pub` | Red Hat's signature on `registry.access.redhat.com/hi/*` | The PEM block of https://security.access.redhat.com/data/63405576.txt ("Red Hat, Inc. (release key 3)", fetched 2026-10-08; that page's SHA-256 was `2d43fc0ec7f773a75b5d4ae70c1c0b93c6ddc4a8f2ef9fd81b2589076032e80c`) | `64f89557ea8030ff839a45bb194594262a83502cdc69a4b04786e9d975a5c5aa` |
| `hummingbird-ci.pub` | The SLSA provenance on `quay.io/hummingbird/*` (Red Hat's Konflux pipeline) | https://gitlab.com/redhat/hummingbird/containers/-/raw/main/ci/key.pub (fetched 2026-10-08) | `40537705f3be25019a6c0c4befb4cff9454968cfb4c984001e755a9e278f2c4c` |
