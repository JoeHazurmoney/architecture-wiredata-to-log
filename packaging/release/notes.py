#!/usr/bin/env python3
"""Release notes for the draft GitHub release (release.yml): what is in it, how to verify it
offline, the exact image and the bases it stands on, and every asset with its SHA-256.

    notes.py --image-digest sha256:... [--platform-digest ARCH=sha256:...] --sums SHA256SUMS
             --base-record base-image-record.json
             --repo-url URL --run-url URL --commit SHA > notes.md"""

import argparse
import json
import os
import sys
from typing import Any, Dict, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import versions  # noqa: E402  (a sibling script, not a package)

IMAGE = "ghcr.io/joehazurmoney/wd2l"


def notes(names: Dict[str, Any], image: str, digest: str, sums_text: str,
          base_record: Dict[str, Any], repo_url: str, run_url: str, commit: str,
          platforms: Dict[str, str]) -> str:
    v, tag = names["pep440"], names["tag"]
    doc = "%s/blob/%s/docs" % (repo_url, tag)
    out = []
    if names["prerelease"]:
        out += ["> **Pre-release** for testing. Not for production.", ""]
    out += ["wd2l %s, built from commit `%s` by [this workflow run](%s)." % (v, commit, run_url), "",
            "## Install", "",
            "* **RPMs** for RHEL 9 (`el9`) and RHEL 10 (`el10`): `wd2l` plus `wd2l-sender` on the "
            "log server ([guide](%s/deployment/log-server.md)), or `wd2l` plus `wd2l-receiver` on "
            "the receiver host ([guide](%s/deployment/receiver.md))." % (doc, doc),
            "* **Container** (FIPS, Red Hat Hardened Images): `%s:%s` "
            "([guide](%s/deployment/containers.md)); `wd2l-%s-image-amd64-oci.tar` and "
            "`wd2l-%s-image-arm64-oci.tar` are the same image, one per platform, "
            "each with its signature and attestations, for enclaves without a registry."
            % (image, " / ".join(names["image_tags"]), doc, v, v),
            "* Bringing a release into an enclave: [releasing.md](%s/releasing.md#bringing-a-release-into-an-enclave)."
            % doc, "",
            "## Verify (works offline)", "",
            "Use a `cosign.pub` you got from a trusted channel (the repository at `%s`, or the "
            "security owner). The copy attached here is for convenience." % tag, "",
            "```bash",
            "cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
            "sha256sum -c SHA256SUMS",
            "tar -xf wd2l-%s-image-amd64-oci.tar   # or -arm64-oci.tar on an arm64 host" % v,
            "cosign verify --key cosign.pub --insecure-ignore-tlog --local-image wd2l-oci",
            "```", ""]
    slug = repo_url.rstrip("/").split("github.com/", 1)[-1]
    pin = ("--repo %s --signer-workflow %s/.github/workflows/attest.yml --source-ref refs/tags/%s "
           "--deny-self-hosted-runners" % (slug, slug, tag))
    out += ["## Build provenance (SLSA Build Level 3)", "",
            "Every asset below and the image have GitHub build provenance, made only by "
            "`attest.yml`. With the GitHub CLI:", "",
            "```bash",
            "gh attestation verify wd2l-%s-py3-none-any.whl %s" % (v, pin)]
    if digest:
        out.append("gh attestation verify oci://%s@%s %s --bundle-from-oci" % (image, digest, pin))
    out += ["# offline: add --bundle wd2l-%s-attestations.jsonl --custom-trusted-root "
            "trusted_root.jsonl (docs/releasing.md)" % v,
            "```", "",
            "## Image", ""]
    out.append("`%s@%s`" % (image, digest) if digest else "Image not published (dry run).")
    if digest and platforms:
        out += ["", "One index for both platforms; each platform's own image:", "",
                "| Platform | Digest |", "|---|---|"]
        out += ["| linux/%s | `%s` |" % (a, d) for a, d in sorted(platforms.items())]
    out += ["", "| Stage | Base image | Source (SRPMs) |", "|---|---|---|"]
    for b in base_record.get("images", []):
        out.append("| %s | `%s` | `%s` |" % (b.get("stage"), b.get("ref"), b.get("source_image")))
    out += ["", "The bases, their Red Hat signatures, SBOMs, provenance and sources are mirrored "
            "in `ghcr.io/joehazurmoney/wd2l-base/python` ([why](%s/decisions/0006-release-artifacts-and-signing.md))."
            % doc, "", "## Assets", "", "| File | SHA-256 |", "|---|---|"]
    for line in sums_text.splitlines():
        if line.strip():
            h, name = line.split(None, 1)
            out.append("| `%s` | `%s` |" % (name.lstrip("*"), h))
    return "\n".join(out) + "\n"


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Release notes for the draft release.")
    p.add_argument("--image", default=IMAGE)
    p.add_argument("--image-digest", default="")
    p.add_argument("--platform-digest", action="append", default=[], metavar="ARCH=DIGEST")
    p.add_argument("--sums", required=True)
    p.add_argument("--base-record", required=True)
    p.add_argument("--repo-url", required=True)
    p.add_argument("--run-url", required=True)
    p.add_argument("--commit", required=True)
    a = p.parse_args(argv)
    with open(a.sums) as f:
        sums = f.read()
    with open(a.base_record) as f:
        rec = json.load(f)
    platforms = dict(x.split("=", 1) for x in a.platform_digest)
    sys.stdout.write(notes(versions.names(versions.read_version()), a.image, a.image_digest, sums,
                           rec, a.repo_url, a.run_url, a.commit, platforms))
    return 0


if __name__ == "__main__":
    sys.exit(main())
