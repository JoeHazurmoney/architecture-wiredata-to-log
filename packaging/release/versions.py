#!/usr/bin/env python3
"""Release names, all from wd2l/__init__.py's __version__ (the one place a version is written):

  pep440      0.3.0 or 0.3.0rc1          wheel, sdist, image label
  tag         v0.3.0 or v0.3.0rc1        git tag, GitHub release
  rpm         0.3.0 or 0.3.0~rc1         RPM Version (the tilde sorts before the release)
  image_tags  0.3.0 0.3, or 0.3.0rc1     ghcr tags
  prerelease  false or true

    versions.py [--github-output FILE] [--check-tag TAG] [--get KEY]"""

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Optional, Sequence

INIT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "wd2l", "__init__.py")
SCHEME = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")


def read_version(path: str = INIT) -> str:
    with open(path) as f:
        m = re.search(r'^__version__ = "([^"]+)"$', f.read(), re.M)
    if not m:
        raise ValueError("no __version__ in %s" % path)
    return m.group(1)


def names(version: str) -> Dict[str, Any]:
    m = SCHEME.match(version)
    if not m:
        raise ValueError("version %r is not X.Y.Z or X.Y.Z{a,b,rc}N" % version)
    major, minor, patch, pre, n = m.groups()
    base = "%s.%s.%s" % (major, minor, patch)
    return {"pep440": version, "tag": "v" + version,
            "rpm": base + ("~%s%s" % (pre, n) if pre else ""),
            "image_tags": [version] if pre else [base, "%s.%s" % (major, minor)],
            "prerelease": bool(pre)}


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Release names from __version__.")
    p.add_argument("--github-output", help="append key=value lines (GitHub Actions outputs)")
    p.add_argument("--check-tag", help="exit 1 unless this is the version's tag")
    p.add_argument("--get", help="print one name")
    a = p.parse_args(argv)
    n = names(read_version())
    if a.check_tag is not None and a.check_tag != n["tag"]:
        print("tag %s doesn't match __version__ (expected %s)" % (a.check_tag, n["tag"]), file=sys.stderr)
        return 1
    if a.github_output:
        with open(a.github_output, "a") as f:
            for k, v in n.items():
                f.write("%s=%s\n" % (k, " ".join(v) if isinstance(v, list) else
                                     str(v).lower() if isinstance(v, bool) else v))
    if a.get:
        v = n[a.get]
        print(" ".join(v) if isinstance(v, list) else v)
    elif not a.github_output and a.check_tag is None:
        print(json.dumps(n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
