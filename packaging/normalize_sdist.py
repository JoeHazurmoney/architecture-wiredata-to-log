#!/usr/bin/env python3
"""Makes the sdist byte-reproducible (#159). setuptools ignores SOURCE_DATE_EPOCH for sdists:
each member, and the gzip header, carries the build time, and the owner and modes are the
builder's. This rewrites the sdist in place, with the same members in the same order and the
same bytes, and only these changed:

* each member's time, and the gzip header's: SOURCE_DATE_EPOCH;
* each member's owner: root (0:0);
* each mode: 0755 for a directory or a file with any execute bit, else 0644.

    SOURCE_DATE_EPOCH=T python3 packaging/normalize_sdist.py SDIST

packaging/build-dist.sh runs it after `python -m build`, which builds the wheel from the sdist
first: the wheel doesn't change."""

import argparse
import gzip
import io
import os
import sys
import tarfile
from typing import Optional, Sequence


def normalize(path: str, epoch: int) -> None:
    out = io.BytesIO()
    with tarfile.open(path, "r:gz") as src:
        name = os.path.basename(path)
        with gzip.GzipFile(name, "wb", compresslevel=9, fileobj=out, mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as dst:
                for m in src.getmembers():
                    data = src.extractfile(m).read() if m.isfile() else None
                    m.mtime, m.uid, m.gid, m.uname, m.gname = epoch, 0, 0, "root", "root"
                    if m.isdir() or m.isfile():
                        m.mode = 0o755 if m.isdir() or m.mode & 0o111 else 0o644
                    m.pax_headers = {}           # the old times, at full precision
                    dst.addfile(m, io.BytesIO(data) if data is not None else None)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(out.getvalue())
    os.replace(tmp, path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Make an sdist byte-reproducible, in place.")
    p.add_argument("sdist")
    a = p.parse_args(argv)
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if not epoch.isdigit():
        raise SystemExit("normalize_sdist: SOURCE_DATE_EPOCH must be set to the commit's time")
    normalize(a.sdist, int(epoch))
    return 0


if __name__ == "__main__":
    sys.exit(main())
