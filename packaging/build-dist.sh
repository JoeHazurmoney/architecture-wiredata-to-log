#!/usr/bin/env bash
# Builds the wheel and the sdist into OUTDIR, the one way CI ships them (image.yml's wheel job)
# and rebuilds them to compare (its reproducible job, which fails on any difference, #159):
#   packaging/build-dist.sh OUTDIR
# The build tools come by hash, with no isolated build environment that would fetch them
# unpinned (#155); this installs them into the running Python. wd2l/BUILD names the commit,
# and SOURCE_DATE_EPOCH, the commit's time, is every file's time. setuptools ignores it for
# the sdist, so normalize_sdist.py sets it there, and the owner and modes too. The umask is
# fixed because setuptools gives the wheel's files the builder's (RHEL's default for a user
# is 002). So neither file depends on who builds it or when. PYTHON=cmd overrides python3.
set -euo pipefail
umask 022
OUT="${1:?usage: build-dist.sh OUTDIR}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
SOURCE_DATE_EPOCH="$(git -C "$REPO" log -1 --format=%ct)"; export SOURCE_DATE_EPOCH
"$PY" -m pip install -q --require-hashes -r "$REPO/packaging/build-tools/requirements.txt"
git -C "$REPO" rev-parse HEAD > "$REPO/wd2l/BUILD"
"$PY" -m build --no-isolation --outdir "$OUT" "$REPO"
"$PY" "$REPO/packaging/normalize_sdist.py" "$OUT"/wd2l-*.tar.gz
