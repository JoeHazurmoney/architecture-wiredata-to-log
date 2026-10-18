#!/usr/bin/env bash
# Builds the wd2l image the same way everywhere (CI, release, by hand):
#   packaging/container/build.sh DIST TAG [CONTAINERFILE]
# DIST holds the wheel (python -m build). CONTAINERFILE is packaging/container/Containerfile (the
# default), or Containerfile.ubi9 for the comparison image on UBI 9 (#192).
# It sets the version, the commit and the base image as labels, and SOURCE_DATE_EPOCH (the
# commit time) as the image time, so the same commit builds the same image. It removes the
# base's Red Hat and Hummingbird product labels: this image is wd2l, not hi/python (or UBI 9),
# and the base is named in org.opencontainers.image.base.*. Environment: PODMAN=cmd overrides
# podman; REVISION and EPOCH override the commit and its time (tests, and checkouts without git).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
DIST="${1:?usage: build.sh DIST TAG [CONTAINERFILE]}"
TAG="${2:?usage: build.sh DIST TAG [CONTAINERFILE]}"
FILE="${3:-$HERE/Containerfile}"
VERSION="$(python3 "$REPO/packaging/release/versions.py" --get pep440)"
REVISION="${REVISION:-$(git -C "$REPO" rev-parse HEAD)}"
EPOCH="${EPOCH:-$(git -C "$REPO" log -1 --format=%ct)}"
BASE="$(python3 "$HERE/check_containerfile.py" "$FILE" --base)"
UNSET=(cpe com.redhat.component distribution-scope build-date release vcs-ref vcs-type
       io.hummingbird-project.containerfile io.hummingbird-project.major-minor-version
       io.hummingbird-project.major-version io.hummingbird-project.repository
       io.hummingbird-project.stream io.hummingbird-project.application-category
       io.hummingbird-project.variant io.hummingbird-project.variant.base
       io.hummingbird-project.variant.description io.hummingbird-project.variant.fips)
# UBI 9's own product labels, which would name the comparison image "Red Hat Universal Base Image 9".
if [ "$(basename "$FILE")" = Containerfile.ubi9 ]; then
  UNSET+=(io.k8s.display-name io.openshift.tags io.openshift.expose-services)
fi
args=(build --timestamp "$EPOCH" -f "$FILE" -t "$TAG"
      --build-arg "VERSION=$VERSION" --build-arg "REVISION=$REVISION"
      --build-arg "BASE_NAME=${BASE%@*}" --build-arg "BASE_DIGEST=${BASE#*@}")
for l in "${UNSET[@]}"; do args+=(--unsetlabel "$l"); done
exec ${PODMAN:-podman} "${args[@]}" "$DIST"
