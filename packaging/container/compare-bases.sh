#!/usr/bin/env bash
# Measures the candidate base images for ADR-0004 (docs/decisions/0004-container-base-image.md),
# each as we would ship on it: Python 3 and its standard library. Prints a Markdown table.
# Needs rootless podman, jq and packaging/ci/tool (syft, grype). Run from the repo root:
#   packaging/container/compare-bases.sh > compare.md
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TOOL="$HERE/../ci/tool"
WORK="$(mktemp -d -p "$PWD" .compare.XXXX)"
REL="${WORK#"$PWD"/}"
trap 'rm -rf "$WORK"' EXIT

# "label|image" or "label|build:<file in candidates/>"
CANDIDATES=(
  "A. Hardened Images, FIPS (chosen)|registry.access.redhat.com/hi/python:3.12-fips"
  "A. Hardened Images, non-FIPS (reference)|registry.access.redhat.com/hi/python:3.12"
  "B. UBI 10 micro + python3|build:ubi10-micro-python.Containerfile"
  "C. UBI 10 python-312-minimal|registry.access.redhat.com/ubi10/python-312-minimal:latest"
  "D. UBI 9 micro + python3 (3.9)|build:ubi9-micro-python.Containerfile"
  "E. Google distroless python3|gcr.io/distroless/python3-debian12:latest"
  "E. Chainguard python|cgr.dev/chainguard/python:latest"
  "E. python:3.12-slim (Debian)|docker.io/library/python:3.12-slim"
)

echo "Measured $(date -u +%Y-%m-%d) on $(uname -m) by \`packaging/container/compare-bases.sh\`."
echo
echo "| Candidate | Image | Size | OS packages | Shell | Package manager | Default user | FIPS crypto policy | Known CVEs | Fixable High/Critical |"
echo "|---|---|---|---|---|---|---|---|---|---|"
i=0
for c in "${CANDIDATES[@]}"; do
  label="${c%%|*}"; src="${c#*|}"; i=$((i + 1)); img="localhost/compare-$i"
  if [[ "$src" == build:* ]]; then
    podman build -q -t "$img" -f "$HERE/candidates/${src#build:}" "$HERE/candidates" >/dev/null
    shown="built from \`candidates/${src#build:}\`"
  else
    podman pull -q "$src" >/dev/null
    podman tag "$src" "$img"
    shown="\`$src@$(podman image inspect --format '{{.Digest}}' "$src" | cut -c1-19)…\`"
  fi
  podman save -q --format oci-archive -o "$WORK/$i.tar" "$img"
  size=$(podman image inspect --format '{{.Size}}' "$img" | awk '{printf "%.0f MB", $1 / 1000000}')
  user=$(podman image inspect --format '{{.Config.User}}' "$img"); user="${user:-root}"
  "$TOOL" syft "oci-archive:/work/$REL/$i.tar" -q -o json > "$WORK/$i.syft.json"
  pkgs=$(jq '[.artifacts[] | select(.type == "rpm" or .type == "deb" or .type == "apk")] | length' "$WORK/$i.syft.json")
  "$TOOL" grype "oci-archive:/work/$REL/$i.tar" -q -o json > "$WORK/$i.grype.json"
  cves=$(jq '[.matches[].vulnerability.id] | unique | length' "$WORK/$i.grype.json")
  fixable=$(jq '[.matches[] | select((.vulnerability.severity == "High" or .vulnerability.severity == "Critical")
                 and .vulnerability.fix.state == "fixed") | .vulnerability.id] | unique | length' "$WORK/$i.grype.json")
  podman create -q --name "compare-$i" "$img" >/dev/null
  podman export "compare-$i" > "$WORK/$i.fs.tar"
  podman rm -f "compare-$i" >/dev/null
  tar -tf "$WORK/$i.fs.tar" | sed 's#^\./##' > "$WORK/$i.files"
  if grep -qxE '(usr/)?bin/(sh|bash|ash|dash|busybox)' "$WORK/$i.files"; then shell=yes; else shell=no; fi
  pm=$(grep -oxE '(usr/)?bin/(dnf|dnf5|microdnf|yum|rpm|apt|apt-get|dpkg|apk)' "$WORK/$i.files" \
       | sed 's#.*/##' | sort -u | paste -sd, - || true)
  fips=$(tar -xOf "$WORK/$i.fs.tar" etc/crypto-policies/config 2>/dev/null | tr -d '[:space:]' || true)
  echo "| $label | $shown | $size | $pkgs | $shell | ${pm:-none} | $user | ${fips:-n/a} | $cves | $fixable |"
done
