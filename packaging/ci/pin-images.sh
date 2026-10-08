#!/usr/bin/env bash
# Pins every FROM NAME:TAG in the given Containerfiles to the digest the tag points at now:
#   FROM NAME:TAG[@sha256:OLD] [AS STAGE]   ->   FROM NAME:TAG@sha256:NEW [AS STAGE]
# The digest is the multi-arch index's when there is one. Looks digests up with skopeo if it
# is installed, else `docker buildx imagetools` (Docker Desktop). RESOLVE=cmd overrides (tests).
# A file is rewritten only when every FROM in it resolved.
set -euo pipefail
resolve() {
  if [ -n "${RESOLVE:-}" ]; then "$RESOLVE" "$1"
  elif command -v skopeo >/dev/null 2>&1; then
    echo "sha256:$(skopeo inspect --raw "docker://$1" | sha256sum | cut -d' ' -f1)"
  else docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$1"; fi
}
re='^([Ff][Rr][Oo][Mm][[:space:]]+)([^@[:space:]]+)(@sha256:[0-9a-f]{64})?(.*)$'
for f in "$@"; do
  tmp="$(mktemp)"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ $re ]]; then
      head="${BASH_REMATCH[1]}"; ref="${BASH_REMATCH[2]}"; rest="${BASH_REMATCH[4]}"
      d="$(resolve "$ref" 2>/dev/null || true)"
      if ! [[ "$d" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        echo "pin-images: no digest for $ref: $d" >&2; rm -f "$tmp"; exit 1
      fi
      printf '%s%s@%s%s\n' "$head" "$ref" "$d" "$rest" >> "$tmp"
      echo "pinned $ref@$d" >&2
    else
      printf '%s\n' "$line" >> "$tmp"
    fi
  done < "$f"
  cat "$tmp" > "$f"; rm -f "$tmp"
done
