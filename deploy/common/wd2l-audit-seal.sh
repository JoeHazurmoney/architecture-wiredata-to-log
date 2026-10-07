#!/bin/sh
# wd2l-audit-seal, hourly as root (wd2l-audit-seal.timer), on both hosts:
#  * makes every wd2l audit file append-only (chattr +a). The wd2l processes only ever append,
#    and can't set the flag themselves (no CAP_LINUX_IMMUTABLE);
#  * deletes files last written more than 366 days ago: each host keeps its own 1-year copy.
# See docs/audit-and-health-plan.md section 10.
set -eu
DIR="${WD2L_AUDIT_DIR:-/var/log/wd2l}"
DAYS="${WD2L_AUDIT_KEEP_DAYS:-366}"
CHATTR="${CHATTR:-chattr}"
find "$DIR" -maxdepth 1 -type f -name 'audit-*.jsonl' -mtime +"$DAYS" | while IFS= read -r f; do
  "$CHATTR" -a "$f"
  rm -f -- "$f"
  echo "wd2l-audit-seal: deleted $f (last written more than $DAYS days ago)"
done
find "$DIR" -maxdepth 1 -type f -name 'audit-*.jsonl' | while IFS= read -r f; do
  "$CHATTR" +a "$f"
done
