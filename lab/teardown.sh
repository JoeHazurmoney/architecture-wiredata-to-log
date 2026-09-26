#!/usr/bin/env bash
# Remove the lab namespaces (and the veth pairs inside them).
for ns in wd2l-enc1 wd2l-bh wd2l-enc2; do
  ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null
  ip netns del "$ns" 2>/dev/null
done
exit 0
