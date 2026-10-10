#!/usr/bin/env bash
# Asks a real chronyd for `tracking` over UDP, as --chrony-addr does, and checks the answer is
# chronyc's: the protocol check that lab/fake_chronyd.py, a stand-in, can't make. As root in
# the pinned Fedora image (tests.yml), from the repo root:
#   podman run --rm -v "$PWD:/src:ro" "$(packaging/ci/tool --ref fedora)" bash /src/packaging/ci/chrony-smoke.sh
set -euo pipefail
dnf install -y -q chrony python3 >/dev/null
printf 'local stratum 8\ndriftfile /tmp/chrony.drift\n' > /tmp/chrony.conf
chronyd -x -d -f /tmp/chrony.conf > /tmp/chronyd.log 2>&1 &
for _ in $(seq 20); do chronyc -c tracking >/dev/null 2>&1 && break; sleep 0.5; done
chronyd --version | head -1
python3 -I - "$(chronyc -c tracking)" <<'PY'
import sys
sys.path.insert(0, "/src")
from wd2l import hostinfo
udp = hostinfo.chrony_tracking(("127.0.0.1", hostinfo.CHRONY_PORT))
cli = hostinfo.parse_chronyc_tracking(sys.argv[1])
print("over UDP:", udp)
print("chronyc: ", cli)
sys.exit(0 if udp == cli else "chrony-smoke: the UDP answer differs from chronyc's")
PY
echo "chrony-smoke: ok"
