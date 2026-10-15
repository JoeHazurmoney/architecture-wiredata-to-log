#!/usr/bin/env bash
# Asks a real chronyd for `tracking` over UDP, as --chrony-addr does, and checks the answer is
# chronyc's: the protocol check that lab/fake_chronyd.py, a stand-in, can't make. As root in
# the pinned AlmaLinux 10 image (tests.yml), from the repo root:
#   podman run --rm -v "$PWD:/src:ro" "$(packaging/ci/tool --ref alma10)" bash /src/packaging/ci/chrony-smoke.sh
set -euo pipefail
dnf install -y -q chrony python3 >/dev/null
# Only paths Ubuntu's AppArmor profile for /usr/sbin/chronyd allows: a rootless container runs
# unconfined, so on an Ubuntu host (the CI runner) that profile confines EL's chronyd (#97).
mkdir -p /etc/chrony
printf 'local stratum 8\ndriftfile /var/lib/chrony/drift\n' > /etc/chrony/chrony.conf
chronyd -x -d -f /etc/chrony/chrony.conf > /tmp/chronyd.log 2>&1 &
echo "chronyd's confinement: $(cat /proc/$!/attr/current 2>/dev/null || echo unknown)"
# On failure, show why: chronyd's log, and the UDP sockets bound (the command port 323 is 0143).
trap 'echo "chrony-smoke: failed. chronyd log:"; cat /tmp/chronyd.log; echo "UDP sockets:"; cat /proc/net/udp /proc/net/udp6' ERR
for _ in $(seq 20); do chronyc -c tracking >/dev/null 2>&1 && break; sleep 0.5; done
chronyc -c tracking >/dev/null
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
