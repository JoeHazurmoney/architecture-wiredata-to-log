#!/usr/bin/env bash
# Keep the black hole's static ARP entry on the egress NIC. Taking the NIC down and up (or a
# driver reset) flushes even permanent neighbour entries, and the sender can't resolve the black
# hole by itself: nothing answers, and the egress firewall drops ARP. Nothing would cross until
# egress-nic.sh ran again. Run by wd2l-egress-arp.service: it puts the entry back at start and
# after every link or neighbour change, and logs each time it does.
#
# Settings come from /etc/wd2l/egress.env (WD2L_EGRESS_ENV overrides the path, for tests).
set -euo pipefail
ENV_FILE="${WD2L_EGRESS_ENV:-/etc/wd2l/egress.env}"
[ -f "$ENV_FILE" ] && . "$ENV_FILE"
IFACE="${IFACE:-ens224}"
BH_IP="${BH_IP:-10.255.255.2}"
BH_MAC="${BH_MAC:-02:00:00:00:00:02}"

ensure() {
  if [ -z "$(ip neigh show to "$BH_IP" dev "$IFACE" nud permanent 2>/dev/null)" ] &&
     ip neigh replace "$BH_IP" lladdr "$BH_MAC" nud permanent dev "$IFACE" 2>/dev/null; then
    echo "egress-arp: restored $BH_IP lladdr $BH_MAC on $IFACE"
  fi
}

ensure
# Any link or neighbour event: check again (cheap, and events are rare on this host).
ip -o monitor link neigh | while read -r _; do ensure; done
