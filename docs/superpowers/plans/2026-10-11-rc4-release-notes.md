## What changed since rc3

Fixes found deploying rc3 on AlmaLinux 10 (Raspberry Pi 5, SELinux enforcing):

* **The capture archive is written under SELinux.** The receiver package labels
  `/var/lib/wd2l/pcap` so tcpdump may write it. Before, every write was denied on an enforcing
  host and there was nothing to replay.
* **The capture NIC's egress drop loads on current nftables,** and the script no longer stops on
  NICs that don't report ring sizes (veth, many USB NICs).
* **`wd2l-egress-nic` loads the egress firewall itself.** Don't include it from
  `nftables.service` any more: its stop and reload flush every table, firewalld's included.
  `egress.env` has a new `PORT` setting (default 5514).
* **`wd2l-egress-arp` keeps the black hole's static ARP entry** after the egress NIC is taken
  down and up, which flushed it and silenced the sender.
* **The receiver keeps running while its capture NIC is down,** and reports it (rule 1).
* **The native units ask chronyd over UDP,** as the containers do, so time checks no longer log
  an SELinux denial each time.
* **The sender and receiver wait for the clock at start** (`chrony-wait`, at most about
  3 minutes), so a reboot no longer raises a time alarm. `chrony-wait` starts chronyd if it isn't
  running; during an NTP outage a restart waits that long too.

The egress firewall now loads before the egress NIC comes up, and if it can't load, the NIC
stays down. The receiver exits if its capture NIC disappears altogether (unplugged, driver
reloaded), so systemd starts it again on the new device.

### Upgrading from rc3

The packages restart nothing. After `dnf upgrade`:

* **Restart `wd2l-egress-nic` and `wd2l-capture-nic`**, in the order `docs/planned-downtime.md`
  gives (restarting `wd2l-egress-nic` restarts the sender). Until then the old firewall stays
  as it was and the ARP watcher doesn't run.
* **If you changed the UDP port** (5514) in `sender.env` and in your copy of
  `nftables-wd2l.nft`, set `PORT=` in `/etc/wd2l/egress.env`: the firewall is now built from it,
  and with the wrong port it drops the sender's traffic.
* If you loaded `nftables-wd2l.nft` through `nftables.service`, remove that include.
* `sender.env` and `receiver.env` keep your edits: add `--chrony-addr 127.0.0.1:323` from the
  `.rpmnew` beside each.
* Remove any local workaround for the archive label
  (`semanage fcontext -d '/var/lib/wd2l/pcap(/.*)?'`); the package's module takes over.
