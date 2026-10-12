rc6 is rc5 plus two small fixes (the last two items below). rc5 was tagged but never released:
its release run stalled during a GitHub Actions incident, after its image was pushed and signed.
Its image (`ghcr.io/joehazurmoney/wd2l:0.3.0rc5`) has no GitHub release; use rc6.

## What changed since rc4

* **An arm64 image.** The container image is built for linux/amd64 and linux/arm64, each
  natively on its own runner, and every check (reproducible build, hardening, FIPS, vulnerability
  gate, SBOM, the lab) runs for both. One image index carries both platforms. For enclaves there
  is one OCI tar per platform (`wd2l-0.3.0rc6-image-amd64-oci.tar`, `…-arm64-oci.tar`), and the
  SBOMs and vulnerability summaries come per platform too.
* **Podman can check the signature itself.** Each platform image is also signed in cosign's older
  format, which Podman's `sigstoreSigned` policy reads; `docs/deployment/containers.md` has the
  policy. The release workflow checks it on both platforms.
* **Container mode works under SELinux.** The Quadlet units no longer mount `/var/lib/wd2l` with
  `:z`, which relabelled the capture archive and stopped host tcpdump writing it. The `wd2l`
  package labels the directory for containers instead, and the receiver's module lets containers
  read the archive, never write it.
* **The ARP watcher** reacts only to its own NIC's events, and keeps retrying if it fails instead
  of giving up after five starts.
* **`capture_down_errors`** in the receiver's health summary counts the reads that found the
  capture NIC down.
* **`--max-stratum`** (default 3) sets the time alarm's stratum limit, for a host whose time comes
  from a public NTP pool rather than the site's GPS.
* The RPMs order their SELinux scriptlets after `policycoreutils`; the lab names its RHEL
  packages (`iproute-tc`).
* **The Quadlet units pass `--chrony-addr` once**, from the env file. rc5's units also added it
  to `Exec`, which put it on the command line twice (harmless, but confusing in `ps`).
* **The release workflow checks the older-format signature with cosign** on each platform image,
  as well as under Podman's policy.

### Upgrading from rc4

* **Native hosts:** `dnf upgrade`, then stop and start as `docs/planned-downtime.md` says. The
  packages relabel `/var/lib/wd2l` themselves.
* **Container hosts:** after `dnf upgrade`, copy the new `.container` files from
  `/usr/share/wd2l/quadlet/` over yours (no `:z` on `/var/lib/wd2l`), relabel once with
  `sudo restorecon -RF /var/lib/wd2l` (rc4's `:z` left the archive with a label a plain
  `restorecon` keeps), check that `ls -dZ /var/lib/wd2l/pcap` shows `netutils_tmp_t`, then
  `sudo systemctl daemon-reload` and restart.
  The new units take `--chrony-addr 127.0.0.1:323` from the env file only, so check that
  `grep -- --chrony-addr /etc/wd2l/*.env` finds it. An env file kept from rc3 without merging
  rc4's `.rpmnew` lacks it, and the time alarm would then say "unavailable".
* **Bringing the image in:** the offline tar's name now carries the platform. Take the one for
  your host (`uname -m`: `x86_64` → `amd64`, `aarch64` → `arm64`).
