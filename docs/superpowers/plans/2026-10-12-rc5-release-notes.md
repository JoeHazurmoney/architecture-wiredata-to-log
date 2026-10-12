## What changed since rc4

* **An arm64 image.** The container image is built for linux/amd64 and linux/arm64, each
  natively on its own runner, and every check (reproducible build, hardening, FIPS, vulnerability
  gate, SBOM, the lab) runs for both. One image index carries both platforms. For enclaves there
  is one OCI tar per platform (`wd2l-0.3.0rc5-image-amd64-oci.tar`, `…-arm64-oci.tar`), and the
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

### Upgrading from rc4

* **Native hosts:** `dnf upgrade`, then stop and start as `docs/planned-downtime.md` says. The
  packages relabel `/var/lib/wd2l` themselves.
* **Container hosts:** after `dnf upgrade`, copy the new `.container` files from
  `/usr/share/wd2l/quadlet/` over yours (no `:z` on `/var/lib/wd2l`), relabel once with
  `sudo restorecon -RF /var/lib/wd2l` (rc4's `:z` left the archive with a label a plain
  `restorecon` keeps), check that `ls -dZ /var/lib/wd2l/pcap` shows `netutils_tmp_t`, then
  `sudo systemctl daemon-reload` and restart.
* **Bringing the image in:** the offline tar's name now carries the platform. Take the one for
  your host (`uname -m`: `x86_64` → `amd64`, `aarch64` → `arm64`).
