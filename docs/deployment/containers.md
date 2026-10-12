# Containers: the sender and receiver under systemd (Quadlet)

`wd2l-sender` and `wd2l-receiver` can run from the release's container image instead of as
native services. Why this image, and why Quadlet:
[ADR-0004](../decisions/0004-container-base-image.md) and
[ADR-0005](../decisions/0005-quadlet.md).

| Runs in a container | Stays on the host |
|---|---|
| `wd2l-sender` (Enclave 1) | The egress and capture NIC scripts, nftables |
| `wd2l-receiver` (Enclave 2) | The tcpdump archive and its prune timer |
| | The audit seal timer, the auditd rules, chrony |

Use the container or the native unit on a host, never both. Both read the same options file,
`/etc/wd2l/sender.env` or `/etc/wd2l/receiver.env`.

## What the host needs

* RHEL 9.2+ or RHEL 10, with Podman 4.4 or later (Quadlet).
* The host pieces. Install the `wd2l-sender` or `wd2l-receiver` RPM: it brings the NIC units,
  the env files, the scripts, the seal timer and these Quadlet files. Leave the native wd2l
  service disabled. Without the RPMs, follow the host steps of the
  [log server](log-server.md) or [receiver](receiver.md) guide.
* On the receiver host, the kernel receive buffer
  ([receiver guide](receiver.md#kernel-receive-buffer)); the receiver RPM applies it.
* chronyd answering on 127.0.0.1:323, which is its default. As a normal user (not root),
  `chronyc -h 127.0.0.1 tracking` asks the way the container does. If it doesn't answer, check
  `cmdport` in `/etc/chrony.conf`.

## Bring the image in (offline)

Verify the release and load the image as [releasing.md](../releasing.md#bringing-a-release-into-an-enclave)
says. Then check that the loaded image is the one the release notes name:

```bash
sudo podman image inspect --format '{{.Digest}}' ghcr.io/joehazurmoney/wd2l:<version>
```

## Or pull it (online)

Verify the image's signature with cosign (see [releasing.md](../releasing.md#bringing-a-release-into-an-enclave)
for where cosign comes from), then pull that digest, so what you run is what you verified:

```bash
D=sha256:<digest from the release notes>
cosign verify --key cosign.pub --insecure-ignore-tlog ghcr.io/joehazurmoney/wd2l@$D
sudo podman pull ghcr.io/joehazurmoney/wd2l@$D
sudo podman tag ghcr.io/joehazurmoney/wd2l@$D ghcr.io/joehazurmoney/wd2l:<version>
```

Podman's own signature policy (`sigstoreSigned` in `/etc/containers/policy.json`) isn't used
here yet. The release's signatures are cosign 3 Sigstore bundles, stored as OCI referrers, and
it isn't confirmed yet that Podman reads them (see the list under
[User, SELinux and FIPS](#user-selinux-and-fips)).

## Install the unit

```bash
sudo systemctl disable --now wd2l-receiver.service 2>/dev/null   # the native unit, if it was on
sudo cp /usr/share/wd2l/quadlet/wd2l-receiver.container /etc/containers/systemd/
# strict change control: name the release's digest instead of the tag
sudo sed -i 's|^Image=.*|Image=ghcr.io/joehazurmoney/wd2l@sha256:<digest from the release notes>|' \
  /etc/containers/systemd/wd2l-receiver.container
# auditd: who changes the Quadlet unit. A file of its own, because the watch needs Podman's
# /etc/containers/systemd; on a host without it, auditd would stop loading rules there.
sudo cp /usr/share/wd2l/audit/receiver-quadlet.rules /etc/audit/rules.d/wd2l-quadlet.rules
sudo augenrules --load
sudo systemctl daemon-reload && sudo systemctl start wd2l-receiver
journalctl -u wd2l-receiver -f
```

On the log server, the same with `wd2l-sender` and
`/usr/share/wd2l/audit/log-server-quadlet.rules`. A Quadlet unit isn't "enabled": its
`[Install]` section takes effect at `daemon-reload`, so it starts at every boot from then on.

**A host that ran wd2l natively first.** The seal timer has made its audit files append-only,
and SELinux can't relabel an append-only file, so the first start with `:z` fails. Podman
relabels `/var/log/wd2l` only while the directory isn't labeled for containers yet: at the first
start, and again after a `restorecon` or a full relabel. Each time, in a planned window, before
the start:

```bash
sudo chattr -a /var/log/wd2l/audit-*.jsonl      # note it in the change record
sudo systemctl start wd2l-receiver               # Podman relabels the directory
sudo systemctl start wd2l-audit-seal.service     # the files are append-only again
```

The units run the container:

* on the host network;
* as the host's `wd2l` user (the host's `/etc/passwd` and `/etc/group` are mounted read-only,
  so audit records name `wd2l`);
* with no capabilities, except `NET_RAW` for the receiver;
* read-only, with no new privileges;
* with `--chrony-addr 127.0.0.1:323` added to the options.

They stop it within the native units' times: 30 s for the sender and 60 s for the receiver.

## User, SELinux and FIPS

* **SELinux.** `/var/lib/wd2l` is mounted without `:z`: Podman's relabel would also relabel the
  capture archive and stop host tcpdump writing it. The `wd2l` RPM labels the directory for
  containers instead (`container_file_t`, needs container-selinux), and the receiver's module
  lets containers read the archive, never write it. `/var/log/wd2l` keeps `:z` (the audit seal
  timer uses it); `/etc/wd2l` is mounted read-only. If Podman (container-selinux) was installed
  after the RPMs, relabel once before the first start: `sudo restorecon -RF /var/lib/wd2l`.
  Then `ls -dZ /var/lib/wd2l /var/lib/wd2l/pcap` shows `container_file_t` and `netutils_tmp_t`.
* **Still to confirm on RHEL 10** with SELinux enforcing (the [release plan's checks](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/blob/813b334/docs/superpowers/plans/2026-10-07-release-packaging/phase-0-checks.md), at the first
  release candidate):
  * the user name resolves;
  * the options from the env file reach wd2l;
  * the first start over sealed audit files, with the steps above;
  * whether Podman's `sigstoreSigned` policy accepts the release's signatures.

  If one doesn't, this section will say what to use instead.
* **FIPS.** The image always uses OpenSSL's FIPS provider, and MD5 is refused. It is **validated
  only on a RHEL host installed in FIPS mode**; on other hosts it is FIPS-configured. The image
  has no CA bundle, so `receiver.env` must keep `--hec-ca`.

## Signals and audit

```bash
sudo podman kill --signal USR1 wd2l-receiver      # debug logging on, then off
```

Inside the container the signal comes from pid 0, so the `debug_toggled` audit record can't name
the person. The host's auditd records who ran `podman`. To make that explicit, add to the
host's wd2l rules:

```text
-w /usr/bin/podman -p x -k wd2l-podman
```

## Replay from the archive

Stop the live receiver first (`sudo systemctl stop wd2l-receiver`), then:

```bash
sudo podman run --rm --network host --user wd2l \
  -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro \
  -v /var/lib/wd2l:/var/lib/wd2l -v /var/log/wd2l:/var/log/wd2l:z -v /etc/wd2l:/etc/wd2l:ro,z \
  ghcr.io/joehazurmoney/wd2l:<version> wd2l-receiver --pcap /var/lib/wd2l/pcap/cap-....pcap \
  <the replay options from operations.md> --chrony-addr 127.0.0.1:323
```

`--network host` lets the replay reach the SIEM. For a replay that writes files only, use
`--network none` and drop `--chrony-addr`.

## Upgrade and roll back

1. Verify and load the new release's image.
2. Change `Image=` in the host's `.container` file, then `sudo systemctl daemon-reload`.
3. Stop and start each side as [planned-downtime.md](../planned-downtime.md) says.

To roll back, name the previous image and do the same.
