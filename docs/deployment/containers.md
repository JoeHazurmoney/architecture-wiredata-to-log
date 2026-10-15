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

Verify the release and load your platform's image as [releasing.md](../releasing.md#bringing-a-release-into-an-enclave)
says. Then check that the loaded image is your platform's image in the release manifest, which
`verify-release` has checked (the release notes list the same digests, but aren't among the
files):

```bash
sudo podman image inspect --format '{{.Digest}}' ghcr.io/joehazurmoney/wd2l:<version>
jq -r '.image.platforms.<arch>' wd2l-<version>-release-manifest.json     # the same digest
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

## Signature policy (registry pulls)

A host that pulls from a registry can have Podman check the signature itself, on every pull.
Put `cosign.pub` (from a trusted channel) at `/etc/pki/wd2l/cosign.pub`. Then
`/etc/containers/registries.d/wd2l.yaml`:

```yaml
docker:
  ghcr.io/joehazurmoney:
    use-sigstore-attachments: true
```

and in `/etc/containers/policy.json`, under `transports.docker`:

```json
"ghcr.io/joehazurmoney/wd2l": [{"type": "sigstoreSigned", "keyPath": "/etc/pki/wd2l/cosign.pub",
                                "signedIdentity": {"type": "matchRepository"}}]
```

Podman reads only cosign's older signature format, so every release also signs each platform
image that way. Pulling by the index digest checks your platform's image. The release workflow
checks this policy on both platforms (`import-check`); it was also checked on AlmaLinux 10
(Podman 5.8).

## Install the unit

```bash
sudo systemctl disable --now wd2l-receiver.service 2>/dev/null   # the native unit, if it was on
sudo cp /usr/share/wd2l/quadlet/wd2l-receiver.container /etc/containers/systemd/
# strict change control: name your platform's digest (above) instead of the tag
sudo sed -i 's|^Image=.*|Image=ghcr.io/joehazurmoney/wd2l@<that digest, sha256:…>|' \
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
sudo sh -c 'chattr -a /var/log/wd2l/audit-*.jsonl'   # root expands the glob; note it in the change record
sudo systemctl start wd2l-receiver                    # Podman relabels the directory
sudo systemctl start wd2l-audit-seal.service          # the files are append-only again
```

If the first start failed because a file was still append-only (the journal shows
`PermissionError` on an `audit-*.jsonl`), unlock as above and start again: Podman relabels the
files then.

The units run the container:

* on the host network;
* as the host's `wd2l` user (the host's `/etc/passwd` and `/etc/group` are mounted read-only,
  so audit records name `wd2l`);
* with no capabilities, except `NET_RAW` for the receiver;
* read-only, with no new privileges;
* with the env file's options, as the native unit; its `--chrony-addr 127.0.0.1:323` matters here,
  because the image has no `chronyc`.

They stop it within the native units' times: 30 s for the sender and 60 s for the receiver.

## User, SELinux and FIPS

* **SELinux.** `/var/lib/wd2l` is mounted without `:z`: Podman's relabel would also relabel the
  capture archive and stop host tcpdump writing it. The `wd2l` RPM labels the directory for
  containers instead (`container_file_t`), and the receiver's module lets containers read the
  archive, never write it. `/var/log/wd2l` keeps `:z` (the audit seal timer uses it);
  `/etc/wd2l` is mounted read-only. Before the first start, `ls -dZ /var/lib/wd2l /var/lib/wd2l/pcap`
  shows `container_file_t` and `netutils_tmp_t`; if not (a host that ran an older Quadlet with
  `:z`, or files restored from a backup), relabel once: `sudo restorecon -RF /var/lib/wd2l`.
* **Confirmed on AlmaLinux 10** (aarch64, SELinux enforcing, Podman 5.8, rc5), the checks the
  [release plan](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/blob/813b334/docs/superpowers/plans/2026-10-07-release-packaging/phase-0-checks.md)
  left open:
  * the user name resolves (`podman top wd2l-receiver user huser`: `wd2l wd2l`);
  * the options from the env file reach wd2l (`podman top wd2l-receiver args`);
  * host tcpdump keeps writing the archive (`netutils_tmp_t`), and the receiver reads it
    (`archive_age_s`) and replays it;
  * the first start over sealed audit files, with the steps above, and later restarts;
  * Podman's signature policy (see [Signature policy](#signature-policy-registry-pulls)).
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
