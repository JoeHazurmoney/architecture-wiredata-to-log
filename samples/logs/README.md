# Sample logs

Three real Linux audit logs for trying the proof of concept with real-world data:

| File | What it is | Lines |
|---|---|---|
| `messages` | General system log (rsyslog, RHEL rule `*.info;mail.none;authpriv.none;cron.none`) | 722 |
| `secure` | Authentication log (rsyslog, RHEL rule `authpriv.*`): SSH logins, sudo, PAM | 1,325 |
| `audit.log` | Linux audit daemon (auditd 3.1.2, enriched format) | 15,577 |

`SHA256SUMS` holds their hashes. Check them with `sha256sum -c SHA256SUMS` from this folder.

## Where they came from

They were generated on 2026-10-02 in a disposable cloud VM (Ubuntu 24.04) by
[`../generate-sample-logs.sh`](../generate-sample-logs.sh). Real daemons wrote them (rsyslog,
sshd, sudo, PAM, auditd), in response to real activity:

* SSH logins by key and by password, wrong passwords, and logins as nonexistent users (`admin`,
  `oracle`, `test`, `ubuntu`)
* `sudo`, both allowed and refused
* a temporary user created, modified and deleted; password changes
* reads and writes of watched files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`,
  `/etc/ssh/sshd_config`) and every command run by the test users (audit rules)
* application messages at several facilities and priorities

They contain no real people or networks:

* The hostname is `sample-host`.
* The only accounts are the throwaway `labuser`, `labadmin` and `tempuser`.
* The only IP address is `127.0.0.1` (sshd also logs that it listens on `0.0.0.0`).

Run the generator again (as root, **on a throwaway VM only**: it installs packages and creates
users) to make a fresh set. The new files will have different contents and hashes.

## Use them

```bash
sudo lab/run-lab.sh --files samples/logs/messages samples/logs/secure samples/logs/audit.log
```

See [docs/running-the-lab.md](../../docs/running-the-lab.md#8-run-real-log-files-through-and-verify-byte-for-byte).
