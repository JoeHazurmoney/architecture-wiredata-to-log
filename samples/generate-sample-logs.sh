#!/usr/bin/env bash
# Generate the three sample logs in samples/logs/ from REAL daemons and REAL activity:
#
#   messages   rsyslog, RHEL rules: *.info;mail.none;authpriv.none;cron.none
#   secure     rsyslog, RHEL rules: authpriv.*
#   audit.log  auditd, with a few watch rules
#
# Activity: SSH key and password logins, failed passwords, invalid usernames, sudo allowed and
# denied, user add/delete, password changes, reads and writes of watched files, and application
# messages at several facilities and priorities.
#
# !! Run this only on a DISPOSABLE VM or container. It installs packages, starts daemons,
# !! creates and deletes local users, and edits /etc/hosts (restored afterwards).
#
# Usage: sudo samples/generate-sample-logs.sh [ROUNDS] [OUTDIR]   (defaults: 40, samples/logs)
# Built for Debian/Ubuntu package names (it was run in an Ubuntu 24.04 cloud container); the
# log formats are configured to match RHEL.
set -euo pipefail

ROUNDS="${1:-40}"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${2:-$HERE/logs}"
WORK="$(mktemp -d /var/tmp/wd2l-samples.XXXXXX)"
SSH_PORT=2222
LOGHOST=sample-host
USER1=labuser
USER2=labadmin

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }

echo "== installing rsyslog, openssh, sudo, auditd, sshpass"
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -q rsyslog openssh-server openssh-client sudo auditd sshpass passwd >/dev/null

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  auditctl -D >/dev/null 2>&1 || true
  for u in "$USER1" "$USER2" tempuser; do userdel -r "$u" >/dev/null 2>&1 || true; done
  rm -f /etc/sudoers.d/wd2l-sample
  [ -f "$WORK/hosts.orig" ] && cp "$WORK/hosts.orig" /etc/hosts
  return 0
}
trap cleanup EXIT

echo "== rsyslog with RHEL-style rules -> $WORK"
cat >"$WORK/rsyslog.conf" <<EOF
module(load="imuxsock")
global(localHostname="$LOGHOST" workDirectory="$WORK")
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
\$FileCreateMode 0644
*.info;mail.none;authpriv.none;cron.none  $WORK/messages
authpriv.*                                $WORK/secure
EOF
pkill -x rsyslogd 2>/dev/null || true
rsyslogd -f "$WORK/rsyslog.conf" -i "$WORK/rsyslogd.pid"
sleep 1

echo "== auditd -> $WORK/audit.log"
cat >"$WORK/auditd.conf" <<EOF
log_file = $WORK/audit.log
log_format = ENRICHED
log_group = root
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 100
max_log_file_action = IGNORE
num_logs = 1
name_format = NONE
space_left = 75
admin_space_left = 50
space_left_action = IGNORE
admin_space_left_action = IGNORE
disk_full_action = IGNORE
disk_error_action = IGNORE
EOF
pkill -x auditd 2>/dev/null || true
sleep 1
auditd -c "$WORK" -n &
PIDS+=($!)
sleep 2
auditctl -s | grep -q '^pid [1-9]' || { echo "auditd did not start (kernel audit unavailable?)" >&2; exit 1; }
auditctl -D >/dev/null
auditctl -w /etc/passwd -p wa -k identity
auditctl -w /etc/shadow -p rwa -k identity
auditctl -w /etc/sudoers -p r -k sudoers
auditctl -w /etc/hosts -p wa -k network-config
auditctl -w /etc/ssh/sshd_config -p r -k sshd-config
auditctl -a always,exit -F arch=b64 -S execve -F auid\>=1000 -F auid!=-1 -k user-commands

echo "== users, sudo rules and sshd on port $SSH_PORT"
for u in "$USER1" "$USER2"; do
  id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"
done
echo "$USER1:Lab-pass-1" | chpasswd
echo "$USER2:Lab-pass-2" | chpasswd
echo "$USER2 ALL=(root) NOPASSWD: /usr/bin/id, /usr/bin/systemctl status *, /usr/bin/cat /etc/hosts" \
  >/etc/sudoers.d/wd2l-sample
chmod 440 /etc/sudoers.d/wd2l-sample
rm -f "$WORK/key" "$WORK/key.pub"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/key"
install -d -m 700 -o "$USER1" -g "$USER1" "/home/$USER1/.ssh"
install -m 600 -o "$USER1" -g "$USER1" "$WORK/key.pub" "/home/$USER1/.ssh/authorized_keys"
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
/usr/sbin/sshd -D -p "$SSH_PORT" -o UsePAM=yes -o PasswordAuthentication=yes \
  -o KbdInteractiveAuthentication=no -o LogLevel=INFO -o MaxAuthTries=3 &
PIDS+=($!)
sleep 1
cp /etc/hosts "$WORK/hosts.orig"

SSH_OPTS=(-p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
          -o LogLevel=ERROR -o ConnectTimeout=5)

echo "== generating activity, $ROUNDS rounds"
for r in $(seq 1 "$ROUNDS"); do
  # SSH: key login, password login, wrong passwords, invalid users.
  ssh "${SSH_OPTS[@]}" -i "$WORK/key" -o PasswordAuthentication=no "$USER1@127.0.0.1" \
    'id >/dev/null; ls /tmp >/dev/null; cat /etc/hostname >/dev/null' || true
  sshpass -p Lab-pass-2 ssh "${SSH_OPTS[@]}" -o PubkeyAuthentication=no "$USER2@127.0.0.1" \
    'sudo -n /usr/bin/id >/dev/null; sudo -n /usr/bin/cat /etc/hosts >/dev/null; sudo -n /usr/bin/cat /etc/shadow >/dev/null 2>&1' || true
  sshpass -p wrong-password ssh "${SSH_OPTS[@]}" -o PubkeyAuthentication=no "$USER1@127.0.0.1" true 2>/dev/null || true
  for bad in admin oracle test ubuntu; do
    if [ $((r % 4)) = $(( ${#bad} % 4 )) ]; then
      sshpass -p 123456 ssh "${SSH_OPTS[@]}" -o PubkeyAuthentication=no "$bad@127.0.0.1" true 2>/dev/null || true
    fi
  done

  # sudo from a user who isn't allowed, and an allowed one, run locally.
  su -s /bin/sh -c 'sudo -n /usr/bin/id >/dev/null 2>&1' "$USER1" || true
  su -s /bin/sh -c 'sudo -n /usr/bin/id >/dev/null' "$USER2" || true

  # Account changes every few rounds.
  if [ $((r % 10)) = 1 ]; then
    useradd -m -s /bin/bash tempuser
    echo "tempuser:Temp-pass-$r" | chpasswd
    usermod -aG adm tempuser
    userdel -r tempuser >/dev/null 2>&1
  fi
  if [ $((r % 15)) = 2 ]; then
    echo "$USER1:Lab-pass-1" | chpasswd
  fi

  # Watched files: a hosts-file change (restored) and reads of sshd_config / sudoers.
  if [ $((r % 8)) = 3 ]; then
    echo "192.0.2.10 app-$r.example.internal" >>/etc/hosts
    cp "$WORK/hosts.orig" /etc/hosts
  fi
  cat /etc/ssh/sshd_config >/dev/null
  [ $((r % 5)) = 0 ] && cat /etc/sudoers >/dev/null

  # Application and system messages at several facilities and priorities.
  logger -p daemon.info -t backupd "job nightly-$r finished: 1,284 files, 3.2 GiB, 0 errors"
  logger -p daemon.warning -t backupd "job nightly-$r: 2 files changed during read, retrying"
  logger -p local0.notice -t webapp "GET /api/v1/orders/$r 200 41ms user=$USER1"
  logger -p local0.err -t webapp "POST /api/v1/payments 502 upstream timeout after 30000ms req=$r"
  logger -p user.info -t cron-wrapper "logrotate completed (rc=0)"
  logger -p mail.info -t postfix "this goes nowhere: mail.none (round $r)"
  logger -p authpriv.notice -t pam_check "account check for $USER2 ok (round $r)"
  [ $((r % 7)) = 0 ] && logger -p daemon.crit -t ntpd "time step of 0.412 s exceeds panic threshold"
  sleep 0.2
done

echo "== stopping daemons and collecting"
sleep 2
cleanup
PIDS=()
sleep 1
pkill -F "$WORK/rsyslogd.pid" 2>/dev/null || pkill -x rsyslogd || true
pkill -x auditd 2>/dev/null || true
sleep 2

mkdir -p "$OUTDIR"
for f in messages secure audit.log; do
  cp "$WORK/$f" "$OUTDIR/$f"
  chmod 644 "$OUTDIR/$f"
done
(cd "$OUTDIR" && sha256sum messages secure audit.log >SHA256SUMS)
wc -l "$OUTDIR"/messages "$OUTDIR"/secure "$OUTDIR"/audit.log
cat "$OUTDIR/SHA256SUMS"
rm -rf "$WORK"
