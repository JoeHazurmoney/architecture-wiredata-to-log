# Phase 5: RPMs for EL9 and EL10

Part of the [release packaging plan](README.md). Read its **Global constraints** first. Spec:
[spec.md](spec.md) "Phase 5". Its unit change was done in Task 3.4.

**Delivers:**

* one noarch source package and three binary packages: **`wd2l`**, **`wd2l-sender`** and
  **`wd2l-receiver`**;
* built in UBI 9 and UBI 10 containers from the wheel and sdist;
* installed and checked in fresh UBI containers three ways: fresh, over a manual install, and
  an upgrade;
* the deployment guides change to `dnf install` and `rpm -V`, and keep the manual install as an
  appendix.

**Layout the RPMs install:**

| What | Where | Package |
|---|---|---|
| Python package, `wd2l-*` commands | `%{python3_sitelib}/wd2l/`, `/usr/bin/` | wd2l |
| User `wd2l`, group `wd2l-audit` | `%pre`, plus `/usr/lib/sysusers.d/wd2l.conf` | wd2l |
| `/etc/wd2l` 0750 root:wd2l; `/var/lib/wd2l` 0750; `/var/log/wd2l` 2750 wd2l:wd2l-audit | `%files` + tmpfiles | wd2l |
| Seal script and timer | `/usr/libexec/wd2l/`, `/usr/lib/systemd/system/` | wd2l |
| Sender, egress-NIC units and script; `sender.env`, `egress.env` | units, `/usr/libexec/wd2l/`, `/etc/wd2l/` | wd2l-sender |
| Receiver, capture, capture-NIC, prune units and script; `receiver.env`, `capture.env`; spool and pcap dirs; sysctl | the same, plus `/usr/lib/sysctl.d/90-wd2l.conf` | wd2l-receiver |
| nft template, auditd rules, Quadlet examples, Splunk examples | `/usr/share/wd2l/` | sender / receiver |
| Empty drop-in dirs `/etc/systemd/system/wd2l-*.d/` (watched by auditd) | `%files` | each package for its units |

Run tests with `T` from the plan README.

---

### Task 5.1: `rpmify.py`: the deploy tree, rewritten for the RPM's paths

**Files:**
- Create: `packaging/rpm/rpmify.py`
- Modify: `deploy/log-server/wd2l.rules`, `deploy/receiver/wd2l.rules` (they watch the Quadlet
  files too), `tests/test_packaging.py`

**Interfaces:**
- Consumes: the `deploy/` tree.
- Produces:
  * `rpmify.rewrite_unit(text, libexec) -> str`;
  * `rpmify.rewrite_rules(text, sitelib, libexec, unitdir) -> str`;
  * `rpmify.drop_in_dirs(rules_text) -> List[str]`;
  * `rpmify.rpmify(src, out, sitelib, libexec, unitdir) -> List[str]`, the relative paths
    written. It raises `SystemExit` if `/opt/wd2l` is left anywhere.

- [ ] **Step 1: The rules watch the Quadlet units.** In `deploy/log-server/wd2l.rules`, after the
  last `wd2l-units` line, add:

```text
-w /etc/containers/systemd/wd2l-sender.container -p wa -k wd2l-units
```

In `deploy/receiver/wd2l.rules`:

```text
-w /etc/containers/systemd/wd2l-receiver.container -p wa -k wd2l-units
```

(`test_auditd_rules_are_well_formed` still passes: same shape.)

- [ ] **Step 2: Write the failing tests** (append to `tests/test_packaging.py`)

```python
import pytest

rpmify = load_script("packaging/rpm/rpmify.py")
SITE, LIBEXEC, UNITDIR = "/usr/lib/python3.9/site-packages", "/usr/libexec/wd2l", "/usr/lib/systemd/system"


def test_units_lose_pythonpath_and_point_at_libexec():
    t = rpmify.rewrite_unit(read("deploy/common/wd2l-audit-seal.service"), LIBEXEC)
    assert "ExecStart=/bin/sh /usr/libexec/wd2l/wd2l-audit-seal.sh" in t
    t = rpmify.rewrite_unit(read("deploy/log-server/wd2l-sender.service"), LIBEXEC)
    assert "PYTHONPATH" not in t and "/opt/wd2l" not in t
    assert "EnvironmentFile=/etc/wd2l/sender.env" in t
    t = rpmify.rewrite_unit(read("deploy/receiver/wd2l-capture-nic.service"), LIBEXEC)
    assert "ExecStart=/usr/libexec/wd2l/capture-nic.sh" in t


def test_rules_watch_the_rpm_paths_too():
    t = rpmify.rewrite_rules(read("deploy/receiver/wd2l.rules"), SITE, LIBEXEC, UNITDIR)
    for line in ("-w /usr/lib/python3.9/site-packages/wd2l/ -p wa -k wd2l-code",
                 "-w /usr/libexec/wd2l/ -p wa -k wd2l-code",
                 "-w /etc/systemd/system/wd2l-receiver.service -p wa -k wd2l-units",
                 "-w /usr/lib/systemd/system/wd2l-receiver.service -p wa -k wd2l-units",
                 "-w /etc/systemd/system/wd2l-receiver.service.d/ -p wa -k wd2l-units",
                 "-w /etc/containers/systemd/wd2l-receiver.container -p wa -k wd2l-units"):
        assert line in t.splitlines(), line
    assert "/opt/wd2l" not in t
    assert "/etc/systemd/system/wd2l-pcap-prune.timer.d" in rpmify.drop_in_dirs(t)


def test_rpmify_copies_the_whole_tree(tmp_path):
    written = rpmify.rpmify(os.path.join(REPO, "deploy"), str(tmp_path / "out"), SITE, LIBEXEC, UNITDIR)
    for rel in ("receiver/splunk/props.conf", "common/wd2l-audit-seal.sh",
                "log-server/sender.env", "receiver/wd2l-receiver.container"):
        assert rel in written, rel


def test_rpmify_refuses_anything_still_naming_opt_wd2l(tmp_path):
    src = tmp_path / "src" / "x"
    src.mkdir(parents=True)
    (src / "notes.txt").write_text("see /opt/wd2l/README\n")
    with pytest.raises(SystemExit) as e:
        rpmify.rpmify(str(tmp_path / "src"), str(tmp_path / "out"), SITE, LIBEXEC, UNITDIR)
    assert "x/notes.txt" in str(e.value)
```

- [ ] **Step 3: Run them to verify they fail**

Run: `T tests/test_packaging.py -k "rpmify or rules_watch or units_lose" -v`
Expected: FAIL (`FileNotFoundError` for `rpmify.py`).

- [ ] **Step 4: Write `packaging/rpm/rpmify.py`**

```python
#!/usr/bin/env python3
"""Rewrites the deploy/ tree for the RPM's paths (packaging/rpm/wd2l.spec runs it in %build):

* units: scripts move from /opt/wd2l/deploy/<side>/x.sh to LIBEXEC/x.sh, and the
  PYTHONPATH=/opt/wd2l line goes (the code is in Python's site-packages);
* auditd rules: /opt/wd2l/ becomes SITELIB/wd2l/ and LIBEXEC/; each watched unit is also
  watched where the RPM puts it (UNITDIR) and in its drop-in directory;
* everything else is copied unchanged. Nothing written may still name /opt/wd2l.

    rpmify.py --sitelib DIR --libexec DIR --unitdir DIR SRC_DEPLOY OUT
    rpmify.py --drop-in-dirs RULES...      print the drop-in dirs the rules watch"""

import argparse
import os
import re
import shutil
import sys
from typing import List, Optional, Sequence

SCRIPT = re.compile(r"/opt/wd2l/deploy/[A-Za-z0-9_-]+/([A-Za-z0-9_.-]+\.sh)")
PYTHONPATH = re.compile(r"^Environment=PYTHONPATH=/opt/wd2l[ \t]*\n", re.M)
UNIT_WATCH = re.compile(r"^-w /etc/systemd/system/(\S+) -p wa -k (\S+)$")
DROP_IN = re.compile(r"^-w (/etc/systemd/system/\S+\.d)/ ")
CODE_WATCH = "-w /opt/wd2l/ -p wa -k wd2l-code"


def rewrite_unit(text: str, libexec: str) -> str:
    return SCRIPT.sub(lambda m: "%s/%s" % (libexec, m.group(1)), PYTHONPATH.sub("", text))


def rewrite_rules(text: str, sitelib: str, libexec: str, unitdir: str) -> str:
    out = []
    for line in text.splitlines():
        if line == CODE_WATCH:
            out += ["-w %s/wd2l/ -p wa -k wd2l-code" % sitelib, "-w %s/ -p wa -k wd2l-code" % libexec]
            continue
        m = UNIT_WATCH.match(line)
        if m:
            unit, key = m.groups()
            out += [line, "-w %s/%s -p wa -k %s" % (unitdir, unit, key),
                    "-w /etc/systemd/system/%s.d/ -p wa -k %s" % (unit, key)]
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def drop_in_dirs(rules_text: str) -> List[str]:
    return [m.group(1) for m in map(DROP_IN.match, rules_text.splitlines()) if m]


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def rpmify(src: str, out: str, sitelib: str, libexec: str, unitdir: str) -> List[str]:
    written = []
    for dirpath, _dirs, files in os.walk(src):
        for name in sorted(files):
            s = os.path.join(dirpath, name)
            rel = os.path.relpath(s, src).replace(os.sep, "/")
            d = os.path.join(out, rel)
            os.makedirs(os.path.dirname(d), exist_ok=True)
            if name.endswith((".service", ".timer")):
                text: Optional[str] = rewrite_unit(_read(s), libexec)
            elif name == "wd2l.rules":
                text = rewrite_rules(_read(s), sitelib, libexec, unitdir)
            else:
                text = None
            if text is None:
                shutil.copy2(s, d)
            else:
                with open(d, "w", encoding="utf-8") as f:
                    f.write(text)
                shutil.copymode(s, d)
            written.append(rel)
    left = [r for r in written if "/opt/wd2l" in _read(os.path.join(out, r))]
    if left:
        raise SystemExit("rpmify: these still name /opt/wd2l: %s" % ", ".join(left))
    return sorted(written)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Rewrite deploy/ for the RPM's paths.")
    p.add_argument("--sitelib")
    p.add_argument("--libexec")
    p.add_argument("--unitdir")
    p.add_argument("--drop-in-dirs", nargs="+", metavar="RULES")
    p.add_argument("src", nargs="?")
    p.add_argument("out", nargs="?")
    a = p.parse_args(argv)
    if a.drop_in_dirs:
        for r in a.drop_in_dirs:
            print("\n".join(drop_in_dirs(_read(r))))
        return 0
    if not (a.sitelib and a.libexec and a.unitdir and a.src and a.out):
        p.error("needs --sitelib, --libexec, --unitdir, SRC and OUT")
    for rel in rpmify(a.src, a.out, a.sitelib, a.libexec, a.unitdir):
        print("rpmify: " + rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `T tests/test_packaging.py tests/test_deploy.py -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packaging/rpm/rpmify.py deploy/log-server/wd2l.rules deploy/receiver/wd2l.rules tests/test_packaging.py
git commit -m "rpmify: the deploy tree rewritten for the RPM's paths; rules watch Quadlet units"
```

---

### Task 5.2: The spec, sysusers and tmpfiles

**Files:**
- Create: `packaging/rpm/wd2l.spec`, `packaging/rpm/wd2l.sysusers`, `packaging/rpm/wd2l.tmpfiles`,
  `packaging/rpm/wd2l-receiver.tmpfiles`
- Modify: `packaging/check_dist.py` (`SDIST_NEEDS`), `tests/test_packaging.py`

**Interfaces:**
- Consumes:
  * `rpmify.py` (Task 5.1), and `versions.py --get pep440|rpm` (Task 4.7);
  * the sdist (Source0) and wheel (Source1), named `wd2l-%{pyversion}.tar.gz` and
    `wd2l-%{pyversion}-py3-none-any.whl`.
- Produces: the defines the spec needs, `pyversion` and `rpmversion`, plus `rel` (default 1).
  Packages: `wd2l`, `wd2l-sender` and `wd2l-receiver`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_packaging.py`)

```python
LEFT_OUT = {"switch/blackhole-port.ios.txt"}      # switch configuration: documentation, not a host file


def spec():
    return read("packaging/rpm/wd2l.spec")


def test_every_deploy_file_is_packaged():
    s = spec()
    for dirpath, _dirs, files in os.walk(os.path.join(REPO, "deploy")):
        for name in files:
            rel = os.path.relpath(os.path.join(dirpath, name), os.path.join(REPO, "deploy")).replace(os.sep, "/")
            if rel in LEFT_OUT or rel.startswith("receiver/splunk/"):
                continue
            assert rel in s, "deploy/%s isn't installed by the spec" % rel
    assert "receiver/splunk/." in s


def test_drop_in_dirs_the_rules_watch_are_owned():
    s = spec()
    for side in ("log-server", "receiver"):
        rules = rpmify.rewrite_rules(read("deploy/%s/wd2l.rules" % side), SITE, LIBEXEC, UNITDIR)
        for d in rpmify.drop_in_dirs(rules):
            assert "%%dir %%{_sysconfdir}/systemd/system/%s" % os.path.basename(d) in s, d


def test_nothing_restarts_on_upgrade_and_nothing_is_enabled():
    s = spec()
    assert "_with_restart" not in s and s.count("%systemd_postun ") == 3
    assert "systemctl enable" not in s


def test_config_files_keep_local_edits():
    s = spec()
    for f in ("sender.env", "egress.env", "receiver.env", "capture.env"):
        assert re.search(r"^%%config\(noreplace\) %%attr\(0640,root,wd2l\) %%\{_sysconfdir\}/wd2l/%s$"
                         % re.escape(f), s, re.M), f


def test_spec_versions_come_from_versions_py():
    s = spec()
    assert "Version:        %{rpmversion}" in s and "License:        MIT" in s
    assert "%{!?rpmversion:%{error:" in s and "%{!?pyversion:%{error:" in s


def test_sdist_carries_the_rpm_sources():
    assert {"packaging/rpm/wd2l.spec", "packaging/rpm/rpmify.py", "packaging/rpm/wd2l.sysusers",
            "packaging/rpm/wd2l.tmpfiles", "packaging/rpm/wd2l-receiver.tmpfiles"} <= set(check_dist.SDIST_NEEDS)


def test_tmpfiles_match_the_spec_modes():
    assert read("packaging/rpm/wd2l.tmpfiles").split("\n", 2)[2].split() == [
        "d", "/var/lib/wd2l", "0750", "wd2l", "wd2l", "-",
        "d", "/var/log/wd2l", "2750", "wd2l", "wd2l-audit", "-"]
    s = spec()
    assert "%dir %attr(2750,wd2l,wd2l-audit) %{_localstatedir}/log/wd2l" in s
    assert "%dir %attr(0750,root,wd2l) %{_sysconfdir}/wd2l" in s
```

- [ ] **Step 2: Run them to verify they fail**

Run: `T tests/test_packaging.py -k "spec or deploy_file or drop_in or restarts or config_files or tmpfiles or rpm_sources" -v`
Expected: FAIL (`FileNotFoundError` for `wd2l.spec`).

- [ ] **Step 3: Write the sources**

`packaging/rpm/wd2l.sysusers`:

```text
# wd2l's service user, and the group that may read the audit files. packaging/rpm/wd2l.spec
# creates both in %pre (also over a manual install); this file tells systemd-sysusers too.
u wd2l - "wd2l one-way log transfer" /var/lib/wd2l /sbin/nologin
g wd2l-audit -
```

`packaging/rpm/wd2l.tmpfiles`. The test reads it from its third line on, so keep exactly two
comment lines on top:

```text
# wd2l state (both hosts) and audit files (both hosts; setgid so files get wd2l-audit).
# Owned by the wd2l package too (packaging/rpm/wd2l.spec %files); this recreates them if removed.
d /var/lib/wd2l 0750 wd2l wd2l -
d /var/log/wd2l 2750 wd2l wd2l-audit -
```

`packaging/rpm/wd2l-receiver.tmpfiles`:

```text
# wd2l receiver: the SIEM spool and the capture archive (packaging/rpm/wd2l.spec).
d /var/lib/wd2l/spool 0750 wd2l wd2l -
d /var/lib/wd2l/pcap 0750 wd2l wd2l -
```

`packaging/rpm/wd2l.spec`:

```spec
# wd2l RPMs: one noarch source package, three binary packages
# (docs/decisions/0006-release-artifacts-and-signing.md). Built by .github/workflows/rpm.yml
# from the release's sdist (Source0, which holds deploy/ and packaging/) and its wheel (Source1),
# with the version names from packaging/release/versions.py:
#   rpmbuild -ba -D "pyversion 0.3.0" -D "rpmversion 0.3.0" [-D "rel 2"] packaging/rpm/wd2l.spec
%{!?pyversion:%{error:define pyversion: packaging/release/versions.py --get pep440}}
%{!?rpmversion:%{error:define rpmversion: packaging/release/versions.py --get rpm}}
%{!?rel:%global rel 1}

Name:           wd2l
Version:        %{rpmversion}
Release:        %{rel}%{?dist}
Summary:        One-way log transfer: frame logs into UDP, rebuild them from tapped packets
License:        MIT
URL:            https://github.com/JoeHazurmoney/architecture-wiredata-to-log
Source0:        wd2l-%{pyversion}.tar.gz
Source1:        wd2l-%{pyversion}-py3-none-any.whl
BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  systemd-rpm-macros
Requires:       python3 >= 3.9
Requires(pre):  shadow-utils
Requires(post): systemd
%{?systemd_requires}

%description
wd2l moves security logs one way across an enclave boundary. The sender frames each event as
sequenced, self-verifying UDP datagrams toward an address that never answers; a network tap
carries that cable to the other side; the receiver rebuilds every event from the captured
packets and reports any that were lost. This package holds the Python code and commands, the
wd2l user and wd2l-audit group, the directories, and the hourly audit seal timer. Install
wd2l-sender or wd2l-receiver for the host's role. Nothing is enabled at install.

%package sender
Summary:        wd2l sender for the Enclave 1 log server: units, egress NIC script, firewall
Requires:       %{name} = %{version}-%{release}
Requires:       nftables
Requires:       iproute

%description sender
The sender's systemd units (or a Quadlet example to run it as a container), the egress NIC
script, its settings in /etc/wd2l, the nftables template and the auditd rules for the log
server. See docs/deployment/log-server.md.

%package receiver
Summary:        wd2l receiver for Enclave 2: units, capture NIC script, archive, SIEM examples
Requires:       %{name} = %{version}-%{release}
Requires:       tcpdump
Requires:       nftables
Requires:       ethtool
Requires:       iproute
Requires:       findutils

%description receiver
The receiver's systemd units (or a Quadlet example to run it as a container), the capture NIC
script, the tcpdump archive and its cleanup timer, settings in /etc/wd2l, the kernel receive
buffer setting, the auditd rules and example SIEM configuration (Splunk). See
docs/deployment/receiver.md.

%prep
%autosetup -n wd2l-%{pyversion}

%build
%{python3} packaging/rpm/rpmify.py --sitelib %{python3_sitelib} --libexec %{_libexecdir}/wd2l \
    --unitdir %{_unitdir} deploy rpmified

%install
%{python3} -m pip install --no-deps --no-index --no-cache-dir --disable-pip-version-check \
    --no-compile --no-warn-script-location --root %{buildroot} --prefix %{_prefix} %{SOURCE1}
di=%{buildroot}%{python3_sitelib}/wd2l-%{pyversion}.dist-info
rm -f $di/RECORD $di/REQUESTED $di/direct_url.json
echo rpm > $di/INSTALLER
%py3_shebang_fix %{buildroot}%{_bindir}/wd2l-*

cd rpmified
install -Dm0644 -t %{buildroot}%{_unitdir} \
    common/wd2l-audit-seal.service common/wd2l-audit-seal.timer \
    log-server/wd2l-sender.service log-server/wd2l-egress-nic.service \
    receiver/wd2l-receiver.service receiver/wd2l-capture.service receiver/wd2l-capture-nic.service \
    receiver/wd2l-pcap-prune.service receiver/wd2l-pcap-prune.timer
install -Dm0755 -t %{buildroot}%{_libexecdir}/wd2l \
    common/wd2l-audit-seal.sh log-server/egress-nic.sh receiver/capture-nic.sh
install -Dm0640 log-server/sender.env %{buildroot}%{_sysconfdir}/wd2l/sender.env
install -Dm0640 log-server/egress.env.example %{buildroot}%{_sysconfdir}/wd2l/egress.env
install -Dm0640 receiver/receiver.env %{buildroot}%{_sysconfdir}/wd2l/receiver.env
install -Dm0640 receiver/capture.env %{buildroot}%{_sysconfdir}/wd2l/capture.env
install -Dm0644 log-server/nftables-wd2l.nft %{buildroot}%{_datadir}/wd2l/nftables-wd2l.nft
install -Dm0644 log-server/wd2l.rules %{buildroot}%{_datadir}/wd2l/audit/log-server.rules
install -Dm0644 receiver/wd2l.rules %{buildroot}%{_datadir}/wd2l/audit/receiver.rules
install -Dm0644 -t %{buildroot}%{_datadir}/wd2l/quadlet \
    log-server/wd2l-sender.container receiver/wd2l-receiver.container
install -d %{buildroot}%{_datadir}/wd2l/splunk
cp -a receiver/splunk/. %{buildroot}%{_datadir}/wd2l/splunk/
install -Dm0644 receiver/90-wd2l.conf %{buildroot}%{_sysctldir}/90-wd2l.conf
for d in $(%{python3} ../packaging/rpm/rpmify.py --drop-in-dirs log-server/wd2l.rules receiver/wd2l.rules | sort -u); do
    install -d %{buildroot}$d
done
cd ..
install -Dm0644 packaging/rpm/wd2l.sysusers %{buildroot}%{_sysusersdir}/wd2l.conf
install -Dm0644 packaging/rpm/wd2l.tmpfiles %{buildroot}%{_tmpfilesdir}/wd2l.conf
install -Dm0644 packaging/rpm/wd2l-receiver.tmpfiles %{buildroot}%{_tmpfilesdir}/wd2l-receiver.conf
install -d %{buildroot}%{_sharedstatedir}/wd2l/spool %{buildroot}%{_sharedstatedir}/wd2l/pcap \
    %{buildroot}%{_localstatedir}/log/wd2l

%pre
getent group wd2l >/dev/null || groupadd -r wd2l
getent group wd2l-audit >/dev/null || groupadd -r wd2l-audit
getent passwd wd2l >/dev/null || \
    useradd -r -g wd2l -d %{_sharedstatedir}/wd2l -s /sbin/nologin -c "wd2l one-way log transfer" wd2l
exit 0

%post
%tmpfiles_create wd2l.conf
%systemd_post wd2l-audit-seal.service wd2l-audit-seal.timer

%preun
%systemd_preun wd2l-audit-seal.service wd2l-audit-seal.timer

%postun
%systemd_postun wd2l-audit-seal.service wd2l-audit-seal.timer

%post sender
%systemd_post wd2l-sender.service wd2l-egress-nic.service

%preun sender
%systemd_preun wd2l-sender.service wd2l-egress-nic.service

%postun sender
# Not restarted on upgrade: stop and start it as docs/planned-downtime.md says.
%systemd_postun wd2l-sender.service wd2l-egress-nic.service

%post receiver
%tmpfiles_create wd2l-receiver.conf
%sysctl_apply 90-wd2l.conf
%systemd_post wd2l-receiver.service wd2l-capture.service wd2l-capture-nic.service wd2l-pcap-prune.service wd2l-pcap-prune.timer

%preun receiver
%systemd_preun wd2l-receiver.service wd2l-capture.service wd2l-capture-nic.service wd2l-pcap-prune.service wd2l-pcap-prune.timer

%postun receiver
# Not restarted on upgrade: stop and start it as docs/planned-downtime.md says.
%systemd_postun wd2l-receiver.service wd2l-capture.service wd2l-capture-nic.service wd2l-pcap-prune.service wd2l-pcap-prune.timer

%files
%license LICENSE
%doc README.md
%{python3_sitelib}/wd2l/
%{python3_sitelib}/wd2l-%{pyversion}.dist-info/
%{_bindir}/wd2l-sender
%{_bindir}/wd2l-receiver
%{_bindir}/wd2l-audit-report
%dir %{_libexecdir}/wd2l
%{_libexecdir}/wd2l/wd2l-audit-seal.sh
%{_unitdir}/wd2l-audit-seal.service
%{_unitdir}/wd2l-audit-seal.timer
%{_sysusersdir}/wd2l.conf
%{_tmpfilesdir}/wd2l.conf
%dir %attr(0750,root,wd2l) %{_sysconfdir}/wd2l
%dir %attr(0750,wd2l,wd2l) %{_sharedstatedir}/wd2l
%dir %attr(2750,wd2l,wd2l-audit) %{_localstatedir}/log/wd2l
%dir %{_datadir}/wd2l
%dir %{_datadir}/wd2l/audit
%dir %{_datadir}/wd2l/quadlet
%dir %{_sysconfdir}/systemd/system/wd2l-audit-seal.service.d
%dir %{_sysconfdir}/systemd/system/wd2l-audit-seal.timer.d

%files sender
%{_unitdir}/wd2l-sender.service
%{_unitdir}/wd2l-egress-nic.service
%{_libexecdir}/wd2l/egress-nic.sh
%config(noreplace) %attr(0640,root,wd2l) %{_sysconfdir}/wd2l/sender.env
%config(noreplace) %attr(0640,root,wd2l) %{_sysconfdir}/wd2l/egress.env
%{_datadir}/wd2l/nftables-wd2l.nft
%{_datadir}/wd2l/audit/log-server.rules
%{_datadir}/wd2l/quadlet/wd2l-sender.container
%dir %{_sysconfdir}/systemd/system/wd2l-sender.service.d
%dir %{_sysconfdir}/systemd/system/wd2l-egress-nic.service.d

%files receiver
%{_unitdir}/wd2l-receiver.service
%{_unitdir}/wd2l-capture.service
%{_unitdir}/wd2l-capture-nic.service
%{_unitdir}/wd2l-pcap-prune.service
%{_unitdir}/wd2l-pcap-prune.timer
%{_libexecdir}/wd2l/capture-nic.sh
%config(noreplace) %attr(0640,root,wd2l) %{_sysconfdir}/wd2l/receiver.env
%config(noreplace) %attr(0640,root,wd2l) %{_sysconfdir}/wd2l/capture.env
%{_tmpfilesdir}/wd2l-receiver.conf
%{_sysctldir}/90-wd2l.conf
%dir %attr(0750,wd2l,wd2l) %{_sharedstatedir}/wd2l/spool
%dir %attr(0750,wd2l,wd2l) %{_sharedstatedir}/wd2l/pcap
%{_datadir}/wd2l/audit/receiver.rules
%{_datadir}/wd2l/quadlet/wd2l-receiver.container
%{_datadir}/wd2l/splunk/
%dir %{_sysconfdir}/systemd/system/wd2l-receiver.service.d
%dir %{_sysconfdir}/systemd/system/wd2l-capture.service.d
%dir %{_sysconfdir}/systemd/system/wd2l-capture-nic.service.d
%dir %{_sysconfdir}/systemd/system/wd2l-pcap-prune.service.d
%dir %{_sysconfdir}/systemd/system/wd2l-pcap-prune.timer.d
```

`packaging/check_dist.py`: add the five RPM sources to `SDIST_NEEDS`:
`"packaging/rpm/wd2l.spec"`, `"packaging/rpm/rpmify.py"`, `"packaging/rpm/wd2l.sysusers"`,
`"packaging/rpm/wd2l.tmpfiles"` and `"packaging/rpm/wd2l-receiver.tmpfiles"`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `T tests/test_packaging.py -v`
Expected: PASS.

- [ ] **Step 5: Build once locally, in UBI 10 with Docker.** This needs `dist/` from `B`:

```bash
B
PY=$(MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src wd2l-test-312 python packaging/release/versions.py --get pep440)
RPMV=$(MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src wd2l-test-312 python packaging/release/versions.py --get rpm)
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/w -w /w registry.access.redhat.com/ubi10/ubi bash -c "
  dnf install -y -q rpm-build python3-devel python3-pip systemd-rpm-macros &&
  mkdir -p /tmp/rb/SOURCES && cp dist/wd2l-$PY.tar.gz dist/wd2l-$PY-py3-none-any.whl /tmp/rb/SOURCES/ &&
  rpmbuild -ba -D '_topdir /tmp/rb' -D 'pyversion $PY' -D 'rpmversion $RPMV' packaging/rpm/wd2l.spec 2>&1 | tail -15 &&
  rpm -qlp /tmp/rb/RPMS/noarch/wd2l-receiver-*.rpm | head -40"
```

Expected:

* `Wrote: …/wd2l-0.3.0-1.el10.noarch.rpm`, and the same for `wd2l-sender` and
  `wd2l-receiver`, plus the SRPM;
* the receiver's file list shows `/usr/lib/systemd/system/wd2l-receiver.service`,
  `/etc/wd2l/receiver.env` and `/usr/lib/sysctl.d/90-wd2l.conf`.

If `%py3_shebang_fix` is undefined on a UBI, replace that line with
`sed -i '1s|^#!.*python.*|#!%{python3} -s|' %{buildroot}%{_bindir}/wd2l-*`, and add an
As-built row.

- [ ] **Step 6: Commit**

```bash
rm -f wd2l/BUILD
git add packaging/rpm/wd2l.spec packaging/rpm/wd2l.sysusers packaging/rpm/wd2l.tmpfiles \
  packaging/rpm/wd2l-receiver.tmpfiles packaging/check_dist.py tests/test_packaging.py
git commit -m "RPM spec: wd2l, wd2l-sender, wd2l-receiver (noarch, EL9 and EL10)"
```

---

### Task 5.3: Build and install-test in CI (`rpm.yml`)

**Files:**
- Create: `packaging/rpm/build-rpms.sh`, `packaging/rpm/install-test.sh`,
  `.github/workflows/rpm.yml`
- Modify: `.github/workflows/tests.yml`

**Interfaces:**
- Consumes: the `dist` artifact (from `image.yml`'s `build` job), `packaging/ci/tool --ref
  ubi9|ubi10`, and `versions.py`.
- Produces:
  * `rpm.yml` (`workflow_call`), with the artifacts `rpms-el9` and `rpms-el10`. Each holds
    `rel1/` and `rel2/`; `rel1` is what a release ships.
  * `install-test.sh fresh|over-manual|upgrade REL1 [REL2]`.

- [ ] **Step 1: Write the two scripts**

`packaging/rpm/build-rpms.sh`:

```bash
#!/usr/bin/env bash
# Builds the wd2l RPMs inside a UBI container (.github/workflows/rpm.yml), from the repo root
# with dist/ holding the sdist and wheel:
#   build-rpms.sh PYVERSION RPMVERSION
# Writes rpms/rel1 (what a release ships) and rpms/rel2 (the same sources as Release 2, for the
# upgrade test). rpmlint (where the UBI has it) is advisory.
set -euo pipefail
PY="$1"; RPMV="$2"
dnf install -y -q rpm-build python3-devel python3-pip systemd-rpm-macros
dnf install -y -q rpmlint >/dev/null 2>&1 || true
for rel in 1 2; do
  top="$(mktemp -d)"; mkdir -p "$top/SOURCES"
  cp "dist/wd2l-$PY.tar.gz" "dist/wd2l-$PY-py3-none-any.whl" "$top/SOURCES/"
  rpmbuild -ba --define "_topdir $top" --define "pyversion $PY" --define "rpmversion $RPMV" \
    --define "rel $rel" packaging/rpm/wd2l.spec
  mkdir -p "rpms/rel$rel"
  cp "$top"/RPMS/noarch/*.rpm "$top"/SRPMS/*.rpm "rpms/rel$rel/"
done
if command -v rpmlint >/dev/null 2>&1; then rpmlint rpms/rel1/*.rpm || true; fi
ls -l rpms/rel1
```

`packaging/rpm/install-test.sh`:

```bash
#!/usr/bin/env bash
# The RPMs' install test, run as root in a fresh UBI container (.github/workflows/rpm.yml):
#   install-test.sh fresh|over-manual|upgrade REL1_DIR [REL2_DIR]
#   fresh        install the three packages on a clean system
#   over-manual  first make what the manual install made (the wd2l user and group, an edited
#                /etc/wd2l/sender.env), then install: nothing fails and the edit stays
#   upgrade      install Release 1, edit sender.env, upgrade to Release 2: the edit stays
set -euo pipefail
leg="$1"; rel1="$2"; rel2="${3:-}"
fail() { echo "FAIL ($leg): $*" >&2; exit 1; }
EDIT='WD2L_SENDER_ARGS="--listen 127.0.0.1:9999"'
case "$leg" in
  fresh)
    dnf install -y -q "$rel1"/*.noarch.rpm ;;
  over-manual)
    dnf install -y -q shadow-utils
    groupadd -r wd2l && useradd -r -g wd2l -s /sbin/nologin wd2l && groupadd -r wd2l-audit
    install -d /etc/wd2l && echo "$EDIT" > /etc/wd2l/sender.env
    dnf install -y -q "$rel1"/*.noarch.rpm
    grep -qxF "$EDIT" /etc/wd2l/sender.env || fail "the edited sender.env was replaced"
    [ -f /etc/wd2l/sender.env.rpmnew ] || fail "no sender.env.rpmnew beside the edited file" ;;
  upgrade)
    dnf install -y -q "$rel1"/*.noarch.rpm
    echo "$EDIT" > /etc/wd2l/sender.env
    dnf upgrade -y -q "$rel2"/*.noarch.rpm
    rpm -q --qf '%{RELEASE}\n' wd2l | grep -q '^2\.' || fail "not upgraded: $(rpm -q wd2l)"
    grep -qxF "$EDIT" /etc/wd2l/sender.env || fail "the upgrade replaced the edited sender.env" ;;
  *) fail "unknown leg" ;;
esac
for c in wd2l-sender wd2l-receiver wd2l-audit-report; do "$c" --help >/dev/null || fail "$c --help"; done
python3 -c 'import sys, wd2l; sys.exit(0 if wd2l.__file__.startswith("/usr/lib/python3") else 1)' \
  || fail "wd2l isn't in the system site-packages"
python3 -c 'import sys; from wd2l import hostinfo; sys.exit(0 if hostinfo.build_id() != "unknown" else 1)' \
  || fail "wd2l/BUILD is missing"
getent passwd wd2l >/dev/null || fail "no wd2l user"
getent group wd2l-audit >/dev/null || fail "no wd2l-audit group"
mode() { stat -c '%a %U %G' "$1"; }
[ "$(mode /var/log/wd2l)" = "2750 wd2l wd2l-audit" ] || fail "/var/log/wd2l is $(mode /var/log/wd2l)"
[ "$(mode /etc/wd2l)" = "750 root wd2l" ] || fail "/etc/wd2l is $(mode /etc/wd2l)"
for d in /var/lib/wd2l /var/lib/wd2l/spool /var/lib/wd2l/pcap; do
  [ "$(mode "$d")" = "750 wd2l wd2l" ] || fail "$d is $(mode "$d")"
done
d=$(mktemp -d)
if python3 -m wd2l.audit verify "$d" >/dev/null 2>&1; then fail "an empty audit directory verified"; fi
out=$(rpm -V wd2l wd2l-sender wd2l-receiver | grep -v ' c /etc/wd2l/' || true)
[ -z "$out" ] || fail "rpm -V: $out"
if grep -rl /opt/wd2l /usr/lib/systemd/system/wd2l-* /usr/share/wd2l/audit /usr/share/wd2l/quadlet; then
  fail "/opt/wd2l is still named"
fi
[ -f /usr/lib/sysctl.d/90-wd2l.conf ] || fail "no sysctl file"
systemd-analyze verify /usr/lib/systemd/system/wd2l-*.service /usr/lib/systemd/system/wd2l-*.timer \
  || fail "systemd-analyze verify"
echo "install test ($leg): ok"
```

- [ ] **Step 2: Write `.github/workflows/rpm.yml`**

```yaml
name: rpm
# RPMs for EL9 and EL10, built and install-tested in UBI containers (docs/decisions/0006).
# Called by tests.yml (every push) and release.yml; needs the run's `dist` artifact.
on:
  workflow_call:
permissions:
  contents: read
jobs:
  build:
    strategy:
      matrix:
        el: ["9", "10"]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          name: dist
          path: dist
      - name: Build in UBI ${{ matrix.el }}
        run: |
          PY=$(python3 packaging/release/versions.py --get pep440)
          RPMV=$(python3 packaging/release/versions.py --get rpm)
          podman run --rm -v "$PWD:/w" -w /w "$(packaging/ci/tool --ref ubi${{ matrix.el }})" \
            bash packaging/rpm/build-rpms.sh "$PY" "$RPMV"
      - uses: actions/upload-artifact@<sha> # <tag>
        with:
          name: rpms-el${{ matrix.el }}
          path: rpms/

  install-test:
    needs: [build]
    strategy:
      matrix:
        el: ["9", "10"]
        leg: [fresh, over-manual, upgrade]
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@<sha> # <tag>
      - uses: actions/download-artifact@<sha> # <tag>
        with:
          name: rpms-el${{ matrix.el }}
          path: rpms
      - name: Install test (${{ matrix.leg }}) in a fresh UBI ${{ matrix.el }}
        run: |
          podman run --rm -v "$PWD:/w:ro" -w /w "$(packaging/ci/tool --ref ubi${{ matrix.el }})" \
            bash packaging/rpm/install-test.sh ${{ matrix.leg }} rpms/rel1 rpms/rel2
```

- [ ] **Step 3: Call it from `tests.yml`**

```yaml
  rpm:
    if: ${{ inputs.image != false }}
    needs: [image]
    uses: ./.github/workflows/rpm.yml
```

(`dist` comes from the `image` job's `build`. When `release.yml` calls `tests.yml` with
`image: false`, it calls `rpm.yml` itself.)

- [ ] **Step 4: Commit, push (with OK) and watch**

```bash
chmod +x packaging/rpm/build-rpms.sh packaging/rpm/install-test.sh
git add --chmod=+x packaging/rpm/build-rpms.sh packaging/rpm/install-test.sh
git add .github/workflows/rpm.yml .github/workflows/tests.yml
git commit -m "CI: build the RPMs in UBI 9 and 10; install-test them fresh, over a manual install, and upgraded"
git push
gh run watch "$(gh run list --branch release-packaging --workflow tests --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: `rpm / build (9)`, `(10)` and all six `install-test` legs are green, and each ends in
`install test (<leg>): ok`. Read the rpmlint output in the EL9 build log:

* errors about permissions on `/var/log/wd2l` or `/etc/wd2l` are deliberate (the modes the
  design sets);
* anything else, fix or record in the As-built log.

If `systemd-analyze verify` fails only because a unit refers to something a container lacks
(for example `network-online.target` dependencies), filter that one message with
`grep -v`. Name it in a comment, and add an As-built row. If anything else fails, fix it.

---

### Task 5.4: The deployment guides install from the RPMs

**Files:**
- Modify: `docs/deployment/log-server.md`, `docs/deployment/receiver.md`, `docs/operations.md`,
  `docs/planned-downtime.md`

**Interfaces:**
- Consumes: what the RPMs install (the table at the top of this phase), and
  `docs/releasing.md`, which Task 6.4 writes. Link `../releasing.md#bringing-a-release-into-an-enclave`.
- Produces: guides that work from the RPMs, with the manual install as an appendix.

- [ ] **Step 1: `docs/deployment/log-server.md` §1 "Install wd2l".** It becomes:

````markdown
## 1. Install wd2l

From a release ([how to bring one into the enclave and verify it](../releasing.md#bringing-a-release-into-an-enclave)),
on RHEL 9 or RHEL 10 (use the `el9` or `el10` files):

```bash
sudo dnf install ./wd2l-<version>-1.el10.noarch.rpm ./wd2l-sender-<version>-1.el10.noarch.rpm
sudo vi /etc/wd2l/sender.env /etc/wd2l/egress.env      # the sender's options; the egress NIC
uuidgen | sudo tee /etc/wd2l/aggregator.token >/dev/null
sudo chown root:wd2l /etc/wd2l/aggregator.token && sudo chmod 640 /etc/wd2l/aggregator.token
sudo usermod -aG wd2l-audit <aggregator service account>         # it copies the audit files (section 5)
rpm -V wd2l wd2l-sender         # prints nothing while every file is as packaged
```

The packages create:

* the `wd2l` user, and the `wd2l-audit` group (who may read the audit files);
* `/etc/wd2l` (0750 root:wd2l), `/var/lib/wd2l`, and `/var/log/wd2l` (2750 wd2l:wd2l-audit,
  setgid so the files get the group).

They install the units in `/usr/lib/systemd/system`, the scripts in `/usr/libexec/wd2l`, and
templates (nftables, auditd rules, the Quadlet unit) in `/usr/share/wd2l`. They enable nothing.
`dnf upgrade` doesn't restart wd2l: restart it as [planned-downtime.md](../planned-downtime.md)
says.

To run the sender as a container instead, see [containers.md](containers.md). Without the RPMs,
see [Appendix: manual install](#appendix-manual-install).
````

- [ ] **Step 2: The later sections.** Each `sudo cp deploy/... /etc/systemd/system/` and
  `daemon-reload` pair becomes the RPM form, and the copy commands move to the appendix:
  * **§2 egress NIC:** `sudo systemctl enable --now wd2l-egress-nic`.
  * **§3 firewall:** `sudo cp /usr/share/wd2l/nftables-wd2l.nft /etc/nftables.d/`.
  * **§4 sender:** `sudo systemctl enable --now wd2l-sender`.
  * **Audit files:** `sudo systemctl enable --now wd2l-audit-seal.timer`, then
    `sudo cp /usr/share/wd2l/audit/log-server.rules /etc/audit/rules.d/wd2l.rules && sudo augenrules --load`.

  Add the appendix at the end of the file: `## Appendix: manual install`, with today's §1
  commands, the `cp` of `sender.env`, and the `cp` lines of each unit.
- [ ] **Step 3: `docs/deployment/receiver.md`.** The same treatment:
  * `dnf install ./wd2l-… ./wd2l-receiver-…`;
  * edit `/etc/wd2l/receiver.env` and `/etc/wd2l/capture.env`;
  * the tokens and the CA bundle, as today;
  * the sysctl is applied by the package (say so in the "Kernel receive buffer" step, and keep
    the manual command in the appendix);
  * `systemctl enable --now wd2l-capture-nic wd2l-capture wd2l-pcap-prune.timer wd2l-receiver wd2l-audit-seal.timer`;
  * the auditd rules from `/usr/share/wd2l/audit/receiver.rules`;
  * the Splunk files from `/usr/share/wd2l/splunk/`;
  * the same appendix.
- [ ] **Step 4: `docs/operations.md`**, "Replay from the capture archive". Change
  `sudo -u wd2l env PYTHONPATH=/opt/wd2l python3 -m wd2l.receiver \` to
  `sudo -u wd2l python3 -m wd2l.receiver \`. After the block, add: "On a manual install (code
  in `/opt/wd2l`), put `env PYTHONPATH=/opt/wd2l` after `sudo -u wd2l`. In a container, see
  [containers.md](deployment/containers.md#replay-from-the-archive)."
- [ ] **Step 5: `docs/planned-downtime.md`.** Add one sentence to its intro: "Package upgrades
  (`dnf upgrade`) don't restart wd2l. After an upgrade, stop and start each side here, in this
  order."
- [ ] **Step 6: Check the links, and commit**

```bash
grep -o '](\.\./releasing[^)]*\|](containers[^)]*\|](#appendix[^)]*' docs/deployment/*.md | sort -u
git add docs/deployment/log-server.md docs/deployment/receiver.md docs/operations.md docs/planned-downtime.md
git commit -m "Deployment guides install from the RPMs; the manual install is an appendix"
```
