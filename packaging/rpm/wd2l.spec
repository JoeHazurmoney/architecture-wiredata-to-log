# wd2l RPMs: one noarch source package, three binary packages
# (docs/decisions/0006-release-artifacts-and-signing.md). Built by .github/workflows/rpm.yml
# from the release's sdist (Source0, which holds deploy/ and packaging/) and its wheel (Source1),
# with the version names from packaging/release/versions.py:
#   rpmbuild -ba -D "wd2l_pyversion 0.3.0" -D "wd2l_rpmversion 0.3.0" [-D "rel 2"] \
#            [-D "wd2l_date Wed Oct 07 2026"] packaging/rpm/wd2l.spec
# wd2l_date (default: today) dates the %changelog entry, which rpmbuild takes the build
# timestamps from.
%{!?wd2l_pyversion:%{error:define wd2l_pyversion: packaging/release/versions.py --get pep440}}
%{!?wd2l_rpmversion:%{error:define wd2l_rpmversion: packaging/release/versions.py --get rpm}}
%{!?rel:%global rel 1}
%{!?wd2l_date:%global wd2l_date %(date -u "+%%a %%b %%d %%Y")}

Name:           wd2l
Version:        %{wd2l_rpmversion}
Release:        %{rel}%{?dist}
Summary:        One-way log transfer: frame logs into UDP, rebuild them from tapped packets
License:        MIT
URL:            https://github.com/JoeHazurmoney/architecture-wiredata-to-log
Source0:        wd2l-%{wd2l_pyversion}.tar.gz
Source1:        wd2l-%{wd2l_pyversion}-py3-none-any.whl
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
%autosetup -n wd2l-%{wd2l_pyversion}

%build
%{python3} packaging/rpm/rpmify.py --sitelib %{python3_sitelib} --libexec %{_libexecdir}/wd2l \
    --unitdir %{_unitdir} deploy rpmified

%install
%{python3} -m pip install --no-deps --no-index --no-cache-dir --disable-pip-version-check \
    --no-compile --no-warn-script-location --root %{buildroot} --prefix %{_prefix} %{SOURCE1}
di=%{buildroot}%{python3_sitelib}/wd2l-%{wd2l_pyversion}.dist-info
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
install -Dm0644 -t %{buildroot}%{_datadir}/wd2l/splunk receiver/splunk/*
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
%{python3_sitelib}/wd2l-%{wd2l_pyversion}.dist-info/
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

%changelog
* %{wd2l_date} Joe Azurmoni - %{version}-%{release}
- Built from the wd2l %{wd2l_pyversion} release sources; its changes are in the GitHub release notes.
