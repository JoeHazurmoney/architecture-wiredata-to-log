import io
import os
import re
import tarfile
import zipfile

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
check_dist = load_script("packaging/check_dist.py")


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


def test_version_has_one_source():
    py = read("pyproject.toml")
    project = py.split("[project]", 1)[1].split("\n[", 1)[0]
    assert 'dynamic = ["version"]' in project
    assert not re.search(r"^version\s*=", project, re.M)
    assert 'version = {attr = "wd2l.__version__"}' in py
    assert check_dist.repo_version() == __import__("wd2l").__version__


def test_license_is_mit():
    assert read("LICENSE").startswith("MIT License\n\nCopyright (c) 2026 ")
    py = read("pyproject.toml")
    assert 'license = "MIT"' in py and 'license-files = ["LICENSE"]' in py
    assert 'requires = ["setuptools>=77"]' in py


def test_build_file_and_rpm_sources_ship_in_the_sdist():
    assert 'wd2l = ["BUILD"]' in read("pyproject.toml")
    manifest = read("MANIFEST.in").splitlines()
    for line in ("include LICENSE", "include wd2l/BUILD", "graft deploy", "graft packaging",
                 "global-exclude __pycache__ *.py[cod]"):
        assert line in manifest, line


def make_wheel(path, version="0.3.0", build="abc123", scripts=check_dist.SCRIPTS,
               license_expr="MIT", license_file=True):
    di = "wd2l-%s.dist-info/" % version
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("wd2l/__init__.py", '__version__ = "%s"\n' % version)
        if build is not None:
            z.writestr("wd2l/BUILD", build + "\n")
        z.writestr(di + "entry_points.txt",
                   "[console_scripts]\n" + "".join("%s = m:main\n" % s for s in scripts))
        z.writestr(di + "METADATA", "Metadata-Version: 2.4\nName: wd2l\nVersion: %s\n"
                                    "License-Expression: %s\n" % (version, license_expr))
        if license_file:
            z.writestr(di + "licenses/LICENSE", "MIT License\n")


def make_sdist(path, version="0.3.0", members=check_dist.SDIST_NEEDS):
    with tarfile.open(path, "w:gz") as t:
        for m in members:
            info = tarfile.TarInfo("wd2l-%s/%s" % (version, m))
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))


def good_dist(tmp_path, version="0.3.0"):
    make_wheel(str(tmp_path / ("wd2l-%s-py3-none-any.whl" % version)), version)
    make_sdist(str(tmp_path / ("wd2l-%s.tar.gz" % version)), version)


def test_good_dist_passes(tmp_path):
    good_dist(tmp_path)
    assert check_dist.check(str(tmp_path), "0.3.0", "abc123") == []


def test_prerelease_names_pass(tmp_path):
    good_dist(tmp_path, "0.3.0rc1")
    assert check_dist.check(str(tmp_path), "0.3.0rc1", "abc123") == []


def test_wheel_problems_are_each_named(tmp_path):
    make_wheel(str(tmp_path / "wd2l-0.3.0-py3-none-any.whl"), build=None,
               scripts=("wd2l-sender",), license_expr="Proprietary", license_file=False)
    make_sdist(str(tmp_path / "wd2l-0.3.0.tar.gz"))
    probs = "\n".join(check_dist.check(str(tmp_path), "0.3.0", "abc123"))
    for word in ("BUILD", "wd2l-receiver", "wd2l-audit-report", "License-Expression",
                 "licenses/LICENSE"):
        assert word in probs, word


def test_wrong_commit_and_wrong_version(tmp_path):
    good_dist(tmp_path)
    assert any("BUILD" in p for p in check_dist.check(str(tmp_path), "0.3.0", "def456"))
    probs = check_dist.check(str(tmp_path), "0.4.0", "abc123")
    assert any("wheel name" in p for p in probs) and any("sdist name" in p for p in probs)


def test_sdist_must_carry_the_deploy_tree(tmp_path):
    make_wheel(str(tmp_path / "wd2l-0.3.0-py3-none-any.whl"))
    make_sdist(str(tmp_path / "wd2l-0.3.0.tar.gz"),
               members=[m for m in check_dist.SDIST_NEEDS if not m.startswith("deploy/")])
    probs = check_dist.check(str(tmp_path), "0.3.0", "abc123")
    assert any("deploy/log-server/wd2l-sender.service" in p for p in probs)


def test_exactly_one_wheel_and_one_sdist(tmp_path):
    probs = check_dist.check(str(tmp_path), "0.3.0", "abc123")
    assert any("one wheel" in p for p in probs) and any("one sdist" in p for p in probs)


import subprocess

TOOLS = os.path.join(REPO, "packaging", "ci", "tools.Containerfile")
TOOL = os.path.join(REPO, "packaging", "ci", "tool")
PIN = os.path.join(REPO, "packaging", "ci", "pin-images.sh")
PINNED_FROM = re.compile(r"^FROM (\S+?):(\S+?)@sha256:[0-9a-f]{64} AS (\S+)$")


def tool_refs():
    out = {}
    for line in read("packaging/ci/tools.Containerfile").splitlines():
        if line.startswith("FROM "):
            m = PINNED_FROM.match(line)
            assert m, "not pinned: " + line
            out[m.group(3)] = line.split()[1]
    return out


def test_every_tool_is_pinned_by_digest():
    assert set(tool_refs()) == {"cosign", "grype", "oras", "syft", "trivy", "hadolint",
                                "ubi9", "ubi10", "fedora"}


def test_tool_runs_the_pinned_image_with_the_work_tree(tmp_path):
    log = tmp_path / "args"
    fake = tmp_path / "podman"
    fake.write_text('#!/bin/sh\nfor a in "$@"; do echo "$a"; done > "%s"\n' % log)
    fake.chmod(0o755)
    env = dict(os.environ, PODMAN=str(fake), TOOL_ENV="COSIGN_PASSWORD", COSIGN_PASSWORD="x",
               TOOL_NETWORK="none", XDG_RUNTIME_DIR=str(tmp_path))
    r = subprocess.run(["bash", TOOL, "cosign", "verify", "--key", "k.pub", "img"],
                       cwd=str(tmp_path), env=env, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr
    args = log.read_text().splitlines()
    ref = tool_refs()["cosign"]
    assert args[0] == "run" and args[args.index(ref) + 1:] == ["verify", "--key", "k.pub", "img"]
    assert args[args.index("--network") + 1] == "none"
    assert "COSIGN_PASSWORD" in args and "%s:/work" % tmp_path in args
    assert "--userns=keep-id" in args and "/tmp:rw,mode=1777" in args
    assert args[args.index("--user") + 1] == "%d:%d" % (os.getuid(), os.getgid())


def test_tool_ref_and_unknown_tool():
    r = subprocess.run(["bash", TOOL, "--ref", "syft"], stdout=subprocess.PIPE)
    assert r.returncode == 0 and r.stdout.decode().strip() == tool_refs()["syft"]
    r = subprocess.run(["bash", TOOL, "nope"], stderr=subprocess.PIPE)
    assert r.returncode == 2 and b"no stage named nope" in r.stderr


def test_pin_images_rewrites_only_from_lines(tmp_path):
    f = tmp_path / "Containerfile"
    old = "sha256:" + "a" * 64
    f.write_text("FROM a.io/x:1 AS one\nFROM b.io/y:2@%s AS two\nRUN echo hi\nFROM c.io/z:3\n" % old)
    resolver = tmp_path / "resolve"
    resolver.write_text("#!/bin/sh\necho sha256:%s\n" % ("b" * 64))
    resolver.chmod(0o755)
    r = subprocess.run(["bash", PIN, str(f)], env=dict(os.environ, RESOLVE=str(resolver)),
                       stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr
    new = "sha256:" + "b" * 64
    assert f.read_text() == ("FROM a.io/x:1@%s AS one\nFROM b.io/y:2@%s AS two\nRUN echo hi\n"
                             "FROM c.io/z:3@%s\n" % (new, new, new))


def test_pin_images_refuses_a_bad_digest(tmp_path):
    f = tmp_path / "Containerfile"
    f.write_text("FROM a.io/x:1\n")
    resolver = tmp_path / "resolve"
    resolver.write_text("#!/bin/sh\necho 'manifest unknown'\n")
    resolver.chmod(0o755)
    r = subprocess.run(["bash", PIN, str(f)], env=dict(os.environ, RESOLVE=str(resolver)),
                       stderr=subprocess.PIPE)
    assert r.returncode == 1 and b"no digest for a.io/x:1" in r.stderr
    assert f.read_text() == "FROM a.io/x:1\n"


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
                 "-w /etc/systemd/system/wd2l-receiver.service.d/ -p wa -k wd2l-units"):
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
    assert "install -Dm0644 -t %{buildroot}%{_datadir}/wd2l/splunk receiver/splunk/*" in s


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
    assert "Version:        %{wd2l_rpmversion}" in s and "License:        MIT" in s
    assert "%{!?wd2l_rpmversion:%{error:" in s and "%{!?wd2l_pyversion:%{error:" in s


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


def test_changelog_entry_is_the_built_version():
    # rpmbuild takes the build timestamps from the top entry (source_date_epoch_from_changelog).
    log = spec().split("\n%changelog\n", 1)[1].splitlines()
    assert log[0] == "* %{wd2l_date} Joe Azurmoni - %{version}-%{release}"
    assert "%{!?wd2l_date:" in spec()


def test_build_script_defines_what_the_spec_requires():
    required = re.findall(r"^%\{!\?(\w+):%\{error:", spec(), re.M)
    assert sorted(required) == ["wd2l_pyversion", "wd2l_rpmversion"]
    script = read("packaging/rpm/build-rpms.sh")
    for name in required + ["rel", "_topdir"]:
        assert '--define "%s ' % name in script, name


def test_descriptions_fit_rpmlint_width():
    for block in re.findall(r"^%description.*?\n(.*?)\n\n", spec(), re.M | re.S):
        assert all(len(line) <= 79 for line in block.splitlines()), block


def cil_lines(path):
    return [x for x in read(path).splitlines() if x.strip() and not x.startswith(";")]


def test_receiver_labels_the_capture_archive_for_tcpdump():
    # tcpdump started by systemd runs as netutils_t, which may only write netutils_tmp_t files.
    # In container mode the receiver (container_t) may read the archive, never write it.
    # /var/lib/wd2l is container_file_t (common/wd2l_container.cil): without the search rule,
    # tcpdump got a silent "Permission denied" opening its file (seen on the Pi, rc5).
    assert cil_lines("deploy/receiver/wd2l_pcap.cil") == [
        '(filecon "/var/lib/wd2l/pcap(/.*)?" any (system_u object_r netutils_tmp_t ((s0) (s0))))',
        '(optional wd2l_pcap_parent_search',
        '  (allow netutils_t container_file_t (dir (getattr search))))',
        '(optional wd2l_pcap_container_read',
        '  (allow container_t netutils_tmp_t (dir (getattr open read search)))',
        '  (allow container_t netutils_tmp_t (file (getattr open read))))']
    s = spec()
    for line in ("install -Dm0644 receiver/wd2l_pcap.cil %{buildroot}%{_datadir}/wd2l/selinux/wd2l_pcap.cil",
                 "semodule -X 200 -i %{_datadir}/wd2l/selinux/wd2l_pcap.cil",
                 "semodule -X 200 -r wd2l_pcap",
                 "%{_datadir}/wd2l/selinux/wd2l_pcap.cil"):
        assert line in s, line
    # -F: Podman's :z (rc4's Quadlet) left pcap/ container_file_t, a "customizable" type that a
    # plain restorecon keeps.
    receiver_post = s.split("%post receiver", 1)[1].split("%preun receiver", 1)[0]
    assert "restorecon -RF %{_sharedstatedir}/wd2l" in receiver_post
    assert "matchpathcon /var/lib/wd2l/pcap/cap-1.pcap" in read("packaging/rpm/install-test.sh")


def test_container_mode_labels_var_lib_wd2l_instead_of_relabelling_it():
    assert cil_lines("deploy/common/wd2l_container.cil") == [
        '(optional wd2l_container_files',
        '  (filecon "/var/lib/wd2l(/.*)?" any (system_u object_r container_file_t ((s0) (s0)))))']
    s = spec()
    base_post = s.split("\n%post\n", 1)[1].split("\n%preun\n", 1)[0]
    for line in ("semodule -X 200 -i %{_datadir}/wd2l/selinux/wd2l_container.cil",
                 "restorecon -RF %{_sharedstatedir}/wd2l"):
        assert line in base_post, line
    assert "semodule -X 200 -r wd2l_container" in s.split("\n%postun\n", 1)[1]
    base_files = s.split("\n%files\n", 1)[1].split("%files sender", 1)[0]
    assert "%{_datadir}/wd2l/selinux/wd2l_container.cil" in base_files
    assert "%dir %{_datadir}/wd2l/selinux" in base_files
    test = read("packaging/rpm/install-test.sh")
    assert "dnf install -y -q container-selinux" in test and ":container_file_t:" in test


def test_scriptlets_that_run_semodule_require_policycoreutils():
    s = spec()
    base = s.split("%package sender", 1)[0]
    receiver = s.split("%package receiver", 1)[1].split("%description receiver", 1)[0]
    for part in (base, receiver):
        assert re.search(r"^Requires\(post\):\s+policycoreutils$", part, re.M)
        assert re.search(r"^Requires\(postun\):\s+policycoreutils$", part, re.M)
