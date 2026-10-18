"""Reading RPM headers with the standard library (packaging/container/rpm_header.py): an RPM file's
signature and main headers, and the headers an RPM database keeps (#190)."""

import sqlite3

import pytest

from helpers import INT16, INT32, STRING, STRING_ARRAY, I18N, load_script, rpm_header_blob as header_blob

rh = load_script("packaging/container/rpm_header.py")


def rpm_file(path, main, sig=((273, STRING, "ab" * 32),)):
    """An RPM file: the 96-byte lead, the signature header padded to 8 bytes, the main header."""
    magic = b"\x8e\xad\xe8\x01\0\0\0\0"
    lead = b"\xed\xab\xee\xdb" + b"\0" * 92
    s = magic + header_blob(list(sig))
    with open(path, "wb") as f:
        f.write(lead + s + b"\0" * (-len(s) % 8) + magic + header_blob(list(main)) + b"payload")
    return str(path)


SENDER = [(1000, STRING, "wd2l-sender"), (1001, STRING, "1.1.0"), (1002, STRING, "1.el9"),
          (1004, I18N, "The sender"), (1014, STRING, "MIT"), (1020, STRING, "https://example/r"),
          (1022, STRING, "noarch"), (1044, STRING, "wd2l-1.1.0-1.el9.src.rpm"),
          (1047, STRING_ARRAY, ["config(wd2l-sender)", "wd2l-sender"]),
          (1048, INT32, [8 | (1 << 24), 0, 12, 8 | (1 << 24) | (1 << 8)]),
          (1049, STRING_ARRAY, ["rpmlib(PayloadIsZstd)", "iproute", "python3", "config(wd2l-sender)"]),
          (1050, STRING_ARRAY, ["5.4.18-1", "", "3.9", "1.1.0-1.el9"]),
          (1030, INT16, [0o40755, 0o100644, 0o100755]),
          (1035, STRING_ARRAY, ["", "11" * 32, "22" * 32]),
          (1116, INT32, [0, 1, 2]),
          (1117, STRING_ARRAY, ["wd2l-sender.service.d", "sender.env", "wd2l-egress-nic"]),
          (1118, STRING_ARRAY, ["/etc/systemd/system/", "/etc/wd2l/", "/usr/libexec/wd2l/"]),
          (5011, INT32, [8]), (5092, STRING_ARRAY, ["cd" * 32]), (5093, INT32, [8])]


def test_an_rpm_file_s_identity_digests_and_license(tmp_path):
    r = rh.read_rpm(rpm_file(tmp_path / "s.rpm", SENDER))
    assert (r["name"], r["version"], r["release"], r["epoch"], r["arch"]) == ("wd2l-sender", "1.1.0", "1.el9", None, "noarch")
    assert (r["license"], r["summary"], r["url"], r["vendor"]) == ("MIT", "The sender", "https://example/r", None)
    assert r["sourcerpm"] == "wd2l-1.1.0-1.el9.src.rpm"
    assert r["header_sha256"] == "ab" * 32 and r["payload_sha256"] == "cd" * 32


def test_an_rpm_file_s_files_with_their_paths_modes_and_digests(tmp_path):
    r = rh.read_rpm(rpm_file(tmp_path / "s.rpm", SENDER))
    assert r["files"] == [
        {"path": "/etc/systemd/system/wd2l-sender.service.d", "mode": 0o40755, "sha256": ""},
        {"path": "/etc/wd2l/sender.env", "mode": 0o100644, "sha256": "11" * 32},
        {"path": "/usr/libexec/wd2l/wd2l-egress-nic", "mode": 0o100755, "sha256": "22" * 32}]


def test_an_rpm_file_s_requirements_and_provides(tmp_path):
    r = rh.read_rpm(rpm_file(tmp_path / "s.rpm", SENDER))
    assert r["requires"] == [{"name": "rpmlib(PayloadIsZstd)", "flags": 8 | (1 << 24), "version": "5.4.18-1"},
                             {"name": "iproute", "flags": 0, "version": ""},
                             {"name": "python3", "flags": 12, "version": "3.9"},
                             {"name": "config(wd2l-sender)", "flags": 8 | (1 << 24) | (1 << 8), "version": "1.1.0-1.el9"}]
    assert r["provides"] == ["config(wd2l-sender)", "wd2l-sender"]


def test_the_main_header_is_found_after_the_signature_header_s_padding(tmp_path):
    # A signature header whose length isn't a multiple of 8 (the case rpm pads).
    sig = [(273, STRING, "ab" * 32), (1000, STRING, "x")]
    assert len(header_blob(sig)) % 8 != 0
    r = rh.read_rpm(rpm_file(tmp_path / "s.rpm", SENDER, sig=sig))
    assert r["name"] == "wd2l-sender" and r["header_sha256"] == "ab" * 32


def test_a_file_digest_that_isn_t_sha256_is_refused(tmp_path):
    md5 = [t for t in SENDER if t[0] != 5011] + [(5011, INT32, [1])]
    with pytest.raises(ValueError, match="SHA-256"):
        rh.read_rpm(rpm_file(tmp_path / "s.rpm", md5))


def test_a_file_that_isn_t_an_rpm_is_refused(tmp_path):
    p = tmp_path / "x.rpm"
    p.write_bytes(b"PK\x03\x04 not an rpm")
    with pytest.raises(ValueError, match="not an RPM"):
        rh.read_rpm(str(p))


def test_an_rpm_database_s_headers(tmp_path):
    db = tmp_path / "rpmdb.sqlite"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")
    for name, digest in (("glibc", "aa" * 32), ("gpg-pubkey", None)):
        tags = [(1000, STRING, name), (1001, STRING, "2.43"), (1002, STRING, "9.2.hum1"), (1022, STRING, "x86_64")]
        if digest:
            tags += [(273, STRING, digest), (1003, INT32, [1])]
        con.execute("INSERT INTO Packages (blob) VALUES (?)", (header_blob(tags),))
    con.commit()
    con.close()
    got = rh.read_rpmdb(str(db))
    assert [(p["name"], p["epoch"], p["arch"], p["header_sha256"]) for p in got] == [
        ("glibc", 1, "x86_64", "aa" * 32), ("gpg-pubkey", None, "x86_64", None)]
