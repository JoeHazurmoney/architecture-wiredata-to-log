import errno
import io
import random
import struct

import pytest

from wd2l import packets

from helpers import DST_IP, DST_MAC, PORT, SRC_IP, SRC_MAC, eth


def test_udp_roundtrip():
    u = packets.parse_udp(eth(b"hello"))
    assert u == packets.Udp(SRC_IP, DST_IP, 40000, PORT, b"hello")


def test_ip_checksum_is_valid():
    ip = eth(b"x")[14:34]
    assert packets._ip_checksum(ip) == 0


def test_vlan_tagged():
    f = eth(b"hi")
    tagged = f[:12] + struct.pack("!HH", 0x8100, 100) + f[12:]
    assert packets.parse_udp(tagged).payload == b"hi"
    qinq = f[:12] + struct.pack("!HHHH", 0x88A8, 10, 0x8100, 100) + f[12:]
    assert packets.parse_udp(qinq).payload == b"hi"


def test_ethernet_padding_ignored():
    assert packets.parse_udp(eth(b"a") + b"\x00" * 20).payload == b"a"


@pytest.mark.parametrize("mutate,reason", [
    (lambda f: f[:12] + b"\x08\x06" + f[14:], "ethertype"),       # ARP
    (lambda f: f[:20] + b"\x20\x00" + f[22:], "fragment"),         # MF flag
    (lambda f: f[:23] + b"\x06" + f[24:], "proto"),                # TCP
    (lambda f: f[:30], "truncated|short"),
    (lambda f: f[:5], "runt"),
])
def test_rejects(mutate, reason):
    with pytest.raises(packets.NotUdp, match=reason):
        packets.parse_udp(mutate(eth(b"hello world")))


def test_fuzz_parse_only_raises_notudp():
    rnd = random.Random(3)
    good = eth(b"x" * 200)
    for _ in range(5000):
        f = bytearray(good)
        for _ in range(rnd.randint(1, 6)):
            f[rnd.randrange(len(f))] = rnd.getrandbits(8)
        for cand in (bytes(f), bytes(f[:rnd.randint(0, len(f))])):
            try:
                packets.parse_udp(cand)
            except packets.NotUdp:
                pass


def test_pcap_roundtrip():
    buf = io.BytesIO()
    w = packets.PcapWriter(buf)
    frames = [(1000.5 + i, eth(bytes([i]) * i)) for i in range(10)]
    for ts, f in frames:
        w.write(ts, f)
    buf.seek(0)
    got = list(packets.read_pcap(buf))
    assert [f for _, f in got] == [f for _, f in frames]
    assert got[3][0] == pytest.approx(1003.5)


def test_pcap_big_endian_nanosecond():
    f = eth(b"z")
    data = struct.pack(">IHHiIII", packets.PCAP_MAGIC_NS, 2, 4, 0, 0, 65535, 1)
    data += struct.pack(">IIII", 10, 500000000, len(f), len(f)) + f
    [(ts, frame)] = list(packets.read_pcap(io.BytesIO(data)))
    assert ts == pytest.approx(10.5) and frame == f


def test_pcap_truncated_tail_is_ignored():
    buf = io.BytesIO()
    w = packets.PcapWriter(buf)
    w.write(1, eth(b"a"))
    w.write(2, eth(b"b"))
    data = buf.getvalue()[:-5]
    assert len(list(packets.read_pcap(io.BytesIO(data)))) == 1


def test_pcap_rejects_other_formats():
    with pytest.raises(ValueError):
        list(packets.read_pcap(io.BytesIO(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)))


def test_mac_bytes():
    assert packets.mac_bytes(DST_MAC) == b"\x02\x00\x00\x00\x00\x02"
    assert packets.mac_bytes(SRC_MAC)[-1] == 1


class FakeSock:
    def __init__(self, items):
        self.items = list(items)

    def recvfrom(self, n):
        x = self.items.pop(0)
        if isinstance(x, BaseException):
            raise x
        return x


def live(items):
    cap = packets.LiveCapture.__new__(packets.LiveCapture)     # no raw socket, no root
    cap.sock, cap.timeout, cap.down_errors = FakeSock(items), 0.5, 0
    return cap


def test_live_capture_rides_out_the_interface_going_down(monkeypatch):
    # `ip link set DEV down` makes the packet socket report ENETDOWN once; it delivers again
    # once the NIC is up. The receiver crashed and restart-looped on it.
    slept = []
    monkeypatch.setattr(packets.time, "sleep", slept.append)
    cap = live([OSError(errno.ENETDOWN, "Network is down"), (b"frame", ("cap0", 3, 0, 1, b""))])
    assert cap.recv() is None and cap.down_errors == 1 and slept == [0.5]
    assert cap.recv() == b"frame"


def test_live_capture_still_raises_other_socket_errors():
    with pytest.raises(OSError):
        live([OSError(errno.EBADF, "Bad file descriptor")]).recv()
