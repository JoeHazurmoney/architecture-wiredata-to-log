"""Ethernet / IPv4 / UDP parsing and building, pcap files, and live AF_PACKET capture.

Only what the receiver needs: pull the UDP payload out of an Ethernet frame. Anything
that is not IPv4/UDP (or is an IP fragment) is reported as such and skipped.
"""

from __future__ import annotations

import hashlib
import os
import socket
import struct
from typing import Any, BinaryIO, Dict, Iterator, List, NamedTuple, Optional, Tuple

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)
IPPROTO_UDP = 17

PCAP_GLOBAL = struct.Struct("IHHiIII")
PCAP_RECORD = struct.Struct("IIII")
LINKTYPE_ETHERNET = 1
PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

# linux/if_packet.h
SOL_PACKET = 263
PACKET_STATISTICS = 6
PACKET_OUTGOING = 4


class Udp(NamedTuple):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes


class NotUdp(Exception):
    """Frame is not an unfragmented IPv4/UDP packet. The message says what it was."""


def parse_udp(frame: bytes) -> Udp:
    """Extract the UDP datagram from an Ethernet frame (optionally VLAN-tagged)."""
    if len(frame) < 14:
        raise NotUdp("runt")
    off = 12
    (ethertype,) = struct.unpack_from("!H", frame, off)
    tags = 0
    while ethertype in VLAN_TPIDS:
        tags += 1
        off += 4
        if tags > 2 or len(frame) < off + 2:
            raise NotUdp("vlan")
        (ethertype,) = struct.unpack_from("!H", frame, off)
    off += 2
    if ethertype != ETH_P_IP:
        raise NotUdp("ethertype 0x%04x" % ethertype)
    if len(frame) < off + 20:
        raise NotUdp("short ip")
    vihl, _tos, total_len, _ident, frag, _ttl, proto, _csum, src, dst = \
        struct.unpack_from("!BBHHHBBH4s4s", frame, off)
    ihl = (vihl & 0x0F) * 4
    if vihl >> 4 != 4 or ihl < 20:
        raise NotUdp("bad ip header")
    if frag & 0x3FFF:  # MF flag or non-zero offset
        raise NotUdp("ip fragment")
    if proto != IPPROTO_UDP:
        raise NotUdp("ip proto %d" % proto)
    if total_len < ihl + 8 or len(frame) < off + total_len:
        raise NotUdp("truncated ip")
    udp_off = off + ihl
    sport, dport, ulen, _ucsum = struct.unpack_from("!HHHH", frame, udp_off)
    if ulen < 8 or ulen > total_len - ihl:
        raise NotUdp("bad udp length")
    return Udp(socket.inet_ntoa(src), socket.inet_ntoa(dst), sport, dport,
               bytes(frame[udp_off + 8:udp_off + ulen]))


def _ip_checksum(header: bytes) -> int:
    s = sum(struct.unpack("!%dH" % (len(header) // 2), header))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def mac_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(":"))


def build_udp_frame(src_mac: str, dst_mac: str, src_ip: str, dst_ip: str,
                    sport: int, dport: int, payload: bytes, ident: int = 0) -> bytes:
    """Build an Ethernet/IPv4/UDP frame (UDP checksum 0). Used by tests and tools."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), ident & 0xFFFF, 0x4000, 64,
                     IPPROTO_UDP, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", ETH_P_IP) + ip + udp


# ---------------------------------------------------------------- pcap files

def read_pcap(f: BinaryIO) -> Iterator[Tuple[float, bytes]]:
    """Yield (timestamp, frame) from a classic libpcap file (what tcpdump -w writes)."""
    head = f.read(PCAP_GLOBAL.size)
    if len(head) < PCAP_GLOBAL.size:
        return
    for endian in ("<", ">"):
        (magic,) = struct.unpack(endian + "I", head[:4])
        if magic in (PCAP_MAGIC_US, PCAP_MAGIC_NS):
            break
    else:
        raise ValueError("not a classic pcap file (pcapng is not supported; use tcpdump -w)")
    divisor = 1e9 if magic == PCAP_MAGIC_NS else 1e6
    gl = struct.Struct(endian + "IHHiIII")
    rec = struct.Struct(endian + "IIII")
    linktype = gl.unpack(head)[6] & 0x0FFFFFFF
    if linktype != LINKTYPE_ETHERNET:
        raise ValueError("pcap linktype %d is not Ethernet" % linktype)
    while True:
        rh = f.read(rec.size)
        if len(rh) < rec.size:
            return
        sec, frac, incl, _orig = rec.unpack(rh)
        if incl > 262144:
            raise ValueError("corrupt pcap record length %d" % incl)
        data = f.read(incl)
        if len(data) < incl:
            return  # file still being written or truncated
        yield sec + frac / divisor, data


class PcapWriter:
    def __init__(self, f: BinaryIO, snaplen: int = 65535):
        self.f = f
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC_US, 2, 4, 0, 0, snaplen, LINKTYPE_ETHERNET))

    def write(self, ts: float, frame: bytes) -> None:
        sec = int(ts)
        usec = int(round((ts - sec) * 1e6))
        if usec >= 1000000:
            sec, usec = sec + 1, usec - 1000000
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)


# ---------------------------------------------------------------- live capture

class LiveCapture:
    """Receive every frame arriving on an interface via an AF_PACKET raw socket.

    The socket is never written to. Needs CAP_NET_RAW.
    """

    def __init__(self, iface: str, rcvbuf: int = 64 * 1024 * 1024, timeout: float = 0.5):
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, 33, rcvbuf)  # SO_RCVBUFFORCE (root)
        except OSError:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.sock.bind((iface, 0))
        self.sock.settimeout(timeout)

    def recv(self) -> Optional[bytes]:
        """Return the next incoming frame, or None on timeout."""
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                return None
            if addr[2] != PACKET_OUTGOING:
                return data

    def kernel_stats(self) -> Tuple[int, int]:
        """(packets, drops) since the last call, as counted by the kernel."""
        raw = self.sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
        return struct.unpack("II", raw)

    def close(self) -> None:
        self.sock.close()


class _Hashing:
    """A file wrapper that hashes what is read through it."""

    def __init__(self, f: BinaryIO):
        self.f, self.h, self.n = f, hashlib.sha256(), 0

    def read(self, size: int = -1) -> bytes:
        b = self.f.read(size)
        self.h.update(b)
        self.n += len(b)
        return b


def iter_pcap_paths(paths, digests: Optional[List[Dict[str, Any]]] = None
                    ) -> Iterator[Tuple[float, bytes]]:
    """Frames from several pcap files, oldest file first (by mtime). With `digests`, each
    file's SHA-256 and size, computed while reading it, is appended once it has been read."""
    for p in sorted(paths, key=lambda p: (os.path.getmtime(p), p)):
        with open(p, "rb") as f:
            src = _Hashing(f) if digests is not None else f
            yield from read_pcap(src)  # type: ignore[arg-type]
            if digests is not None:
                digests.append({"file": os.path.basename(p), "sha256": src.h.hexdigest(),
                                "bytes": src.n})
