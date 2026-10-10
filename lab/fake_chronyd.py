#!/usr/bin/env python3
"""Stand-in for chronyd's command port in the lab, for --chrony-addr (the containers have no
chronyc). Answers `tracking` like the hosts: synchronised at stratum 3 to a GPS reference
clock, 4 µs off; or "not synchronised" while the flag file exists (lab --fault clock).
Like chronyd, it ignores requests shorter than its reply.

    python3 lab/fake_chronyd.py [--listen 127.0.0.1:323] [--flag FILE]

float_to_chrony() is chrony's UTI_FloatHostToNetwork. The tests use it to build replies."""

import argparse
import math
import os
import socket
import struct
from typing import Optional

REQ = struct.Struct("!BBBBHHIII")
RPY = struct.Struct("!BBBBHHHHHHIII")
TRACKING = struct.Struct("!I16sHHHHIII9I")      # chronyd sends no EOR marker
GPS = 0x47505300          # "GPS\0"
COEF_MAX = (1 << 24) - 1


def float_to_chrony(x: float) -> int:
    neg = x < 0
    x = abs(x) if x == x else 0.0        # NaN is sent as zero
    if x < 1.0e-100:
        exp = coef = 0
    elif x > 1.0e100:
        exp, coef = 63, COEF_MAX + neg
    else:
        exp = int(math.log(x) / math.log(2) + 1)
        coef = int(x * 2.0 ** (-exp + 25) + 0.5)
        while coef > COEF_MAX + neg:
            coef >>= 1
            exp += 1
        if exp > 63:
            exp, coef = 63, COEF_MAX + neg
        elif exp < -64:
            if exp + 25 >= -64:
                coef >>= -64 - exp
                exp = -64
            else:
                exp = coef = 0
    if neg:
        coef = (-coef) & ((1 << 25) - 1)
    return ((exp & 0x7F) << 25) | coef


def tracking_reply(seq: int, ref_id: int = GPS, family: int = 0, addr: bytes = b"",
                   stratum: int = 3, leap: int = 0, correction: float = 0.000004,
                   status: int = 0) -> bytes:
    head = RPY.pack(6, 2, 0, 0, 33, 5, status, 0, 0, 0, seq, 0, 0)
    if status:
        return head                       # chronyd sends only the header with an error status
    floats = [float_to_chrony(v) for v in
              (correction, 0.000001, 0.000003, -1.0, 0.0, 0.01, 0.0001, 0.00005, 16.0)]
    return head + TRACKING.pack(ref_id, addr.ljust(16, b"\0"), family, 0, stratum, leap,
                                0, 1791209000, 0, *floats)


def answer(data: bytes, unsynced: bool = False) -> Optional[bytes]:
    if len(data) < RPY.size + TRACKING.size:
        return None
    version, ptype, _r1, _r2, command, _attempt, seq, _p1, _p2 = REQ.unpack_from(data)
    if (version, ptype, command) != (6, 1, 33):
        return None
    if unsynced:
        return tracking_reply(seq, ref_id=0, stratum=0, leap=3, correction=0.0)
    return tracking_reply(seq)


def respond(data: bytes, flag: Optional[str]) -> Optional[bytes]:
    return answer(data, unsynced=bool(flag) and os.path.exists(flag))


def main() -> None:
    p = argparse.ArgumentParser(description="chronyd stand-in for the lab (--chrony-addr)")
    p.add_argument("--listen", default="127.0.0.1:323")
    p.add_argument("--flag", help="answer 'not synchronised' while this file exists")
    a = p.parse_args()
    host, port = a.listen.rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host, int(port)))
    while True:
        data, peer = s.recvfrom(4096)
        out = respond(data, a.flag)
        if out:
            s.sendto(out, peer)


if __name__ == "__main__":
    main()
