#!/usr/bin/env python3
"""Stand-in log aggregator: header line, then one JSON event per line over TCP (the same
format as, e.g., Cribl Stream's TCP JSON destination)."""

import argparse
import json
import socket
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("events", help="JSONL file from gen_events.py")
    p.add_argument("--to", default="127.0.0.1:10070")
    p.add_argument("--eps", type=float, default=1000, help="events per second, 0 = as fast as possible")
    p.add_argument("--token", default="")
    a = p.parse_args()
    host, _, port = a.to.rpartition(":")
    s = socket.create_connection((host, int(port)))
    s.sendall(json.dumps({"authToken": a.token, "fields": {}}).encode() + b"\n")
    start = time.monotonic()
    n = 0
    with open(a.events, "rb") as f:
        for line in f:
            s.sendall(line if line.endswith(b"\n") else line + b"\n")
            n += 1
            if a.eps > 0:
                ahead = n / a.eps - (time.monotonic() - start)
                if ahead > 0:
                    time.sleep(ahead)
    s.close()
    print("fake_cribl: sent %d events in %.1fs" % (n, time.monotonic() - start))


if __name__ == "__main__":
    main()
