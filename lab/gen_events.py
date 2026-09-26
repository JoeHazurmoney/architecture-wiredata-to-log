#!/usr/bin/env python3
"""Write a known set of test events (JSONL, in the log aggregator's output format) for the lab.

Mix: firewall syslog, multi-KB Windows XML events, hypervisor lines with non-ASCII text,
multi-line app errors, and one event bigger than the sender's max (it must arrive truncated).
"""

import argparse
import json
import random


def make(n: int, seed: int, oversize: int):
    rnd = random.Random(seed)
    base = 1727265600.0
    for i in range(n):
        kind = i % 5
        t = round(base + i * 0.001, 3)
        if kind == 0:
            e = {"host": "fw0%d" % (i % 2 + 1), "sourcetype": "pan:traffic", "source": "udp:514",
                 "_raw": "<14>Sep 25 12:00:00 fw01 1,2026/09/25 12:00:00,TRAFFIC,end,%d,"
                         "10.1.%d.%d,10.2.0.5,allow,tcp,443" % (i, i % 250, i % 200)}
        elif kind == 1:
            data = "".join("<Data Name='f%d'>%s</Data>" % (k, "".join(
                rnd.choice("abcdefghijklmnopqrstuvwxyz0123456789 ") for _ in range(rnd.randint(20, 400))))
                for k in range(rnd.randint(5, 40)))
            e = {"host": "ws%02d" % (i % 4), "sourcetype": "XmlWinEventLog",
                 "source": "XmlWinEventLog:Security",
                 "_raw": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
                         "<System><EventID>4624</EventID></System><EventData>%s</EventData></Event>" % data}
        elif kind == 2:
            e = {"host": "esx%02d" % (i % 3 + 1), "sourcetype": "vmw-syslog", "source": "udp:514",
                 "_raw": "Hostd: [Originator@6876] Tâche terminée — ユーザー root ✓ seq=%d" % i}
        elif kind == 3:
            e = {"host": "srv0%d" % (i % 2 + 1), "sourcetype": "linux_secure", "source": "/var/log/secure",
                 "_raw": "Sep 25 12:00:00 srv01 sshd[%d]: Accepted publickey for admin from 10.0.0.%d"
                         % (1000 + i, i % 250)}
        else:
            e = {"host": "srv02", "sourcetype": "app:error", "source": "/opt/app/log/error.log",
                 "_raw": "ERROR request %d failed\nTraceback (most recent call last):\n"
                         "  File \"app.py\", line 42, in handle\n\tKeyError: 'user'" % i}
        e["_time"] = t
        e["index"] = "enclave1"
        yield e
    if oversize:
        yield {"_time": base + n * 0.001, "host": "srv01", "sourcetype": "app:dump",
               "source": "/opt/app/dump.log", "index": "enclave1", "_raw": "Z" * oversize}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("out")
    p.add_argument("-n", type=int, default=5000)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--oversize", type=int, default=300000, help="size of the oversize event, 0 = none")
    a = p.parse_args()
    with open(a.out, "w", encoding="utf-8") as f:
        for e in make(a.n, a.seed, a.oversize):
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
