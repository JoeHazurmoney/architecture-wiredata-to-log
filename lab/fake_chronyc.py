#!/usr/bin/env python3
"""Stand-in for `chronyc -c tracking` in the lab: synchronised at stratum 3, as the hosts are
behind a GPS receiver and a stratum-2 switch, or "Not synchronised" while the flag file named
by the first argument exists (lab --fault clock)."""

import os
import sys

SYNCED = ("47505300,GPS,3,1791209000.000000000,0.000004000,0.000001000,0.000003000,-1.000,"
          "0.000,0.010,0.000100000,0.000050000,16.0,Normal")
UNSYNCED = ("00000000,,0,0.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,"
            "1.000000000,1.000000000,0.0,Not synchronised")

flag = sys.argv[1] if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
print(UNSYNCED if flag and os.path.exists(flag) else SYNCED)
