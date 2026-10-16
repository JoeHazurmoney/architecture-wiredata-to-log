"""Command-line options that wd2l-sender and wd2l-receiver both take, defined once (#169).
Each guide's option table lists them (docs/deployment/log-server.md, receiver.md)."""

from __future__ import annotations

import argparse

from . import hostinfo


def add_common_args(p: argparse.ArgumentParser, max_stratum_help: str = "") -> None:
    """The audit trail, time quality and log format options. `max_stratum_help` ends
    --max-stratum's help, for what only one side does with it."""
    p.add_argument("--audit-dir", help="write hash-chained audit records here "
                                       "(deployed: /var/log/wd2l)")
    p.add_argument("--audit-min-free-mb", type=int, default=256,
                   help="free space below this raises audit_failure")
    p.add_argument("--chronyc", default="chronyc",
                   help="chronyc command for time quality (\"-c tracking\" is added)")
    p.add_argument("--chrony-addr", type=hostinfo.chrony_address, metavar="HOST[:PORT]",
                   help="ask chronyd over UDP (its command port, 323) for time quality instead "
                        "of running --chronyc; the container units use 127.0.0.1:323")
    p.add_argument("--max-stratum", type=hostinfo.stratum, default=hostinfo.MAX_STRATUM,
                   metavar="N", help="time alarm when chrony's stratum is above N (1 is a server with its own "
                        "reference clock, e.g. GPS)" + max_stratum_help)
    p.add_argument("--log-format", choices=("text", "json"), default="text",
                   help="operational log lines: text, or one JSON object per line")
