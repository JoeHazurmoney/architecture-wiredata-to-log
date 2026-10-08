import os

from wd2l import packets, receiver

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class BufSock:
    """setsockopt/getsockopt like the kernel: SO_RCVBUFFORCE needs CAP_NET_ADMIN, SO_RCVBUF is
    capped at rmem_max, and getsockopt reports double what was set."""

    def __init__(self, admin, rmem_max):
        self.admin, self.rmem_max, self.size = admin, rmem_max, 0

    def setsockopt(self, level, opt, value):
        if opt == packets.SO_RCVBUFFORCE:
            if not self.admin:
                raise PermissionError(1, "Operation not permitted")
            self.size = value
        else:
            self.size = min(value, self.rmem_max)

    def getsockopt(self, level, opt):
        return 2 * self.size


def test_rcvbuf_is_forced_with_net_admin():
    assert packets.set_rcvbuf(BufSock(True, 212992), 64 << 20) == 128 << 20


def test_rcvbuf_falls_back_and_reports_the_cap():
    assert packets.set_rcvbuf(BufSock(False, 212992), 64 << 20) == 425984


def test_rcvbuf_with_rmem_max_raised_is_enough():
    got = packets.set_rcvbuf(BufSock(False, 67108864), 64 << 20)
    assert receiver.rcvbuf_warning(got, 64 << 20) is None


def test_rcvbuf_warning():
    assert receiver.rcvbuf_warning(128 << 20, 64 << 20) is None
    w = receiver.rcvbuf_warning(425984, 64 << 20)
    for part in ("208 KiB", "65536 KiB", "net.core.rmem_max", "67108864", "90-wd2l.conf"):
        assert part in w, part


def test_sysctl_file_matches_the_default_buffer():
    with open(os.path.join(REPO, "deploy", "receiver", "90-wd2l.conf")) as f:
        lines = [x for x in f.read().splitlines() if x.strip() and not x.startswith("#")]
    assert lines == ["net.core.rmem_max = 67108864"]
    assert receiver.build_parser().get_default("capture_rcvbuf") == 67108864
