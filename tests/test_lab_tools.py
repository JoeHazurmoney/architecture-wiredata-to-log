import socket
import threading
import time

from lab import fake_cribl


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_the_stand_in_aggregator_waits_for_a_sender_that_starts_late():
    # The lab starts the sender, then the stand-in; on a slow runner the sender may not be
    # listening yet. A real aggregator retries, and so does the stand-in.
    port = free_port()
    accepted = []

    def listen_late():
        time.sleep(0.5)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(1)
        srv.settimeout(5)
        try:
            accepted.append(srv.accept()[0])
        except socket.timeout:
            pass
        srv.close()

    t = threading.Thread(target=listen_late, daemon=True)
    t.start()
    s = fake_cribl.connect("127.0.0.1", port, wait=5.0)
    t.join(6)
    assert accepted
    s.close()
    accepted[0].close()


def test_the_stand_in_aggregator_gives_up_after_its_wait():
    port = free_port()
    start = time.monotonic()
    try:
        fake_cribl.connect("127.0.0.1", port, wait=0.3)
    except ConnectionRefusedError:
        pass
    else:
        raise AssertionError("connected to nothing")
    assert time.monotonic() - start < 2
