import json

from wd2l import wire
from wd2l.receiver import Receiver

from helpers import MemOutput, eth

SID = 0x1111


def test_health_summary_carries_the_receivers_signals():
    nic = {"carrier": True, "carrier_changes": 1, "rx_packets": 50, "rx_crc_errors": 0}
    arch = {"archive_file": "cap-1.pcap", "archive_age_s": 0.4, "archive_bytes": 1000}
    out = MemOutput()
    r = Receiver(out, dst_ip="10.255.255.2", dst_port=5514, health_interval=1e9,
                 nic_probe=lambda: dict(nic), archive_probe=lambda: dict(arch), sample_interval=1)
    r.handle_frame(eth(wire.encode_event(SID, 1, json.dumps({"_raw": "x"}).encode())[0]), 0)
    r.handle_frame(eth(wire.encode_heartbeat(SID, 1, {"events_in": 7})), 0.5)
    r.tick(1)
    rec = r.emit_health(3)
    assert (rec["nic_carrier"], rec["nic_rx_packets"], rec["archive_age_s"]) == (True, 50, 0.4)
    assert rec["cpu_pct"] >= 0 and rec["rss_mb"] > 0
    assert (rec["packet_age_s"], rec["frame_age_s"], rec["sender_events_in"]) == (2.5, 2.5, 7)
