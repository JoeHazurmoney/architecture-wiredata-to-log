"""Sender -> (lossy) wire -> pcap file -> receiver CLI -> events.jsonl, all in-process."""

import json
import random

from wd2l import packets, receiver, wire
from wd2l.sender import Sender

from helpers import FakeSock, eth, make_events


def run_sender(events, max_dg=wire.DEFAULT_MAX_DATAGRAM):
    sock = FakeSock()
    snd = Sender(("10.255.255.2", 5514), sock=sock, rate_pps=0, max_datagram=max_dg)
    marks = []  # (index into sock.sent where event starts, seq)
    for i, e in enumerate(events):
        marks.append(len(sock.sent))
        snd.send_event(e)
        if i % 50 == 49:
            snd.send_heartbeat()
    snd.send_heartbeat(final=True)
    return snd, sock.sent


def write_pcap(path, datagrams, keep=lambda i, d: True, t0=1000.0):
    with open(path, "wb") as f:
        w = packets.PcapWriter(f)
        for i, d in enumerate(datagrams):
            if keep(i, d):
                w.write(t0 + i * 0.0005, eth(d, i))


def read_jsonl(path):
    with open(path) as f:
        return [json.loads(line) for line in f]


def expected(evt):
    return wire.parse_event(wire.serialize_event(evt))


def test_lossless_path_is_exact(tmp_path):
    events = make_events(400)
    _, sent = run_sender(events)
    write_pcap(tmp_path / "a.pcap", sent)
    receiver.main(["--pcap", str(tmp_path / "a.pcap"), "--out-dir", str(tmp_path / "out")])
    got = read_jsonl(tmp_path / "out" / "events.jsonl")
    assert [g["wd2l_seq"] for g in got] == list(range(1, 401))
    for g, e in zip(got, events):
        g.pop("wd2l_seq"), g.pop("wd2l_stream")
        assert g == expected(e)
    health = read_jsonl(tmp_path / "out" / "health.jsonl")
    assert [h for h in health if h["type"] == "gap"] == []
    assert health[-1]["other_packets"] == 0 and health[-1]["bad_frames"] == 0


def test_loss_is_reported_exactly_and_replay_fills_it(tmp_path):
    events = make_events(600, seed=5)
    _, sent = run_sender(events)
    rnd = random.Random(9)
    dropped = set()
    for i, d in enumerate(sent):
        f = wire.decode(d)
        if f.type == wire.TYPE_DATA and rnd.random() < 0.03:
            dropped.add(i)
    lost_seqs = {wire.decode(sent[i]).seq for i in dropped}
    assert lost_seqs

    state = str(tmp_path / "state.json")
    out1 = tmp_path / "out1"
    write_pcap(tmp_path / "lossy.pcap", sent, lambda i, d: i not in dropped)
    receiver.main(["--pcap", str(tmp_path / "lossy.pcap"), "--out-dir", str(out1),
                   "--state", state])
    got = {g["wd2l_seq"] for g in read_jsonl(out1 / "events.jsonl")}
    gap_seqs = set()
    for h in read_jsonl(out1 / "health.jsonl"):
        if h["type"] == "gap":
            gap_seqs |= set(range(h["first_seq"], h["last_seq"] + 1))
    assert gap_seqs == lost_seqs
    assert got | gap_seqs == set(range(1, 601)) and not got & gap_seqs

    # The capture archive has the full stream (the loss was in the live receiver).
    out2 = tmp_path / "out2"
    write_pcap(tmp_path / "archive.pcap", sent)
    receiver.main(["--pcap", str(tmp_path / "archive.pcap"), "--out-dir", str(out2),
                   "--state", state])
    refilled = [g["wd2l_seq"] for g in read_jsonl(out2 / "events.jsonl")]
    assert sorted(refilled) == sorted(lost_seqs)
    with open(state) as f:
        st = json.load(f)
    [s] = st["streams"].values()
    assert s["gaps"] == []


def test_jumbo_frames(tmp_path):
    events = make_events(40)
    _, sent = run_sender(events, max_dg=8972)
    assert max(len(d) for d in sent) > 1472
    write_pcap(tmp_path / "j.pcap", sent)
    receiver.main(["--pcap", str(tmp_path / "j.pcap"), "--out-dir", str(tmp_path / "o")])
    assert len(read_jsonl(tmp_path / "o" / "events.jsonl")) == 40
