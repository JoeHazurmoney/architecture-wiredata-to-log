import hashlib
import random

from wd2l import reconcile
from wd2l.receiver import RangeSet
from wd2l.reconcile import SetHash, StreamReconciler


def d(i):
    return hashlib.sha256(b"event %d" % i).digest()


def sender_hash(seqs):
    h = SetHash()
    for s in seqs:
        h.add(s, d(s))
    return h.hex()


def test_term_is_sha256_of_seq_and_digest():
    want = int.from_bytes(hashlib.sha256((7).to_bytes(8, "big") + d(7)).digest(), "big")
    assert reconcile.term(7, d(7)) == want


def test_set_hash_ignores_order_and_wraps():
    seqs = list(range(1, 200))
    shuffled = seqs[:]
    random.Random(3).shuffle(shuffled)
    assert sender_hash(seqs) == sender_hash(shuffled)
    assert len(SetHash().hex()) == 64 and SetHash().hex() == "0" * 64
    big = SetHash(reconcile.MOD - 1)
    big.add(1, d(1))
    assert big.value == reconcile.term(1, d(1)) - 1
    assert SetHash.from_hex(sender_hash(seqs)).hex() == sender_hash(seqs)


def ready(rc, seqs, lo, gaps=None, pending=()):
    for s in seqs:
        rc.delivered(s, d(s))
    rc.settle(set(pending))
    return rc.check(lo, gaps or RangeSet())


def test_everything_delivered_balances():
    rc = StreamReconciler()
    rc.cut(10, sender_hash(range(1, 11)))
    res = ready(rc, range(1, 11), lo=11)
    assert res == {"cut": 10, "sender_hash": sender_hash(range(1, 11)),
                   "receiver_hash": sender_hash(range(1, 11)), "balanced": True}


def test_no_comparison_until_the_cut_is_resolved_and_durable():
    rc = StreamReconciler()
    rc.cut(10, sender_hash(range(1, 11)))
    assert ready(rc, range(1, 10), lo=10) is None                 # 10 not resolved yet
    assert ready(rc, [10], lo=11, pending={10}) is None           # 10 not durable yet
    rc.settle(set())
    assert rc.check(11, RangeSet())["balanced"] is True


def test_an_open_gap_unbalances_and_a_late_fill_rebalances():
    rc = StreamReconciler()
    rc.cut(5, sender_hash(range(1, 6)))
    gaps = RangeSet([[3, 3]])
    res = ready(rc, [1, 2, 4, 5], lo=6, gaps=gaps)
    assert res["balanced"] is False and res["receiver_hash"] != res["sender_hash"]
    gaps.remove(3)
    rc.filled += 1
    res = ready(rc, [3], lo=6, gaps=gaps)                         # same cut, compared again
    assert res["balanced"] is True and res["cut"] == 5


def test_events_past_the_cut_wait_for_the_next_cut():
    rc = StreamReconciler()
    rc.cut(3, sender_hash(range(1, 4)))
    assert ready(rc, range(1, 6), lo=6)["balanced"] is True       # 4 and 5 kept apart
    rc.cut(5, sender_hash(range(1, 6)))
    assert rc.check(6, RangeSet())["balanced"] is True


def test_dropped_before_durable_is_not_counted():
    rc = StreamReconciler()
    rc.cut(2, sender_hash([1, 2]))
    rc.delivered(1, d(1))
    rc.delivered(2, d(2))
    rc.dropped(2)
    rc.settle(set())
    assert rc.check(3, RangeSet([[2, 2]]))["balanced"] is False


def test_state_round_trip_and_old_state_is_disabled():
    rc = StreamReconciler()
    rc.cut(3, sender_hash(range(1, 4)))
    ready(rc, range(1, 6), lo=6)
    rc.cut(9, "f" * 64)
    back = StreamReconciler.from_json(rc.to_json())
    assert back.to_json()["base"] == rc.to_json()["base"] and back.last == rc.last
    assert sorted(back.above) == [4, 5] and list(back.cuts) == [(9, "f" * 64)]
    assert StreamReconciler.from_json(None).enabled is False
