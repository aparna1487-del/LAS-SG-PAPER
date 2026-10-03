import pytest
from las_sg import NANGateway, SmartMeter, Point


def setup_pair():
    gw = NANGateway(master_secret=123456789)
    reg = gw.register("sm-001")
    return gw, SmartMeter(reg), reg


def test_point_round_trip_and_group_invariant():
    p = 17 * Point.generator()
    assert Point.decode(p.encode()) == p
    q = 29 * Point.generator()
    assert 17 * q == 29 * (17 * Point.generator())


def test_authentication_derives_same_key():
    gw, sm, _ = setup_pair()
    m1 = sm.message1(now=1000)
    m2, nan_key = gw.authenticate(m1, now=1001)
    assert sm.finish(m1, m2, now=1001) == nan_key


def test_tampered_message_one_rejected():
    gw, sm, _ = setup_pair()
    m1 = sm.message1(now=1000)
    m1["y1"] = m1["y1"][:-1] + ("A" if m1["y1"][-1] != "A" else "B")
    with pytest.raises(ValueError, match="MAC"):
        gw.authenticate(m1, now=1001)


def test_replay_and_timeout_rejected():
    gw, sm, _ = setup_pair()
    m1 = sm.message1(now=1000)
    with pytest.raises(ValueError, match="stale"):
        gw.authenticate(m1, now=1031)


def test_tampered_message_two_rejected():
    gw, sm, _ = setup_pair()
    m1 = sm.message1(now=1000)
    m2, _ = gw.authenticate(m1, now=1001)
    m2["fn"] = m2["fn"][:-1] + ("A" if m2["fn"][-1] != "A" else "B")
    with pytest.raises(ValueError):
        sm.finish(m1, m2, now=1001)


def test_fresh_sessions_use_different_keys():
    gw, sm, _ = setup_pair()
    m1a = sm.message1(now=1000); m2a, ka = gw.authenticate(m1a, now=1001); sm.finish(m1a, m2a, now=1001)
    m1b = sm.message1(now=1002); m2b, kb = gw.authenticate(m1b, now=1003); sm.finish(m1b, m2b, now=1003)
    assert ka != kb
