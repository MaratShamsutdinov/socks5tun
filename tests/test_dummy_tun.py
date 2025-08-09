import collections
from socks5tun.dummy_tun import DummyTun


def test_dummy_tun_read_write_cycle():
    tun = DummyTun()
    tun.open()
    # Inject data and then read it
    data = b"hello"
    tun.inject(data)
    result = tun.read()
    assert result == data
    # Write data to tun and verify outgoing queue
    out_data = b"world"
    written = tun.write(out_data)
    assert written == len(out_data)
    assert isinstance(tun._outgoing_data, collections.deque)
    assert tun._outgoing_data[-1] == out_data


def test_dummy_tun_partial_read():
    tun = DummyTun()
    tun.open()
    long_data = b"x" * 2000
    tun.inject(long_data)
    part = tun.read(1500)
    assert len(part) == 1500
    # The remaining data should be available on next read
    remainder = tun.read()
    assert remainder == b"x" * 500


def test_dummy_tun_close_behavior():
    tun = DummyTun()
    tun.open()
    # Inject data before closing
    tun.inject(b"abc")
    tun.close()
    # First read should yield the remaining data
    result = tun.read()
    assert result == b"abc"
    # Subsequent read returns b'' since interface is closed and no data
    result2 = tun.read()
    assert result2 == b""
