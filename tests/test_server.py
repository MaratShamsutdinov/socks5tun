import socket
import struct
import logging
import ipaddress
import pytest
from socks5tun.config import Config
from socks5tun.server import SocksServer


class DummySocket:
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent_data = b""
        self.closed = False

    def recv(self, bufsize):
        if not self._responses:
            return b""
        data = self._responses.pop(0)
        if len(data) > bufsize:
            part = data[:bufsize]
            remaining = data[bufsize:]
            self._responses.insert(0, remaining)
            return part
        return data

    def sendall(self, data):
        self.sent_data += data

    def close(self):
        self.closed = True


def test_is_client_allowed():
    cfg = Config({"allowed_clients": ["10.0.0.0/8"]})
    server = SocksServer(cfg)
    assert server._is_client_allowed("10.1.2.3") is True
    assert server._is_client_allowed("192.168.1.100") is False


def test_is_dest_allowed_rules():
    cfg = Config({})
    server = SocksServer(cfg)
    # No rules: any valid IP should be allowed
    assert server._is_dest_allowed("1.2.3.4", 80) is True
    # Invalid IP string
    assert server._is_dest_allowed("not_an_ip", 8080) is False

    # Deny rule present
    cfg2 = Config({})
    cfg2.deny_rules = [(ipaddress.ip_network("192.168.0.0/16"), None)]
    server2 = SocksServer(cfg2)
    assert server2._is_dest_allowed("192.168.1.1", 8080) is False
    assert server2._is_dest_allowed("8.8.8.8", 53) is True

    # Allow rules present
    cfg3 = Config({})
    cfg3.allow_rules = [(ipaddress.ip_network("10.0.0.0/8"), None)]
    server3 = SocksServer(cfg3)
    assert server3._is_dest_allowed("10.5.5.5", 1234) is True
    assert server3._is_dest_allowed("8.8.8.8", 53) is False

    # Deny and allow conflict (deny takes precedence)
    cfg4 = Config({})
    net = ipaddress.ip_network("10.0.0.0/8")
    cfg4.deny_rules = [(net, None)]
    cfg4.allow_rules = [(net, None)]
    server4 = SocksServer(cfg4)
    assert server4._is_dest_allowed("10.9.0.1", 8080) is False


def test_read_dest_address_ipv4():
    server = SocksServer(Config({}))
    ip = "203.0.113.5"
    port = 3000
    addr_bytes = socket.inet_aton(ip)
    port_bytes = struct.pack("!H", port)
    dummy = DummySocket([addr_bytes, port_bytes])
    result = server._read_dest_address(dummy, 0x01)
    assert result == (ip, port)


def test_read_dest_address_ipv4_incomplete():
    server = SocksServer(Config({}))
    # Incomplete IPv4 address
    dummy1 = DummySocket([b"\x01\x02"])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy1, 0x01)
    assert "Incomplete IPv4 address" in str(excinfo.value)
    # Incomplete port
    addr_bytes = socket.inet_aton("10.0.0.1")
    dummy2 = DummySocket([addr_bytes, b"\x99"])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy2, 0x01)
    assert "Incomplete port" in str(excinfo.value)


def test_read_dest_address_domain(monkeypatch):
    server = SocksServer(Config({}))
    # Monkey-patch DNS resolution
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda name: "203.0.113.10" if name == "example.com" else socket.gaierror(),
    )
    domain = "example.com"
    port = 8080
    length_byte = bytes([len(domain)])
    dummy = DummySocket([length_byte, domain.encode("utf-8"), struct.pack("!H", port)])
    result = server._read_dest_address(dummy, 0x03)
    assert result == ("203.0.113.10", port)


def test_read_dest_address_domain_incomplete(monkeypatch):
    server = SocksServer(Config({}))
    # Incomplete domain length
    dummy1 = DummySocket([])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy1, 0x03)
    assert "Incomplete domain length" in str(excinfo.value)
    # Incomplete domain name
    length = 5
    dummy2 = DummySocket([bytes([length]), b"abc"])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy2, 0x03)
    assert "Incomplete domain name" in str(excinfo.value)
    # Incomplete port
    dummy3 = DummySocket([bytes([3]), b"abc", b"\x01"])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy3, 0x03)
    assert "Incomplete port" in str(excinfo.value)
    # DNS resolution failure logs warning and raises
    monkeypatch.setattr(
        socket,
        "gethostbyname",
        lambda name: (_ for _ in ()).throw(Exception("resolve_fail")),
    )
    dummy4 = DummySocket([bytes([3]), b"bad", struct.pack("!H", 80)])
    caplog = logging.getLogger("socks5-server")
    with pytest.raises(Exception):
        server._read_dest_address(dummy4, 0x03)


def test_read_dest_address_ipv6():
    server = SocksServer(Config({}))
    ip = "2001:db8::1"
    port = 9090
    addr_bytes = socket.inet_pton(socket.AF_INET6, ip)
    port_bytes = struct.pack("!H", port)
    dummy = DummySocket([addr_bytes, port_bytes])
    result = server._read_dest_address(dummy, 0x04)
    assert result == (ip, port)


def test_read_dest_address_ipv6_incomplete():
    server = SocksServer(Config({}))
    dummy1 = DummySocket([b"\x00" * 15])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy1, 0x04)
    assert "Incomplete IPv6 address" in str(excinfo.value)
    addr_bytes = socket.inet_pton(socket.AF_INET6, "2001:db8::2")
    dummy2 = DummySocket([addr_bytes, b"\x00"])
    with pytest.raises(IOError) as excinfo:
        server._read_dest_address(dummy2, 0x04)
    assert "Incomplete port" in str(excinfo.value)


def test_read_dest_address_unsupported_type():
    server = SocksServer(Config({}))
    dummy = DummySocket([])
    with pytest.raises(ValueError) as excinfo:
        server._read_dest_address(dummy, 0x09)
    assert "Unsupported address type" in str(excinfo.value)


def test_handshake_no_auth_accept():
    cfg = Config({"auth": None})
    server = SocksServer(cfg)
    dummy = DummySocket([b"\x05\x01", b"\x00"])
    server._handle_client(dummy, ("1.2.3.4", 5000))
    # Server should select NO_AUTH and not close immediately (will close when no request follows)
    assert dummy.sent_data.startswith(b"\x05\x00")
    assert dummy.closed is True


def test_handshake_no_auth_reject():
    cfg = Config({"auth": None})
    server = SocksServer(cfg)
    dummy = DummySocket([b"\x05\x01", b"\x02"])
    server._handle_client(dummy, ("1.2.3.4", 5001))
    # Server should respond with NO_ACCEPTABLE and close
    assert dummy.sent_data == b"\x05\xff"
    assert dummy.closed is True


def test_handshake_auth_success():
    cfg = Config({"auth": {"username": "user", "password": "pass"}})
    server = SocksServer(cfg)
    dummy = DummySocket(
        [
            b"\x05\x01",
            b"\x02",  # SOCKS5 greeting with USER_AUTH method
            b"\x01",  # Auth version 1
            b"\x04",  # Username length 4
            b"user",  # Username
            b"\x04",  # Password length 4
            b"pass",  # Password
        ]
    )
    server._handle_client(dummy, ("1.2.3.4", 5002))
    # Should select USER_AUTH and then auth success
    assert dummy.sent_data == b"\x05\x02\x01\x00"
    assert dummy.closed is True


def test_handshake_auth_failure(caplog):
    cfg = Config({"auth": {"username": "user", "password": "pass"}})
    server = SocksServer(cfg)
    dummy = DummySocket(
        [
            b"\x05\x01",
            b"\x02",  # greeting
            b"\x01",  # auth version
            b"\x04",  # username length
            b"user",  # username
            b"\x04",  # password length
            b"fail",  # wrong password
        ]
    )
    caplog.set_level(logging.WARNING)
    server._handle_client(dummy, ("1.2.3.4", 5003))
    # Should respond with auth failure and close
    assert dummy.sent_data == b"\x05\x02\x01\x01"
    assert dummy.closed is True
    # Warning log for auth failure
    warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
    assert any("Authentication failed for 1.2.3.4" in rec.message for rec in warnings)


def test_handshake_auth_no_method():
    cfg = Config({"auth": {"username": "u", "password": "p"}})
    server = SocksServer(cfg)
    dummy = DummySocket([b"\x05\x01", b"\x00"])
    server._handle_client(dummy, ("1.2.3.4", 5004))
    # Server should reject because client didn't offer USER_AUTH
    assert dummy.sent_data == b"\x05\xff"
    assert dummy.closed is True
