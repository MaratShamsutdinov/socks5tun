import socket
import struct
import logging
import pytest
from socks5tun.udp_handler import UDPHandler


class DummyTun:
    def __init__(self):
        self.packets = []

    def write(self, data: bytes):
        self.packets.append(data)
        return len(data)


class DummyConfig:
    def __init__(self):
        self.dns_resolver = "system"
        # Simulate forbidden networks (common private ranges)
        self.forbidden_networks = [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "192.168.0.0/16",
            "172.16.0.0/12",
        ]
        self.deny_rules = []
        self.allow_rules = []
        self.udp_host = "127.0.0.1"
        self.tun = {}
        # пустой dict ок, хэндлер сам
        # возьмет client_addr при отсутствии peer_address


@pytest.fixture
def udp_handler():
    cfg = DummyConfig()
    tun = DummyTun()
    handler = UDPHandler(cfg, tun)
    return handler, tun


def test_udp_allow_logging(udp_handler, caplog):
    handler, tun = udp_handler
    dest_ip = "8.8.8.8"
    dest_port = 53
    payload = b"hello"
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(dest_ip)
        + struct.pack("!H", dest_port)
        + payload
    )
    client_addr = ("192.0.2.10", 40000)
    caplog.set_level(logging.INFO)
    handler.handle_client_packet(packet, client_addr)
    # Should log an INFO [UDP-ALLOW] message
    records = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.INFO and "[UDP-ALLOW]" in rec.message
    ]
    assert len(records) == 1
    msg = records[0].message
    assert (
        "192.0.2.10:40000" in msg
        and "8.8.8.8:53" in msg
        and f"len={len(payload)}" in msg
    )
    # Packet should be written to tun
    assert len(tun.packets) == 1
    out_packet = tun.packets[0]
    # Check IP and UDP header fields of output packet
    src_ip_bytes = out_packet[12:16]
    dst_ip_bytes = out_packet[16:20]
    assert src_ip_bytes == socket.inet_aton(client_addr[0])
    assert dst_ip_bytes == socket.inet_aton(dest_ip)
    udp_header = out_packet[20:28]
    src_port, dst_port, udp_len, udp_checksum = struct.unpack("!HHHH", udp_header)
    assert src_port == client_addr[1] and dst_port == dest_port
    assert out_packet[28:] == payload


def test_udp_deny_logging(udp_handler, caplog):
    handler, tun = udp_handler
    dest_ip = "192.168.0.1"  # falls within forbidden networks
    dest_port = 80
    payload = b"data"
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(dest_ip)
        + struct.pack("!H", dest_port)
        + payload
    )
    client_addr = ("10.0.0.5", 50000)
    caplog.set_level(logging.WARNING)
    handler.handle_client_packet(packet, client_addr)
    # Should log a WARNING [UDP-DENY] message
    records = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.WARNING and "[UDP-DENY" in rec.message
    ]
    assert len(records) == 1
    msg = records[0].message
    assert "10.0.0.5:50000" in msg and "192.168.0.1:80" in msg
    assert "reason=deny_rule" in msg
    # No packet written to tun
    assert len(tun.packets) == 0


def test_udp_domain_name_resolution(monkeypatch, udp_handler, caplog):
    handler, tun = udp_handler
    resolved_ip = "93.184.216.34"  # example.com resolved result

    def fake_getaddrinfo(name, port, *args, **kwargs):
        assert name == "example.com"
        return [
            (
                socket.AF_INET,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                "",
                (resolved_ip, port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    domain = "example.com"
    dest_port = 80
    payload = b"test"
    packet = (
        b"\x00\x00\x00\x03"
        + bytes([len(domain)])
        + domain.encode()
        + struct.pack("!H", dest_port)
        + payload
    )
    client_addr = ("192.0.2.99", 12345)
    caplog.set_level(logging.INFO)
    handler.handle_client_packet(packet, client_addr)
    # Should log an INFO [UDP-ALLOW] message for resolved domain
    records = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.INFO and "[UDP-ALLOW]" in rec.message
    ]
    assert len(records) == 1
    msg = records[0].message
    assert (
        "192.0.2.99:12345" in msg
        and f"{resolved_ip}:80" in msg
        and f"len={len(payload)}" in msg
    )
    # Packet written to tun should use the resolved IP
    assert len(tun.packets) == 1
    out_packet = tun.packets[0]
    dst_ip_bytes = out_packet[16:20]
    assert dst_ip_bytes == socket.inet_aton(resolved_ip)


def test_udp_fragmented_packet(udp_handler, caplog):
    handler, tun = udp_handler
    packet = (
        b"\x00\x00\x01\x01"
        + socket.inet_aton("8.8.8.8")
        + struct.pack("!H", 53)
        + b"data"
    )
    caplog.set_level(logging.WARNING)
    handler.handle_client_packet(packet, ("192.0.2.10", 11111))
    # Should log warning about fragmented packet
    warnings = [rec for rec in caplog.records if rec.levelno == logging.WARNING]
    assert any("fragmented UDP packet" in rec.message for rec in warnings)
    assert tun.packets == []


@pytest.mark.parametrize(
    "packet",
    [
        b"\x00\x00\x00",  # too short (len < 4)
        b"\x01\x00\x00\x01"
        + socket.inet_aton("1.2.3.4")
        + struct.pack("!H", 80),  # bad reserved byte
        b"\x00\x01\x00\x01"
        + socket.inet_aton("1.2.3.4")
        + struct.pack("!H", 80),  # bad reserved byte
        b"\x00\x00\x00\x05",  # unknown ATYP
        b"\x00\x00\x00\x01\x7f\x00\x00",  # incomplete IPv4 address/port
        b"\x00\x00\x00\x03\x03abc",  # incomplete domain (missing port)
        b"\x00\x00\x00\x04" + b"12345678",  # incomplete IPv6 address
    ],
)
def test_udp_invalid_packets_drop(udp_handler, packet):
    handler, tun = udp_handler
    handler.handle_client_packet(packet, ("192.0.2.10", 22222))
    # No packet should be written to tun for any invalid input
    assert tun.packets == []


def test_udp_ipv6_supported(udp_handler, caplog):
    handler, tun = udp_handler
    dest_ip = "2001:db8::1"
    dest_port = 53
    packet = (
        b"\x00\x00\x00\x04"
        + socket.inet_pton(socket.AF_INET6, dest_ip)
        + struct.pack("!H", dest_port)
        + b"data"
    )
    caplog.set_level(logging.WARNING, logger="socks5-server")
    handler.handle_client_packet(packet, ("2001:db8::100", 33333))

    assert any(
        rec.name == "socks5-server" and rec.levelno == logging.WARNING
        for rec in caplog.records
    )


def test_ip_checksum(udp_handler):
    handler, _ = udp_handler
    # Even-length data
    assert handler._ip_checksum(b"\x00\x00") == 0xFFFF
    assert handler._ip_checksum(b"\xff\xff") == 0x0000
    # Odd-length data
    assert handler._ip_checksum(b"\x00") == 0xFFFF
    assert handler._ip_checksum(b"\xff") == 0x00FF
