import socket
import struct
import logging
import pytest
from socks5tun.udp_handler import UDPHandler


class DummyTun:
    """Dummy TUN device for testing: collects written packets."""

    def __init__(self):
        self.packets = []

    def write(self, data: bytes):
        # Simply store the packet data written to TUN
        self.packets.append(data)


class DummyConfig:
    def __init__(self):
        # Use system DNS resolver by default
        self.dns_resolver = "system"
        # Define forbidden networks to simulate
        # blocking (default: block private IP ranges)
        self.forbidden_networks = [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "192.168.0.0/16",
            "172.16.0.0/12",
        ]
        # >>> добавь недостающие атрибуты:
        self.udp_host = "127.0.0.1"  # чтобы резолв доменов работал без AttributeError
        self.tun = (
            {}
        )  # пустой dict ок: хэндлер возьмёт client_addr как src при отсутствии peer_address

        # (не обязательно, но можно явно задать)
        self.deny_rules = []
        self.allow_rules = []


@pytest.fixture
def udp_handler():
    cfg = DummyConfig()
    tun = DummyTun()
    handler = UDPHandler(cfg, tun)
    return handler, tun


def test_udp_allow_logging(udp_handler, caplog):
    handler, tun = udp_handler
    # Prepare a UDP packet to a public IP (should be allowed)
    dest_ip = "8.8.8.8"
    dest_port = 53
    payload = b"hello"
    # Build SOCKS5 UDP request: 0x00 0x00
    # (reserved), 0x00 (FRAG), 0x01 (ATYP=IPv4),
    # then dest IPv4 (4 bytes), dest port (2 bytes), then payload
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(dest_ip)
        + struct.pack("!H", dest_port)
        + payload
    )
    client_addr = ("192.0.2.10", 39522)
    # Capture logs at INFO level
    caplog.set_level(logging.INFO)
    handler.handle_client_packet(packet, client_addr)
    # Verify that an INFO log was generated for allowed UDP packet
    records = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.INFO and "[UDP-ALLOW]" in rec.message
    ]
    assert len(records) == 1
    log_msg = records[0].message
    # Log message should contain source, destination and length
    assert log_msg.startswith("[UDP-ALLOW] ")
    assert "192.0.2.10:39522" in log_msg
    assert "8.8.8.8:53" in log_msg
    assert f"len={len(payload)}" in log_msg
    # Verify that the packet was written to TUN
    assert len(tun.packets) == 1
    packet_out = tun.packets[0]
    # The output packet should have correct IP and UDP headers (IPv4)
    # Check IP header source and destination
    src_ip_bytes = packet_out[12:16]
    dst_ip_bytes = packet_out[16:20]
    assert src_ip_bytes == socket.inet_aton(client_addr[0])
    assert dst_ip_bytes == socket.inet_aton(dest_ip)
    # Check UDP header (immediately after 20-byte IP header)
    udp_header = packet_out[20:28]
    src_port, dst_port, udp_len, udp_checksum = struct.unpack(
        "!HHHH",
        udp_header,
    )
    assert src_port == client_addr[1]
    assert dst_port == dest_port
    # Payload in output should match input payload
    output_payload = packet_out[28:]
    assert output_payload == payload


def test_udp_deny_logging(udp_handler, caplog):
    handler, tun = udp_handler
    # Prepare a UDP packet to a forbidden IP (should be denied)
    dest_ip = "192.168.0.1"
    dest_port = 80
    payload = b"data"
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(dest_ip)
        + struct.pack("!H", dest_port)
        + payload
    )
    client_addr = ("10.0.0.5", 60234)
    caplog.set_level(logging.WARNING)
    handler.handle_client_packet(packet, client_addr)
    # Verify that a WARNING log was generated for denied UDP packet
    records = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.WARNING and "[UDP-DENY" in rec.message
    ]
    assert len(records) == 1
    log_msg = records[0].message
    # Log message should indicate the source, destination and deny reason
    assert log_msg.startswith("[UDP-DENY ] ")
    assert "10.0.0.5:60234" in log_msg
    assert "192.168.0.1:80" in log_msg
    assert "reason=deny_rule" in log_msg
    # Ensure that no packet was written to TUN for the denied packet
    # (TUN still has only any packets
    # from previous allowed tests, but no new one added here)
    assert len(tun.packets) == 0  # unchanged from previous state (no new packets)


def test_udp_domain_name_resolution(monkeypatch, udp_handler, caplog):
    handler, tun = udp_handler
    # Monkey-patch socket.getaddrinfo to simulate DNS resolution for a domain
    resolved_ip = "93.184.216.34"  # example.com

    def fake_getaddrinfo(name, port, *args, **kwargs):
        # Should be called with the domain name
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
    # Build a UDP packet with a domain name address (ATYP=3)
    domain = "example.com"
    dest_port = 80
    payload = b"test"
    # SOCKS5 UDP header: reserved,
    # frag=0, ATYP=3, length byte, domain bytes, port, then payload
    packet = (
        b"\x00\x00\x00\x03"
        + bytes([len(domain)])
        + domain.encode('ascii')
        + struct.pack("!H", dest_port)
        + payload
    )
    client_addr = ("192.0.2.10", 40000)
    caplog.set_level(logging.INFO)
    handler.handle_client_packet(packet, client_addr)
    # After handling, there should be an
    # INFO log for the allowed UDP (resolved domain)
    records = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.INFO and "[UDP-ALLOW]" in rec.message
    ]
    assert len(records) == 1
    log_msg = records[0].message
    # The log should contain the resolved IP and port
    assert "192.0.2.10:40000" in log_msg
    assert f"{resolved_ip}:80" in log_msg
    assert f"len={len(payload)}" in log_msg
    # Verify that a packet was written to TUN with the resolved destination IP
    assert len(tun.packets) == 1
    packet_out = tun.packets[0]
    dst_ip_bytes = packet_out[16:20]
    assert dst_ip_bytes == socket.inet_aton(resolved_ip)
