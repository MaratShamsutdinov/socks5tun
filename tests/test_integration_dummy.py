import socket
import threading
import struct
import time
import pytest
from socks5tun.dummy_tun import DummyTun
from socks5tun.config import Config
from socks5tun.server import SocksServer
from socks5tun.udp_handler import start_udp_loop, UDPHandler


def test_udp_relay_ping_pong():
    # Configure and start Socks5 server with DummyTun
    cfg = Config(
        {
            "tcp_host": "127.0.0.1",
            "tcp_port": 1080,
            "udp_host": "127.0.0.1",
            "udp_port": 1080,
            "tun_mode": "dummy",
        }
    )
    tun = DummyTun()
    tun.open()
    server = SocksServer(cfg, tun=tun)
    udp_thread = threading.Thread(target=start_udp_loop, args=(cfg, tun), daemon=True)
    server_thread = threading.Thread(target=server.start, daemon=True)
    udp_thread.start()
    server_thread.start()
    time.sleep(0.1)  # give threads time to start
    # SOCKS5 UDP Associate handshake
    client_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_tcp.connect(("127.0.0.1", cfg.tcp_port))
    # Negotiation (no auth)
    client_tcp.sendall(b"\x05\x01\x00")
    resp = client_tcp.recv(2)
    assert resp == b"\x05\x00"
    # Request UDP ASSOCIATE (IPv4 0.0.0.0:0)
    request = b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
    client_tcp.sendall(request)
    reply = client_tcp.recv(10)
    ver, rep, rsv, atyp = reply[0], reply[1], reply[2], reply[3]
    assert ver == 5 and rep == 0
    if atyp == 0x01:
        bnd_addr = socket.inet_ntoa(reply[4:8])
        bnd_port = struct.unpack("!H", reply[8:10])[0]
    else:
        pytest.skip("Unexpected ATYP in UDP ASSOCIATE reply")
    assert bnd_port == cfg.udp_port
    # UDP communication: send ping, expect pong
    client_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_udp.bind(("127.0.0.1", 0))
    dest_ip = "1.1.1.1"
    dest_port = 4321
    payload = b"ping"
    packet = (
        b"\x00\x00\x00\x01"
        + socket.inet_aton(dest_ip)
        + struct.pack("!H", dest_port)
        + payload
    )
    client_udp.sendto(packet, ("127.0.0.1", cfg.udp_port))
    # Wait for packet to be written to DummyTun
    start_time = time.time()
    while not tun._outgoing_data:
        if time.time() - start_time > 1:
            pytest.fail("Timed out waiting for outgoing packet in DummyTun")
        time.sleep(0.01)
    out_packet = tun._outgoing_data.popleft()
    # Verify IP header and UDP header of outgoing packet
    src_ip = socket.inet_ntoa(out_packet[12:16])
    dst_ip = socket.inet_ntoa(out_packet[16:20])
    src_port = int.from_bytes(out_packet[20:22], "big")
    dst_port = int.from_bytes(out_packet[22:24], "big")
    assert src_ip == "127.0.0.1" and dst_ip == dest_ip
    assert dst_port == dest_port and src_port == client_udp.getsockname()[1]
    assert out_packet[28:] == payload
    # Simulate a UDP reply from remote (pong)
    client_port = client_udp.getsockname()[1]
    src_ip_reply = dest_ip
    dst_ip_reply = "127.0.0.1"
    src_port_reply = dest_port
    dst_port_reply = client_port
    payload_reply = b"pong"
    total_length = 20 + 8 + len(payload_reply)
    # Build IPv4 header with zero checksum first
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        socket.inet_aton(src_ip_reply),
        socket.inet_aton(dst_ip_reply),
    )
    # Compute checksum
    udp_handler = UDPHandler(cfg, tun)
    checksum = udp_handler._ip_checksum(ip_header)
    # Construct final IP header with checksum
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        socket.IPPROTO_UDP,
        checksum,
        socket.inet_aton(src_ip_reply),
        socket.inet_aton(dst_ip_reply),
    )
    udp_header = struct.pack(
        "!HHHH", src_port_reply, dst_port_reply, 8 + len(payload_reply), 0
    )
    response_packet = ip_header + udp_header + payload_reply
    tun.inject(response_packet)
    client_udp.settimeout(1)
    resp_data, resp_addr = client_udp.recvfrom(65535)
    # Verify received UDP response has pong payload
    assert resp_addr[0] == "127.0.0.1"
    # SOCKS5 UDP response header: 0x00 0x00 0x00 0x01 + src IP + src port
    assert resp_data[:4] == b"\x00\x00\x00\x01"
    recv_ip = socket.inet_ntoa(resp_data[4:8])
    recv_port = struct.unpack("!H", resp_data[8:10])[0]
    assert recv_ip == src_ip_reply and recv_port == src_port_reply
    assert resp_data[10:] == payload_reply
    # Clean up
    client_udp.close()
    client_tcp.close()
    tun.close()


def test_tcp_tunnel_echo():
    # Start a simple echo server
    class EchoServer(threading.Thread):
        def __init__(self):
            super().__init__(daemon=True)
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.bind(("127.0.0.1", 0))
            self.sock.listen()
            self.port = self.sock.getsockname()[1]

        def run(self):
            conn, addr = self.sock.accept()
            data = conn.recv(1024)
            if data:
                conn.sendall(data)
            conn.close()
            self.sock.close()

    echo_server = EchoServer()
    echo_server.start()
    # Configure and start Socks5 server
    cfg = Config(
        {
            "tcp_host": "127.0.0.1",
            "tcp_port": 1081,
            "udp_host": "127.0.0.1",
            "udp_port": 1081,
            "tun_mode": "dummy",
        }
    )
    tun = DummyTun()
    tun.open()
    server = SocksServer(cfg, tun=tun)
    udp_thread = threading.Thread(target=start_udp_loop, args=(cfg, tun), daemon=True)
    server_thread = threading.Thread(target=server.start, daemon=True)
    udp_thread.start()
    server_thread.start()
    time.sleep(0.1)
    # SOCKS5 handshake and TCP connect
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", cfg.tcp_port))
    client.sendall(b"\x05\x01\x00")
    resp = client.recv(2)
    assert resp == b"\x05\x00"
    dest_ip = "127.0.0.1"
    dest_port = echo_server.port
    request = (
        b"\x05\x01\x00\x01" + socket.inet_aton(dest_ip) + struct.pack("!H", dest_port)
    )
    client.sendall(request)
    reply = client.recv(10)
    ver, rep = reply[0], reply[1]
    assert ver == 5 and rep == 0
    # Send data and verify echo
    message = b"Hello, world"
    client.sendall(message)
    echoed = client.recv(len(message))
    assert echoed == message
    client.close()
    echo_server.join(timeout=1)
    tun.close()
