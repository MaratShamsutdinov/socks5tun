import socket
import struct
import time


def test_udp_associate_to_dns():
    # === 1. Установим TCP-соединение с SOCKS5-прокси ===
    proxy_addr = ("127.0.0.1", 1080)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(proxy_addr)

    # === 2. Рукопожатие: версия 5, 1 метод, без авторизации ===
    sock.sendall(b"\x05\x01\x00")
    resp = sock.recv(2)
    assert resp == b"\x05\x00", f"Unexpected handshake response: {resp!r}"

    # === 3. Отправим команду UDP ASSOCIATE ===
    # Формат: VER, CMD=3, RSV=0, ATYP=1, ADDR=0.0.0.0, PORT=0
    udp_request = b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00"
    sock.sendall(udp_request)
    resp = sock.recv(10)
    assert resp[1] == 0x00, f"UDP ASSOCIATE failed: {resp!r}"

    # Извлекаем адрес и порт, куда нужно отправлять UDP (скорее всего 127.0.0.1:1080)
    bnd_addr = socket.inet_ntoa(resp[4:8])
    bnd_port = struct.unpack("!H", resp[8:10])[0]

    print(f"[UDP ASSOCIATE] → {bnd_addr}:{bnd_port}")

    # === 4. Отправим UDP-пакет в формате SOCKS5 ===
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind(("127.0.0.1", 0))  # подставим src-порт

    # SOCKS5 UDP header:
    # RSV=0x00 0x00, FRAG=0x00, ATYP=IPv4 (0x01), DST.ADDR, DST.PORT
    dns_server = "8.8.8.8"
    dns_port = 53
    dummy_payload = b"hello"
    udp_header = (
        b"\x00\x00\x00\x01" + socket.inet_aton(dns_server) + struct.pack("!H", dns_port)
    )
    packet = udp_header + dummy_payload

    udp_sock.sendto(packet, (bnd_addr, bnd_port))
    print(f"[UDP SENT] {dns_server}:{dns_port} ← 'hello'")

    # === 5. Ждём 1 сек и завершаем соединения ===
    time.sleep(1)
    udp_sock.close()
    sock.close()
