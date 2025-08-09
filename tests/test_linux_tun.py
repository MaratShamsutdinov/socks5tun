import os
import fcntl
import struct
import sys
import select
import socket
import subprocess
import time
import shutil
import pytest

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000


def _ip_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2))
    s = (s >> 16) + (s & 0xFFFF)
    s = (s >> 16) + (s & 0xFFFF)
    return (~s) & 0xFFFF


def _minimal_ipv4_packet(src="10.0.0.1", dst="10.0.0.2", proto=1) -> bytes:
    version_ihl = 0x45  # v4, IHL=5 (20 байт)
    tos = 0
    total_len = 20
    ident = 0
    flags_frag = 0
    ttl = 64
    chk = 0
    src_i = struct.unpack("!I", socket.inet_aton(src))[0]
    dst_i = struct.unpack("!I", socket.inet_aton(dst))[0]
    hdr = struct.pack(
        "!BBHHHBBHII",
        version_ihl,
        tos,
        total_len,
        ident,
        flags_frag,
        ttl,
        proto,
        chk,
        src_i,
        dst_i,
    )
    chk = _ip_checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", chk) + hdr[12:]
    return hdr  # 20 байт


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux")
    or os.getuid() != 0
    or not os.path.exists("/dev/net/tun"),
    reason="Requires root on Linux with /dev/net/tun",
)


def _read_stat(path):
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except Exception:
        return None


def test_linux_tun_open_read_write():
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    try:
        ifs = fcntl.ioctl(
            tun_fd, TUNSETIFF, struct.pack("16sH", b"testtun%d", IFF_TUN | IFF_NO_PI)
        )
        tun_name = ifs[:16].strip(b"\x00").decode("utf-8")
        assert tun_name.startswith("testtun")

        # Поднимаем интерфейс, если есть утилита ip
        if shutil.which("ip"):
            subprocess.run(
                ["ip", "link", "set", tun_name, "up"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        stats_dir = f"/sys/class/net/{tun_name}/statistics"
        rx_before = _read_stat(os.path.join(stats_dir, "rx_packets"))
        rx_bytes_before = _read_stat(os.path.join(stats_dir, "rx_bytes"))

        pkt = _minimal_ipv4_packet()
        try:
            written = os.write(tun_fd, pkt)
            assert written == len(pkt)
        except OSError as e:
            assert e.errno in (5, 22), f"unexpected errno: {e.errno}"
            return

        time.sleep(0.1)  # дать ядру время обновить статистику

        rx_after = _read_stat(os.path.join(stats_dir, "rx_packets"))
        rx_bytes_after = _read_stat(os.path.join(stats_dir, "rx_bytes"))
        if rx_before is not None and rx_after is not None:
            assert (
                rx_after >= rx_before + 1
            ), f"rx_packets not increased: {rx_before} -> {rx_after}"
        if rx_bytes_before is not None and rx_bytes_after is not None:
            assert rx_bytes_after >= rx_bytes_before + len(
                pkt
            ), f"rx_bytes not increased enough"

        rlist, _, _ = select.select([tun_fd], [], [], 0.05)
        if rlist:
            _ = os.read(tun_fd, 1500)
    finally:
        try:
            os.close(tun_fd)
        except OSError:
            pass
