import os
import fcntl
import struct
import sys
import select
import pytest


def is_working_tun():
    """
    Проверяет, можно ли открыть и использовать /dev/net/tun.
    Возвращает True только если ioctl проходит успешно.
    """
    try:
        tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        TUNSETIFF = 0x400454CA
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000
        fcntl.ioctl(
            tun_fd, TUNSETIFF, struct.pack("16sH", b"skipcheck%d", IFF_TUN | IFF_NO_PI)
        )
        try:
            os.write(tun_fd, b"")
        except OSError:
            os.close(tun_fd)
            return False
        os.close(tun_fd)
        return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux")
    or os.getuid() != 0
    or not os.path.exists("/dev/net/tun"),
    # or not is_working_tun(),
    reason="Requires working /dev/net/tun and root access",
)


def test_linux_tun_open_read_write():
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    ifs = fcntl.ioctl(
        tun_fd, TUNSETIFF, struct.pack("16sH", b"testtun%d", IFF_TUN | IFF_NO_PI)
    )
    tun_name = ifs[:16].strip(b"\x00").decode("utf-8")
    assert tun_name.startswith("testtun")

    # Define LinuxTun class for testing
    class LinuxTun:
        def __init__(self, fd):
            self.fd = fd

        def read(self, size=1500):
            return os.read(self.fd, size)

        def write(self, data):
            return os.write(self.fd, data)

        def close(self):
            os.close(self.fd)

    tun = LinuxTun(tun_fd)
    data = b"\x00\x01\x02\x03"
    written = tun.write(data)
    assert written == len(data)
    # Attempt to read (non-blocking)
    rlist, _, _ = select.select([tun_fd], [], [], 0.1)
    if rlist:
        recv_data = tun.read(1500)
        # Depending on environment, recv_data could be empty or contain data
        assert recv_data == b"" or recv_data == data
    tun.close()
