# run.py
#!/usr/bin/env python3
"""
Entry point for the Socks5 proxy server.
"""
import argparse
import logging
import os
import sys
import threading
import subprocess
import json
import fcntl
import struct
from datetime import datetime

from socks5tun.config import load_config
from socks5tun.logger import setup_logging
from socks5tun.server import SocksServer

logger = logging.getLogger(__name__)


def _ipv4_netmask_to_prefixlen(netmask: str) -> int:
    """
    Convert dotted-decimal netmask (e.g. 255.255.255.0) to prefixlen (e.g. 24).
    Raises ValueError on invalid input.
    """
    parts = netmask.split(".")
    if len(parts) != 4:
        raise ValueError(f"Invalid netmask: {netmask}")
    val = 0
    for p in parts:
        n = int(p)
        if n < 0 or n > 255:
            raise ValueError(f"Invalid netmask octet: {p}")
        val = (val << 8) | n
    # must be contiguous ones followed by zeros
    if val == 0 or val == 0xFFFFFFFF:
        raise ValueError(f"Suspicious netmask: {netmask}")
    if (val | (val - 1)) != 0xFFFFFFFF:
        raise ValueError(f"Non-contiguous netmask: {netmask}")
    return bin(val).count("1")


def main():
    parser = argparse.ArgumentParser(description="Socks5 Proxy Server")
    parser.add_argument(
        "-c",
        "--config",
        default="config_prod.json",
        help="Path to configuration JSON file",
    )
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except FileNotFoundError:
        logger.error("Configuration file not found: %s", args.config)
        sys.exit(1)
    except ValueError as e:
        logger.error("Error in configuration: %s", e)
        sys.exit(1)

    # Setup logging with level from config
    setup_logging(cfg.log_level)
    log = logging.getLogger("socks5-server")

    from ipaddress import ip_network

    # Normalize ACLs
    cfg.allowed_clients = [ip_network(net) for net in cfg.allowed_clients]
    log.debug(">> allowed_clients converted to: %s", cfg.allowed_clients)

    if hasattr(cfg, "blocked_destinations"):
        cfg.blocked_destinations = [ip_network(net) for net in cfg.blocked_destinations]

    if hasattr(cfg, "deny_rules"):
        cfg.deny_rules = [(ip_network(net), port) for net, port in cfg.deny_rules]
        log.debug(">> deny_rules converted to: %s", cfg.deny_rules)

    if hasattr(cfg, "allow_rules"):
        cfg.allow_rules = [(ip_network(net), port) for net, port in cfg.allow_rules]
        log.debug(">> allow_rules converted to: %s", cfg.allow_rules)

    log.info("Starting Socks5 proxy server on %s:%d", cfg.tcp_host, cfg.tcp_port)

    # If TUN interface is enabled in config, open it
    tun = None
    tun_name = None
    if cfg.tun_mode:
        try:
            if cfg.tun_mode == "dummy":
                from socks5tun.dummy_tun import DummyTun

                tun = DummyTun()
                tun.open()
                log.info("Dummy TUN interface opened (not connected to system network)")
            elif cfg.tun_mode == "linux":
                # Set desired name from config (fallback to tun%d if busy)
                desired_name = cfg.tun.get("name", "tun0").encode("utf-8")
                if len(desired_name) > 15:
                    raise ValueError("TUN name too long (max 15 bytes)")

                TUNSETIFF = 0x400454CA
                IFF_TUN = 0x0001
                IFF_NO_PI = 0x1000

                tun_fd = os.open("/dev/net/tun", os.O_RDWR)
                # try desired name first
                ifr = struct.pack(
                    "16sH", desired_name.ljust(16, b"\x00"), IFF_TUN | IFF_NO_PI
                )
                try:
                    ifs = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
                except OSError:
                    # fallback to auto name
                    ifs = fcntl.ioctl(
                        tun_fd,
                        TUNSETIFF,
                        struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI),
                    )
                tun_name = ifs[:16].strip(b"\x00").decode("utf-8")
                log.info("🔧 Created TUN interface with name: %s", tun_name)

                class LinuxTun:
                    def __init__(self, fd):
                        self.fd = fd

                    def read(self, size: int = 1500):
                        return os.read(self.fd, size)

                    def write(self, data: bytes):
                        return os.write(self.fd, data)

                    def close(self):
                        os.close(self.fd)

                tun = LinuxTun(tun_fd)
                log.info("Linux TUN interface %s opened", tun_name)

                # --- Auto-configure interface (IPv4 + IPv6). NAT66 остаётся в ExecStartPre. ---
                if os.geteuid() == 0:
                    tun_ip = cfg.tun.get("address", "10.8.0.1")
                    tun_netmask = cfg.tun.get("netmask", "255.255.255.0")
                    try:
                        prefix4 = _ipv4_netmask_to_prefixlen(tun_netmask)
                    except Exception as e:
                        log.warning(
                            "Invalid netmask '%s' (%s); falling back to /24",
                            tun_netmask,
                            e,
                        )
                        prefix4 = 24

                    peer_ip = cfg.tun.get("peer_address", "10.8.0.2")
                    mtu = cfg.tun.get("mtu", 1500)
                    out_iface = cfg.nat.get("out_iface")

                    try:
                        # IPv4 address + peer
                        subprocess.run(
                            [
                                "ip",
                                "addr",
                                "add",
                                f"{tun_ip}/{prefix4}",
                                "peer",
                                peer_ip,
                                "dev",
                                tun_name,
                            ],
                            check=True,
                        )
                    except subprocess.CalledProcessError as e:
                        log.warning(
                            "IPv4 address may already be set on %s: %s", tun_name, e
                        )

                    # MTU + UP
                    subprocess.run(
                        ["ip", "link", "set", tun_name, "mtu", str(mtu)], check=True
                    )
                    subprocess.run(["ip", "link", "set", tun_name, "up"], check=True)

                    log.info(
                        "Configured IPv4 %s/%d peer %s mtu %s on %s",
                        tun_ip,
                        prefix4,
                        peer_ip,
                        mtu,
                        tun_name,
                    )

                    # Enable IPv4 forwarding (temporary; persistent is up to the host)
                    try:
                        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                            f.write("1\n")
                    except Exception as e:
                        log.warning("Failed to enable IPv4 forwarding: %s", e)

                    # (Backward-compat) add IPv4 MASQUERADE if out_iface present
                    if out_iface:
                        try:
                            subprocess.run(
                                [
                                    "iptables",
                                    "-t",
                                    "nat",
                                    "-C",
                                    "POSTROUTING",
                                    "-s",
                                    f"{tun_ip}/{prefix4}",
                                    "-o",
                                    out_iface,
                                    "-j",
                                    "MASQUERADE",
                                ],
                                check=True,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            )
                            added_v4 = False
                        except subprocess.CalledProcessError:
                            subprocess.run(
                                [
                                    "iptables",
                                    "-t",
                                    "nat",
                                    "-A",
                                    "POSTROUTING",
                                    "-s",
                                    f"{tun_ip}/{prefix4}",
                                    "-o",
                                    out_iface,
                                    "-j",
                                    "MASQUERADE",
                                ],
                                check=True,
                            )
                            added_v4 = True
                        if added_v4:
                            log.info(
                                "Added IPv4 MASQUERADE rule for %s → %s",
                                tun_name,
                                out_iface,
                            )

                    # IPv6 address (no NAT here; NAT66 handled by ExecStartPre script)
                    addr6 = cfg.tun.get("address6")  # e.g. "fd00:0:0:8::1/64"
                    peer6 = cfg.tun.get("peer_address6")
                    if addr6:
                        try:
                            subprocess.run(
                                ["ip", "-6", "addr", "add", addr6, "dev", tun_name],
                                check=True,
                            )
                            log.info(
                                "Configured IPv6 %s%s on %s",
                                addr6,
                                f" (peer {peer6})" if peer6 else "",
                                tun_name,
                            )
                        except subprocess.CalledProcessError as e:
                            log.warning(
                                "IPv6 address may already be set on %s: %s", tun_name, e
                            )

                else:
                    log.warning(
                        "Skipping TUN auto-setup: not running as root (UID != 0)"
                    )
            else:
                tun = None
        except Exception as e:
            log.error("Failed to initialize TUN interface: %s", e)
            if os.environ.get("ALLOW_CONTINUE_ON_TUN_ERROR") == "1":
                return
            else:
                sys.exit(1)

    # Start the Socks5 server and UDP relay thread
    from socks5tun.udp_handler import start_udp_loop

    def udp_wrapper():
        try:
            start_udp_loop(cfg, tun)
        except Exception as e:
            log.exception("Exception in UDP thread: %s", e)

    threading.Thread(target=udp_wrapper, daemon=True).start()

    # Prevent self-check from hammering the TCP port as "HTTP"
    os.environ["DISABLE_SELF_CONNECT"] = "1"
    server = SocksServer(cfg, tun=tun)

    try:
        log.info(
            "✅ Starting server, patch is active at %s",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        server.start()
    except KeyboardInterrupt:
        log.info("Server interrupted by user, shutting down")
    finally:
        if tun:
            tun.close()

            if getattr(cfg, "tun_mode", None) == "linux":
                # Clean up IPv4 MASQUERADE (we only add v4 inside run.py)
                try:
                    tun_ip = cfg.tun.get("address", "10.8.0.1")
                    tun_netmask = cfg.tun.get("netmask", "255.255.255.0")
                    try:
                        prefix4 = _ipv4_netmask_to_prefixlen(tun_netmask)
                    except Exception:
                        prefix4 = 24
                    out_iface = cfg.nat.get("out_iface")
                    if out_iface:
                        subprocess.run(
                            [
                                "iptables",
                                "-t",
                                "nat",
                                "-D",
                                "POSTROUTING",
                                "-s",
                                f"{tun_ip}/{prefix4}",
                                "-o",
                                out_iface,
                                "-j",
                                "MASQUERADE",
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                        log.info(
                            "Removed IPv4 MASQUERADE rule for %s → %s",
                            tun_name or "tun",
                            out_iface,
                        )
                except Exception as e:
                    log.warning("Failed to remove IPv4 MASQUERADE rule: %s", e)

                # Optionally remove IPv6 addr (not strictly required)
                try:
                    addr6 = cfg.tun.get("address6")
                    if addr6:
                        subprocess.run(
                            [
                                "ip",
                                "-6",
                                "addr",
                                "del",
                                addr6,
                                "dev",
                                tun_name or cfg.tun.get("name", "tun0"),
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            check=False,
                        )
                except Exception:
                    pass

                # Delete TUN device
                try:
                    subprocess.run(
                        [
                            "ip",
                            "tuntap",
                            "del",
                            "dev",
                            (tun_name or cfg.tun.get("name", "tun0")),
                            "mode",
                            "tun",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    log.info(
                        "Removed TUN interface: %s",
                        tun_name or cfg.tun.get("name", "tun0"),
                    )
                except Exception as e:
                    log.warning("Failed to delete tun %s: %s", tun_name, e)


if __name__ == "__main__":
    main()
