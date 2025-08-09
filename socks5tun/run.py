# run.py
# !/usr/bin/env python3
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

    cfg.allowed_clients = [ip_network(net) for net in cfg.allowed_clients]
    logger.debug(">> allowed_clients converted to: %s", cfg.allowed_clients)

    cfg.blocked_destinations = [ip_network(net) for net in cfg.blocked_destinations]

    if hasattr(cfg, "deny_rules"):
        cfg.deny_rules = [(ip_network(net), port) for net, port in cfg.deny_rules]
        log.debug(">> deny_rules converted to: %s", cfg.deny_rules)

    if hasattr(cfg, "allow_rules"):
        cfg.allow_rules = [(ip_network(net), port) for net, port in cfg.allow_rules]
        log.debug(">> allow_rules converted to: %s", cfg.allow_rules)

    log.info(
        "Starting Socks5 proxy server on %s:%d",
        cfg.tcp_host,
        cfg.tcp_port,
    )
    # If TUN interface is enabled in config, open it
    tun = None
    if cfg.tun_mode:
        try:
            if cfg.tun_mode == "dummy":
                from socks5tun.dummy_tun import DummyTun

                tun = DummyTun()
                tun.open()
                log.info(
                    "Dummy TUN interface opened "
                    "(not connected to "
                    "system network)",
                )
            elif cfg.tun_mode == "linux":

                TUNSETIFF = 0x400454CA
                IFF_TUN = 0x0001
                IFF_NO_PI = 0x1000
                tun_fd = os.open("/dev/net/tun", os.O_RDWR)
                ifs = fcntl.ioctl(
                    tun_fd,
                    TUNSETIFF,
                    struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI),
                )
                tun_name = ifs[:16].strip(b"\x00").decode('utf-8')
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

                # --- NEW: авто-конфигурация интерфейса и NAT ---

                if os.geteuid() == 0:
                    tun_ip = cfg.tun.get("address", "10.8.0.1")
                    tun_netmask = cfg.tun.get("netmask", "255.255.255.0")
                    peer_ip = cfg.tun.get("peer_address", "10.8.0.2")
                    mtu = cfg.tun.get("mtu", 1500)
                    out_iface = cfg.nat.get("out_iface")

                    try:
                        subprocess.run(
                            [
                                "ip",
                                "addr",
                                "add",
                                f"{tun_ip}/{tun_netmask}",
                                "peer",
                                peer_ip,
                                "dev",
                                tun_name,
                            ],
                            check=True,
                        )
                        subprocess.run(
                            ["ip", "link", "set", tun_name, "mtu", str(mtu)],
                            check=True,
                        )
                        subprocess.run(
                            ["ip", "link", "set", tun_name, "up"],
                            check=True,
                        )
                        log.info(
                            "Configured IP %s peer %s mtu %s on %s",
                            tun_ip,
                            peer_ip,
                            mtu,
                            tun_name,
                        )
                        # Включаем форвардинг
                        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                            f.write("1\n")
                        if out_iface:
                            subprocess.run(
                                [
                                    "iptables",
                                    "-t",
                                    "nat",
                                    "-C",
                                    "POSTROUTING",
                                    "-s",
                                    f"{tun_ip}/{tun_netmask}",
                                    "-o",
                                    out_iface,
                                    "-j",
                                    "MASQUERADE",
                                ],
                                check=False,
                            )
                            subprocess.run(
                                [
                                    "iptables",
                                    "-t",
                                    "nat",
                                    "-A",
                                    "POSTROUTING",
                                    "-s",
                                    f"{tun_ip}/{tun_netmask}",
                                    "-o",
                                    out_iface,
                                    "-j",
                                    "MASQUERADE",
                                ],
                                check=False,
                            )
                            log.info(
                                "Added MASQUERADE rule for %s → %s", tun_name, out_iface
                            )
                    except subprocess.CalledProcessError as e:
                        log.error("Failed to configure TUN/NAT: %s", e)
                        if os.environ.get("ALLOW_CONTINUE_ON_TUN_ERROR") == "1":
                            return
                        else:
                            sys.exit(1)
                else:
                    log.warning(
                        "Skipping TUN/NAT auto-setup: not running as root (UID != 0)"
                    )

                # ------------------------------------------------

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

    threading.Thread(
        target=udp_wrapper,
        daemon=True,
    ).start()
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
                tun_name = cfg.tun.get("name", "tun0")

                # --- Удаляем NAT-правило ---
                try:
                    tun_ip = cfg.tun.get("address", "10.8.0.1")
                    tun_netmask = cfg.tun.get("netmask", "255.255.255.0")
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
                                f"{tun_ip}/{tun_netmask}",
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
                            "Removed MASQUERADE rule for %s → %s",
                            tun_name,
                            out_iface,
                        )
                except Exception as e:
                    log.warning(f"Failed to remove MASQUERADE rule: {e}")

                # --- Удаляем TUN при остановке ---
                log.info(f"Removing TUN interface: {tun_name}")
                try:
                    subprocess.run(
                        [
                            "ip",
                            "tuntap",
                            "del",
                            "dev",
                            tun_name,
                            "mode",
                            "tun",
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                except Exception as e:
                    log.warning(f"Failed to delete tun {tun_name}: {e}")


if __name__ == "__main__":
    main()
