# udp_handler.py
import socket
import logging
import struct
import threading
from ipaddress import ip_address, ip_network

logger = logging.getLogger("socks5-server")


class UDPHandler:
    def __init__(self, cfg, tun):
        self.cfg = cfg
        self.tun = tun
        self.remote_map = {}
        # Load legacy forbidden networks if present (for compatibility)
        self.forbidden_networks = []
        if hasattr(cfg, "forbidden_networks"):
            for net in cfg.forbidden_networks:
                try:
                    self.forbidden_networks.append(ip_network(net))
                except ValueError:
                    continue

    def _ip_checksum(self, data: bytes) -> int:
        """Calculate IPv4 header checksum."""
        if len(data) % 2 == 1:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            word = data[i] << 8 | data[i + 1]
            total += word
        total = (total >> 16) + (total & 0xFFFF)
        total = ~total & 0xFFFF
        return total

    def handle_client_packet(self, data: bytes, client_addr):
        """
        Handle a UDP packet from client (SOCKS5 UDP ASSOCIATE).
        data: raw UDP datagram from client (including SOCKS5 UDP header).
        client_addr: tuple (src_ip, src_port) of the client.
        """
        # Minimum UDP header length is 4 bytes
        if len(data) < 4:
            return
        # Check reserved bytes and fragmentation field
        if data[0] != 0x00 or data[1] != 0x00:
            return  # Invalid reserved field
        frag = data[2]
        if frag != 0x00:
            logger.warning(
                f"Received fragmented UDP packet from {client_addr}, dropping"
            )
            return
        atyp = data[3]
        offset = 4
        dest_addr = None
        dest_port = None
        # Parse destination based on ATYP
        if atyp == 0x01:  # IPv4
            if len(data) < offset + 6:
                return
            dest_addr = socket.inet_ntoa(data[offset : offset + 4])
            offset += 4
            dest_port = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
        elif atyp == 0x03:  # Domain name
            if len(data) < offset + 1:
                return
            name_len = data[offset]
            offset += 1
            if len(data) < offset + name_len + 2:
                return
            dest_name = data[offset : offset + name_len].decode(
                'ascii', errors='ignore'
            )
            offset += name_len
            dest_port = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            # Resolve domain to IP
            if getattr(self.cfg, "dns_resolver", "system") == "system":
                try:
                    addrs = socket.getaddrinfo(
                        dest_name, dest_port, proto=socket.IPPROTO_UDP
                    )
                except Exception:
                    logger.warning(
                        f"[UDP-DENY ] {client_addr[0]}:{client_addr[1]}"
                        f" → {dest_name}:{dest_port} reason=resolve_fail"
                    )
                    return
            else:
                try:
                    addrs = socket.getaddrinfo(
                        dest_name, dest_port, proto=socket.IPPROTO_UDP
                    )
                except Exception:
                    logger.warning(
                        f"[UDP-DENY ] {client_addr[0]}:{client_addr[1]}"
                        f" → {dest_name}:{dest_port} reason=resolve_fail"
                    )
                    return
            if not addrs:
                logger.warning(
                    f"[UDP-DENY ] {client_addr[0]}:{client_addr[1]}"
                    f" → {dest_name}:{dest_port} reason=resolve_fail"
                )
                return
            dest_addr = addrs[0][4][0]
        elif atyp == 0x04:  # IPv6
            if len(data) < offset + 18:
                return
            try:
                dest_addr = socket.inet_ntop(
                    socket.AF_INET6, data[offset : offset + 16]
                )
            except OSError:
                return
            offset += 16
            dest_port = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
        else:
            return
        payload = data[offset:]
        if dest_addr is None:
            return
        # Apply allow/deny filtering
        allowed = True
        reason = "deny_rule"
        try:
            ip_obj = ip_address(dest_addr)
        except ValueError:
            ip_obj = None
        if ip_obj:
            # Check deny rules
            for net, port in getattr(self.cfg, "deny_rules", []):
                if ip_obj in net and (port is None or dest_port == port):
                    allowed = False
                    break

            # Check legacy forbidden networks if no explicit deny rules
            if allowed and not getattr(self.cfg, "deny_rules", []):
                for net in self.forbidden_networks:
                    if ip_obj in net:
                        allowed = False
                        break

            # Check allow rules
            if allowed and getattr(self.cfg, "allow_rules", []):
                matched = False
                for net, port in self.cfg.allow_rules:
                    if ip_obj in net and (port is None or dest_port == port):
                        matched = True
                        break
                if not matched:
                    allowed = False
        else:
            allowed = False
        if not allowed:
            logger.warning(
                f"[UDP-DENY ] {client_addr[0]}:{client_addr[1]}"
                f" → {dest_addr}:{dest_port} reason={reason}"
            )
            return
        # Build packet and forward to TUN (IPv4 only)
        ip_obj = ip_address(dest_addr)
        if ip_obj.version == 4:
            src_ip = client_addr[0]
            src_port = client_addr[1] & 0xFFFF
            dst_ip = dest_addr
            # IPv4 header
            version = 4
            ihl = 5
            ver_ihl = (version << 4) + ihl
            tos = 0
            total_length = 20 + 8 + len(payload)
            identification = 0
            flags_offset = 0
            ttl = 64
            protocol = socket.IPPROTO_UDP
            src_ip_bytes = socket.inet_aton(src_ip)
            dst_ip_bytes = socket.inet_aton(dst_ip)
            # Initial header with zero checksum
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                ver_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                0,
                src_ip_bytes,
                dst_ip_bytes,
            )
            checksum = self._ip_checksum(ip_header)
            # Final IP header with checksum
            ip_header = struct.pack(
                "!BBHHHBBH4s4s",
                ver_ihl,
                tos,
                total_length,
                identification,
                flags_offset,
                ttl,
                protocol,
                checksum,
                src_ip_bytes,
                dst_ip_bytes,
            )
            # UDP header
            dst_port_net = dest_port & 0xFFFF
            udp_length = 8 + len(payload)
            udp_header = struct.pack(
                "!HHHH",
                src_port,
                dst_port_net,
                udp_length,
                0,
            )
            packet = ip_header + udp_header + payload
            self.tun.write(packet)
            self.remote_map[(dest_addr, dest_port)] = client_addr
        elif ip_obj.version == 6:
            logger.warning(
                f"Cannot forward UDP to IPv6 address"
                f" {dest_addr} "
                f"(not supported)"
            )
            return
        else:
            return
        # Log forwarded packet as allowed
        logger.info(
            f"[UDP-ALLOW] {client_addr[0]}:{client_addr[1]}"
            f" → {dest_addr}:{dest_port} len={len(payload)}"
        )


def start_udp_loop(cfg, tun):
    """
    Start a loop to handle global UDP relay.
    Listens on cfg.udp_host:cfg.udp_port for UDP traffic.
    """
    family = socket.AF_INET6 if ':' in cfg.udp_host else socket.AF_INET
    udp_sock = socket.socket(family, socket.SOCK_DGRAM)
    logger.debug("[BOOT] Entered start_udp_loop()")
    try:
        udp_sock.bind((cfg.udp_host, cfg.udp_port))
    except OSError as e:
        logger.error(
            "Failed to bind UDP socket on %s:%d — %s",
            cfg.udp_host,
            cfg.udp_port,
            e,
        )
        return

    logger.info(
        "[DEBUG] Bound UDP socket on %s:%d",
        cfg.udp_host,
        cfg.udp_port,
    )
    logger.info(f"UDP relay socket listening on {cfg.udp_host}:{cfg.udp_port}")
    # Mapping for direct UDP mode (dest -> client)
    remote_map = {}
    # Handler for client packets
    handler = UDPHandler(cfg, tun)
    handler.remote_map = remote_map
    # If TUN interface is available, start thread to handle incoming packets from TUN
    if tun:

        def tun_reader():
            while True:
                try:
                    packet = tun.read()
                except Exception as e:
                    logger.error("UDP tun read error: %s", e)
                    break
                if not packet:
                    break
                # Only handle IPv4 UDP packets from tun
                if len(packet) < 20:
                    continue
                version = packet[0] >> 4
                if version != 4:
                    # Only IPv4 supported for now
                    continue
                proto = packet[9]
                if proto != socket.IPPROTO_UDP:
                    continue
                src_ip = socket.inet_ntoa(packet[12:16])
                dst_ip = socket.inet_ntoa(packet[16:20])
                src_port = int.from_bytes(packet[20:22], 'big')
                dst_port = int.from_bytes(packet[22:24], 'big')
                payload = packet[28:]
                client_key = (src_ip, src_port)
                # If we have a client for this dest, forward to it
                if client_key in remote_map:
                    client_addr = remote_map[client_key]
                else:
                    # No mapping, drop
                    logger.warning(
                        f"Received UDP packet from {src_ip}:{src_port} with "
                        "no client mapping for {dst_ip}:{dst_port}"
                    )
                    continue
                # Build SOCKS UDP response
                try:
                    if ':' in src_ip:
                        addr_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
                        resp_atyp = 0x04
                    else:
                        addr_bytes = socket.inet_aton(src_ip)
                        resp_atyp = 0x01
                    port_bytes = src_port.to_bytes(2, 'big')
                    resp_header = (
                        b"\x00\x00\x00" + bytes([resp_atyp]) + addr_bytes + port_bytes
                    )
                except Exception as e:
                    logger.error(
                        "Failed to build UDP response header for %s: %s", src_ip, e
                    )
                    continue
                response_data = resp_header + payload
                try:
                    udp_sock.sendto(response_data, client_addr)
                except Exception as e:
                    logger.error(
                        "Failed to send UDP packet to client %s:%d - %s",
                        client_addr[0],
                        client_addr[1],
                        e,
                    )

        threading.Thread(target=tun_reader, daemon=True).start()
    # Main loop to handle incoming UDP datagrams on socket
    logger.debug("[BOOT] Entering UDP receive loop...")

    while True:
        try:
            logger.debug("[LOOP] Waiting for UDP packet...")
            data, addr = udp_sock.recvfrom(65535)
            logger.debug(
                "[TRACE] --- UDP packet received from %s:%d ---",
                addr[0],
                addr[1],
            )

            logger.debug(
                "[DEBUG] Got UDP from %s:%d, len=%d",
                addr[0],
                addr[1],
                len(data),
            )
            client_ip, client_port = addr[0], addr[1]
            try:
                ip_obj = ip_address(client_ip)
            except ValueError:
                ip_obj = None
            is_client = ip_obj is not None and any(
                ip_obj in net for net in cfg.allowed_clients
            )

            # ✅ ДОПОЛНИТЕЛЬНЫЕ ЛОГИ
            logger.debug("[TRACE] UDP packet from: %s:%d", client_ip, client_port)
            logger.debug("[TRACE] Evaluated ip_obj: %s", ip_obj)
            logger.debug("[TRACE] allowed_clients: %s", cfg.allowed_clients)
            logger.debug("[TRACE] is_client: %s", is_client)

        except Exception as e:
            logger.error("UDP socket error: %s", e)
            break
        client_ip, client_port = addr[0], addr[1]
        try:
            ip_obj = ip_address(client_ip)
        except ValueError:
            ip_obj = None
        is_client = ip_obj is not None and any(
            ip_obj in net for net in cfg.allowed_clients
        )
        logger.debug("[CHECK] Incoming UDP from %s:%d", client_ip, client_port)
        logger.debug("[CHECK] allowed_clients = %s", cfg.allowed_clients)
        logger.debug("[CHECK] ip_obj = %s", ip_obj)
        logger.debug("[CHECK] is_client = %s", is_client)

        if is_client:
            # UDP datagram from an allowed client
            if tun:
                logger.debug(
                    "[DEBUG] handle_client_packet from %s:%d, raw: %s",
                    addr[0],
                    addr[1],
                    data.hex(),
                )
                try:
                    handler.handle_client_packet(data, addr)
                except Exception as e:
                    logger.error("Exception in handle_client_packet: %s", e)

            else:
                # Handle direct UDP forward (no TUN)

                if len(data) < 4:
                    continue
                if data[0] != 0x00 or data[1] != 0x00:
                    continue
                frag = data[2]
                if frag != 0x00:
                    continue
                atyp = data[3]
                off = 4
                dest_addr = None
                dest_port = None
                if atyp == 0x01:
                    if len(data) < off + 6:
                        continue
                    dest_addr = socket.inet_ntoa(data[off : off + 4])
                    off += 4
                    dest_port = int.from_bytes(data[off : off + 2], 'big')
                    off += 2
                elif atyp == 0x03:
                    if len(data) < off + 1:
                        continue
                    name_len = data[off]
                    off += 1
                    if len(data) < off + name_len + 2:
                        continue
                    dest_name = data[off : off + name_len].decode(
                        'ascii', errors='ignore'
                    )
                    off += name_len
                    dest_port = int.from_bytes(data[off : off + 2], 'big')
                    off += 2
                    try:
                        dest_addr = socket.gethostbyname(dest_name)
                    except Exception as e:
                        logger.warning(
                            f"[UDP-DENY ] {client_ip}:{client_port}"
                            f" → {dest_name}:{dest_port} reason=resolve_fail"
                        )
                        continue
                elif atyp == 0x04:
                    if len(data) < off + 18:
                        continue
                    try:
                        dest_addr = socket.inet_ntop(
                            socket.AF_INET6, data[off : off + 16]
                        )
                    except OSError:
                        continue
                    off += 16
                    dest_port = int.from_bytes(data[off : off + 2], 'big')
                    off += 2
                else:
                    continue
                payload = data[off:]
                if dest_addr is None:
                    continue
                # Filtering
                allowed = True
                reason = "deny_rule"
                try:
                    dest_ip_obj = ip_address(dest_addr)
                except ValueError:
                    dest_ip_obj = None
                if dest_ip_obj:
                    for net, port in getattr(cfg, "deny_rules", []):
                        if dest_ip_obj in net and (port is None or dest_port == port):
                            allowed = False
                            break
                    if allowed and getattr(cfg, "allow_rules", []):
                        match = False
                        for net, port in cfg.allow_rules:
                            if dest_ip_obj in net and (
                                port is None or dest_port == port
                            ):
                                match = True
                                break
                        if not match:
                            allowed = False
                else:
                    allowed = False
                if not allowed:
                    logger.warning(
                        f"[UDP-DENY ] {client_ip}:{client_port}"
                        f" → {dest_addr}:{dest_port} reason={reason}"
                    )
                    continue
                # Forward to remote
                try:
                    logger.debug(
                        "[SEND] Sending UDP to %s:%d (payload %d bytes): %s",
                        dest_addr,
                        dest_port,
                        len(payload),
                        payload.hex(),
                    )
                    udp_sock.sendto(payload, (dest_addr, dest_port))
                except Exception as e:
                    logger.error(
                        "Failed to relay UDP to %s:%d - %s",
                        dest_addr,
                        dest_port,
                        e,
                    )
                    continue
                # Update mapping for return traffic
                remote_map[(dest_addr, dest_port)] = addr
                logger.info(
                    f"[UDP-ALLOW] {client_ip}:{client_port}"
                    f" → {dest_addr}:{dest_port} len={len(payload)}"
                )
        else:
            # UDP datagram from remote host
            logger.debug(
                "[REJECT] UDP from %s:%d rejected: not in allowed_clients",
                client_ip,
                client_port,
            )
            if tun:
                # Should not happen (remote replies handled via tun), ignore
                continue
            # Direct mode: relay back to client if known
            remote_ip, remote_port = client_ip, client_port
            if (remote_ip, remote_port) not in remote_map:
                continue
            client_addr = remote_map[(remote_ip, remote_port)]
            # Build SOCKS UDP response
            try:
                if ':' in remote_ip:
                    addr_bytes = socket.inet_pton(socket.AF_INET6, remote_ip)
                    resp_atyp = 0x04
                else:
                    addr_bytes = socket.inet_aton(remote_ip)
                    resp_atyp = 0x01
                port_bytes = remote_port.to_bytes(2, 'big')
                resp_header = (
                    b"\x00\x00\x00" + bytes([resp_atyp]) + addr_bytes + port_bytes
                )
            except Exception as e:
                logger.error(
                    "Failed to build UDP response header for %s: %s",
                    remote_ip,
                    e,
                )
                continue
            response_data = resp_header + data
            udp_sock.sendto(response_data, client_addr)
