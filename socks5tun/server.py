# server.py
import os
import inspect
import psutil
import traceback
import socket
import threading
import select
import logging
import ipaddress

from socks5tun.config import Config

# SOCKS5 protocol constants and values
SOCKS_VERSION = 5
# Authentication methods
NO_AUTH = 0x00
USER_AUTH = 0x02
NO_ACCEPTABLE = 0xFF
# Command codes
CMD_CONNECT = 0x01
CMD_BIND = 0x02  # BIND not implemented
CMD_UDP_ASSOCIATE = 0x03
# Address types
ADDR_IPV4 = 0x01
ADDR_DOMAIN = 0x03
ADDR_IPV6 = 0x04
# Reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONN_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_CMD_NOT_SUPPORTED = 0x07
REP_ADDR_NOT_SUPPORTED = 0x08


# Порты, с которых мы ожидаем локальный форвардинг (stunnel, ssh -L, tun2socks и т.п.)
LOCAL_FORWARD_WHITELIST = {443, 1080, 1194}


def is_self_connection(
    client_ip: str, client_port: int, server_port: int
) -> tuple[str, str]:
    """
    Определяет тип соединения:
    - 'self' — loopback + клиентский порт = порт сервера (реальный self-connect)
    - 'local_forward' — loopback + порт клиента в whitelist (ожидаемый локальный форвардер)
    - 'local_other' — loopback всё остальное
    - 'other' — всё остальное
    """
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        ip_obj = None

    if ip_obj and ip_obj.is_loopback:
        pname = "unknown"
        pid = None
        for conn in psutil.net_connections(kind='tcp'):
            if not conn.laddr or not conn.raddr:
                continue
            if (
                conn.laddr[1] == server_port
                and conn.raddr[0] == client_ip
                and conn.raddr[1] == client_port
            ):
                pid = conn.pid
                if pid:
                    try:
                        pname = psutil.Process(pid).name()
                    except Exception:
                        pass
                break

        # 1. Настоящий self-connect
        if client_port == server_port:
            return "self", f"{pid} {pname}"

        # 2. Локальный форвард (по whitelist портов)
        if client_port in LOCAL_FORWARD_WHITELIST:
            return "local_forward", f"{pid} {pname}"

        # 3. Остальное loopback
        return "local_other", f"{pid} {pname if pname else 'unknown'}"

    return "other", "unknown"


def recv_exact(conn, n):
    """Читает ровно n байт из сокета, иначе выбрасывает исключение."""
    data = b''
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise IOError("Connection closed prematurely")
        data += chunk
    return data


class SocksServer:
    """
    A Socks5 proxy server that handles TCP CONNECT and UDP ASSOCIATE commands.
    """

    def __init__(self, config: Config, tun=None):
        self.config = config
        self.tun = tun  # DummyTun or real TUN interface if provided
        self._log = logging.getLogger("socks5-server")
        # Prepare allowed client networks
        self.allowed_nets = config.allowed_clients
        # Authentication setup
        self.auth_required = config.auth is not None
        self.auth_credentials = config.auth if config.auth else {}

    def start(self):
        """
        Start the Socks5 server: bind and listen for incoming connections,
        handle each in a new thread.
        """

        self._log.warning(
            "[DEBUG] Server started — stack:\n%s",
            ''.join(traceback.format_stack(limit=10)),
        )

        # Выбираем тип адреса
        family = socket.AF_INET6 if ':' in self.config.tcp_host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.config.tcp_host, self.config.tcp_port))
            server_sock.listen()
            self._log.info(
                "Listening on %s:%d",
                self.config.tcp_host,
                self.config.tcp_port,
            )

            while True:
                try:
                    client_sock, client_addr = server_sock.accept()

                    # --- NEW: проверка IP клиента ---
                    if not self._is_client_allowed(client_addr[0]):
                        self._log.warning(
                            "Rejected connection from %s:%d "
                            "(not in allowed_clients)",
                            client_addr[0],
                            client_addr[1],
                        )
                        client_sock.close()
                        continue  # ждём следующий accept
                    # --------------------------------

                    # Определяем тип подключения и информацию о процессе
                    ctype, who = is_self_connection(
                        client_addr[0], client_addr[1], self.config.tcp_port
                    )

                    if ctype == "self":
                        # Настоящий self-test
                        self._log.info(
                            "[🧪 SELF-TEST] Accepted internal connection "
                            "from %s:%d (%s)",
                            client_addr[0],
                            client_addr[1],
                            who,
                        )
                        stack = inspect.stack()
                        self._log.debug(
                            "Top call: %s:%d in %s()",
                            stack[1].filename,
                            stack[1].lineno,
                            stack[1].function,
                        )

                    elif ctype == "local_stunnel":
                        # Локальный stunnel на loopback
                        self._log.info(
                            "[LOCAL STUNNEL] TCP connection from %s:%d (%s)",
                            client_addr[0],
                            client_addr[1],
                            who,
                        )

                    elif ctype == "local_other":
                        self._log.info(
                            "[LOCAL] TCP connection from %s:%d (%s)",
                            client_addr[0],
                            client_addr[1],
                            who,
                        )

                    elif ctype == "local_forward":
                        self._log.info(
                            "[LOCAL FORWARD] TCP connection from %s:%d (%s)",
                            client_addr[0],
                            client_addr[1],
                            who,
                        )

                    else:
                        # Любое другое подключение
                        self._log.info(
                            "[ACCEPT] TCP connection from %s:%d by %s",
                            client_addr[0],
                            client_addr[1],
                            who,
                        )
                        self._log.debug(
                            "[TRACE] Stack trace for connection from %s:%d:\n%s",
                            client_addr[0],
                            client_addr[1],
                            ''.join(traceback.format_stack(limit=8)),
                        )

                    # Запускаем обработчик клиента в отдельном потоке
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_addr),
                        daemon=True,
                    ).start()

                except OSError:
                    break

    def _is_client_allowed(self, client_ip: str) -> bool:
        """Check if the client IP is in allowed networks."""
        ip_obj = ipaddress.ip_address(client_ip)
        return any(ip_obj in net for net in self.allowed_nets)

    def _is_dest_allowed(self, dest_ip: str, dest_port: int) -> bool:
        """Check if the destination IP:
        port is permitted by allow/deny rules."""
        try:
            ip_obj = ipaddress.ip_address(dest_ip)
        except Exception:
            return False
        # Deny rules
        for net, port in getattr(self.config, "deny_rules", []):
            if ip_obj in net and (port is None or dest_port == port):
                return False
        # Allow rules
        allow_rules = getattr(self.config, "allow_rules", [])
        if allow_rules:
            allowed = False
            for net, port in allow_rules:
                if ip_obj in net and (port is None or dest_port == port):
                    allowed = True
                    break
            if not allowed:
                return False
        return True

    def _handle_client(self, conn: socket.socket, client_addr):
        if client_addr[0] == "127.0.0.1":
            self._log.warning(
                "👀 LOCAL connection from %s — likely self-initiated",
                client_addr[0],
            )

        try:
            # Для DummySocket в тестах отключаем setsockopt
            if hasattr(conn, "setsockopt"):
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            header = recv_exact(conn, 2)
            self._log.warning(
                "[SNIFF] First 2 bytes from %s:%d: hex=%s ascii=%r",
                client_addr[0],
                client_addr[1],
                header.hex(),
                header,
            )
            proto_guess = None
            if header.startswith(b"PO") or header.startswith(b"GE"):
                proto_guess = "HTTP"
            elif header.startswith(b"\x16\x03"):
                proto_guess = "TLS"
            elif header.startswith(b"CO"):
                proto_guess = "HTTPS proxy (CONNECT)"
            elif header[0] != 0x05:
                proto_guess = "Unknown non-SOCKS"

            if proto_guess:
                self._log.warning(
                    "[GUESS] %s:%d likely using %s instead of SOCKS5",
                    client_addr[0],
                    client_addr[1],
                    proto_guess,
                )
            ver, nmethods = header[0], header[1]
            self._log.info(
                "SOCKS5 handshake header from %s: %s", client_addr[0], header.hex()
            )

            if ver != SOCKS_VERSION:
                self._log.error(
                    "Unsupported SOCKS version %d from %s", ver, client_addr[0]
                )
                conn.close()
                return

            methods = recv_exact(conn, nmethods)
            self._log.info(
                "SOCKS5 methods from %s: %s",
                client_addr[0],
                methods.hex(),
            )

            self._log.debug(
                "[DEBUG] Waiting for SOCKS5 request from %s:%d...",
                client_addr[0],
                client_addr[1],
            )

            if self.auth_required:
                if USER_AUTH not in methods:
                    conn.sendall(bytes([SOCKS_VERSION, NO_ACCEPTABLE]))
                    conn.close()
                    return
                conn.sendall(bytes([SOCKS_VERSION, USER_AUTH]))

                ver_auth = recv_exact(conn, 1)
                if ver_auth[0] != 0x01:
                    conn.close()
                    return

                ulen = recv_exact(conn, 1)[0]
                username = recv_exact(conn, ulen).decode()

                plen = recv_exact(conn, 1)[0]
                password = recv_exact(conn, plen).decode()

                if username != self.auth_credentials.get(
                    "username"
                ) or password != self.auth_credentials.get("password"):
                    conn.sendall(bytes([0x01, 0x01]))
                    self._log.warning(
                        "Authentication failed for %s",
                        client_addr[0],
                    )
                    conn.close()
                    return
                else:
                    conn.sendall(bytes([0x01, 0x00]))
            else:
                if NO_AUTH in methods:
                    conn.sendall(bytes([SOCKS_VERSION, NO_AUTH]))
                else:
                    conn.sendall(bytes([SOCKS_VERSION, NO_ACCEPTABLE]))
                    conn.close()
                    return

            self._log.debug(
                "[DEBUG] Waiting for SOCKS5 request from %s:%d...",
                client_addr[0],
                client_addr[1],
            )

            # Добавь timeout через select (например, 3 секунды)
            ready, _, _ = select.select([conn], [], [], 3)
            if not ready:
                self._log.warning(
                    "[TIMEOUT] Client %s:%d did not send "
                    "SOCKS5 request after handshake",
                    client_addr[0],
                    client_addr[1],
                )
                conn.close()
                return
            request = recv_exact(conn, 4)

            self._log.info(
                "SOCKS5 request header from %s: %s",
                client_addr[0],
                request.hex(),
            )
            ver, cmd, _, atyp = request

            if ver != SOCKS_VERSION:
                self._log.error(
                    "Mismatched SOCKS version in request from %s",
                    client_addr[0],
                )
                conn.close()
                return

            if cmd == CMD_CONNECT:
                self._handle_connect(conn, atyp, client_addr)
            elif cmd == CMD_UDP_ASSOCIATE:
                self._handle_udp_associate(conn, atyp, client_addr)
            else:
                self._send_reply(
                    conn,
                    REP_CMD_NOT_SUPPORTED,
                    bind_ip="0.0.0.0",
                    bind_port=0,
                    atyp=ADDR_IPV4,
                )
                conn.close()

        except ConnectionResetError:
            self._log.warning(
                "Client %s forcibly closed the connection (RST)",
                client_addr[0],
            )
        except EOFError:
            self._log.warning(
                "Client %s closed connection with EOF",
                client_addr[0],
            )
        except Exception as e:
            is_self, who = is_self_connection(
                client_addr[0], client_addr[1], self.config.tcp_port
            )
            if is_self or client_addr[0] == "127.0.0.1":
                self._log.info(
                    "🔁 [LOCAL/SELF] "
                    "Connection from %s "
                    "closed prematurely "
                    "(%s)",
                    client_addr[0],
                    who if is_self else str(e),
                )
            else:
                self._log.error(
                    "Error handling client %s: %s",
                    client_addr[0],
                    e,
                )

        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_connect(self, conn: socket.socket, atyp: int, client_addr):
        """Handle SOCKS5 CONNECT (TCP forwarding)"""
        try:
            dest_addr, dest_port = self._read_dest_address(conn, atyp)
        except Exception as e:
            self._log.error(
                "Failed to parse destination address from %s: %s",
                client_addr[0],
                e,
            )
            rep = (
                REP_ADDR_NOT_SUPPORTED
                if isinstance(e, ValueError)
                else REP_GENERAL_FAILURE
            )
            self._send_reply(
                conn,
                rep,
                bind_ip="0.0.0.0",
                bind_port=0,
                atyp=ADDR_IPV4,
            )
            conn.close()
            return
        # Check against allow/deny rules
        if not self._is_dest_allowed(dest_addr, dest_port):
            self._log.info(
                "Blocked destination %s requested by %s",
                dest_addr,
                client_addr[0],
            )
            self._send_reply(
                conn,
                REP_CONN_NOT_ALLOWED,
                bind_ip="0.0.0.0",
                bind_port=0,
                atyp=ADDR_IPV4,
            )
            conn.close()
            return
        # Create remote socket to target
        remote_family = socket.AF_INET6 if ':' in dest_addr else socket.AF_INET
        try:
            remote_sock = socket.socket(remote_family, socket.SOCK_STREAM)
            remote_sock.connect((dest_addr, dest_port))
        except socket.error as e:
            err_no = getattr(e, 'errno', None)
            if err_no in (111, 61):
                rep = REP_CONN_REFUSED
            elif err_no in (113, 101):
                rep = REP_HOST_UNREACHABLE
            else:
                rep = REP_GENERAL_FAILURE
            self._log.error(
                "TCP Connect to %s:%d failed: %s",
                dest_addr,
                dest_port,
                e,
            )
            self._send_reply(
                conn,
                rep,
                bind_ip="0.0.0.0",
                bind_port=0,
                atyp=ADDR_IPV4,
            )
            conn.close()
            return
        # Connected successfully
        bind_ip, bind_port = remote_sock.getsockname()[:2]
        reply_atyp = ADDR_IPV6 if remote_family == socket.AF_INET6 else ADDR_IPV4
        self._send_reply(
            conn,
            REP_SUCCESS,
            bind_ip=bind_ip,
            bind_port=bind_port,
            atyp=reply_atyp,
        )
        self._log.info(
            "Established TCP tunnel from %s to %s:%d",
            client_addr[0],
            dest_addr,
            dest_port,
        )
        try:
            self._exchange_loop(conn, remote_sock)
        finally:
            remote_sock.close()
            conn.close()
            self._log.info("Closed TCP tunnel for %s", client_addr[0])

    def _handle_udp_associate(
        self,
        conn: socket.socket,
        atyp: int,
        client_addr,
    ):
        """Handle SOCKS5 UDP ASSOCIATE (UDP relay)"""
        try:
            client_ip, client_port = self._read_dest_address(conn, atyp)
        except Exception:
            client_ip, client_port = client_addr[0], 0
        # Determine address and port for UDP relay from config
        bind_ip = self.config.udp_host
        if bind_ip == "0.0.0.0":
            bind_ip = conn.getsockname()[0]
            if bind_ip == "0.0.0.0":
                bind_ip = "0.0.0.0"
        if bind_ip in ("::", "::0", "0:0:0:0:0:0:0:0"):
            local_ip = conn.getsockname()[0]
            if local_ip and local_ip != "::":
                bind_ip = local_ip
            else:
                bind_ip = "::"
        reply_atyp = ADDR_IPV6 if ':' in bind_ip else ADDR_IPV4
        self._send_reply(
            conn,
            REP_SUCCESS,
            bind_ip=bind_ip,
            bind_port=self.config.udp_port,
            atyp=reply_atyp,
        )
        self._log.info(
            "UDP association established with %s, UDP relay port %d",
            client_addr[0],
            self.config.udp_port,
        )
        try:
            conn.recv(1)
        except Exception:
            pass
        conn.close()
        self._log.info("Closed UDP association for %s", client_addr[0])

    def _exchange_loop(
        self,
        client_sock: socket.socket,
        remote_sock: socket.socket,
    ):
        """Relay data between client
        and remote sockets until one side closes."""
        while True:
            rlist, _, _ = select.select([client_sock, remote_sock], [], [])
            if client_sock in rlist:
                data = client_sock.recv(4096)
                if not data:
                    break
                remote_sock.sendall(data)
            if remote_sock in rlist:
                data = remote_sock.recv(4096)
                if not data:
                    break
                client_sock.sendall(data)

    def _send_reply(
        self,
        conn: socket.socket,
        rep: int,
        bind_ip: str,
        bind_port: int,
        atyp: int,
    ):
        """Send a SOCKS5 reply packet
        with given reply code and bind address/port."""
        try:
            if atyp == ADDR_IPV4:
                addr_bytes = socket.inet_aton(bind_ip)
            elif atyp == ADDR_IPV6:
                addr_bytes = socket.inet_pton(socket.AF_INET6, bind_ip)
            elif atyp == ADDR_DOMAIN:
                addr_bytes = bytes([len(bind_ip)]) + bind_ip.encode('utf-8')
            else:
                atyp = ADDR_IPV4
                addr_bytes = b"\x00\x00\x00\x00"
            port_bytes = int(bind_port).to_bytes(2, 'big')
            response = (
                bytes(
                    [
                        SOCKS_VERSION,
                        rep,
                        0x00,
                        atyp,
                    ]
                )
                + addr_bytes
                + port_bytes
            )
            conn.sendall(response)
        except Exception as e:
            self._log.error("Failed to send reply to client: %s", e)

    def _read_dest_address(self, conn: socket.socket, atyp: int):
        """
        Read destination address and port from the client request.
        Returns a tuple (dest_addr, dest_port).
        """
        if atyp == ADDR_IPV4:
            addr_bytes = conn.recv(4)
            if len(addr_bytes) < 4:
                raise IOError("Incomplete IPv4 address")
            dest_addr = socket.inet_ntoa(addr_bytes)
            port_bytes = conn.recv(2)
            if len(port_bytes) < 2:
                raise IOError("Incomplete port")
            dest_port = int.from_bytes(port_bytes, 'big')
            return dest_addr, dest_port
        elif atyp == ADDR_DOMAIN:
            length_byte = conn.recv(1)
            if not length_byte:
                raise IOError("Incomplete domain length")
            length = length_byte[0]
            domain_bytes = conn.recv(length)
            if len(domain_bytes) < length:
                raise IOError("Incomplete domain name")
            dest_domain = domain_bytes.decode('utf-8', 'ignore')
            port_bytes = conn.recv(2)
            if len(port_bytes) < 2:
                raise IOError("Incomplete port")
            dest_port = int.from_bytes(port_bytes, 'big')
            try:
                dest_addr = socket.gethostbyname(dest_domain)
            except Exception as e:
                self._log.warning(
                    "Failed to resolve domain %s: %s",
                    dest_domain,
                    e,
                )
                raise e
            return dest_addr, dest_port
        elif atyp == ADDR_IPV6:
            addr_bytes = conn.recv(16)
            if len(addr_bytes) < 16:
                raise IOError("Incomplete IPv6 address")
            dest_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            port_bytes = conn.recv(2)
            if len(port_bytes) < 2:
                raise IOError("Incomplete port")
            dest_port = int.from_bytes(port_bytes, 'big')
            return dest_addr, dest_port
        else:
            raise ValueError("Unsupported address type %d" % atyp)
