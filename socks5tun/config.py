"""
Configuration handling for Socks5 proxy server.
"""

import json
import ipaddress


class Config:
    """
    Holds configuration for the Socks5 server.
    """

    def __init__(self, data: dict):
        # TCP and UDP listening addresses and ports
        self.tcp_host: str = data.get("tcp_host", "127.0.0.1")
        self.tcp_port: int = data.get("tcp_port", 1080)
        self.udp_host: str = data.get("udp_host", "127.0.0.1")
        self.udp_port: int = data.get("udp_port", 1080)

        # Full tun/nat configs for easier access (НЕ выбрасываем поля!)
        self.tun = data.get("tun", {}) or {}
        self.nat = data.get("nat", {}) or {}

        # TUN interface mode (default "dummy")
        self.tun_mode: str = data.get("tun_mode", "dummy")

        self.dns_resolver = data.get("dns_resolver", "system")

        # Logging level
        self.log_level: str = data.get("log_level", "INFO").upper()

        # Authentication credentials (if any)
        auth_data = data.get("auth")
        if (
            auth_data
            and isinstance(auth_data, dict)
            and "username" in auth_data
            and "password" in auth_data
        ):
            self.auth = {
                "username": auth_data["username"],
                "password": auth_data["password"],
            }
        else:
            self.auth = None

        # Allowed client networks
        allowed_list = data.get("allowed_clients", ["0.0.0.0/0"])
        self.allowed_clients = [ipaddress.ip_network(net) for net in allowed_list]

        # Blocked destination networks
        blocked_list = data.get("blocked_destinations", [])
        self.blocked_destinations = [ipaddress.ip_network(net) for net in blocked_list]

        # Backward compatibility
        self.forbidden_networks = data.get("forbidden_networks", [])

        # Derived rules (deny everything from blocked_destinations by default)
        self.deny_rules = [(net, None) for net in self.blocked_destinations]
        self.allow_rules = []


def load_config(path: str) -> Config:
    """
    Load configuration from a JSON file and return a Config object.
    Raises FileNotFoundError if file is not found,
    or ValueError if JSON is invalid or contents are not as expected.
    """
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON configuration: {e}")

    # Backward compatibility for old keys:
    # 1) НЕ выбрасываем 'tun' — он нужен. Только подставляем tun_mode, если не задан.
    if "tun" in data:
        if "tun_mode" not in data:
            data["tun_mode"] = "linux" if data["tun"] else "disabled"
        # НИЧЕГО не pop-аем!

        # Мини-валидация структуры tun
        if not isinstance(data["tun"], dict):
            raise ValueError("'tun' must be an object")

    # 2) Устаревшие имена ключей
    if "bind_host" in data or "bind_port" in data:
        raise ValueError(
            "Outdated config keys 'bind_host'/'bind_port' detected; "
            "use 'tcp_host'/'tcp_port' instead."
        )

    # Validate required field types and values
    if "tcp_host" in data and not isinstance(data["tcp_host"], str):
        raise ValueError("tcp_host must be a string")
    if "tcp_port" in data and not isinstance(data["tcp_port"], int):
        raise ValueError("tcp_port must be an integer")
    if "udp_host" in data and not isinstance(data["udp_host"], str):
        raise ValueError("udp_host must be a string")
    if "udp_port" in data and not isinstance(data["udp_port"], int):
        raise ValueError("udp_port must be an integer")
    if "tun_mode" in data:
        if not isinstance(data["tun_mode"], str):
            raise ValueError("tun_mode must be a string")
        if data["tun_mode"] not in {"dummy", "linux", "disabled"}:
            raise ValueError("tun_mode must be one of: 'dummy', 'linux', or 'disabled'")
    if "log_level" in data and not isinstance(data["log_level"], str):
        raise ValueError("log_level must be a string")
    if "allowed_clients" in data and not isinstance(data["allowed_clients"], list):
        raise ValueError("allowed_clients must be a list of network strings")
    if "blocked_destinations" in data and not isinstance(
        data["blocked_destinations"], list
    ):
        raise ValueError("blocked_destinations must be a list of network strings")
    if "auth" in data:
        if data["auth"] is not None:
            if not (
                isinstance(data["auth"], dict)
                and "username" in data["auth"]
                and "password" in data["auth"]
            ):
                raise ValueError(
                    "auth must be an object with 'username' and 'password', or null"
                )

    return Config(data)
