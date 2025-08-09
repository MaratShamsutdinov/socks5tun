import json
import ipaddress
import pytest
from socks5tun.config import load_config, Config


def test_load_config_default_values(tmp_path):
    config_file = tmp_path / "config_dev.json"
    config_file.write_text(json.dumps({}))
    cfg = load_config(str(config_file))
    # Default values
    assert isinstance(cfg, Config)
    assert cfg.tcp_host == "127.0.0.1"
    assert cfg.tcp_port == 1080
    assert cfg.udp_host == "127.0.0.1"
    assert cfg.udp_port == 1080
    assert cfg.tun_mode == "dummy"
    assert cfg.log_level == "INFO"
    assert cfg.auth is None
    # allowed_clients default includes all networks
    assert any(net == ipaddress.ip_network("0.0.0.0/0") for net in cfg.allowed_clients)
    # blocked_destinations default empty
    assert cfg.blocked_destinations == []
    # deny_rules derived from blocked_destinations (empty by default)
    assert cfg.deny_rules == []
    # allow_rules default empty
    assert cfg.allow_rules == []


def test_load_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_config("nonexistent_file.json")


def test_load_config_invalid_json(tmp_path):
    config_file = tmp_path / "config_dev.json"
    # Write invalid JSON content
    config_file.write_text('{"tcp_port": ')
    with pytest.raises(ValueError) as excinfo:
        load_config(str(config_file))
    # Should raise ValueError with message about invalid JSON
    msg = str(excinfo.value)
    assert "Invalid JSON configuration" in msg


def test_load_config_outdated_keys(tmp_path):
    config_file = tmp_path / "config_dev.json"
    data = {"bind_host": "0.0.0.0", "bind_port": 1080}
    config_file.write_text(json.dumps(data))
    with pytest.raises(ValueError) as excinfo:
        load_config(str(config_file))
    msg = str(excinfo.value)
    assert "tcp_host" in msg and "tcp_port" in msg


@pytest.mark.parametrize(
    "data, error_substring",
    [
        ({"tcp_host": 123}, "tcp_host must be a string"),
        ({"tcp_port": "123"}, "tcp_port must be an integer"),
        ({"udp_host": 123}, "udp_host must be a string"),
        ({"udp_port": "123"}, "udp_port must be an integer"),
        ({"tun_mode": 5}, "tun_mode must be a string"),
        ({"tun_mode": "invalid"}, "tun_mode must be one of"),
        ({"log_level": 10}, "log_level must be a string"),
        ({"allowed_clients": "not_a_list"}, "allowed_clients must be a list"),
        ({"blocked_destinations": "not_a_list"}, "blocked_destinations must be a list"),
        ({"auth": "user"}, "auth must be an object"),
        ({"auth": {}}, "auth must be an object"),
    ],
)
def test_load_config_invalid_types(tmp_path, data, error_substring):
    config_file = tmp_path / "config_dev.json"
    config_file.write_text(json.dumps(data))
    with pytest.raises(ValueError) as excinfo:
        load_config(str(config_file))
    assert error_substring in str(excinfo.value)


@pytest.mark.parametrize(
    "tun_value, expected_mode", [(True, "linux"), (False, "disabled")]
)
def test_load_config_backward_compat_tun(tmp_path, tun_value, expected_mode):
    config_file = tmp_path / "config_dev.json"
    config_file.write_text(json.dumps({"tun": tun_value}))
    cfg = load_config(str(config_file))
    assert cfg.tun_mode == expected_mode


def test_load_config_network_lists(tmp_path):
    data = {
        "allowed_clients": ["10.0.0.0/8"],
        "blocked_destinations": ["192.0.2.0/24"],
    }
    config_file = tmp_path / "config_dev.json"
    config_file.write_text(json.dumps(data))
    cfg = load_config(str(config_file))
    # allowed_clients converted to ip_network
    assert any(net == ipaddress.ip_network("10.0.0.0/8") for net in cfg.allowed_clients)
    # blocked_destinations converted to ip_network and reflected in deny_rules
    blocked_net = ipaddress.ip_network("192.0.2.0/24")
    assert any(net == blocked_net for net, port in cfg.deny_rules)
    # allow_rules remains empty by default
    assert cfg.allow_rules == []


def test_load_config_auth_fields(tmp_path):
    creds = {"username": "user1", "password": "pass123"}
    config_file = tmp_path / "config_dev.json"
    config_file.write_text(json.dumps({"auth": creds}))
    cfg = load_config(str(config_file))
    assert cfg.auth == creds
