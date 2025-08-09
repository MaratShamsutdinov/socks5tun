import sys
import json
import subprocess
import importlib
import logging
import pytest


def test_missing_config_subprocess():
    result = subprocess.run(
        [sys.executable, "-m", "socks5tun.run", "-c", "nonexistent.json"],
        capture_output=True,
    )
    assert result.returncode != 0
    stderr = result.stderr.decode()
    assert "Configuration file not found" in stderr


def test_invalid_config_subprocess(tmp_path):
    config_file = tmp_path / "config_dev.json"
    config_file.write_text("{ invalid json }")
    result = subprocess.run(
        [sys.executable, "-m", "socks5tun.run", "-c", str(config_file)],
        capture_output=True,
    )
    assert result.returncode != 0
    stderr = result.stderr.decode()
    assert "Error in configuration" in stderr


def test_run_main_dummy(monkeypatch, tmp_path, caplog):
    # Prepare a temporary config file for dummy TUN mode
    cfg = {
        "tcp_host": "127.0.0.1",
        "tcp_port": 0,
        "udp_host": "127.0.0.1",
        "udp_port": 0,
        "tun_mode": "dummy",
        "log_level": "INFO",
    }
    config_path = tmp_path / "config_dev.json"
    config_path.write_text(json.dumps(cfg))
    # Simulate command-line arguments
    monkeypatch.setattr(sys, "argv", ["socks5tun.run", "-c", str(config_path)])
    # Monkeypatch DummyTun and SocksServer.start
    DummyTun_called = {"open": False, "close": False}

    class DummyTunStub:
        def open(self):
            DummyTun_called["open"] = True

        def close(self):
            DummyTun_called["close"] = True

    import socks5tun.dummy_tun as dummy_tun

    monkeypatch.setattr(dummy_tun, "DummyTun", DummyTunStub)
    import socks5tun.udp_handler as udp_handler

    monkeypatch.setattr(udp_handler, "start_udp_loop", lambda cfg, tun: None)
    import socks5tun.server as server

    def fake_start(self):
        raise KeyboardInterrupt

    monkeypatch.setattr(server.SocksServer, "start", fake_start)
    caplog.set_level(logging.INFO)
    # Import and run main
    from socks5tun.run import main

    main()
    # Verify that the server was interrupted and tun opened/closed
    assert any("Server interrupted by user" in rec.message for rec in caplog.records)
    assert DummyTun_called["open"] is True
    assert DummyTun_called["close"] is True
