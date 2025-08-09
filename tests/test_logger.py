import logging
from socks5tun.logger import setup_logging


def test_setup_logging(monkeypatch):
    recorded = {}

    def fake_basicConfig(**kwargs):
        recorded.update(kwargs)

    dummy_urllib3_logger = type(
        "DummyLogger",
        (),
        {"level": None, "setLevel": lambda self, lvl: setattr(self, "level", lvl)},
    )()
    original_getLogger = logging.getLogger

    def fake_getLogger(name=None):
        if name == "urllib3":
            return dummy_urllib3_logger
        return original_getLogger(name)

    monkeypatch.setattr(logging, "basicConfig", fake_basicConfig)
    monkeypatch.setattr(logging, "getLogger", fake_getLogger)

    # Test with recognized level
    setup_logging("DeBuG")
    assert recorded.get("level") == logging.DEBUG
    assert "%(threadName)s" in recorded.get("format", "")
    # urllib3 logger should be set to WARNING
    assert dummy_urllib3_logger.level == logging.WARNING

    # Test with unrecognized level (defaults to INFO)
    recorded.clear()
    dummy_urllib3_logger.level = None
    setup_logging("UNKNOWN_LEVEL")
    assert recorded.get("level") == logging.INFO
    assert dummy_urllib3_logger.level == logging.WARNING
