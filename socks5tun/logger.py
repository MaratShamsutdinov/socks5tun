"""
Logging configuration for Socks5 proxy server.
"""
import logging

def setup_logging(level: str):
    """
    Configure logging for the proxy server with the given level.
    """
    # Convert level name to numeric value (default to INFO if unrecognized)
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    # Optionally, adjust logging levels for third-party libraries if needed
    logging.getLogger("urllib3").setLevel(logging.WARNING)
