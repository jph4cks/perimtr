"""
Network utility functions for Perimtr.

Common networking helpers used across modules: connection testing,
banner grabbing, DNS resolution with caching, and rate limiting.
"""

import logging
import socket
import threading
import time
from functools import lru_cache
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class RateLimiter:
    """Thread-safe rate limiter for network operations.

    Limits the number of calls per second to avoid overwhelming targets
    or triggering rate-limit defences.

    Usage:
        limiter = RateLimiter(max_per_second=10)
        limiter.wait()  # blocks if needed
        do_network_operation()
    """

    def __init__(self, max_per_second: float = 10.0) -> None:
        """
        Args:
            max_per_second: Maximum number of ``wait()`` calls allowed per second.
        """
        if max_per_second <= 0:
            raise ValueError("max_per_second must be positive.")
        self._interval: float = 1.0 / max_per_second
        self._lock = threading.Lock()
        self._last_call: float = 0.0

    @property
    def max_per_second(self) -> float:
        """The configured maximum rate."""
        return 1.0 / self._interval

    def wait(self) -> None:
        """Block until the next call is within the rate limit.

        Thread-safe: multiple threads can share a single RateLimiter instance.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            sleep_time = self._interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            self._last_call = time.monotonic()


@lru_cache(maxsize=1024)
def resolve_domain(domain: str, timeout: int = 5) -> Optional[str]:
    """Resolve a domain name to its primary IPv4 address with caching.

    Results are cached via ``lru_cache`` so repeated lookups for the
    same domain are served instantly without additional DNS queries.

    Args:
        domain: The hostname to resolve.
        timeout: Socket timeout in seconds for the resolution attempt.

    Returns:
        The resolved IP address string, or ``None`` if resolution fails.
    """
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(domain)
        logger.debug("Resolved %s -> %s", domain, ip)
        return ip
    except (socket.gaierror, socket.timeout, OSError) as exc:
        logger.debug("Failed to resolve domain '%s': %s", domain, exc)
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)


def test_connectivity(host: str, port: int, timeout: int = 3) -> bool:
    """Perform a quick TCP connectivity test.

    Attempts to open a TCP connection to ``host:port`` and returns
    immediately after the handshake succeeds or fails.

    Args:
        host: Target hostname or IP address.
        port: Target TCP port.
        timeout: Connection timeout in seconds.

    Returns:
        ``True`` if the connection succeeds, ``False`` otherwise.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as _:
            logger.debug("Connectivity check %s:%d -> OK", host, port)
            return True
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug("Connectivity check %s:%d -> FAILED (%s)", host, port, exc)
        return False


def grab_banner(
    host: str,
    port: int,
    timeout: int = 5,
    probe: bytes = b"",
) -> str:
    """Grab a service banner from an open TCP port.

    Connects to ``host:port``, optionally sends a probe payload, then
    reads up to 4096 bytes of the response. Always returns a string —
    never raises an exception.

    Args:
        host: Target hostname or IP address.
        port: Target TCP port.
        timeout: Socket timeout in seconds.
        probe: Optional bytes to send after connecting (e.g. ``b"HEAD / HTTP/1.0\\r\\n\\r\\n"``).

    Returns:
        The decoded banner string, or an empty string on any failure.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                sock.sendall(probe)
            try:
                raw = sock.recv(4096)
            except (socket.timeout, OSError):
                raw = b""
            banner = raw.decode("utf-8", errors="replace").strip()
            logger.debug("Banner from %s:%d -> %r", host, port, banner[:80])
            return banner
    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        logger.debug("Could not grab banner from %s:%d: %s", host, port, exc)
        return ""
