"""Tests for perimtr.utils.network."""

import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

import perimtr.utils.network as _network_utils
from perimtr.utils.network import (
    RateLimiter,
    grab_banner,
    resolve_domain,
)
# Import under a non-'test_' name to avoid pytest collection confusion
check_connectivity = _network_utils.test_connectivity


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_invalid_rate(self):
        with pytest.raises(ValueError):
            RateLimiter(max_per_second=0)

    def test_invalid_negative_rate(self):
        with pytest.raises(ValueError):
            RateLimiter(max_per_second=-5)

    def test_max_per_second_property(self):
        limiter = RateLimiter(max_per_second=20.0)
        assert abs(limiter.max_per_second - 20.0) < 1e-9

    def test_actually_rate_limits(self):
        """Verify that 5 wait() calls at 10/sec take at least 4 * interval."""
        limiter = RateLimiter(max_per_second=100)  # 10 ms interval
        start = time.monotonic()
        for _ in range(5):
            limiter.wait()
        elapsed = time.monotonic() - start
        # 5 calls at 100/sec should take >= 4 * 0.01 = 0.04 s (first call free)
        assert elapsed >= 0.03, f"Rate limiter did not wait long enough: {elapsed:.4f}s"

    def test_single_call_not_blocked(self):
        """First call should not be artificially delayed."""
        limiter = RateLimiter(max_per_second=1)
        start = time.monotonic()
        limiter.wait()
        elapsed = time.monotonic() - start
        # First call: _last_call is 0.0, so elapsed >= interval -> no sleep
        assert elapsed < 0.5, "First call to wait() was unexpectedly slow."

    def test_thread_safety(self):
        """Multiple threads sharing a limiter should not raise errors."""
        limiter = RateLimiter(max_per_second=200)
        errors = []

        def worker():
            try:
                for _ in range(5):
                    limiter.wait()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert errors == [], f"Thread errors: {errors}"


# ---------------------------------------------------------------------------
# resolve_domain (with cache clearing)
# ---------------------------------------------------------------------------

class TestResolveDomain:
    def setup_method(self):
        """Clear the lru_cache before each test."""
        resolve_domain.cache_clear()

    def test_returns_string_for_known_host(self):
        """Use localhost which always resolves."""
        result = resolve_domain("localhost")
        assert result is not None
        assert isinstance(result, str)

    def test_returns_none_for_invalid(self):
        result = resolve_domain("this.domain.absolutely.does.not.exist.invalid")
        assert result is None

    def test_caching(self):
        """Second call should be served from cache (much faster)."""
        # Warm up
        resolve_domain("localhost")
        start = time.monotonic()
        for _ in range(50):
            resolve_domain("localhost")
        elapsed = time.monotonic() - start
        # 50 cache hits should complete in well under 1 second
        assert elapsed < 1.0, f"Cache lookups too slow: {elapsed:.3f}s"

    def test_cache_info(self):
        resolve_domain.cache_clear()
        resolve_domain("localhost")
        info = resolve_domain.cache_info()
        # After one call: 1 miss, 0 hits
        assert info.misses >= 1

        resolve_domain("localhost")
        info2 = resolve_domain.cache_info()
        assert info2.hits >= 1

    def test_with_mock_success(self):
        resolve_domain.cache_clear()
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            result = resolve_domain("mock.example.com")
        assert result == "1.2.3.4"

    def test_with_mock_failure(self):
        resolve_domain.cache_clear()
        with patch(
            "socket.gethostbyname",
            side_effect=socket.gaierror("no such host"),
        ):
            result = resolve_domain("fail.example.com")
        assert result is None


# ---------------------------------------------------------------------------
# check_connectivity (wraps network.test_connectivity)
# ---------------------------------------------------------------------------

class TestTestConnectivity:
    def test_success(self):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_conn) as mock_cc:
            result = check_connectivity("127.0.0.1", 9999)
        assert result is True
        mock_cc.assert_called_once_with(("127.0.0.1", 9999), timeout=3)

    def test_connection_refused(self):
        with patch(
            "socket.create_connection",
            side_effect=ConnectionRefusedError("refused"),
        ):
            result = check_connectivity("127.0.0.1", 1)
        assert result is False

    def test_timeout(self):
        with patch(
            "socket.create_connection",
            side_effect=socket.timeout("timed out"),
        ):
            result = check_connectivity("192.0.2.1", 80)
        assert result is False

    def test_os_error(self):
        with patch(
            "socket.create_connection",
            side_effect=OSError("network unreachable"),
        ):
            result = check_connectivity("10.255.255.1", 80)
        assert result is False

    def test_custom_timeout_passed(self):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_conn) as mock_cc:
            check_connectivity("host", 443, timeout=10)
        mock_cc.assert_called_once_with(("host", 443), timeout=10)


# ---------------------------------------------------------------------------
# grab_banner
# ---------------------------------------------------------------------------

class TestGrabBanner:
    def _make_mock_socket(self, recv_data: bytes = b""):
        """Create a mock socket context manager."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = recv_data
        mock_sock.sendall = MagicMock()
        mock_sock.settimeout = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        return mock_sock

    def test_returns_banner(self):
        mock_sock = self._make_mock_socket(b"SSH-2.0-OpenSSH_8.9\r\n")
        with patch("socket.create_connection", return_value=mock_sock):
            result = grab_banner("127.0.0.1", 22)
        assert result == "SSH-2.0-OpenSSH_8.9"

    def test_returns_empty_on_connection_refused(self):
        with patch(
            "socket.create_connection",
            side_effect=ConnectionRefusedError("refused"),
        ):
            result = grab_banner("127.0.0.1", 9999)
        assert result == ""

    def test_returns_empty_on_timeout(self):
        with patch(
            "socket.create_connection",
            side_effect=socket.timeout("timed out"),
        ):
            result = grab_banner("192.0.2.1", 80)
        assert result == ""

    def test_returns_empty_on_os_error(self):
        with patch(
            "socket.create_connection",
            side_effect=OSError("unreachable"),
        ):
            result = grab_banner("10.255.255.1", 80)
        assert result == ""

    def test_sends_probe(self):
        mock_sock = self._make_mock_socket(b"HTTP/1.0 200 OK\r\n")
        with patch("socket.create_connection", return_value=mock_sock):
            grab_banner("127.0.0.1", 80, probe=b"HEAD / HTTP/1.0\r\n\r\n")
        mock_sock.sendall.assert_called_once_with(b"HEAD / HTTP/1.0\r\n\r\n")

    def test_no_probe_no_sendall(self):
        mock_sock = self._make_mock_socket(b"banner")
        with patch("socket.create_connection", return_value=mock_sock):
            grab_banner("127.0.0.1", 80)
        mock_sock.sendall.assert_not_called()

    def test_handles_recv_timeout(self):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = socket.timeout("recv timeout")
        mock_sock.settimeout = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            result = grab_banner("127.0.0.1", 80)
        # Should not raise; returns empty string
        assert result == ""

    def test_handles_non_utf8_bytes(self):
        mock_sock = self._make_mock_socket(b"\xff\xfe binary \x00 data")
        with patch("socket.create_connection", return_value=mock_sock):
            result = grab_banner("127.0.0.1", 80)
        # Should not raise; garbled chars replaced
        assert isinstance(result, str)

    def test_strips_whitespace(self):
        mock_sock = self._make_mock_socket(b"  banner text  \r\n")
        with patch("socket.create_connection", return_value=mock_sock):
            result = grab_banner("127.0.0.1", 80)
        assert result == "banner text"

    def test_custom_timeout(self):
        mock_sock = self._make_mock_socket(b"data")
        with patch("socket.create_connection", return_value=mock_sock) as mock_cc:
            grab_banner("host", 8080, timeout=10)
        mock_cc.assert_called_once_with(("host", 8080), timeout=10)
