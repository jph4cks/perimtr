"""Tests for perimtr.core.validators."""

import pytest
from perimtr.core.validators import (
    is_private_ip,
    sanitize_targets,
    validate_cidr,
    validate_domain,
    validate_port,
    validate_port_range,
)


# ---------------------------------------------------------------------------
# validate_domain
# ---------------------------------------------------------------------------

class TestValidateDomain:
    def test_valid_simple(self):
        ok, err = validate_domain("example.com")
        assert ok is True
        assert err == ""

    def test_valid_subdomain(self):
        ok, err = validate_domain("sub.example.com")
        assert ok is True

    def test_valid_hyphen(self):
        ok, err = validate_domain("my-host.example.com")
        assert ok is True

    def test_valid_numeric_label(self):
        ok, err = validate_domain("123.example.com")
        assert ok is True

    def test_valid_long_tld(self):
        ok, err = validate_domain("example.museum")
        assert ok is True

    def test_empty_string(self):
        ok, err = validate_domain("")
        assert ok is False
        assert "empty" in err.lower()

    def test_too_long_total(self):
        # 254 characters total (exceeds 253)
        long_domain = ("a" * 50 + ".") * 4 + "example.com"
        # build something definitely > 253
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + ".com"
        ok, err = validate_domain(long_domain)
        assert ok is False
        assert "253" in err or "length" in err.lower()

    def test_label_too_long(self):
        label = "a" * 64  # 64 chars — exceeds 63
        ok, err = validate_domain(f"{label}.example.com")
        assert ok is False
        assert "63" in err or "length" in err.lower()

    def test_unicode_rejected(self):
        ok, err = validate_domain("münchen.de")
        assert ok is False

    def test_no_tld(self):
        ok, err = validate_domain("localhost")
        assert ok is False

    def test_leading_hyphen(self):
        ok, err = validate_domain("-bad.example.com")
        assert ok is False

    def test_trailing_dot(self):
        # Trailing dot makes the TLD part empty — should fail
        ok, err = validate_domain("example.com.")
        assert ok is False

    def test_consecutive_dots(self):
        ok, err = validate_domain("example..com")
        assert ok is False

    def test_single_label(self):
        ok, err = validate_domain("com")
        assert ok is False


# ---------------------------------------------------------------------------
# validate_cidr
# ---------------------------------------------------------------------------

class TestValidateCidr:
    def test_valid_ipv4(self):
        ok, err = validate_cidr("192.168.1.0/24")
        assert ok is True
        assert err == ""

    def test_valid_host_bits_stripped(self):
        # strict=False should accept this
        ok, err = validate_cidr("10.0.0.5/8")
        assert ok is True

    def test_valid_ipv6(self):
        ok, err = validate_cidr("2001:db8::/32")
        assert ok is True

    def test_invalid_cidr_garbage(self):
        ok, err = validate_cidr("not_a_cidr")
        assert ok is False
        assert "invalid" in err.lower() or "cidr" in err.lower()

    def test_invalid_cidr_bad_prefix(self):
        ok, err = validate_cidr("192.168.1.0/33")
        assert ok is False

    def test_empty(self):
        ok, err = validate_cidr("")
        assert ok is False

    def test_loopback_accepted_with_warning(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="perimtr.core.validators"):
            ok, err = validate_cidr("127.0.0.0/8")
        assert ok is True  # still valid, just warned
        assert any("loopback" in r.message.lower() for r in caplog.records)


# ---------------------------------------------------------------------------
# validate_port
# ---------------------------------------------------------------------------

class TestValidatePort:
    def test_valid_port(self):
        ok, err = validate_port(80)
        assert ok is True

    def test_min_port(self):
        ok, err = validate_port(1)
        assert ok is True

    def test_max_port(self):
        ok, err = validate_port(65535)
        assert ok is True

    def test_zero(self):
        ok, err = validate_port(0)
        assert ok is False

    def test_negative(self):
        ok, err = validate_port(-1)
        assert ok is False

    def test_too_large(self):
        ok, err = validate_port(65536)
        assert ok is False

    def test_non_integer(self):
        ok, err = validate_port("80")  # type: ignore[arg-type]
        assert ok is False


# ---------------------------------------------------------------------------
# validate_port_range
# ---------------------------------------------------------------------------

class TestValidatePortRange:
    def test_single_port(self):
        ok, err = validate_port_range("80")
        assert ok is True

    def test_multiple_ports(self):
        ok, err = validate_port_range("80,443,8080")
        assert ok is True

    def test_range(self):
        ok, err = validate_port_range("8000-9000")
        assert ok is True

    def test_mixed(self):
        ok, err = validate_port_range("22,80,443,8000-8100")
        assert ok is True

    def test_empty(self):
        ok, err = validate_port_range("")
        assert ok is False

    def test_invalid_text(self):
        ok, err = validate_port_range("http,https")
        assert ok is False

    def test_range_reversed(self):
        ok, err = validate_port_range("9000-8000")
        assert ok is False

    def test_out_of_range(self):
        ok, err = validate_port_range("0,80")
        assert ok is False

    def test_trailing_comma(self):
        ok, err = validate_port_range("80,")
        assert ok is False


# ---------------------------------------------------------------------------
# sanitize_targets
# ---------------------------------------------------------------------------

class TestSanitizeTargets:
    def test_clean_domains(self):
        result = sanitize_targets({"domains": ["Example.COM", "sub.Example.ORG"]})
        assert result["domains"] == ["example.com", "sub.example.org"]

    def test_strips_whitespace(self):
        result = sanitize_targets({"domains": ["  example.com  "]})
        assert result["domains"] == ["example.com"]

    def test_removes_duplicates(self):
        result = sanitize_targets({"domains": ["example.com", "EXAMPLE.COM", "example.com"]})
        assert result["domains"] == ["example.com"]

    def test_skips_invalid_domains(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="perimtr.core.validators"):
            result = sanitize_targets({"domains": ["not_a_domain", "example.com"]})
        assert result["domains"] == ["example.com"]
        assert any("not_a_domain" in r.message for r in caplog.records)

    def test_valid_cidrs(self):
        result = sanitize_targets({"cidrs": ["10.0.0.0/8", "192.168.0.0/16"]})
        assert result["cidrs"] == ["10.0.0.0/8", "192.168.0.0/16"]

    def test_removes_duplicate_cidrs(self):
        result = sanitize_targets({"cidrs": ["10.0.0.0/8", "10.0.0.0/8"]})
        assert result["cidrs"] == ["10.0.0.0/8"]

    def test_skips_invalid_cidrs(self):
        result = sanitize_targets({"cidrs": ["bad/cidr", "10.0.0.0/8"]})
        assert result["cidrs"] == ["10.0.0.0/8"]

    def test_empty_input(self):
        result = sanitize_targets({})
        assert result == {}

    def test_none_list(self):
        result = sanitize_targets({"domains": None})
        assert "domains" not in result

    def test_preserves_other_keys(self):
        result = sanitize_targets({"domains": ["example.com"], "extra": "value"})
        assert result["extra"] == "value"

    def test_non_string_entry_skipped(self):
        result = sanitize_targets({"domains": [123, "example.com"]})
        assert result["domains"] == ["example.com"]


# ---------------------------------------------------------------------------
# is_private_ip
# ---------------------------------------------------------------------------

class TestIsPrivateIp:
    def test_private_10(self):
        assert is_private_ip("10.0.0.1") is True

    def test_private_172(self):
        assert is_private_ip("172.16.0.1") is True

    def test_private_192(self):
        assert is_private_ip("192.168.1.1") is True

    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True

    def test_public_ip(self):
        assert is_private_ip("8.8.8.8") is False

    def test_public_ip2(self):
        assert is_private_ip("1.1.1.1") is False

    def test_link_local(self):
        assert is_private_ip("169.254.0.1") is True

    def test_ipv6_loopback(self):
        assert is_private_ip("::1") is True

    def test_ipv6_private(self):
        # fc00::/7 is unique local in IPv6
        assert is_private_ip("fc00::1") is True

    def test_invalid_address(self):
        assert is_private_ip("not_an_ip") is False

    def test_unspecified(self):
        assert is_private_ip("0.0.0.0") is True
