"""
Input validation utilities for Perimtr.

Provides reusable validation functions for domains, CIDRs, ports,
and other common inputs used across the application.
"""

import ipaddress
import logging
import re
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# Domain name regex per RFC 1035 (relaxed for practical use)
DOMAIN_REGEX = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*'
    r'\.[a-zA-Z]{2,}$'
)

# Maximum lengths per DNS spec
_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63

# Valid port range
_PORT_MIN = 1
_PORT_MAX = 65535


def validate_domain(domain: str) -> Tuple[bool, str]:
    """Validate a domain name.

    Args:
        domain: Domain string to validate.

    Returns:
        Tuple of (is_valid, error_message). Error message is empty if valid.
    """
    if not domain:
        return False, "Domain must not be empty."

    if len(domain) > _MAX_DOMAIN_LENGTH:
        return False, (
            f"Domain '{domain}' exceeds maximum length of {_MAX_DOMAIN_LENGTH} characters "
            f"(got {len(domain)})."
        )

    # Check each label length (split on dots)
    labels = domain.split(".")
    for label in labels:
        if len(label) > _MAX_LABEL_LENGTH:
            return False, (
                f"Label '{label}' in domain '{domain}' exceeds maximum length of "
                f"{_MAX_LABEL_LENGTH} characters (got {len(label)})."
            )
        if not label:
            return False, f"Domain '{domain}' contains an empty label (consecutive dots)."

    # Reject non-ASCII (unicode / IDN not supported at this layer)
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        return False, (
            f"Domain '{domain}' contains non-ASCII characters. "
            "Use ACE-encoded (punycode) form for internationalized domains."
        )

    if not DOMAIN_REGEX.match(domain):
        return False, f"Domain '{domain}' does not match the expected format (RFC 1035)."

    return True, ""


def validate_cidr(cidr: str) -> Tuple[bool, str]:
    """Validate a CIDR network range.

    Args:
        cidr: CIDR string like "192.168.1.0/24"

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not cidr:
        return False, "CIDR must not be empty."

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        return False, f"Invalid CIDR '{cidr}': {exc}"

    # Warn (but still accept) loopback / link-local ranges
    if network.is_loopback:
        logger.warning("CIDR '%s' is a loopback range — scanning may produce no results.", cidr)
    elif network.is_link_local:
        logger.warning(
            "CIDR '%s' is a link-local range — scanning may produce no results.", cidr
        )

    return True, ""


def validate_port(port: int) -> Tuple[bool, str]:
    """Validate a port number.

    Args:
        port: Integer port number.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not isinstance(port, int):
        return False, f"Port must be an integer, got {type(port).__name__}."
    if port < _PORT_MIN or port > _PORT_MAX:
        return False, (
            f"Port {port} is out of valid range [{_PORT_MIN}, {_PORT_MAX}]."
        )
    return True, ""


def validate_port_range(port_str: str) -> Tuple[bool, str]:
    """Validate a port range string like '80,443,8000-9000'.

    Args:
        port_str: Comma-separated ports and/or hyphen-delimited ranges.

    Returns:
        Tuple of (is_valid, error_message).
    """
    if not port_str:
        return False, "Port range string must not be empty."

    segments = [seg.strip() for seg in port_str.split(",")]
    for segment in segments:
        if not segment:
            return False, f"Empty segment found in port range string '{port_str}'."

        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                return False, (
                    f"Invalid range segment '{segment}' in '{port_str}': "
                    "expected format 'start-end'."
                )
            try:
                start, end = int(parts[0]), int(parts[1])
            except ValueError:
                return False, (
                    f"Non-integer value in range segment '{segment}' in '{port_str}'."
                )
            valid_start, err = validate_port(start)
            if not valid_start:
                return False, f"In range '{segment}': {err}"
            valid_end, err = validate_port(end)
            if not valid_end:
                return False, f"In range '{segment}': {err}"
            if start > end:
                return False, (
                    f"Range start {start} is greater than end {end} in '{segment}'."
                )
        else:
            try:
                port = int(segment)
            except ValueError:
                return False, (
                    f"Non-integer port value '{segment}' in '{port_str}'."
                )
            valid, err = validate_port(port)
            if not valid:
                return False, err

    return True, ""


def sanitize_targets(targets: dict) -> dict:
    """
    Clean and validate a targets dict.

    Strips whitespace, lowercases domains, removes duplicates,
    validates all entries. Returns cleaned dict.

    Logs warnings for invalid entries that are skipped.

    Args:
        targets: Dict with optional keys 'domains' (list[str]) and
                 'cidrs' (list[str]).

    Returns:
        Cleaned dict with same structure, invalid entries removed.
    """
    cleaned: Dict[str, list] = {}

    # --- Domains ---
    raw_domains: List[str] = targets.get("domains", []) or []
    seen_domains: set = set()
    valid_domains: List[str] = []

    for entry in raw_domains:
        if not isinstance(entry, str):
            logger.warning("Skipping non-string domain entry: %r", entry)
            continue
        domain = entry.strip().lower()
        if not domain:
            continue
        if domain in seen_domains:
            logger.debug("Removing duplicate domain: %s", domain)
            continue
        seen_domains.add(domain)
        is_valid, error = validate_domain(domain)
        if is_valid:
            valid_domains.append(domain)
        else:
            logger.warning("Skipping invalid domain '%s': %s", domain, error)

    if valid_domains:
        cleaned["domains"] = valid_domains

    # --- CIDRs ---
    raw_cidrs: List[str] = targets.get("cidrs", []) or []
    seen_cidrs: set = set()
    valid_cidrs: List[str] = []

    for entry in raw_cidrs:
        if not isinstance(entry, str):
            logger.warning("Skipping non-string CIDR entry: %r", entry)
            continue
        cidr = entry.strip()
        if not cidr:
            continue
        if cidr in seen_cidrs:
            logger.debug("Removing duplicate CIDR: %s", cidr)
            continue
        seen_cidrs.add(cidr)
        is_valid, error = validate_cidr(cidr)
        if is_valid:
            valid_cidrs.append(cidr)
        else:
            logger.warning("Skipping invalid CIDR '%s': %s", cidr, error)

    if valid_cidrs:
        cleaned["cidrs"] = valid_cidrs

    # Carry over any other keys unchanged
    for key, value in targets.items():
        if key not in ("domains", "cidrs"):
            cleaned[key] = value

    return cleaned


def is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is in a private/reserved range.

    Args:
        ip_str: IPv4 or IPv6 address string.

    Returns:
        True if the address is private, loopback, link-local, or reserved.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    )
