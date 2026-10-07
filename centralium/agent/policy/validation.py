"""Strict target validation shared by the policy engine and the response executor.

Everything that ends up in a firewall/process/service command line must pass through here.
Validators raise ``ValidationError`` (a ``ValueError``); they never "fix up" input.
"""

from __future__ import annotations

import ipaddress
import re

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_UNIT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@\-]{0,200}\.(service|timer|socket|path)$")
_WIN_SERVICE_RE = re.compile(r"^[A-Za-z0-9_.\- ]{1,80}$")
PROTOCOLS = frozenset({"tcp", "udp"})
MAX_PID = 2**22  # linux pid_max upper bound; windows pids are far smaller in practice


class ValidationError(ValueError):
    pass


def validate_ip(value: object) -> IPAddress:
    """Parse a *literal* IP (no hostnames, no CIDR, no zone ids, no whitespace)."""
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > 45:
        raise ValidationError("ip must be a literal address string")
    if "%" in value or "/" in value:
        raise ValidationError("ip must not contain zone id or prefix")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"invalid ip address: {value!r}") from exc


def validate_network(value: object) -> IPNetwork:
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > 50:
        raise ValidationError("network must be a literal CIDR string")
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValidationError(f"invalid network: {value!r}") from exc


def validate_port(value: object, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("port must be an integer")
    if not ((0 if allow_zero else 1) <= value <= 65535):
        raise ValidationError(f"port out of range: {value}")
    return value


def validate_protocol(value: object) -> str:
    if not isinstance(value, str) or value.lower() not in PROTOCOLS:
        raise ValidationError("protocol must be 'tcp' or 'udp'")
    return value.lower()


def validate_pid(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("pid must be an integer")
    if not (1 <= value <= MAX_PID):
        raise ValidationError(f"pid out of range: {value}")
    return value


def validate_unit_name(value: object) -> str:
    if not isinstance(value, str) or not _UNIT_RE.fullmatch(value) or ".." in value:
        raise ValidationError(f"invalid systemd unit name: {value!r}")
    return value


def validate_windows_service(value: object) -> str:
    if not isinstance(value, str) or not _WIN_SERVICE_RE.fullmatch(value) or value.startswith("-"):
        raise ValidationError(f"invalid windows service name: {value!r}")
    return value


def validate_path_str(value: object) -> str:
    """Basic path string hygiene (canonicalisation happens where the filesystem is touched)."""
    if not isinstance(value, str) or not value or len(value) > 4096 or "\x00" in value:
        raise ValidationError("invalid path string")
    return value


def non_blockable_reason(ip: IPAddress) -> str | None:
    """Addresses that must never be firewalled by automated response."""
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified address"
    if ip.is_multicast:
        return "multicast"
    if ip.is_link_local:
        return "link-local"
    return None
