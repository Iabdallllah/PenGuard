"""Target-scope validation — stop the scanner from becoming an SSRF proxy.

Custom targets are resolved before dispatch. Loopback is allowed only in local
development; private ranges require an explicit lab override; link-local and
cloud metadata addresses are always rejected. The sandbox's own 127.0.0.1
target is handled separately and never passes through this check.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlsplit

from security_model import normalize_target


class TargetScopeError(ValueError):
    """Raised when a target is malformed or out of the authorized scope."""


_METADATA_HOSTS = frozenset({
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
})


def _resolved_addresses(host: str, port: Optional[int], timeout: float) -> List[ipaddress._BaseAddress]:
    previous = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    finally:
        socket.setdefaulttimeout(previous)
    addresses = []
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if address not in addresses:
            addresses.append(address)
    return addresses


def _is_metadata(address: ipaddress._BaseAddress) -> bool:
    if isinstance(address, ipaddress.IPv4Address):
        return address in ipaddress.ip_network("169.254.169.254/32")
    return address in ipaddress.ip_network("fd00:ec2::254/128")


def _is_private_or_local(address: ipaddress._BaseAddress) -> bool:
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
        or not address.is_global
    )


def validate_target_url(
    url: str,
    *,
    production: bool = False,
    allow_private: bool = False,
    allow_nonstandard_ports: bool = False,
    dns_timeout: float = 3.0,
    resolver=None,
) -> str:
    """Validate a custom target and return it cleaned of credentials.

    ``resolver`` is injectable for tests: ``(host, port, timeout) -> [ip]``.
    """
    raw = (url or "").strip()
    if not raw:
        raise TargetScopeError("target_url is empty")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise TargetScopeError(f"Invalid target URL: {exc}") from exc
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise TargetScopeError("target_url must use http or https")
    if parsed.username or parsed.password:
        raise TargetScopeError("target_url must not contain embedded credentials")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        raise TargetScopeError("target_url must include a host")
    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetScopeError("target_url contains an invalid port") from exc
    if host in _METADATA_HOSTS:
        raise TargetScopeError("Cloud metadata targets are not authorized")
    if port and not allow_nonstandard_ports and production and port not in (80, 443):
        raise TargetScopeError("Non-standard target ports are disabled in production")

    resolve = resolver or _resolved_addresses
    try:
        addresses = resolve(host, port, dns_timeout)
    except Exception:
        addresses = []

    for address in addresses:
        if _is_metadata(address):
            raise TargetScopeError("Cloud metadata addresses are not authorized")
        if _is_private_or_local(address):
            if address.is_loopback and not production:
                continue
            if not allow_private:
                raise TargetScopeError(
                    "Private, loopback, link-local, and reserved targets require "
                    "PENGUARD_ALLOW_PRIVATE_TARGETS=1"
                )
        # Public addresses are in scope.

    # Return a credential-free URL with the original path/query preserved.
    netloc = host
    if ":" in host and not host.startswith("["):
        netloc = f"[{host}]"
    if port:
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}{parsed.path or ''}{(('?' + parsed.query) if parsed.query else '')}"


def describe_scope(url: str) -> str:
    """Audit-friendly target identity (never includes query or credentials)."""
    return normalize_target(url)


def is_authorized_target(url: str, **kwargs) -> bool:
    try:
        validate_target_url(url, **kwargs)
        return True
    except TargetScopeError:
        return False
