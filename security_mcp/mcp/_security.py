"""SSRF protection utilities for MCP tools.

Blocks requests to internal/private IP ranges unless explicitly allowed
via the ``SECMCP_ALLOW_INTERNAL`` environment variable.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

_INTERNAL_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
]


def is_internal_target(url: str) -> bool:
    """Check if URL points to an internal/private IP.

    Returns ``True`` when the hostname resolves to a private/loopback address
    **and** the ``SECMCP_ALLOW_INTERNAL`` env-var is not set to a truthy
    value (``1``, ``true``, ``yes``).

    Args:
        url: Full URL (e.g. ``http://localhost:3000/api``).

    Returns:
        ``True`` if the target is internal and access is not allowed.
    """
    if os.environ.get("SECMCP_ALLOW_INTERNAL", "").strip() in ("1", "true", "yes"):
        return False
    try:
        # Normalize bare hostnames/IPs (no scheme) so urlparse extracts hostname correctly
        normalized = url if "://" in url else f"http://{url}"
        hostname = urlparse(normalized).hostname or ""
        if hostname in ("localhost", ""):
            return True
        ip = ipaddress.ip_address(hostname)
        return any(ip in net for net in _INTERNAL_NETS)
    except (ValueError, OSError):
        return False  # Can't resolve, allow (DNS will handle it)
