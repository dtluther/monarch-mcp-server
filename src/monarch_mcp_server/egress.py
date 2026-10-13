"""In-process egress allowlist (fork hardening).

Every HTTP request this server makes, from our code, the monarchmoney library
and gql, goes through aiohttp. This patches aiohttp's BaseConnector.connect so
a request to anything other than Monarch's API on port 443 is refused before a
socket is opened. It is defence in depth, not a substitute for an OS-level
firewall rule: code that opens its own sockets, or uses another HTTP client,
would bypass it.

The check sits on connect, not ClientSession._request, because aiohttp follows
redirects inside _request: a guard there sees only the first URL, so a redirect
from api.monarch.com to another host would go through. connect runs once per
hop, redirects included. It also sees req.proxy, which aiohttp fills from
HTTPS_PROXY when trust_env is on, not only from a proxy= argument.
"""

import logging
from typing import Any

from aiohttp.connector import BaseConnector

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset({"api.monarch.com"})
ALLOWED_PORT = 443


class EgressBlocked(RuntimeError):
    """Raised when code tries to reach a destination outside the allowlist."""


_installed = False


def check(url: Any, proxy: Any = None) -> None:
    """Raise EgressBlocked unless ``url`` is https://api.monarch.com:443."""
    if url.scheme != "https" or url.host not in ALLOWED_HOSTS or url.port != ALLOWED_PORT:
        logger.error("Blocked outbound request to %s://%s:%s", url.scheme, url.host, url.port)
        raise EgressBlocked(f"Outbound request to {url.host!r} is not allowed")
    if proxy:
        logger.error("Blocked proxied request to %s", url.host)
        raise EgressBlocked("Proxied requests are not allowed")


def install() -> None:
    global _installed
    if _installed:
        return

    original = BaseConnector.connect

    async def guarded(self: BaseConnector, req: Any, *args: Any, **kwargs: Any) -> Any:
        check(req.url, req.proxy)
        return await original(self, req, *args, **kwargs)

    BaseConnector.connect = guarded  # type: ignore[method-assign]
    _installed = True
