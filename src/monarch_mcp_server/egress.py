"""In-process egress allowlist (fork hardening).

Every HTTP request this server makes, from our code, the monarchmoney library
and gql, goes through aiohttp. This patches aiohttp.ClientSession._request so
a request to any host other than Monarch's API is refused before a socket is
opened. It is defence in depth, not a substitute for an OS-level firewall
rule: code that opens its own sockets would bypass it.
"""

import logging
from typing import Any

from aiohttp import ClientSession
from yarl import URL

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset({"api.monarch.com"})


class EgressBlocked(RuntimeError):
    """Raised when code tries to reach a host outside ALLOWED_HOSTS."""


_installed = False


def install() -> None:
    global _installed
    if _installed:
        return

    original = ClientSession._request

    async def guarded(self: ClientSession, method: str, str_or_url: Any, **kwargs: Any) -> Any:
        url = URL(str(str_or_url))
        base = getattr(self, "_base_url", None)
        if not url.is_absolute() and base is not None:
            url = base.join(url)
        if url.scheme != "https" or url.host not in ALLOWED_HOSTS:
            logger.error("Blocked outbound request to %s://%s", url.scheme, url.host)
            raise EgressBlocked(f"Outbound request to {url.host!r} is not allowed")
        if kwargs.get("proxy"):
            raise EgressBlocked("Proxied requests are not allowed")
        return await original(self, method, str_or_url, **kwargs)

    ClientSession._request = guarded  # type: ignore[method-assign]
    _installed = True
