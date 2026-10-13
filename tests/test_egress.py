"""Tests for the fork's in-process egress allowlist."""

import aiohttp
import pytest
from aiohttp import web
from yarl import URL

from monarch_mcp_server import egress


@pytest.mark.parametrize(
    "url",
    [
        "https://api.monarch.com/graphql",
        "https://api.monarch.com:443/auth/login/",
    ],
)
def test_monarch_api_is_allowed(url):
    egress.check(URL(url))


@pytest.mark.parametrize(
    "url",
    [
        "http://api.monarch.com/graphql",
        "https://api.monarch.com:8443/graphql",
        "https://evil.example/graphql",
        "https://api.monarch.com.evil.example/graphql",
        "https://app.monarch.com/",
    ],
)
def test_everything_else_is_blocked(url):
    with pytest.raises(egress.EgressBlocked):
        egress.check(URL(url))


def test_proxy_is_blocked():
    with pytest.raises(egress.EgressBlocked):
        egress.check(URL("https://api.monarch.com/graphql"), URL("http://proxy:3128"))


async def test_guard_is_installed_on_package_import():
    """A plain aiohttp request to another host never reaches a socket."""
    async with aiohttp.ClientSession() as session:
        with pytest.raises(egress.EgressBlocked):
            await session.get("http://127.0.0.1:9/")


async def test_redirect_hop_is_checked(monkeypatch):
    """A guard on the first URL only would let a redirect leave the allowlist.

    The local server stands in for api.monarch.com: the first check is relaxed
    for it, and the redirect to another host must still be refused.
    """
    hops = []

    async def redirect(request):
        raise web.HTTPFound("http://evil.example/steal")

    app = web.Application()
    app.router.add_get("/", redirect)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]

    real_check = egress.check

    def check_allowing_local(url, proxy=None):
        hops.append(str(url))
        if url.host == "127.0.0.1" and url.port == port:
            return
        real_check(url, proxy)

    monkeypatch.setattr(egress, "check", check_allowing_local)
    try:
        async with aiohttp.ClientSession() as session:
            with pytest.raises(egress.EgressBlocked):
                await session.get(f"http://127.0.0.1:{port}/")
    finally:
        await runner.cleanup()

    assert hops[-1].startswith("http://evil.example/")
