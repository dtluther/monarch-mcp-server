"""FastMCP application instance and entry point."""

import argparse
import logging
import os

try:  # mcp >= 2.0 renamed FastMCP to MCPServer
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp < 2.0
    from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# The gql aiohttp transport logs full GraphQL requests/responses at INFO, which
# can include Monarch account payloads. Raise its floor to WARNING so those
# payloads are not written to logs. Transport-level errors still surface; drop
# this to INFO/DEBUG temporarily if you need to trace GraphQL traffic.
logging.getLogger("gql.transport.aiohttp").setLevel(logging.WARNING)

# Initialize FastMCP server
mcp = FastMCP("Monarch Money MCP Server")

# Must run before the tool modules are imported, since it works by wrapping
# mcp.tool() and registration happens at import time.
from monarch_mcp_server import read_only  # noqa: E402

read_only.install(mcp)

# Import tools package to trigger @mcp.tool() registration
import monarch_mcp_server.tools  # noqa: E402, F401

# Starlette redirects /mcp/ to /mcp at routing time, before the endpoint and so
# before the Host check, and it builds the Location header from the request's
# own Host. A request with Host: evil.example therefore got a 307 to
# http://evil.example/mcp, and a 307 preserves the method and body, which here
# means tool arguments. Behind the reverse proxy the README recommends, which
# passes the public Host through, a client configured with a trailing slash
# would resend its body to an attacker chosen host.
#
# mcp.run() builds the Starlette app internally, so the builder is wrapped
# rather than the run path, which leaves the transport selection untouched.
_build_streamable_http_app = mcp.streamable_http_app


def _streamable_http_app_without_slash_redirect():  # type: ignore[no-untyped-def]
    http_app = _build_streamable_http_app()
    http_app.router.redirect_slashes = False
    return http_app


mcp.streamable_http_app = _streamable_http_app_without_slash_redirect

# Export for `mcp run`
app = mcp


def main(argv: list[str] | None = None) -> None:
    """Main entry point. Fork hardening: stdio transport only.

    The HTTP transport, its Host/Origin settings and the Docker image were
    removed. Nothing listens on a port, so nothing on the network can reach the
    stored Monarch session through this process.
    """
    parser = argparse.ArgumentParser(description="Monarch Money MCP Server (stdio only)")
    parser.parse_args(argv)
    if os.environ.get("MONARCH_MCP_TRANSPORT", "stdio") != "stdio":
        parser.error("This fork only supports the stdio transport")

    logger.info("Starting Monarch Money MCP Server (stdio)...")
    try:
        mcp.run()
    except Exception as e:
        logger.error(f"Failed to run server: {str(e)}")
        raise


if __name__ == "__main__":
    main()
