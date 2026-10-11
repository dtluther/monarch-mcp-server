"""Monarch Money MCP Server."""

__version__ = "0.1.0"

# Fork hardening: refuse any outbound HTTP request that is not to Monarch's API.
# Installed on package import so the server and login_setup.py both get it.
from monarch_mcp_server import egress as _egress

_egress.install()
