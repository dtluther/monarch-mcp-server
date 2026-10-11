"""Tests for the fork's always-on, allowlist-based read only mode."""

import pytest

from monarch_mcp_server import read_only


def test_read_only_ignores_environment(monkeypatch):
    for value in ("", "0", "false", "off"):
        monkeypatch.setenv("MONARCH_MCP_READ_ONLY", value)
        assert read_only.is_read_only() is True


def _fake_mcp(registered):
    class FakeMCP:
        def tool(self, *args, **kwargs):
            def decorator(fn):
                registered.append(args[0] if args else kwargs.get("name") or fn.__name__)
                return fn

            return decorator

    return FakeMCP()


def test_unknown_tools_are_not_registered():
    registered = []
    mcp = _fake_mcp(registered)
    read_only.install(mcp)

    @mcp.tool()
    def get_accounts():
        pass

    @mcp.tool()
    def delete_transaction():
        pass

    @mcp.tool()
    def some_new_upstream_tool():
        pass

    @mcp.tool("delete_everything")
    def get_accounts_alias():
        pass

    assert registered == ["get_accounts"]


async def test_registered_set_is_exactly_the_allowlist():
    from monarch_mcp_server.app import mcp

    registered = {t.name for t in await mcp.list_tools()}
    assert registered == set(read_only.ALLOWED_TOOLS)


class TestGateCannotSilentlyMissANewWriteTool:
    """The direction that actually matters.

    Asserting every name in MUTATING_TOOLS exists catches a typo. It cannot
    catch a newly added writing tool that nobody put in the set, which is the
    failure that exposes a write in a deployment whose whole premise is that it
    cannot write. This derives the mutating set from the code instead.
    """

    # Library calls that write. Derived from the upstream client surface.
    WRITING_CLIENT_METHODS = frozenset(
        {
            "create_transaction",
            "update_transaction",
            "delete_transaction",
            "set_transaction_tags",
            "create_transaction_tag",
            "update_transaction_splits",
            "create_transaction_category",
            "delete_transaction_category",
            "set_budget_amount",
            "update_account",
            "delete_account",
            "request_accounts_refresh",
            "request_accounts_refresh_and_wait",
            "upload_account_balance_history",
        }
    )

    @staticmethod
    def _is_mutation_document(obj):
        """Whether a module level gql constant is a mutation.

        Read from the parsed AST rather than the source text. gql 4.x wraps the
        DocumentNode in a GraphQLRequest, so both shapes are handled; a text
        match would also be fooled by the word "mutation" in a comment.
        """
        from graphql.language.ast import DocumentNode, OperationDefinitionNode

        doc = getattr(obj, "document", obj)
        if not isinstance(doc, DocumentNode):
            return False
        return any(
            isinstance(d, OperationDefinitionNode)
            and getattr(d.operation, "value", d.operation) == "mutation"
            for d in doc.definitions
        )

    def _mutating_from_source(self):
        import inspect
        import re

        from monarch_mcp_server import read_only as ro
        from monarch_mcp_server import server as srv

        mutating = set()
        for name in dir(srv):
            fn = getattr(srv, name)
            if not callable(fn) or not hasattr(fn, "__module__"):
                continue
            if not str(fn.__module__).startswith("monarch_mcp_server.tools"):
                continue
            try:
                source = inspect.getsource(fn)
            except (OSError, TypeError):
                continue

            module = __import__(fn.__module__, fromlist=["x"])

            for const in re.findall(r"\b([A-Z][A-Z0-9_]{3,})\b", source):
                if self._is_mutation_document(getattr(module, const, None)):
                    mutating.add(name)

            for method in self.WRITING_CLIENT_METHODS:
                if f"client.{method}(" in source:
                    mutating.add(name)

            # The two checks above only see a mutation held in an UPPERCASE
            # module constant or sent through a named client method. gql_call
            # accepts an arbitrary document, so a mutation written inline, or
            # held in a lowercase or local name, would slip past both and
            # register ungated with this test still green.
            inline_mutation = r"gql\(\s*[\"']{1,3}\s*mutation\b"
            if re.search(inline_mutation, source, re.I):
                mutating.add(name)
            for ident in re.findall(
                r"graphql_query\s*=\s*([A-Za-z_][A-Za-z0-9_]*)", source
            ):
                if self._is_mutation_document(getattr(module, ident, None)):
                    mutating.add(name)
        return mutating, ro

    async def test_no_allowlisted_tool_writes(self):
        mutating, ro = self._mutating_from_source()
        leaked = sorted(mutating & ro.ALLOWED_TOOLS)
        assert not leaked, f"allowlisted tools that write: {leaked}"

    async def test_no_registered_tool_writes(self):
        from monarch_mcp_server.app import mcp

        mutating, _ = self._mutating_from_source()
        registered = {t.name for t in await mcp.list_tools()}
        assert not (mutating & registered)

    async def test_the_detector_actually_detects_something(self):
        """Guard against the check above silently matching nothing."""
        mutating, _ = self._mutating_from_source()
        assert len(mutating) >= 25
