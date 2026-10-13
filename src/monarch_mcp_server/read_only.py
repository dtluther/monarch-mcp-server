"""Tool registration allowlist (fork hardening).

Upstream gates writes with an opt in env var and a *denylist* of mutating
tools. This fork registers tools from an *allowlist* instead: a tool that
upstream adds later is not registered unless it is reviewed and added here, so
a new tool, mutating or not, cannot slip in through a merge.

Writes are on, but every write must be approved by hand in the MCP client.
Never "always allow" a tool in WRITE_TOOLS: a model can be talked into a write
by a merchant name or memo it read back.

Some tools are never registered: monarch_login, monarch_login_with_token and
monarch_logout replace or clear the stored session (log in with
login_setup.py instead), and refresh_accounts posts refresh requests to the
linked institutions.
"""

import logging
from typing import Any, Callable, FrozenSet, TypeVar

logger = logging.getLogger(__name__)

# Every tool here has been checked to issue only GraphQL queries (or no network
# call at all). Re-audit before adding anything.
READ_TOOLS: FrozenSet[str] = frozenset(
    {
        # Session status (local only, no credential values returned)
        "check_auth_status",
        "debug_session_loading",
        "setup_authentication",
        # Identity / capabilities
        "monarch_whoami",
        # Accounts
        "get_accounts",
        "get_account_holdings",
        "get_account_balance_history",
        "get_account_sync_health",
        # Transactions
        "get_transactions",
        "search_transactions",
        "get_transaction_details",
        "get_transactions_needing_review",
        "get_transactions_summary",
        "get_recurring_transactions",
        "get_transaction_splits",
        "get_transaction_tags",
        "get_transaction_rules",
        "get_spending_summary",
        "get_business_entities",
        # Categories and budgets
        "get_transaction_categories",
        "get_transaction_category_groups",
        "get_category_details",
        "get_cashflow_by_month",
        "get_budgets",
        # Financial overview
        "get_cashflow",
        "get_net_worth",
        "get_net_worth_by_account_type",
        "get_debt_paydown",
        # Goals and merchants
        "get_goals",
        "get_goal_contributions",
        "get_merchant",
    }
)

# Tools that change Monarch data. Each call needs manual approval in the client.
WRITE_TOOLS: FrozenSet[str] = frozenset(
    {
        # Accounts
        "update_account",
        # Transactions
        "create_transaction",
        "update_transaction",
        "delete_transaction",
        "categorize_transaction",
        "update_transaction_notes",
        "mark_transaction_reviewed",
        "bulk_categorize_transactions",
        "bulk_update_transactions",
        "split_transaction",
        "set_business_entity",
        "upload_account_balance_history",
        # Tags
        "set_transaction_tags",
        "add_transaction_tag",
        "create_transaction_tag",
        # Rules
        "create_transaction_rule",
        "update_transaction_rule",
        "delete_transaction_rule",
        "reorder_transaction_rule",
        # Categories and budgets
        "create_transaction_category",
        "update_category",
        "set_budget_amount",
        # Goals
        "update_savings_goal",
        "set_goal_contribution",
        # Merchants
        "update_merchant",
        "review_recurring_stream",
    }
)

ALLOWED_TOOLS: FrozenSet[str] = READ_TOOLS | WRITE_TOOLS

F = TypeVar("F", bound=Callable[..., Any])


def install(mcp: Any) -> None:
    """Make ``mcp.tool()`` register only allowlisted tools."""
    original_tool = mcp.tool

    def guarded_tool(*args: Any, **kwargs: Any) -> Callable[[F], F]:
        register = original_tool(*args, **kwargs)

        def decorator(fn: F) -> F:
            # FastMCP.tool() takes `name` as its first positional parameter, so
            # @mcp.tool("some_name") must be honoured too.
            positional = args[0] if args and isinstance(args[0], str) else None
            name = positional or kwargs.get("name") or getattr(fn, "__name__", "")
            if name not in ALLOWED_TOOLS:
                logger.info("Not in the fork allowlist, not registering %s", name)
                return fn
            return register(fn)

        return decorator

    mcp.tool = guarded_tool  # type: ignore[method-assign]
    logger.warning(
        "Fork allowlist: only %d tools will be registered (%d of them write)",
        len(ALLOWED_TOOLS),
        len(WRITE_TOOLS),
    )
