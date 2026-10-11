"""Hard read only mode (fork hardening).

Upstream gates writes with an opt in env var and a *denylist* of mutating
tools. This fork inverts both:

- Read only is always on. There is no env var to turn writes back on.
- Registration is gated by an *allowlist*. A tool that upstream adds later is
  not registered unless it is reviewed and added here, so a new mutating tool
  cannot slip in through a merge.

Unregistered tools never appear in the tool list and cannot be called, so a
model that was talked into a write by a merchant name or memo it read back has
nothing to call.
"""

import logging
from typing import Any, Callable, FrozenSet, TypeVar

logger = logging.getLogger(__name__)

# Every tool here has been checked to issue only GraphQL queries (or no network
# call at all). Re-audit before adding anything.
ALLOWED_TOOLS: FrozenSet[str] = frozenset(
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

F = TypeVar("F", bound=Callable[..., Any])


def is_read_only() -> bool:
    """Always True in this fork."""
    return True


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
                logger.info("Read only fork: not registering %s", name)
                return fn
            return register(fn)

        return decorator

    mcp.tool = guarded_tool  # type: ignore[method-assign]
    logger.warning(
        "Read only fork: only %d allowlisted tools will be registered",
        len(ALLOWED_TOOLS),
    )
