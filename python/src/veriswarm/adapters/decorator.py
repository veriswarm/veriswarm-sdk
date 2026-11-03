"""VeriSwarm @guard_protected decorator for custom tools.

The simplest way to add Guard protection to any Python function — no framework
required. Works with sync and async functions.

Usage:
    from veriswarm.adapters.decorator import guard_protected, configure_guard

    # Configure once at startup
    configure_guard(api_key="vs_...", agent_id="agt_...")

    # Decorate any function
    @guard_protected
    def read_customer(customer_id: str) -> str:
        return db.get_customer(customer_id)

    @guard_protected
    async def search_records(query: str) -> str:
        return await db.search(query)

    # PII in string arguments (including strings inside dict/list/tuple
    # arguments) and in string return values is tokenized.
    # Dangerous calls are blocked by policy. Everything is audited.

    # To rehydrate PII for writing:
    from veriswarm.adapters.decorator import rehydrate
    real_data = rehydrate(tokenized_text)
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from .guard_mixin import GuardMixin, GuardContext, run_blocking

logger = logging.getLogger("veriswarm.guard.decorator")

# Module-level guard instance
_guard: GuardMixin | None = None


def configure_guard(
    api_key: str,
    agent_id: str,
    base_url: str = "https://api.veriswarm.ai",
    guard_pii: bool = True,
    guard_enforce: bool = True,
    guard_injection_scan: bool = True,
    guard_audit: bool = True,
    on_deny: str = "raise",
    timeout_seconds: int = 5,
) -> GuardMixin:
    """Configure the module-level Guard instance. Call once at startup.

    Returns the Guard instance for advanced use.
    """
    global _guard
    _guard = GuardMixin(
        api_key=api_key,
        agent_id=agent_id,
        base_url=base_url,
        guard_pii=guard_pii,
        guard_enforce=guard_enforce,
        guard_injection_scan=guard_injection_scan,
        guard_audit=guard_audit,
        on_deny=on_deny,
        timeout_seconds=timeout_seconds,
    )
    return _guard


def _get_guard() -> GuardMixin:
    if _guard is None:
        raise RuntimeError(
            "Guard not configured. Call configure_guard(api_key=..., agent_id=...) first."
        )
    return _guard


def guard_protected(fn: Callable | None = None, *, name: str | None = None) -> Callable:
    """Decorator that wraps any function with Guard protection.

    PII in string arguments (positional or keyword, including strings nested
    in dict / list / tuple arguments) and in string return values is
    tokenized, and secrets are redacted; the function receives the guarded
    values. Other argument types are passed through unchanged.
    Policy decisions are enforced. Tool calls are audited.

    Can be used with or without arguments:
        @guard_protected
        def my_tool(query: str) -> str: ...

        @guard_protected(name="custom_tool_name")
        def my_tool(query: str) -> str: ...
    """
    def decorator(f: Callable) -> Callable:
        tool_name = name or getattr(f, "__name__", "unknown")
        is_async = _is_async(f)

        if is_async:
            @functools.wraps(f)
            async def async_wrapper(*args, **kwargs):
                guard = _get_guard()
                args, kwargs, ctx = await run_blocking(guard.guard_before_call, tool_name, args, kwargs)

                if ctx.blocked:
                    return ctx.block_message

                try:
                    result = await f(*args, **kwargs)
                except Exception as e:
                    await run_blocking(guard.guard_on_error, tool_name, e, ctx)
                    raise
                if isinstance(result, str):
                    result = await run_blocking(guard.guard_after_tool, tool_name, result, ctx)
                return result

            async_wrapper._guard_ctx = None  # type: ignore
            return async_wrapper
        else:
            @functools.wraps(f)
            def sync_wrapper(*args, **kwargs):
                guard = _get_guard()
                args, kwargs, ctx = guard.guard_before_call(tool_name, args, kwargs)

                if ctx.blocked:
                    return ctx.block_message

                try:
                    result = f(*args, **kwargs)
                    if isinstance(result, str):
                        result = guard.guard_after_tool(tool_name, result, ctx)
                    return result
                except Exception as e:
                    guard.guard_on_error(tool_name, e, ctx)
                    raise

            sync_wrapper._guard_ctx = None  # type: ignore
            return sync_wrapper

    # Support both @guard_protected and @guard_protected(name="...")
    if fn is not None:
        return decorator(fn)
    return decorator


def rehydrate(text: str, session_id: str | None = None) -> str:
    """Restore original PII values from Guard tokens.

    Call this when you need to write tokenized data back to a real system
    (database, email, CRM, etc.).
    """
    guard = _get_guard()
    return guard.guard_rehydrate(text, session_id)


def _is_async(fn: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)
