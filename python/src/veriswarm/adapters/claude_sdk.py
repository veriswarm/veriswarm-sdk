"""VeriSwarm Claude Agent SDK adapter with Guard enforcement.

Wraps Claude Agent SDK tool execution with PII tokenization, policy
enforcement, prompt injection scanning, and audit logging.

The Claude Agent SDK uses tool functions decorated with @tool or passed
as Tool objects. This adapter wraps those functions to intercept inputs
and outputs through the Guard pipeline.

Usage:
    from veriswarm.adapters.claude_sdk import VeriSwarmClaudeGuard

    guard = VeriSwarmClaudeGuard(api_key="vs_...", agent_id="agt_...", guard_pii=True)

    # Wrap tools before passing to the agent
    @guard.protect
    def read_customer_data(customer_id: str) -> str:
        '''Read customer record from database.'''
        return db.get_customer(customer_id)

    # Or wrap existing tools
    safe_tools = guard.wrap_tools([tool1, tool2])

    # Use with Claude Agent SDK
    agent = Agent(
        model="claude-sonnet-4-20250514",
        tools=safe_tools,
    )
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from .guard_mixin import GuardMixin, GuardContext

logger = logging.getLogger("veriswarm.claude_sdk")


class VeriSwarmClaudeGuard(GuardMixin):
    """Guard adapter for Claude Agent SDK. Wraps tool functions with Guard pipeline."""

    def __init__(self, api_key: str, agent_id: str, **kwargs):
        super().__init__(api_key=api_key, agent_id=agent_id, **kwargs)
        self._last_ctx: GuardContext | None = None

    def protect(self, fn: Callable) -> Callable:
        """Decorator to wrap a tool function with Guard protection.

        Usage:
            @guard.protect
            def my_tool(query: str) -> str:
                return database.search(query)
        """
        return self._wrap_callable(fn, getattr(fn, "__name__", "unknown"))

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap a Claude Agent SDK tool with Guard protection.

        Works with:
        - claude_agent_sdk.Tool instances
        - @tool decorated functions
        - Plain callables
        """
        # Try Claude Agent SDK Tool class
        try:
            from claude_agent_sdk import Tool as ClaudeTool
            if isinstance(tool, ClaudeTool):
                return self._wrap_claude_tool(tool)
        except ImportError:
            pass

        # Try Anthropic's tool_use pattern
        if callable(tool):
            return self._wrap_callable(tool, getattr(tool, "__name__", "unknown"))

        logger.warning(f"Cannot wrap tool of type {type(tool)}, returning unwrapped")
        return tool

    def wrap_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap a list of tools with Guard protection."""
        return [self.wrap_tool(t) for t in tools]

    def _wrap_claude_tool(self, tool: Any) -> Any:
        """Wrap a Claude Agent SDK Tool by intercepting its callable."""
        if hasattr(tool, "function") and callable(tool.function):
            original_fn = tool.function
            tool_name = getattr(tool, "name", getattr(original_fn, "__name__", "unknown"))
            tool.function = self._make_guarded(original_fn, tool_name)
        elif hasattr(tool, "__call__"):
            tool_name = getattr(tool, "name", "unknown")
            original_call = tool.__call__
            tool.__call__ = self._make_guarded(original_call, tool_name)
        return tool

    def _wrap_callable(self, fn: Callable, name: str) -> Callable:
        """Wrap a plain callable with Guard protection."""
        return self._make_guarded(fn, name)

    def _make_guarded(self, fn: Callable, name: str) -> Callable:
        """Create a guarded version of a function."""
        guard = self
        is_async = _is_async(fn)

        if is_async:
            @functools.wraps(fn)
            async def guarded_async(*args, **kwargs):
                input_str = _serialize_args(args, kwargs)
                filtered_input, ctx = guard.guard_before_tool(name, input_str)
                guard._last_ctx = ctx

                if ctx.blocked:
                    return ctx.block_message

                try:
                    result = await fn(*args, **kwargs)
                    if isinstance(result, str):
                        result = guard.guard_after_tool(name, result, ctx)
                    return result
                except Exception as e:
                    guard.guard_on_error(name, e, ctx)
                    raise

            return guarded_async
        else:
            @functools.wraps(fn)
            def guarded_sync(*args, **kwargs):
                input_str = _serialize_args(args, kwargs)
                filtered_input, ctx = guard.guard_before_tool(name, input_str)
                guard._last_ctx = ctx

                if ctx.blocked:
                    return ctx.block_message

                try:
                    result = fn(*args, **kwargs)
                    if isinstance(result, str):
                        result = guard.guard_after_tool(name, result, ctx)
                    return result
                except Exception as e:
                    guard.guard_on_error(name, e, ctx)
                    raise

            return guarded_sync

    @property
    def last_pii_session(self) -> str | None:
        return self._last_ctx.pii_session_id if self._last_ctx else None


def _is_async(fn: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)


def _serialize_args(args: tuple, kwargs: dict) -> str:
    parts = [str(a) for a in args]
    parts.extend(f"{k}={v}" for k, v in kwargs.items())
    return " ".join(parts)
