"""VeriSwarm OpenAI Agents SDK adapter with Guard enforcement.

Wraps OpenAI Agents SDK tool execution with PII tokenization, policy
enforcement, prompt injection scanning, and audit logging.

Usage:
    from veriswarm.adapters.openai_agents import VeriSwarmOpenAIGuard

    guard = VeriSwarmOpenAIGuard(api_key="vs_...", agent_id="agt_...", guard_pii=True)

    # Wrap tools before passing to the agent
    safe_tools = guard.wrap_tools([my_tool_1, my_tool_2])

    agent = Agent(
        name="my-agent",
        tools=safe_tools,
    )
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from .guard_mixin import GuardMixin, GuardContext

logger = logging.getLogger("veriswarm.openai_agents")


class VeriSwarmOpenAIGuard(GuardMixin):
    """Guard adapter for OpenAI Agents SDK. Wraps tool functions with Guard pipeline."""

    def __init__(self, api_key: str, agent_id: str, **kwargs):
        super().__init__(api_key=api_key, agent_id=agent_id, **kwargs)
        self._last_ctx: GuardContext | None = None

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap an OpenAI Agents SDK tool with Guard protection.

        Works with:
        - @function_tool decorated functions
        - FunctionTool instances
        - Plain callables
        """
        try:
            from agents import FunctionTool
            if isinstance(tool, FunctionTool):
                return self._wrap_function_tool(tool)
        except ImportError:
            pass

        if callable(tool):
            return self._wrap_callable(tool, getattr(tool, "__name__", "unknown"))

        logger.warning(f"Cannot wrap tool of type {type(tool)}, returning unwrapped")
        return tool

    def wrap_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap a list of tools with Guard protection."""
        return [self.wrap_tool(t) for t in tools]

    def _wrap_function_tool(self, tool: Any) -> Any:
        """Wrap an OpenAI FunctionTool by intercepting its on_invoke_tool handler."""
        original_invoke = tool.on_invoke_tool
        tool_name = getattr(tool, "name", "unknown")
        guard = self

        @functools.wraps(original_invoke)
        async def guarded_invoke(ctx, input_str: str) -> str:
            filtered_input, gctx = guard.guard_before_tool(tool_name, input_str)
            guard._last_ctx = gctx

            if gctx.blocked:
                return gctx.block_message

            try:
                result = await original_invoke(ctx, filtered_input if isinstance(filtered_input, str) else input_str)
                if isinstance(result, str):
                    result = guard.guard_after_tool(tool_name, result, gctx)
                return result
            except Exception as e:
                guard.guard_on_error(tool_name, e, gctx)
                raise

        tool.on_invoke_tool = guarded_invoke
        return tool

    def _wrap_callable(self, fn: Callable, name: str) -> Callable:
        """Wrap a plain callable with Guard protection."""
        guard = self

        @functools.wraps(fn)
        async def guarded(*args, **kwargs):
            input_str = " ".join(str(a) for a in args)
            filtered_input, ctx = guard.guard_before_tool(name, input_str)
            guard._last_ctx = ctx

            if ctx.blocked:
                return ctx.block_message

            try:
                result = await fn(*args, **kwargs) if _is_async(fn) else fn(*args, **kwargs)
                if isinstance(result, str):
                    result = guard.guard_after_tool(name, result, ctx)
                return result
            except Exception as e:
                guard.guard_on_error(name, e, ctx)
                raise

        return guarded

    @property
    def last_pii_session(self) -> str | None:
        return self._last_ctx.pii_session_id if self._last_ctx else None


def _is_async(fn: Callable) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)
