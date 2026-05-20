"""VeriSwarm CrewAI adapter with Guard enforcement.

Wraps CrewAI tool execution with PII tokenization, policy enforcement,
prompt injection scanning, and audit logging.

Usage:
    from veriswarm.adapters.crewai import VeriSwarmCrewGuard

    guard = VeriSwarmCrewGuard(api_key="vs_...", agent_id="agt_...", guard_pii=True)

    # Wrap individual tools
    safe_tool = guard.wrap_tool(my_tool)

    # Or wrap all tools for a crew
    safe_tools = guard.wrap_tools([tool1, tool2, tool3])

    crew = Crew(agents=[...], tasks=[...], tools=safe_tools)
"""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable

from .guard_mixin import GuardMixin, GuardContext

logger = logging.getLogger("veriswarm.crewai")


class VeriSwarmCrewGuard(GuardMixin):
    """Guard adapter for CrewAI. Wraps tool functions with Guard pipeline."""

    def __init__(self, api_key: str, agent_id: str, **kwargs):
        super().__init__(api_key=api_key, agent_id=agent_id, **kwargs)
        self._last_ctx: GuardContext | None = None

    def wrap_tool(self, tool: Any) -> Any:
        """Wrap a CrewAI tool with Guard protection.

        Works with both crewai.Tool instances and plain functions.
        The original tool's name, description, and schema are preserved.
        """
        try:
            from crewai.tools import BaseTool as CrewBaseTool
            if isinstance(tool, CrewBaseTool):
                return self._wrap_crewai_tool(tool)
        except ImportError:
            pass

        # Fall back to wrapping as a callable
        if callable(tool):
            return self._wrap_callable(tool, getattr(tool, "__name__", "unknown"))

        logger.warning(f"Cannot wrap tool of type {type(tool)}, returning unwrapped")
        return tool

    def wrap_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap a list of tools with Guard protection."""
        return [self.wrap_tool(t) for t in tools]

    def _wrap_crewai_tool(self, tool: Any) -> Any:
        """Wrap a CrewAI BaseTool by monkey-patching its _run method."""
        original_run = tool._run
        tool_name = getattr(tool, "name", "unknown")
        guard = self

        @functools.wraps(original_run)
        def guarded_run(*args, **kwargs):
            # Combine args into a string representation for PII scanning
            input_str = " ".join(str(a) for a in args) + " ".join(f"{k}={v}" for k, v in kwargs.items())

            filtered_input, ctx = guard.guard_before_tool(tool_name, input_str)
            guard._last_ctx = ctx

            if ctx.blocked:
                return ctx.block_message

            try:
                result = original_run(*args, **kwargs)

                if isinstance(result, str):
                    result = guard.guard_after_tool(tool_name, result, ctx)
                return result
            except Exception as e:
                guard.guard_on_error(tool_name, e, ctx)
                raise

        tool._run = guarded_run
        return tool

    def _wrap_callable(self, fn: Callable, name: str) -> Callable:
        """Wrap a plain callable with Guard protection."""
        guard = self

        @functools.wraps(fn)
        def guarded(*args, **kwargs):
            input_str = " ".join(str(a) for a in args) + " ".join(f"{k}={v}" for k, v in kwargs.items())

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

        return guarded

    @property
    def last_pii_session(self) -> str | None:
        """Get the most recent PII session ID for rehydration."""
        return self._last_ctx.pii_session_id if self._last_ctx else None
