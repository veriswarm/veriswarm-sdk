"""VeriSwarm LangChain callback handler. Auto-instruments agent tool calls."""
from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError("Install langchain-core: pip install veriswarm[langchain]")

from veriswarm.client import VeriSwarmClient

from .guard_mixin import guard_secrets_in, warn_rate_limited

logger = logging.getLogger("veriswarm.langchain")


class VeriSwarmCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that reports agent activity to VeriSwarm.

    Usage:
        handler = VeriSwarmCallbackHandler(api_key="vs_...", agent_id="agt_...")
        agent = initialize_agent(tools, llm, callbacks=[handler])
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        base_url: str = "https://api.veriswarm.ai",
        enforce: bool = False,
        on_deny: str = "raise",  # "raise", "skip", "log"
        timeout_seconds: int = 5,
    ):
        super().__init__()
        self.agent_id = agent_id
        self.enforce = enforce
        self.on_deny = on_deny
        # LangChain swallows callback exceptions unless raise_error is set, which
        # would silently turn a deny into an allow.
        self.raise_error = enforce
        self._client = VeriSwarmClient(
            base_url, api_key, timeout_seconds=timeout_seconds, secrets_detection=True
        )
        self._active_tools: dict[str, float] = {}  # run_id -> start_time

    def on_tool_start(
        self, serialized: dict[str, Any], input_str: str, *, run_id: uuid.UUID, **kwargs: Any
    ) -> None:
        """Enforce the trust decision, then record tool start time."""
        if self.enforce:
            self._enforce(((serialized or {}).get("name")) or kwargs.get("name") or "unknown")
        self._active_tools[str(run_id)] = time.monotonic()

    def _enforce(self, tool_name: str) -> None:
        """Raise PermissionError unless the decision is an explicit "allow" (fail closed)."""
        decision: Any = None
        reason = "decision_unavailable"
        try:
            result = self._client.check_decision(
                agent_id=self.agent_id,
                action_type="tool_call",
                resource_type=tool_name,
            )
            if isinstance(result, dict):
                decision = result.get("decision")
                reason = result.get("reason_code") or "policy_denied"
        except Exception as e:  # noqa: BLE001 - fail closed on anything
            warn_rate_limited(
                logger, "decision-check",
                "VeriSwarm decision check failed for tool '%s': %s", tool_name, e,
            )
        if decision == "allow":
            return
        if self.on_deny == "log":
            logger.warning(
                "VeriSwarm did not allow tool '%s' (decision=%s) but on_deny=log, continuing",
                tool_name, decision,
            )
            return
        if decision == "review":
            raise PermissionError(
                f"VeriSwarm requires review before tool '{tool_name}' can run: {reason}"
            )
        raise PermissionError(f"VeriSwarm denied tool call '{tool_name}': {reason}")

    def on_tool_end(self, output: str, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        """Report successful tool call."""
        start = self._active_tools.pop(str(run_id), None)
        duration_ms = int((time.monotonic() - start) * 1000) if start else None

        tool_name = kwargs.get("name", "unknown")
        self._report_event("tool.call.success", {
            "tool_name": tool_name,
            "duration_ms": duration_ms,
            "output_summary": str(output)[:200] if output else None,
        })

    def on_tool_error(self, error: BaseException, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        """Report failed tool call."""
        self._active_tools.pop(str(run_id), None)
        tool_name = kwargs.get("name", "unknown")
        self._report_event("tool.call.failure", {
            "tool_name": tool_name,
            "error_type": type(error).__name__,
        })

    def on_chain_end(self, outputs: dict[str, Any], *, run_id: uuid.UUID, **kwargs: Any) -> None:
        """Report chain/task completion."""
        self._report_event("task.completed", {
            "task_type": "langchain_chain",
        })

    def on_chain_error(self, error: BaseException, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        """Report chain/task failure."""
        self._report_event("task.failed", {
            "task_type": "langchain_chain",
            "error_type": type(error).__name__,
        })

    def _report_event(self, event_type: str, payload: dict) -> None:
        """Fire-and-forget event reporting. Never blocks or raises."""
        try:
            safe = guard_secrets_in(self._client, payload, agent_id=self.agent_id)
            self._client.ingest_event(
                event_id=f"lc-{uuid.uuid4().hex[:16]}",
                agent_id=self.agent_id,
                source_type="agent",
                event_type=event_type,
                occurred_at=datetime.now(timezone.utc).isoformat(),
                payload={k: v for k, v in safe.items() if v is not None},
            )
        except Exception as e:
            warn_rate_limited(
                logger, "event-report", "VeriSwarm event report failed (non-blocking): %s", e
            )
