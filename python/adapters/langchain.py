"""VeriSwarm LangChain callback handler. Auto-instruments agent tool calls."""
from __future__ import annotations

import logging
import time
import uuid
from typing import Any

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    raise ImportError("Install langchain-core: pip install veriswarm[langchain]")

from veriswarm_client import VeriSwarmClient

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
        self._client = VeriSwarmClient(base_url, api_key, timeout_seconds=timeout_seconds)
        self._active_tools: dict[str, float] = {}  # run_id -> start_time

    def on_tool_start(
        self, serialized: dict[str, Any], input_str: str, *, run_id: uuid.UUID, **kwargs: Any
    ) -> None:
        """Record tool start time for duration calculation."""
        self._active_tools[str(run_id)] = time.monotonic()

        if self.enforce:
            tool_name = serialized.get("name", "unknown")
            try:
                result = self._client.check_decision(self.agent_id, "tool_call", tool_name)
                decision = result.get("decision", "review")
                if decision == "deny":
                    if self.on_deny == "raise":
                        raise PermissionError(
                            f"VeriSwarm denied tool call '{tool_name}': {result.get('reason_code', 'unknown')}"
                        )
                    elif self.on_deny == "log":
                        logger.warning(f"VeriSwarm denied tool '{tool_name}' but on_deny=log, continuing")
                    elif self.on_deny == "skip":
                        raise PermissionError(f"VeriSwarm denied tool '{tool_name}'")
            except PermissionError:
                raise
            except Exception as e:
                logger.debug(f"VeriSwarm decision check failed, allowing: {e}")

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
            self._client.ingest_event(
                event_id=f"lc-{uuid.uuid4().hex[:16]}",
                agent_id=self.agent_id,
                source_type="agent",
                event_type=event_type,
                occurred_at=None,  # server will use current time
                payload={k: v for k, v in payload.items() if v is not None},
            )
        except Exception as e:
            logger.debug(f"VeriSwarm event report failed (non-blocking): {e}")
