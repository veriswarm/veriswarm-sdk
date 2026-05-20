"""VeriSwarm Guard Mixin — shared guardrail logic for all framework adapters.

Provides PII tokenization, policy enforcement, prompt injection scanning,
and audit logging that any framework adapter can use by mixing in GuardMixin.

Usage in an adapter:
    class MyFrameworkAdapter(GuardMixin):
        def __init__(self, api_key, agent_id, **kwargs):
            super().__init__(api_key=api_key, agent_id=agent_id, **kwargs)

        def on_tool_call(self, tool_name, tool_input):
            # Before tool executes
            filtered_input, ctx = self.guard_before_tool(tool_name, tool_input)
            if ctx.blocked:
                return ctx.block_message

            # ... execute tool with filtered_input ...

            # After tool returns
            filtered_output = self.guard_after_tool(tool_name, output, ctx)
            return filtered_output
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from veriswarm_client import VeriSwarmClient, VeriSwarmClientError

logger = logging.getLogger("veriswarm.guard")


@dataclass
class GuardContext:
    """Context passed between guard_before_tool and guard_after_tool."""
    tool_name: str = ""
    blocked: bool = False
    block_reason: str = ""
    block_message: str = ""
    pii_session_id: str | None = None
    tokens_created: int = 0
    start_time: float = 0.0
    decision: str = "allow"


class GuardMixin:
    """Mixin providing Guard pipeline for framework adapters.

    Handles: PII tokenization, policy enforcement, prompt injection scanning,
    and audit logging. Framework adapters inherit this and call guard_before_tool /
    guard_after_tool around tool execution.
    """

    def __init__(
        self,
        api_key: str,
        agent_id: str,
        base_url: str = "https://api.veriswarm.ai",
        guard_pii: bool = True,
        guard_enforce: bool = True,
        guard_injection_scan: bool = True,
        guard_audit: bool = True,
        on_deny: str = "raise",  # "raise", "skip", "log"
        timeout_seconds: int = 5,
        **kwargs,
    ):
        self.agent_id = agent_id
        self.guard_pii = guard_pii
        self.guard_enforce = guard_enforce
        self.guard_injection_scan = guard_injection_scan
        self.guard_audit = guard_audit
        self.on_deny = on_deny
        self._guard_client = VeriSwarmClient(base_url, api_key, timeout_seconds=timeout_seconds)

    def guard_before_tool(
        self,
        tool_name: str,
        tool_input: str | dict | Any,
    ) -> tuple[str | dict | Any, GuardContext]:
        """Run Guard pipeline BEFORE a tool executes.

        Returns:
            (filtered_input, context) — filtered_input has PII tokenized,
            context tracks state for guard_after_tool.
        """
        ctx = GuardContext(tool_name=tool_name, start_time=time.monotonic())

        # Step 1: Policy enforcement (decision check)
        if self.guard_enforce:
            ctx = self._check_policy(tool_name, ctx)
            if ctx.blocked:
                self._audit_event("tool.blocked", {
                    "tool_name": tool_name,
                    "reason": ctx.block_reason,
                    "decision": ctx.decision,
                })
                return tool_input, ctx

        # Step 2: PII tokenization on input
        if self.guard_pii:
            tool_input, ctx = self._tokenize_input(tool_input, ctx)

        return tool_input, ctx

    def guard_after_tool(
        self,
        tool_name: str,
        tool_output: str | Any,
        ctx: GuardContext,
    ) -> str | Any:
        """Run Guard pipeline AFTER a tool executes.

        Returns:
            filtered_output — PII tokenized, injection-scanned output.
        """
        # Step 3: PII tokenization on output
        if self.guard_pii and isinstance(tool_output, str) and len(tool_output) > 3:
            tool_output, ctx = self._tokenize_output(tool_output, ctx)

        # Step 4: Prompt injection scan
        if self.guard_injection_scan and isinstance(tool_output, str):
            tool_output = self._scan_injection(tool_output, tool_name)

        # Step 5: Audit log
        duration_ms = int((time.monotonic() - ctx.start_time) * 1000)
        if self.guard_audit:
            self._audit_event("tool.call.success", {
                "tool_name": tool_name,
                "duration_ms": duration_ms,
                "pii_tokens_created": ctx.tokens_created,
                "pii_session_id": ctx.pii_session_id,
            })

        return tool_output

    def guard_on_error(self, tool_name: str, error: BaseException, ctx: GuardContext) -> None:
        """Report a tool error to Guard audit."""
        if self.guard_audit:
            self._audit_event("tool.call.failure", {
                "tool_name": tool_name,
                "error_type": type(error).__name__,
                "error_message": str(error)[:200],
            })

    def guard_rehydrate(self, text: str, session_id: str | None = None) -> str:
        """Restore original PII values from tokens. Call when writing to real systems."""
        if not session_id:
            return text
        try:
            result = self._guard_client.rehydrate_pii(text=text, session_id=session_id)
            return result.get("rehydrated_text", text)
        except Exception as e:
            logger.debug(f"Rehydration failed: {e}")
            return text

    # ── Internal methods ──────────────────────────────────────────────────

    def _check_policy(self, tool_name: str, ctx: GuardContext) -> GuardContext:
        """Check trust decision before allowing tool call."""
        try:
            result = self._guard_client.check_decision(
                agent_id=self.agent_id,
                action_type="tool_call",
                resource_type=tool_name,
            )
            ctx.decision = result.get("decision", "allow")
            if ctx.decision == "deny":
                reason = result.get("reason_code", "policy_denied")
                ctx.blocked = True
                ctx.block_reason = reason
                ctx.block_message = f"[VeriSwarm Guard] Tool '{tool_name}' blocked: {reason}"

                if self.on_deny == "raise":
                    raise PermissionError(ctx.block_message)
                elif self.on_deny == "log":
                    logger.warning(ctx.block_message)
                    ctx.blocked = False  # Log but don't block
        except PermissionError:
            raise
        except VeriSwarmClientError:
            # API error — fail open (allow the call)
            logger.debug(f"Guard decision check failed for '{tool_name}', allowing")
        except Exception as e:
            logger.debug(f"Guard decision check error: {e}")

        return ctx

    def _tokenize_input(
        self, tool_input: str | dict | Any, ctx: GuardContext
    ) -> tuple[str | dict | Any, GuardContext]:
        """Tokenize PII in tool input."""
        try:
            if isinstance(tool_input, str) and len(tool_input) > 3:
                result = self._guard_client.tokenize_pii(
                    text=tool_input, agent_id=self.agent_id
                )
                if result.get("tokens_created", 0) > 0:
                    ctx.pii_session_id = result.get("session_id")
                    ctx.tokens_created += result["tokens_created"]
                    return result["tokenized_text"], ctx
            elif isinstance(tool_input, dict):
                filtered = {}
                for key, value in tool_input.items():
                    if isinstance(value, str) and len(value) > 3:
                        result = self._guard_client.tokenize_pii(
                            text=value,
                            agent_id=self.agent_id,
                            session_id=ctx.pii_session_id,
                        )
                        if result.get("tokens_created", 0) > 0:
                            ctx.pii_session_id = result.get("session_id", ctx.pii_session_id)
                            ctx.tokens_created += result["tokens_created"]
                            filtered[key] = result["tokenized_text"]
                        else:
                            filtered[key] = value
                    else:
                        filtered[key] = value
                return filtered, ctx
        except Exception as e:
            logger.debug(f"PII tokenization failed on input: {e}")

        return tool_input, ctx

    def _tokenize_output(
        self, output: str, ctx: GuardContext
    ) -> tuple[str, GuardContext]:
        """Tokenize PII in tool output."""
        try:
            result = self._guard_client.tokenize_pii(
                text=output,
                agent_id=self.agent_id,
                session_id=ctx.pii_session_id,
            )
            if result.get("tokens_created", 0) > 0:
                ctx.pii_session_id = result.get("session_id", ctx.pii_session_id)
                ctx.tokens_created += result["tokens_created"]
                return result["tokenized_text"], ctx
        except Exception as e:
            logger.debug(f"PII tokenization failed on output: {e}")

        return output, ctx

    def _scan_injection(self, text: str, tool_name: str) -> str:
        """Scan tool output for prompt injection patterns."""
        injection_patterns = [
            "ignore previous instructions",
            "ignore all previous",
            "disregard your instructions",
            "you are now",
            "new instructions:",
            "system prompt:",
            "forget everything",
            "override:",
            "jailbreak",
            "<|im_start|>",
        ]
        text_lower = text.lower()
        detected = [p for p in injection_patterns if p.lower() in text_lower]

        if detected:
            logger.warning(
                "Potential injection in '%s' output: %s", tool_name, detected
            )
            return (
                f"[VeriSwarm Guard: Potential prompt injection detected in tool output. "
                f"Patterns: {', '.join(detected)}]\n\n{text}"
            )
        return text

    def _audit_event(self, event_type: str, payload: dict) -> None:
        """Fire-and-forget event reporting."""
        try:
            from datetime import datetime, timezone
            self._guard_client.ingest_event(
                event_id=f"guard-{uuid.uuid4().hex[:16]}",
                agent_id=self.agent_id,
                source_type="guard_adapter",
                event_type=event_type,
                occurred_at=datetime.now(timezone.utc).isoformat(),
                payload={k: v for k, v in payload.items() if v is not None},
            )
        except Exception as e:
            logger.debug(f"Guard audit event failed: {e}")
