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

import asyncio
import functools
import logging
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from veriswarm.client import VeriSwarmClient, VeriSwarmClientError  # noqa: F401 - re-exported

logger = logging.getLogger("veriswarm.guard")

# Placeholder substituted when a secret/PII guard step itself fails (fail closed).
GUARD_FAILED_PLACEHOLDER = "[VS:REDACTED:guard_unavailable]"
_WARN_INTERVAL_SECONDS = 60.0
_last_warned: dict[str, float] = {}
_warn_lock = threading.Lock()


def warn_rate_limited(log: logging.Logger, key: str, message: str, *args: Any) -> None:
    """Log a warning at most once per interval per key (keeps hot paths quiet)."""
    now = time.monotonic()
    with _warn_lock:
        last = _last_warned.get(key)
        if last is not None and now - last < _WARN_INTERVAL_SECONDS:
            return
        _last_warned[key] = now
    log.warning(message, *args)


def map_strings(value: Any, fn: Callable[[str], str]) -> Any:
    """Return a copy of ``value`` with ``fn`` applied to every nested string.

    Recurses through dicts, lists and tuples; other leaves are returned as-is.
    The input is never mutated.
    """
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: map_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [map_strings(v, fn) for v in value]
    if isinstance(value, tuple):
        return tuple(map_strings(v, fn) for v in value)
    return value


def guard_secrets_in(
    client: VeriSwarmClient, value: Any, *, agent_id: str | None, session_id: str | None = None
) -> Any:
    """Run the client's secret tripwire over every string in ``value``. Fails closed."""

    def _one(text: str) -> str:
        try:
            guarded = client.guard_outbound_text(text, agent_id=agent_id, session_id=session_id)
        except Exception as e:  # noqa: BLE001 - fail closed on anything
            warn_rate_limited(logger, "secret-guard", "Secret tripwire failed; redacting: %s", e)
            return GUARD_FAILED_PLACEHOLDER
        return guarded if isinstance(guarded, str) else GUARD_FAILED_PLACEHOLDER

    return map_strings(value, _one)


def guarded_excerpt(
    client: VeriSwarmClient, value: Any, limit: int, *, agent_id: str | None
) -> str:
    """Secret-guard the FULL text, then truncate to ``limit`` chars.

    Truncating first can cut a secret below the tripwire's detection threshold
    and leak its leading characters; guarding first cannot.
    """
    return guard_secrets_in(client, str(value), agent_id=agent_id)[:limit]


async def run_blocking(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run a blocking (urllib-based) call off the event loop."""
    if hasattr(asyncio, "to_thread"):
        return await asyncio.to_thread(fn, *args, **kwargs)
    loop = asyncio.get_running_loop()  # pragma: no cover - Python 3.8
    return await loop.run_in_executor(None, functools.partial(fn, *args, **kwargs))


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
        guard_secrets: bool = True,
        **kwargs,
    ):
        self.agent_id = agent_id
        self.guard_pii = guard_pii
        self.guard_enforce = guard_enforce
        self.guard_injection_scan = guard_injection_scan
        self.guard_audit = guard_audit
        self.on_deny = on_deny
        self.guard_secrets = guard_secrets
        self._guard_client = VeriSwarmClient(
            base_url, api_key, timeout_seconds=timeout_seconds, secrets_detection=guard_secrets
        )

    def guard_before_tool(
        self,
        tool_name: str,
        tool_input: str | dict | Any,
    ) -> tuple[str | dict | Any, GuardContext]:
        """Run Guard pipeline BEFORE a tool executes.

        Returns:
            (filtered_input, context) — filtered_input has secrets redacted and
            PII tokenized (recursively), context tracks state for guard_after_tool.
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

        # Step 2: Secret tripwire on input (before anything leaves for the API)
        tool_input = self._guard_secrets(tool_input, ctx)

        # Step 3: PII tokenization on input
        if self.guard_pii:
            tool_input, ctx = self._tokenize_input(tool_input, ctx)

        return tool_input, ctx

    def guard_output(self, tool_name: str, tool_output: Any, ctx: GuardContext) -> Any:
        """Filter a tool output (secrets, PII, injection scan) without auditing."""
        if isinstance(tool_output, str):
            tool_output = self._guard_secrets(tool_output, ctx)
            if self.guard_pii and len(tool_output) > 3:
                tool_output, ctx = self._tokenize_output(tool_output, ctx)
            if self.guard_injection_scan:
                tool_output = self._scan_injection(tool_output, tool_name)
        return tool_output

    def guard_audit_success(self, tool_name: str, ctx: GuardContext) -> None:
        """Record a successful tool call in the audit log."""
        if self.guard_audit:
            duration_ms = int((time.monotonic() - ctx.start_time) * 1000)
            self._audit_event("tool.call.success", {
                "tool_name": tool_name,
                "duration_ms": duration_ms,
                "pii_tokens_created": ctx.tokens_created,
                "pii_session_id": ctx.pii_session_id,
            })

    def guard_after_tool(
        self,
        tool_name: str,
        tool_output: str | Any,
        ctx: GuardContext,
    ) -> str | Any:
        """Run Guard pipeline AFTER a tool executes.

        Returns:
            filtered_output — secret-redacted, PII tokenized, injection-scanned output.
        """
        tool_output = self.guard_output(tool_name, tool_output, ctx)
        self.guard_audit_success(tool_name, ctx)
        return tool_output

    def guard_on_error(self, tool_name: str, error: BaseException, ctx: GuardContext) -> None:
        """Report a tool error to Guard audit."""
        if self.guard_audit:
            self._audit_event("tool.call.failure", {
                "tool_name": tool_name,
                "error_type": type(error).__name__,
                "error_message": (
                    guarded_excerpt(self._guard_client, error, 200, agent_id=self.agent_id)
                    if self.guard_secrets else str(error)[:200]
                ),
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
        """Check trust decision before allowing tool call.

        Fails closed: anything other than an explicit ``"allow"`` (deny, review,
        unknown values, malformed responses, API errors) blocks the call.
        """
        decision: Any = None
        reason = "decision_unavailable"
        try:
            result = self._guard_client.check_decision(
                agent_id=self.agent_id,
                action_type="tool_call",
                resource_type=tool_name,
            )
            if isinstance(result, dict):
                decision = result.get("decision")
                reason = result.get("reason_code") or "policy_denied"
        except Exception as e:  # noqa: BLE001 - fail closed on anything
            warn_rate_limited(logger, "decision-check", "Guard decision check failed for '%s': %s", tool_name, e)

        ctx.decision = decision if isinstance(decision, str) and decision else "unavailable"
        if decision == "allow":
            return ctx

        if decision == "review":
            ctx.block_message = (
                f"[VeriSwarm Guard] Tool '{tool_name}' requires review and was not run: {reason}"
            )
        else:
            ctx.block_message = f"[VeriSwarm Guard] Tool '{tool_name}' blocked: {reason}"
        ctx.blocked = True
        ctx.block_reason = reason

        if self.on_deny == "raise":
            raise PermissionError(ctx.block_message)
        if self.on_deny == "log":
            logger.warning(ctx.block_message)
            ctx.blocked = False  # Log but don't block
        return ctx

    def _guard_secrets(self, value: Any, ctx: GuardContext) -> Any:
        """Redact provider secrets in every string of ``value`` (fail closed)."""
        if not self.guard_secrets:
            return value
        return guard_secrets_in(
            self._guard_client, value, agent_id=self.agent_id, session_id=ctx.pii_session_id
        )

    def _tokenize_text(self, text: str, ctx: GuardContext) -> str:
        """Tokenize PII in one string; raises on API failure."""
        if len(text) <= 3:
            return text
        result = self._guard_client.tokenize_pii(
            text=text, agent_id=self.agent_id, session_id=ctx.pii_session_id
        )
        if result.get("tokens_created", 0) > 0:
            ctx.pii_session_id = result.get("session_id", ctx.pii_session_id)
            ctx.tokens_created += result["tokens_created"]
            return result["tokenized_text"]
        return text

    def _tokenize_input(
        self, tool_input: str | dict | Any, ctx: GuardContext
    ) -> tuple[str | dict | Any, GuardContext]:
        """Tokenize PII in every string of the tool input (nested dicts/lists too).

        Fails closed: if the tokenizer is unavailable the call is blocked rather
        than letting raw PII through.
        """
        try:
            return map_strings(tool_input, lambda t: self._tokenize_text(t, ctx)), ctx
        except Exception as e:  # noqa: BLE001
            warn_rate_limited(logger, "pii-input", "PII tokenization failed on input: %s", e)
            ctx.blocked = True
            ctx.block_reason = "pii_tokenization_unavailable"
            ctx.block_message = (
                f"[VeriSwarm Guard] Tool '{ctx.tool_name}' blocked: PII tokenization unavailable"
            )
            if self.on_deny == "raise":
                raise PermissionError(ctx.block_message) from e
            return tool_input, ctx

    def _tokenize_output(
        self, output: str, ctx: GuardContext
    ) -> tuple[str, GuardContext]:
        """Tokenize PII in tool output; withholds the output if the tokenizer fails."""
        try:
            return self._tokenize_text(output, ctx), ctx
        except Exception as e:  # noqa: BLE001
            warn_rate_limited(logger, "pii-output", "PII tokenization failed on output: %s", e)
            return GUARD_FAILED_PLACEHOLDER, ctx

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
        """Fire-and-forget event reporting. Strings are secret-guarded first."""
        try:
            safe = guard_secrets_in(
                self._guard_client, payload, agent_id=self.agent_id
            ) if self.guard_secrets else payload
            self._guard_client.ingest_event(
                event_id=f"guard-{uuid.uuid4().hex[:16]}",
                agent_id=self.agent_id,
                source_type="guard_adapter",
                event_type=event_type,
                occurred_at=datetime.now(timezone.utc).isoformat(),
                payload={k: v for k, v in safe.items() if v is not None},
            )
        except Exception as e:
            warn_rate_limited(logger, "audit-event", "Guard audit event failed (non-blocking): %s", e)
