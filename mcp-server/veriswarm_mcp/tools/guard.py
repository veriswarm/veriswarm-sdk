"""Guard security tools for VeriSwarm MCP."""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import bounded_string, safe_error_response, safe_optional_id

# Maximum character budgets for Session Sentry turn text fields.
# Large prompts are the vector; cap generously enough for real usage
# while blocking quota-exhaustion via oversized LLM-controlled inputs.
# (Audit 2026-05-08 HIGH-SDK-17.)
_MAX_SESSION_ID_CHARS = 64
_MAX_TURN_TEXT_CHARS = 32_768   # 32 KB — covers long agent replies
_MAX_SYSTEM_PROMPT_CHARS = 16_384  # 16 KB


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def scan_tool(tool_name: str, tool_config: str = "") -> str:
        """Scan text/tool content for security threats (injection and moderation).

        tool_name: name of the tool or MCP server to scan
        tool_config: optional JSON string with tool configuration/schema details
        """
        try:
            text = f"Tool: {tool_name}"
            if tool_config:
                text += f"\nConfig: {tool_config}"
            result = client.post("/v1/suite/guard/scan", json={"text": text})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def check_tool_allowed(tool_name: str) -> str:
        """Check whether a tool is permitted under active Guard policies for this workspace.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = client.get("/v1/suite/guard/policies", params={"tool_name": tool_name})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def get_findings(agent_id: str = "") -> str:
        """List Guard security findings. Optionally filter by agent_id."""
        try:
            params = {}
            if agent_id:
                params["agent_id"] = agent_id
            result = client.get("/v1/suite/guard/findings", params=params if params else None)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def kill_agent(agent_id: str, reason: str) -> str:
        """Activate the kill switch for an agent, immediately blocking all trust decisions.

        Requires session auth (x-account-access-token). Not available with API key only.

        agent_id: the agent to kill-switch
        reason: human-readable reason for the kill switch activation
        """
        try:
            result = client.post(
                f"/v1/suite/guard/kill/{agent_id}",
                json={"reason": reason},
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def unkill_agent(agent_id: str) -> str:
        """Deactivate the kill switch for an agent, restoring normal trust decision processing.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = client.post(f"/v1/suite/guard/unkill/{agent_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def tokenize_pii(text: str, agent_id: str = "", session_id: str = "") -> str:
        """Remove PII from text, replacing with safe tokens like [VS:EMAIL:a1b2c3].

        Use BEFORE sending text containing personal data to an LLM.
        The LLM will see tokens instead of real emails, phone numbers, SSNs, etc.
        Tokens carry type information so the LLM knows what kind of data was there.

        text: the text that may contain PII
        agent_id: optional agent ID to associate with the tokenization
        session_id: optional session ID to group tokens (auto-generated if empty)
        """
        try:
            body: dict = {"text": text}
            if agent_id:
                body["agent_id"] = agent_id
            if session_id:
                body["session_id"] = session_id
            result = client.post("/v1/suite/guard/pii/tokenize", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def scan_injection(text: str) -> str:
        """Scan text for prompt injection patterns.

        Returns is_injection (bool), confidence score, and matched patterns.
        """
        try:
            result = client.post("/v1/suite/guard/scan", json={"text": text})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def get_pii_session(session_id: str) -> str:
        """Get details of a PII tokenization session including all tokens created."""
        try:
            result = client.get(f"/v1/suite/guard/pii/sessions/{session_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def revoke_pii_session(session_id: str) -> str:
        """Revoke a PII tokenization session, deleting all stored tokens.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = client.delete(f"/v1/suite/guard/pii/sessions/{session_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def list_guard_policies() -> str:
        """List all active Guard policies for the workspace.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = client.get("/v1/suite/guard/policies")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def rehydrate_pii(text: str, session_id: str) -> str:
        """Restore original PII values from VeriSwarm tokens in text.

        Use AFTER the LLM has processed tokenized text and you need to write
        the real values back to a database, email, CRM, or other system.

        text: text containing VeriSwarm tokens like [VS:EMAIL:a1b2c3]
        session_id: the session ID from the original tokenize_pii call
        """
        try:
            result = client.post("/v1/suite/guard/pii/rehydrate", json={
                "text": text,
                "session_id": session_id,
            })
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": "VeriSwarm tool failed; check API connectivity", "type": type(exc).__name__})

    @server.tool()
    async def guard_scan_session(
        session_id: str,
        turn_index: int,
        user_text: str = "",
        agent_text: str = "",
        system_prompt: str = "",
        agent_id: str = "",
        actor_id: str = "",
    ) -> str:
        """Score one conversation turn for multi-turn exfiltration risk (Session Sentry).

        Call this once per turn — after the agent has generated its reply and
        before you send it to the user. Pass a stable ``session_id`` for the
        entire conversation and a monotonically increasing ``turn_index`` (0, 1,
        2 …). The scorer accumulates canary-token egress and system-prompt
        extraction signals across turns with time decay.

        Key response fields:
        - ``blocked`` (bool) — if True, suppress the reply and halt the turn;
          the enforcement_level and block_threshold explain why.
        - ``session_score`` — cumulative exfiltration risk for the session
          (0.0–1.0).
        - ``turn_value`` — this turn's raw contribution before decay.
        - ``highest_severity`` — "none" | "low" | "medium" | "high" | "critical".
        - ``contributions`` — list of scored signals (type, value, weight).
        - ``enabled`` — False while the tenant is on the free tier (dormant);
          blocked will always be False in that state.

        session_id: stable identifier for this conversation (≤64 chars,
            alphanumeric / hyphens / underscores). Use the same value for
            every turn in the same conversation.
        turn_index: zero-based turn counter; must increase monotonically within
            a session. The scorer uses ordering to apply time decay.
        user_text: the user's message for this turn (optional but improves signal).
        agent_text: the agent's reply for this turn — primary exfil surface;
            always pass this.
        system_prompt: the system prompt active for this turn (optional; used to
            detect system-prompt extraction attempts in agent_text).
        agent_id: optional VeriSwarm agent ID (`agt_*`) to associate the scan
            with a registered agent's trust record.
        actor_id: optional caller / user identifier for audit purposes.
        """
        # --- input validation ---
        try:
            bounded_string(session_id, field_name="session_id", max_chars=_MAX_SESSION_ID_CHARS)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

        try:
            turn_index = int(turn_index)
        except (TypeError, ValueError):
            return json.dumps({"error": "turn_index must be a non-negative integer"})
        if turn_index < 0:
            return json.dumps({"error": "turn_index must be >= 0"})

        try:
            user_text = bounded_string(user_text, field_name="user_text", max_chars=_MAX_TURN_TEXT_CHARS)
            agent_text = bounded_string(agent_text, field_name="agent_text", max_chars=_MAX_TURN_TEXT_CHARS)
            system_prompt = bounded_string(system_prompt, field_name="system_prompt", max_chars=_MAX_SYSTEM_PROMPT_CHARS)
        except Exception as exc:
            return json.dumps({"error": str(exc)})

        agent_id_clean = safe_optional_id(agent_id or None, "agent_id")
        actor_id_clean = safe_optional_id(actor_id or None, "actor_id")

        # --- API call ---
        body: dict = {
            "session_id": session_id,
            "turn_index": turn_index,
            "user_text": user_text,
            "agent_text": agent_text,
            "system_prompt": system_prompt,
        }
        if agent_id_clean:
            body["agent_id"] = agent_id_clean
        if actor_id_clean:
            body["actor_id"] = actor_id_clean

        try:
            result = client.post("/v1/suite/guard/scan-session", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return safe_error_response(exc, context="guard_scan_session")
