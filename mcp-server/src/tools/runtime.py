"""Runtime intelligence tools for VeriSwarm MCP.

Tools for conversation analytics, security testing, trust permissions,
GDPR compliance, A2A reputation, benchmarks, and LLM provider health.
"""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:

    # ── Conversation Analytics ───────────────────────────────────────

    @server.tool()
    async def get_agent_analytics(agent_id: str, days: int = 30) -> str:
        """Get aggregated quality analytics for an agent.

        agent_id: the agent to analyze
        days: lookback period (1-365)

        Returns resolution rate, accuracy, tone, efficiency, security scores,
        escalation rate, cost, and grade distribution.
        """
        try:
            result = client.get(f"/v1/suite/analytics/agent/{agent_id}", params={"days": days})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    @server.tool()
    async def get_cost_recommendations(agent_id: str, days: int = 30) -> str:
        """Get cost optimization recommendations for an agent.

        Analyzes conversation patterns and suggests: model downgrades,
        KB improvements, prompt optimization, and security reviews.
        """
        try:
            result = client.get(f"/v1/suite/analytics/cost-recommendations/{agent_id}", params={"days": days})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    # ── Security ─────────────────────────────────────────────────────

    @server.tool()
    async def list_red_team_attacks() -> str:
        """List available adversarial red team attack patterns.

        Returns attack counts by category: injection, PII extraction,
        policy boundary, off-topic, and jailbreak.
        """
        try:
            result = client.get("/v1/suite/security/red-team/attacks")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    @server.tool()
    async def check_tool_permission(agent_id: str, tool_name: str) -> str:
        """Check if an agent has trust-gated permission to use a tool.

        agent_id: the agent requesting the tool
        tool_name: name of the tool to check (e.g., 'process_refund')

        Returns whether the tool is allowed based on the agent's trust score.
        """
        try:
            result = client.post("/v1/suite/security/check-permission", json={
                "agent_id": agent_id,
                "tool_name": tool_name,
            })
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    @server.tool()
    async def score_conversation_security(
        conversation_id: str,
        pii_tokens_in_response: int = 0,
        injection_attempts: int = 0,
        injection_blocked: int = 0,
        policy_violations: int = 0,
    ) -> str:
        """Compute a security grade (A-F) for a conversation.

        Uses Guard + Vault audit data to score PII exposure, injection
        resistance, policy adherence, tool authorization, and grounding.
        """
        try:
            result = client.post("/v1/suite/security/conversation-score", json={
                "conversation_id": conversation_id,
                "pii_tokens_in_response": pii_tokens_in_response,
                "injection_attempts_detected": injection_attempts,
                "injection_attempts_blocked": injection_blocked,
                "policy_violations": policy_violations,
            })
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    # ── GDPR Compliance ──────────────────────────────────────────────

    @server.tool()
    async def forget_contact(contact_identifier: str, contact_type: str = "email", dry_run: bool = True) -> str:
        """GDPR: Delete all data associated with a contact.

        Requires session auth (x-account-access-token). Not available with API key only.

        contact_identifier: email, phone, or contact ID to purge
        contact_type: 'email', 'phone', or 'contact_id'
        dry_run: if True, shows what would be deleted without deleting

        Purges from PII tokens, events, and KB chunks. Generates a
        cryptographic deletion proof stored in Vault.
        """
        try:
            result = client.post("/v1/suite/compliance/forget-contact", json={
                "contact_identifier": contact_identifier,
                "contact_type": contact_type,
                "dry_run": dry_run,
            })
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    @server.tool()
    async def list_deletion_records() -> str:
        """List GDPR deletion records with verification hashes.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = client.get("/v1/suite/compliance/deletion-records")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    @server.tool()
    async def verify_deletion(record_id: str) -> str:
        """Verify a GDPR deletion record exists and return its cryptographic proof."""
        try:
            result = client.get(f"/v1/suite/compliance/deletion-records/{record_id}/verify")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    # ── A2A Trust ────────────────────────────────────────────────────

    @server.tool()
    async def get_agent_reputation(agent_id: str, days: int = 90) -> str:
        """Get an agent's cross-platform reputation score.

        Returns reputation score (0-100), platform count, positive/negative
        interaction counts, and per-platform breakdown.
        """
        try:
            result = client.get(f"/v1/suite/a2a/reputation/{agent_id}", params={"days": days})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    @server.tool()
    async def get_a2a_history(agent_id: str, role: str = "requesting", limit: int = 20) -> str:
        """Get agent-to-agent interaction history.

        agent_id: the agent to query
        role: 'requesting' (outbound) or 'receiving' (inbound)
        """
        try:
            result = client.get(f"/v1/suite/a2a/history/{agent_id}", params={"role": role, "limit": limit})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    # ── Benchmarking ─────────────────────────────────────────────────

    @server.tool()
    async def get_benchmark_history(agent_id: str, limit: int = 10) -> str:
        """Get benchmark results for an agent across versions.

        Returns scores, pass rates, and promote/review/block recommendations.
        """
        try:
            result = client.get(f"/v1/suite/benchmarks/{agent_id}", params={"limit": limit})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})

    # ── LLM Provider Health ──────────────────────────────────────────

    @server.tool()
    async def get_provider_health() -> str:
        """Get health status of all LLM providers.

        Returns per-provider: success rate, P95 latency, active requests,
        cooldown status, and consecutive failure count.
        """
        try:
            result = client.get("/v1/suite/llm/provider-health")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
