"""MCP tools for compliance, Cedar policies, SRE, context governance,
MCP scanning, cross-model verification, and A2A transport keys.

These wrap the API endpoints shipped on 2026-04-06.
"""
from __future__ import annotations

import json

import httpx
from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    # ── Compliance ──────────────────────────────────────────────────

    @server.tool()
    async def get_owasp_attestation() -> str:
        """Get a per-tenant OWASP Agentic AI Top 10 (2026) coverage report.

        Returns covered/partial/gap status for each of the 10 risks,
        evidence counts from Guard/Vault, and an overall coverage score.
        """
        try:
            result = client.get("/v1/compliance/owasp-attestation")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def list_compliance_frameworks() -> str:
        """List supported compliance frameworks (eu-ai-act, nist-ai-rmf, iso-42001)."""
        try:
            result = client.get("/v1/compliance/frameworks")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_compliance_report(framework_id: str) -> str:
        """Get a per-tenant compliance report for a specific framework.

        framework_id: 'eu-ai-act' | 'nist-ai-rmf' | 'iso-42001'
        Returns pass/warn/fail per control with evidence counts and recommendations.
        """
        try:
            result = client.get(f"/v1/compliance/{framework_id}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Cedar Policies ──────────────────────────────────────────────

    @server.tool()
    async def list_cedar_policies() -> str:
        """List active Cedar declarative policies for the tenant."""
        try:
            result = client.get("/v1/policies")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def validate_cedar_policy(policy_text: str) -> str:
        """Validate Cedar policy syntax without persisting.

        Returns {"valid": true} on success, {"valid": false, "error": "..."} on failure.
        """
        try:
            result = client.post("/v1/policies/validate", json={"policy_text": policy_text})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def test_cedar_policy(
        policy_text: str,
        agent_id: str = "test_agent",
        action_type: str = "tool_call",
        policy_tier: str = "tier_1",
        risk_score: int = 50,
        is_verified: bool = False,
    ) -> str:
        """Dry-run a Cedar policy against test input. Returns the decision."""
        try:
            result = client.post(
                "/v1/policies/test",
                json={
                    "policy_text": policy_text,
                    "agent_id": agent_id,
                    "action_type": action_type,
                    "policy_tier": policy_tier,
                    "risk_score": risk_score,
                    "is_verified": is_verified,
                },
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── SRE: Circuit Breakers + SLOs + Error Budgets ───────────────

    @server.tool()
    async def get_sre_dashboard() -> str:
        """Combined SRE dashboard — circuit breakers + SLO + error budget + provider health."""
        try:
            result = client.get("/v1/analytics/sre/dashboard")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_circuit_breakers() -> str:
        """Get current state of all LLM provider circuit breakers (closed/open/half-open)."""
        try:
            result = client.get("/v1/analytics/sre/circuit-breakers")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def reset_circuit_breaker(provider: str, model: str) -> str:
        """Manually reset a circuit breaker to closed state (e.g., after fixing a provider outage)."""
        try:
            result = client.post(f"/v1/analytics/sre/circuit-breakers/{provider}/{model}/reset")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_error_budget() -> str:
        """Get error budget status based on tenant SLO targets and recent LLM usage."""
        try:
            result = client.get("/v1/analytics/sre/error-budget")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Context Governance ─────────────────────────────────────────

    @server.tool()
    async def get_context_dashboard(days: int = 30) -> str:
        """Combined context governance dashboard — topics + quality + gaps."""
        try:
            result = client.get("/v1/analytics/context/dashboard", params={"days": days})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_context_gaps(days: int = 30) -> str:
        """Detect agents with high failure rates and low knowledge base coverage."""
        try:
            result = client.get("/v1/analytics/context/gaps", params={"days": days})
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Guard Extensions: MCP Scanner + Cross-Model Verification ───

    @server.tool()
    async def scan_mcp_tools(tools_json: str) -> str:
        """Scan MCP tool definitions for security risks (pre-deploy audit).

        tools_json: JSON string of an array of MCP tool definitions
        Checks for tool poisoning, typosquatting, schema manipulation,
        rug-pull patterns, prompt injection, and excessive permissions.
        """
        try:
            tools = json.loads(tools_json)
            result = client.post("/v1/suite/guard/scan-mcp", json={"tools": tools})
            return json.dumps(result, indent=2)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid JSON in tools_json: {exc}"})
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def verify_response(prompt: str, response: str) -> str:
        """Cross-model verification — route a response through multiple LLMs and check consensus.

        Defends against memory poisoning (OWASP ASI06). Results are logged to Vault.
        """
        try:
            result = client.post(
                "/v1/suite/guard/verify",
                json={"prompt": prompt, "response": response},
            )
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── A2A Transport (Ed25519 signing) ────────────────────────────

    @server.tool()
    async def provision_a2a_keys(agent_id: str) -> str:
        """Provision Ed25519 transport keys for an agent. Returns the public key.

        After provisioning, the agent's public key appears in agent cards under
        x-veriswarm-transport. Inter-agent messages can then be cryptographically signed.
        """
        try:
            result = client.post(f"/v1/a2a/{agent_id}/keys")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Content Provenance (EU AI Act Article 50) ──────────────────

    @server.tool()
    async def label_content(
        content: str,
        agent_id: str = "",
        model: str = "",
        content_type: str = "text/plain",
    ) -> str:
        """Generate an Ed25519-signed provenance manifest for AI-generated content.

        Returns the manifest (signature, content hash, metadata). Machine-readable
        format compatible with EU AI Act Article 50 transparency requirements.
        """
        try:
            body = {"content": content, "content_type": content_type}
            if agent_id:
                body["agent_id"] = agent_id
            if model:
                body["model"] = model
            result = client.post("/v1/content/label", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def get_content_provenance(content_hash: str) -> str:
        """Public lookup of a provenance manifest by SHA-256 content hash.

        Use this to verify whether a piece of content was AI-generated by a
        VeriSwarm agent. No authentication required on the server side.
        """
        try:
            result = client.get(f"/v1/content/provenance/{content_hash}")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── ABAC: Agent Attributes ─────────────────────────────────────

    @server.tool()
    async def get_agent_attributes(agent_id: str) -> str:
        """Read the tenant-defined ABAC attributes for an agent.

        These attributes are merged into the Cedar entity at decision time
        and can be referenced in custom policies as principal.<key>.
        """
        try:
            result = client.get(f"/v1/agents/{agent_id}/attributes")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def set_agent_attributes(agent_id: str, attributes_json: str) -> str:
        """Set ABAC attributes for an agent (replaces existing).

        attributes_json: JSON string of the attributes dict.
        Values must be strings, numbers, booleans, or lists of those.
        Reserved keys (policy_tier, risk_score, is_verified) are silently rejected.
        """
        try:
            attrs = json.loads(attributes_json)
            result = client.put(
                f"/v1/agents/{agent_id}/attributes",
                json={"attributes": attrs},
            )
            return json.dumps(result, indent=2)
        except json.JSONDecodeError as exc:
            return json.dumps({"error": f"Invalid JSON in attributes_json: {exc}"})
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # ── Passport JIT (Just-in-Time Access Grants) ─────────────────

    @server.tool()
    async def request_jit_grant(
        agent_id: str,
        action_type: str,
        resource_type: str = "",
        resource_id: str = "",
        reason: str = "",
        ttl_seconds: int = 300,
    ) -> str:
        """Request a just-in-time access grant for an agent.

        Trusted agents (composite_trust >= 75, risk_score <= 30, verified,
        ttl <= 10min) are auto-approved. Others go to pending for human review.
        """
        try:
            body = {"agent_id": agent_id, "action_type": action_type, "ttl_seconds": ttl_seconds}
            if resource_type:
                body["resource_type"] = resource_type
            if resource_id:
                body["resource_id"] = resource_id
            if reason:
                body["reason"] = reason
            result = client.post("/v1/passport/jit/request", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def approve_jit_grant(grant_id: str) -> str:
        """Approve a pending JIT grant (requires account session — use session auth)."""
        try:
            result = client.post(f"/v1/passport/jit/{grant_id}/approve")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def revoke_jit_grant(grant_id: str, reason: str = "") -> str:
        """Revoke an approved JIT grant immediately."""
        try:
            body = {"reason": reason} if reason else {}
            result = client.post(f"/v1/passport/jit/{grant_id}/revoke", json=body)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def issue_jit_token(grant_id: str) -> str:
        """Issue the ES256 JIT token for an approved grant.

        Only callable once per grant — subsequent calls fail. Returns a dict
        with 'token' (the signed JWT) and 'expires_at'.
        """
        try:
            result = client.post(f"/v1/passport/jit/{grant_id}/token")
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    @server.tool()
    async def list_jit_grants(
        agent_id: str = "",
        status: str = "",
        limit: int = 50,
    ) -> str:
        """List JIT grants for the tenant, optionally filtered by agent or status."""
        try:
            params = {"limit": limit}
            if agent_id:
                params["agent_id"] = agent_id
            if status:
                params["status"] = status
            result = client.get("/v1/passport/jit/grants", params=params)
            return json.dumps(result, indent=2)
        except httpx.HTTPStatusError as exc:
            return json.dumps({"error": f"API error {exc.response.status_code}: {exc.response.text}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
