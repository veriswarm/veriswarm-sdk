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
