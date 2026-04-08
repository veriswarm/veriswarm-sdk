from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class VeriSwarmClientError(RuntimeError):
    pass


@dataclass(slots=True)
class VeriSwarmClient:
    """VeriSwarm Python SDK — trust scoring, event ingestion, and agent management.

    Usage:
        client = VeriSwarmClient(base_url="https://api.veriswarm.ai", api_key="vsk_...")
        decision = client.check_decision(agent_id="agt_123", action_type="post_message")
    """
    base_url: str
    api_key: str
    timeout_seconds: int = 15

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ValueError("base_url is required")
        if not self.api_key:
            raise ValueError("api_key is required")
        self.base_url = self.base_url.rstrip("/")

    # --- Decisions ---

    def check_decision(
        self,
        *,
        agent_id: str,
        action_type: str,
        resource_type: str | None = None,
    ) -> dict[str, Any]:
        """Check a trust decision before a sensitive action."""
        return self._request(
            "/v1/decisions/check",
            method="POST",
            body={
                "agent_id": agent_id,
                "action_type": action_type,
                "resource_type": resource_type,
            },
        )

    # --- Events ---

    def ingest_event(
        self,
        *,
        event_id: str,
        agent_id: str,
        source_type: str,
        event_type: str,
        occurred_at: str,
        payload: dict[str, Any] | None = None,
        signature: str | None = None,
    ) -> dict[str, Any]:
        """Ingest a single agent behavioral event."""
        body: dict[str, Any] = {
            "event_id": event_id,
            "agent_id": agent_id,
            "source_type": source_type,
            "event_type": event_type,
            "occurred_at": occurred_at,
            "payload": payload or {},
        }
        if signature:
            body["signature"] = signature
        return self._request("/v1/events", method="POST", body=body)

    def ingest_events_batch(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        """Ingest up to 50 events in a single request."""
        return self._request("/v1/events/batch", method="POST", body=events)

    # --- Provider Reports ---

    def ingest_provider_report(self, report: dict[str, Any]) -> dict[str, Any]:
        """Submit a provider report (spam, abuse, quality signal)."""
        return self._request("/v1/public/providers/reports", method="POST", body=report)

    def ingest_provider_reports_batch(self, reports: list[dict[str, Any]]) -> dict[str, Any]:
        """Submit multiple provider reports in a single request."""
        return self._request(
            "/v1/public/providers/reports/batch",
            method="POST",
            body={"reports": reports},
        )

    # --- Agent Management ---

    def register_agent(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Register a new agent."""
        return self._request("/v1/public/agents/register", method="POST", body=payload)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Get public agent profile."""
        return self._request(f"/v1/public/agents/{agent_id}")

    def get_agent_scores(self, agent_id: str) -> dict[str, Any]:
        """Get an agent's current trust scores."""
        return self._request(f"/v1/public/agents/{agent_id}/scores/current")

    def get_agent_score_history(self, agent_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Get an agent's score history (last N snapshots)."""
        return self._request(f"/v1/public/agents/{agent_id}/scores/history?limit={limit}")

    def get_agent_score_breakdown(self, agent_id: str) -> dict[str, Any]:
        """Get detailed score breakdown with contributing factors."""
        return self._request(f"/v1/public/agents/{agent_id}/scores/breakdown")

    def get_agent_flags(self, agent_id: str) -> list[dict[str, Any]]:
        """Get active moderation flags for an agent."""
        return self._request(f"/v1/public/agents/{agent_id}/flags")

    def appeal_flag(self, agent_id: str, flag_id: int) -> dict[str, Any]:
        """Appeal a moderation flag for review."""
        return self._request(
            f"/v1/public/agents/{agent_id}/flags/{flag_id}/appeal",
            method="POST",
        )

    def get_agent_manifests(self, agent_id: str) -> list[dict[str, Any]]:
        """Get agent capability manifests (public)."""
        return self._request(f"/v1/public/agents/{agent_id}/manifests")

    # --- Platform Status ---

    def get_platform_status(self) -> dict[str, Any]:
        """Check platform health and feature flags."""
        return self._request("/v1/public/status")

    # --- Guard (PII + Injection) ---

    def tokenize_pii(
        self,
        *,
        text: str,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        """Tokenize PII in text via Guard. Returns tokenized_text + session_id."""
        body: dict[str, Any] = {"text": text}
        if agent_id:
            body["agent_id"] = agent_id
        if session_id:
            body["session_id"] = session_id
        return self._post("/v1/suite/guard/pii/tokenize", body)

    def rehydrate_pii(
        self,
        *,
        text: str,
        session_id: str,
    ) -> dict[str, Any]:
        """Restore original PII values from Guard tokens."""
        return self._post("/v1/suite/guard/pii/rehydrate", {
            "text": text,
            "session_id": session_id,
        })

    def scan_injection(self, *, text: str) -> dict[str, Any]:
        """Scan text for prompt injection patterns."""
        return self._post("/v1/suite/guard/scan", {"text": text})

    # --- Credentials ---

    def issue_credential(self) -> dict[str, Any]:
        """Issue a signed JWT trust credential for the authenticated agent."""
        return self._post("/v1/credentials/issue")

    def verify_credential(self, credential: str) -> dict[str, Any]:
        """Verify a JWT trust credential."""
        return self._post("/v1/credentials/verify", {"credential": credential})

    # --- Agent Self-Service ---

    def get_my_scores(self) -> dict[str, Any]:
        """Get own trust scores with improvement guidance. Requires agent key auth."""
        return self._get("/v1/agents/me/scores")

    # --- Scoring Profiles ---

    def get_scoring_profile(self) -> dict[str, Any]:
        """Get the current tenant's scoring profile."""
        return self._get("/v1/suite/scoring/profile")

    def set_scoring_profile(
        self,
        profile_code: str,
        weight_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Set the tenant's scoring profile."""
        body: dict[str, Any] = {"profile_code": profile_code}
        if weight_overrides:
            body["weight_overrides"] = weight_overrides
        return self._post("/v1/suite/scoring/profile", body)

    # --- Agent Timeline ---

    def get_agent_timeline(self, agent_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
        """Get an agent's event timeline."""
        return self._get(f"/v1/public/agents/{agent_id}/timeline?limit={limit}")

    # --- Agent API Keys ---

    def get_agent_api_keys(self, agent_id: str) -> list[dict[str, Any]]:
        """List API keys for an agent."""
        return self._get(f"/v1/public/agents/{agent_id}/api-keys")

    def rotate_agent_api_key(self, agent_id: str) -> dict[str, Any]:
        """Rotate (regenerate) an agent's API key."""
        return self._post(f"/v1/public/agents/{agent_id}/api-keys/rotate")

    def revoke_agent_api_key(self, agent_id: str, key_id: str) -> dict[str, Any]:
        """Revoke a specific agent API key."""
        return self._post(f"/v1/public/agents/{agent_id}/api-keys/{key_id}/revoke")

    # --- Guard PII Sessions ---

    def get_pii_session(self, session_id: str) -> dict[str, Any]:
        """Get details of a PII tokenization session."""
        return self._get(f"/v1/suite/guard/pii/sessions/{session_id}")

    def revoke_pii_session(self, session_id: str) -> dict[str, Any]:
        """Revoke (delete) a PII tokenization session and all its tokens."""
        return self._request(f"/v1/suite/guard/pii/sessions/{session_id}", method="DELETE")

    # --- Guard Policies ---

    def list_guard_policies(self) -> list[dict[str, Any]]:
        """List all Guard policies for the workspace."""
        return self._get("/v1/suite/guard/policies")

    def create_guard_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Create a new Guard policy rule."""
        return self._post("/v1/suite/guard/policies", policy)

    def update_guard_policy(self, policy_id: int, updates: dict[str, Any]) -> dict[str, Any]:
        """Update a Guard policy rule."""
        return self._request(f"/v1/suite/guard/policies/{policy_id}", method="PATCH", body=updates)

    def delete_guard_policy(self, policy_id: int) -> dict[str, Any]:
        """Delete a Guard policy rule."""
        return self._request(f"/v1/suite/guard/policies/{policy_id}", method="DELETE")

    # --- Guard Kill Switch ---

    def kill_agent(self, agent_id: str, *, reason: str) -> dict[str, Any]:
        """Activate the kill switch for an agent, blocking all trust decisions."""
        return self._post(f"/v1/suite/guard/kill/{agent_id}", {"reason": reason})

    def unkill_agent(self, agent_id: str) -> dict[str, Any]:
        """Deactivate the kill switch for an agent."""
        return self._post(f"/v1/suite/guard/unkill/{agent_id}")

    # --- Guard Findings ---

    def list_guard_findings(self, *, agent_id: str | None = None) -> list[dict[str, Any]]:
        """List Guard security findings, optionally filtered by agent."""
        path = "/v1/suite/guard/findings"
        if agent_id:
            path += f"?agent_id={agent_id}"
        return self._get(path)

    def update_guard_finding(self, finding_id: int, updates: dict[str, Any]) -> dict[str, Any]:
        """Update a Guard finding (e.g. resolve, dismiss)."""
        return self._request(f"/v1/suite/guard/findings/{finding_id}", method="PATCH", body=updates)

    # --- Passport Delegations ---

    def create_delegation(self, delegation: dict[str, Any]) -> dict[str, Any]:
        """Create a new Passport delegation grant."""
        return self._post("/v1/suite/passport/delegations", delegation)

    def list_delegations(self) -> list[dict[str, Any]]:
        """List active Passport delegations."""
        return self._get("/v1/suite/passport/delegations")

    def revoke_delegation(self, delegation_id: int) -> dict[str, Any]:
        """Revoke a Passport delegation."""
        return self._request(f"/v1/suite/passport/delegations/{delegation_id}", method="DELETE")

    # --- Passport Verification ---

    def verify_agent_identity(self, agent_id: str) -> dict[str, Any]:
        """Mark an agent as identity-verified in Passport."""
        return self._post(f"/v1/suite/passport/verify/{agent_id}")

    # --- Passport Manifests ---

    def create_manifest(self, agent_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """Create or update an agent capability manifest."""
        return self._post(f"/v1/suite/passport/manifests/{agent_id}", manifest)

    def get_manifests(self, agent_id: str) -> list[dict[str, Any]]:
        """Get agent capability manifests from Passport."""
        return self._get(f"/v1/suite/passport/manifests/{agent_id}")

    # --- Vault ---

    def query_vault_ledger(self, *, agent_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Query the immutable Vault audit ledger."""
        path = f"/v1/suite/vault/ledger?limit={limit}"
        if agent_id:
            path += f"&agent_id={agent_id}"
        return self._get(path)

    def verify_vault_chain(self, *, limit: int = 100) -> dict[str, Any]:
        """Verify hash-chain integrity of the Vault ledger."""
        return self._get(f"/v1/suite/vault/verify?limit={limit}")

    def export_vault(self, *, export_type: str = "json") -> dict[str, Any]:
        """Create a Vault export job."""
        return self._post("/v1/suite/vault/export", {"export_type": export_type})

    def get_vault_export_status(self, job_id: str) -> dict[str, Any]:
        """Check the status of a Vault export job."""
        return self._get(f"/v1/suite/vault/export/{job_id}")

    # --- Notifications ---

    def list_notifications(self) -> list[dict[str, Any]]:
        """List notifications for the current workspace."""
        return self._get("/v1/suite/notifications")

    def mark_notification_read(self, notification_id: int) -> dict[str, Any]:
        """Mark a single notification as read."""
        return self._post(f"/v1/suite/notifications/{notification_id}/read")

    def mark_all_notifications_read(self) -> dict[str, Any]:
        """Mark all notifications as read."""
        return self._post("/v1/suite/notifications/read-all")

    # --- IP Allowlist ---

    def get_ip_allowlist(self) -> dict[str, Any]:
        """Get the current IP allowlist for the workspace."""
        return self._get("/v1/public/providers/ip-allowlist")

    def set_ip_allowlist(self, *, cidrs: list[str], enabled: bool = True) -> dict[str, Any]:
        """Set the IP allowlist for the workspace."""
        return self._post("/v1/public/providers/ip-allowlist", {"cidrs": cidrs, "enabled": enabled})

    # --- Custom Domains ---

    def get_custom_domain(self) -> dict[str, Any]:
        """Get the custom domain configuration for the workspace."""
        return self._get("/v1/public/providers/custom-domain")

    def set_custom_domain(self, *, domain: str) -> dict[str, Any]:
        """Set a custom domain for the workspace."""
        return self._post("/v1/public/providers/custom-domain", {"domain": domain})

    def verify_custom_domain(self) -> dict[str, Any]:
        """Verify DNS configuration for the custom domain."""
        return self._post("/v1/public/providers/custom-domain/verify")

    def delete_custom_domain(self) -> dict[str, Any]:
        """Remove the custom domain from the workspace."""
        return self._request("/v1/public/providers/custom-domain", method="DELETE")

    # --- Team Management ---

    def list_team_members(self) -> list[dict[str, Any]]:
        """List team members in the current workspace."""
        return self._get("/v1/public/providers/team")

    def invite_team_member(self, *, email: str, role: str = "member") -> dict[str, Any]:
        """Invite a new team member to the workspace."""
        return self._post("/v1/public/providers/team/invite", {"email": email, "role": role})

    def remove_team_member(self, user_id: str) -> dict[str, Any]:
        """Remove a team member from the workspace."""
        return self._request(f"/v1/public/providers/team/{user_id}", method="DELETE")

    # --- Workspaces ---

    def list_workspaces(self) -> list[dict[str, Any]]:
        """List workspaces the current user belongs to."""
        return self._get("/v1/public/accounts/workspaces")

    def switch_workspace(self, tenant_id: str) -> dict[str, Any]:
        """Switch the user's active workspace."""
        return self._post(f"/v1/public/accounts/workspaces/{tenant_id}/switch")

    # --- Reputation Lookup ---

    def reputation_lookup(self, *, slug: str) -> dict[str, Any]:
        """Look up an agent's shared reputation by slug."""
        return self._get(f"/v1/public/reputation/lookup?slug={slug}")

    # --- Badges ---

    def get_badge_url(
        self,
        agent_slug: str,
        style: str = "compact",
        theme: str = "dark",
    ) -> str:
        """Get the URL for an agent's embeddable trust badge."""
        return f"{self.base_url}/v1/badge/{agent_slug}.svg?style={style}&theme={theme}"

    # --- Cortex Workflows ---

    def list_workflows(self, *, is_active: bool | None = None) -> dict[str, Any]:
        """List all Cortex Workflows for the current tenant."""
        params = ""
        if is_active is not None:
            params = f"?is_active={'true' if is_active else 'false'}"
        return self._get(f"/v1/workflows{params}")

    def get_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Get a workflow's details and recent executions."""
        return self._get(f"/v1/workflows/{workflow_id}")

    def create_workflow(
        self,
        *,
        name: str,
        slug: str,
        definition: dict[str, Any],
        description: str = "",
    ) -> dict[str, Any]:
        """Create a new workflow from a definition dict."""
        return self._post("/v1/workflows", body={
            "name": name,
            "slug": slug,
            "description": description,
            "definition": definition,
        })

    def update_workflow(
        self,
        workflow_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        definition: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Update a workflow's name, description, or definition."""
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if definition is not None:
            body["definition"] = definition
        return self._request(f"/v1/workflows/{workflow_id}", method="PUT", body=body)

    def delete_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Delete a workflow."""
        return self._request(f"/v1/workflows/{workflow_id}", method="DELETE")

    def activate_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Activate a workflow's triggers."""
        return self._post(f"/v1/workflows/{workflow_id}/activate")

    def deactivate_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Deactivate a workflow's triggers."""
        return self._post(f"/v1/workflows/{workflow_id}/deactivate")

    def run_workflow(
        self,
        workflow_id: str,
        *,
        inputs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Manually trigger a workflow execution."""
        return self._post(f"/v1/workflows/{workflow_id}/run", body={"inputs": inputs or {}})

    def get_execution(self, execution_id: str) -> dict[str, Any]:
        """Get execution details including step-by-step results."""
        return self._get(f"/v1/workflows/executions/{execution_id}")

    def list_executions(
        self,
        workflow_id: str,
        *,
        status: str | None = None,
    ) -> dict[str, Any]:
        """List executions for a workflow."""
        params = ""
        if status:
            params = f"?status={status}"
        return self._get(f"/v1/workflows/{workflow_id}/executions{params}")

    def cancel_execution(self, execution_id: str) -> dict[str, Any]:
        """Cancel a running execution."""
        return self._post(f"/v1/workflows/executions/{execution_id}/cancel")

    def retry_execution(self, execution_id: str) -> dict[str, Any]:
        """Retry a failed execution."""
        return self._post(f"/v1/workflows/executions/{execution_id}/retry")

    def approve_step(
        self,
        execution_id: str,
        step_id: str,
        *,
        action: str = "approve",
        edited_output: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Approve, reject, or edit a human review step."""
        body: dict[str, Any] = {"action": action}
        if edited_output:
            body["edited_output"] = edited_output
        return self._post(
            f"/v1/workflows/executions/{execution_id}/steps/{step_id}/approve",
            body=body,
        )

    def list_workflow_templates(self) -> dict[str, Any]:
        """List available workflow templates."""
        return self._get("/v1/workflows/templates")

    def deploy_template(self, template_id: str) -> dict[str, Any]:
        """Deploy a workflow template as a new workflow."""
        return self._post(f"/v1/workflows/templates/{template_id}/deploy")

    # --- Compliance ---

    def get_owasp_attestation(self) -> dict[str, Any]:
        """Get a per-tenant OWASP Agentic AI Top 10 (2026) coverage report.

        Returns covered/partial/gap status for each of the 10 risks,
        evidence counts from Guard/Vault, and an overall coverage score.
        """
        return self._get("/v1/compliance/owasp-attestation")

    def list_compliance_frameworks(self) -> dict[str, Any]:
        """List all supported compliance frameworks (eu-ai-act, nist-ai-rmf, iso-42001)."""
        return self._get("/v1/compliance/frameworks")

    def get_compliance_report(self, framework_id: str) -> dict[str, Any]:
        """Get a per-tenant compliance report for a specific framework.

        framework_id: 'eu-ai-act' | 'nist-ai-rmf' | 'iso-42001'
        Returns pass/warn/fail per control with evidence counts and recommendations.
        """
        return self._get(f"/v1/compliance/{framework_id}")

    # --- Cedar Policies ---

    def list_cedar_policies(self) -> dict[str, Any]:
        """List active Cedar policies for the tenant."""
        return self._get("/v1/policies")

    def create_cedar_policy(
        self,
        *,
        name: str,
        policy_text: str,
        description: str = "",
    ) -> dict[str, Any]:
        """Create a Cedar policy. Requires Max or Enterprise plan."""
        return self._post(
            "/v1/policies",
            body={"name": name, "description": description, "policy_text": policy_text},
        )

    def get_cedar_policy(self, policy_id: str) -> dict[str, Any]:
        """Get a Cedar policy by id (includes full policy text)."""
        return self._get(f"/v1/policies/{policy_id}")

    def update_cedar_policy(
        self,
        policy_id: str,
        *,
        name: str | None = None,
        description: str | None = None,
        policy_text: str | None = None,
        is_active: bool | None = None,
    ) -> dict[str, Any]:
        """Update a Cedar policy. Increments version if policy_text changes."""
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if policy_text is not None:
            body["policy_text"] = policy_text
        if is_active is not None:
            body["is_active"] = is_active
        return self._request(f"/v1/policies/{policy_id}", method="PUT", body=body)

    def delete_cedar_policy(self, policy_id: str) -> dict[str, Any]:
        """Soft-delete a Cedar policy (sets is_active=False)."""
        return self._request(f"/v1/policies/{policy_id}", method="DELETE")

    def validate_cedar_policy(self, policy_text: str) -> dict[str, Any]:
        """Validate Cedar syntax without persisting."""
        return self._post("/v1/policies/validate", body={"policy_text": policy_text})

    def test_cedar_policy(
        self,
        *,
        policy_text: str,
        agent_id: str = "test_agent",
        action_type: str = "tool_call",
        policy_tier: str = "tier_1",
        risk_score: int = 50,
        is_verified: bool = False,
    ) -> dict[str, Any]:
        """Dry-run a Cedar policy against test input. Returns the decision."""
        return self._post(
            "/v1/policies/test",
            body={
                "policy_text": policy_text,
                "agent_id": agent_id,
                "action_type": action_type,
                "policy_tier": policy_tier,
                "risk_score": risk_score,
                "is_verified": is_verified,
            },
        )

    # --- SRE: Circuit Breakers, SLOs, Error Budgets ---

    def get_sre_dashboard(self) -> dict[str, Any]:
        """Combined SRE dashboard — circuit breakers + SLO + error budget + provider health."""
        return self._get("/v1/analytics/sre/dashboard")

    def get_circuit_breakers(self) -> dict[str, Any]:
        """Get current state of all LLM provider circuit breakers."""
        return self._get("/v1/analytics/sre/circuit-breakers")

    def reset_circuit_breaker(self, provider: str, model: str) -> dict[str, Any]:
        """Manually reset a circuit breaker to closed state."""
        return self._post(f"/v1/analytics/sre/circuit-breakers/{provider}/{model}/reset")

    def get_error_budget(self) -> dict[str, Any]:
        """Get error budget status based on SLO targets and recent LLM usage."""
        return self._get("/v1/analytics/sre/error-budget")

    def get_slo_config(self) -> dict[str, Any]:
        """Get the tenant's current SLO configuration."""
        return self._get("/v1/analytics/sre/slo-config")

    def update_slo_config(
        self,
        *,
        availability_target: float | None = None,
        latency_p95_target_ms: float | None = None,
        error_budget_window_hours: int | None = None,
        budget_exhausted_action: str | None = None,
    ) -> dict[str, Any]:
        """Update tenant SLO targets. Stored in tenant.llm_config.slo."""
        body: dict[str, Any] = {}
        if availability_target is not None:
            body["availability_target"] = availability_target
        if latency_p95_target_ms is not None:
            body["latency_p95_target_ms"] = latency_p95_target_ms
        if error_budget_window_hours is not None:
            body["error_budget_window_hours"] = error_budget_window_hours
        if budget_exhausted_action is not None:
            body["budget_exhausted_action"] = budget_exhausted_action
        return self._request("/v1/analytics/sre/slo-config", method="PUT", body=body)

    # --- Context Governance ---

    def get_context_dashboard(self, *, days: int = 30) -> dict[str, Any]:
        """Combined context governance dashboard — topics + quality + gaps."""
        return self._get(f"/v1/analytics/context/dashboard?days={days}")

    def get_context_topics(self, *, days: int = 30, limit: int = 20) -> dict[str, Any]:
        """Event topic distribution and trending categories."""
        return self._get(f"/v1/analytics/context/topics?days={days}&limit={limit}")

    def get_context_quality(self) -> dict[str, Any]:
        """Knowledge base coverage, event health, per-agent breakdown."""
        return self._get("/v1/analytics/context/quality")

    def get_context_gaps(self, *, days: int = 30) -> dict[str, Any]:
        """Detect agents with high failure rates and low knowledge base coverage."""
        return self._get(f"/v1/analytics/context/gaps?days={days}")

    # --- Guard Extensions: MCP Scanner + Cross-Model Verification ---

    def scan_mcp_tools(self, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Scan MCP tool definitions for security risks (pre-deploy audit).

        Checks for tool poisoning, typosquatting, schema manipulation,
        rug-pull patterns, prompt injection, and excessive permissions.
        Returns a structured report with verdict (pass/warn/fail).
        """
        return self._post("/v1/suite/guard/scan-mcp", body={"tools": tools})

    def verify_response(
        self,
        *,
        prompt: str,
        response: str,
        models: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Cross-model verification — check a response with multiple LLMs.

        Defends against memory poisoning (OWASP ASI06) by routing the
        response through 2-3 verifiers and computing majority consensus.
        Results are logged to Vault for audit.
        """
        body: dict[str, Any] = {"prompt": prompt, "response": response}
        if models:
            body["models"] = models
        return self._post("/v1/suite/guard/verify", body=body)

    # --- A2A Transport (Ed25519 signing) ---

    def provision_a2a_keys(self, agent_id: str) -> dict[str, Any]:
        """Provision Ed25519 transport keys for an agent. Returns the public key.

        After provisioning, the agent's public_key appears in agent cards under
        x-veriswarm-transport. Inter-agent messages can then be signed.
        """
        return self._post(f"/v1/a2a/{agent_id}/keys")

    # --- Content Provenance (EU AI Act Article 50) ---

    def label_content(
        self,
        *,
        content: str,
        agent_id: str | None = None,
        model: str | None = None,
        content_type: str = "text/plain",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Generate an Ed25519-signed provenance manifest for AI-generated content.

        Returns the manifest (including signature, content hash, tenant/agent
        metadata). Machine-readable format compatible with EU AI Act Article 50
        transparency requirements.
        """
        body: dict[str, Any] = {"content": content, "content_type": content_type}
        if agent_id is not None:
            body["agent_id"] = agent_id
        if model is not None:
            body["model"] = model
        if metadata is not None:
            body["metadata"] = metadata
        return self._post("/v1/content/label", body=body)

    def get_content_provenance(self, content_hash: str) -> dict[str, Any]:
        """Public lookup of a provenance manifest by SHA-256 content hash.

        No authentication required on the server side — third parties can
        verify AI-generated content labels without a VeriSwarm account.
        """
        return self._get(f"/v1/content/provenance/{content_hash}")

    def verify_content(
        self,
        *,
        manifest: dict[str, Any],
        content: str | None = None,
    ) -> dict[str, Any]:
        """Verify a provenance manifest's Ed25519 signature.

        If ``content`` is supplied, also verifies the content hash matches.
        Public endpoint — no auth required on the server side.
        """
        body: dict[str, Any] = {"manifest": manifest}
        if content is not None:
            body["content"] = content
        return self._post("/v1/content/verify", body=body)

    # --- ABAC: Agent Attributes (Cedar policy context) ---

    def get_agent_attributes(self, agent_id: str) -> dict[str, Any]:
        """Read tenant-defined ABAC attributes for an agent.

        These attributes are merged into the Cedar entity at decision time
        and can be referenced in custom policies as ``principal.<key>``.
        """
        return self._get(f"/v1/agents/{agent_id}/attributes")

    def set_agent_attributes(
        self,
        agent_id: str,
        attributes: dict[str, Any],
    ) -> dict[str, Any]:
        """Replace an agent's ABAC attributes.

        Values must be Cedar-compatible types (strings, ints, bools, or lists
        of those). Reserved keys (``policy_tier``, ``risk_score``, ``is_verified``)
        are silently rejected.
        """
        return self._request(
            f"/v1/agents/{agent_id}/attributes",
            method="PUT",
            body={"attributes": attributes},
        )

    # --- Passport JIT (Just-in-Time Access Grants) ---

    def request_jit_grant(
        self,
        *,
        agent_id: str,
        action_type: str,
        resource_type: str | None = None,
        resource_id: str | None = None,
        reason: str | None = None,
        ttl_seconds: int = 300,
    ) -> dict[str, Any]:
        """Request a just-in-time access grant for an agent.

        Trusted agents (composite_trust >= 75, risk_score <= 30, verified,
        ttl <= 10min) are auto-approved. Others go to pending state for human
        review via ``approve_jit_grant``.
        """
        body: dict[str, Any] = {
            "agent_id": agent_id,
            "action_type": action_type,
            "ttl_seconds": ttl_seconds,
        }
        if resource_type is not None:
            body["resource_type"] = resource_type
        if resource_id is not None:
            body["resource_id"] = resource_id
        if reason is not None:
            body["reason"] = reason
        return self._post("/v1/passport/jit/request", body=body)

    def approve_jit_grant(self, grant_id: str) -> dict[str, Any]:
        """Approve a pending JIT grant (requires account session token)."""
        return self._post(f"/v1/passport/jit/{grant_id}/approve")

    def deny_jit_grant(self, grant_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """Deny a pending JIT grant."""
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/passport/jit/{grant_id}/deny", body=body)

    def revoke_jit_grant(self, grant_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """Revoke an approved JIT grant immediately."""
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/passport/jit/{grant_id}/revoke", body=body)

    def issue_jit_token(self, grant_id: str) -> dict[str, Any]:
        """Issue the ES256 JIT token for an approved grant.

        Only callable once per grant — subsequent calls fail. Returns a dict
        containing ``token`` (the signed JWT) and ``expires_at``.
        """
        return self._post(f"/v1/passport/jit/{grant_id}/token")

    def verify_jit_token(
        self,
        *,
        token: str,
        expected_action: str | None = None,
        expected_resource_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify a JIT token at use-time. Public endpoint — no auth required.

        Checks signature, revocation state, expiry, and optional scope match.
        """
        body: dict[str, Any] = {"token": token}
        if expected_action is not None:
            body["expected_action"] = expected_action
        if expected_resource_id is not None:
            body["expected_resource_id"] = expected_resource_id
        return self._post("/v1/passport/jit/verify", body=body)

    def list_jit_grants(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """List JIT grants for the tenant, optionally filtered by agent or status."""
        params = [f"limit={limit}"]
        if agent_id:
            params.append(f"agent_id={agent_id}")
        if status:
            params.append(f"status={status}")
        return self._get(f"/v1/passport/jit/grants?{'&'.join(params)}")

    def get_jit_grant(self, grant_id: str) -> dict[str, Any]:
        """Get a single JIT grant by id."""
        return self._get(f"/v1/passport/jit/grants/{grant_id}")

    # --- Internal ---

    def _get(self, path: str) -> Any:
        """Convenience wrapper for GET requests."""
        return self._request(path, method="GET")

    def _post(self, path: str, body: Any = None) -> Any:
        """Convenience wrapper for POST requests."""
        return self._request(path, method="POST", body=body)

    def _request(self, path: str, *, method: str = "GET", body: Any = None) -> Any:
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=encoded,
            method=method,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "veriswarm-python-sdk/0.1.0",
                "x-api-key": self.api_key,
            },
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except HTTPError as exc:
            details = ""
            try:
                details = exc.read().decode("utf-8")
            except Exception:
                details = str(exc)
            raise VeriSwarmClientError(f"VeriSwarm API {exc.code}: {details}") from exc
        except URLError as exc:
            raise VeriSwarmClientError(f"VeriSwarm request failed: {exc.reason}") from exc
