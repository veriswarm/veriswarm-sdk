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
