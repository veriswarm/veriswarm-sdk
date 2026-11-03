from __future__ import annotations

import functools
import json
import math
import socket
import time
from http.client import HTTPException
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar
from urllib.error import HTTPError, URLError
from urllib.parse import quote as _q, urlencode as _qs
from urllib.request import HTTPRedirectHandler, Request, build_opener

from veriswarm._version import __version__
from veriswarm.secret_tripwire import SecretTripwire, ensure_tripwire

_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
_USER_AGENT = f"veriswarm-python-sdk/{__version__}"


# Path-component encoder. quote(..., safe="") percent-encodes every
# character that's not in the unreserved set (A-Za-z0-9-_.~), so a
# value like "../admin" becomes "..%2Fadmin" and cannot escape the
# intended path segment. "." and ".." survive quoting unchanged and are
# resolved by URL normalization, so they are rejected outright, as are
# empty/None ids. Used at every f-string path-interpolation call site.
def _path(value: Any) -> str:
    """Quote an ID for safe use as a single URL path segment."""
    if value is None:
        raise ValueError("path segment must not be None")
    segment = str(value)
    if segment in ("", ".", ".."):
        raise ValueError(f'path segment must not be empty, "." or ".." (got {segment!r})')
    return _q(segment, safe="")


def _with_query(path: str, query: dict[str, Any] | None) -> str:
    """Append ``query`` to ``path``, encoding every value and skipping ``None``."""
    if not query:
        return path
    pairs = [(key, _query_value(value)) for key, value in query.items() if value is not None]
    return f"{path}?{_qs(pairs)}" if pairs else path


def _normalize_cidrs(cidrs: list[str] | str | None) -> str:
    """Join a CIDR list (or comma/newline-separated string) into the server's format."""
    if cidrs is None:
        return ""
    parts = cidrs.replace("\n", ",").split(",") if isinstance(cidrs, str) else cidrs
    return ",".join(p.strip() for p in (str(x) for x in parts) if p.strip())


def _query_value(value: Any) -> str:
    # Match the Node SDK / server expectations for booleans.
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


_CREDENTIAL_HEADERS = ("x-api-key", "x-account-access-token", "authorization")


class _StripAuthRedirectHandler(HTTPRedirectHandler):
    """Strip credential headers when urllib follows a redirect.

    urllib's default re-attaches custom headers (`x-api-key`,
    `Authorization`) to the redirected URL. A compromised or MITM'd
    response from the configured base_url could 302 to attacker host
    and steal the workspace API key. (Mirrors the audit closure
    2026-05-08 CRIT-D-7 fix in the main repo.)
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new_req is None:
            return None
        new_req.headers = {
            k: v for k, v in new_req.headers.items()
            if k.lower() not in _CREDENTIAL_HEADERS
        }
        return new_req


_OPENER = build_opener(_StripAuthRedirectHandler())


class VeriSwarmClientError(RuntimeError):
    """Error raised by the client.

    ``status`` is the HTTP status when a response was received (``None`` for
    local or network failures); ``code`` names local failure classes such as
    ``"ACCOUNT_TOKEN_REQUIRED"``.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


_F = TypeVar("_F", bound=Callable[..., Any])

# How long to keep built-in-only tripwire rules before retrying the fetch.
_TRIPWIRE_RETRY_SECONDS = 60.0


def _requires_account_token(method: _F) -> _F:
    """Fail fast for endpoints whose server route accepts only a session token."""

    @functools.wraps(method)
    def wrapper(self: "VeriSwarmClient", *args: Any, **kwargs: Any) -> Any:
        if not self.account_token:
            raise VeriSwarmClientError(
                f"{method.__name__} requires an account session token: pass "
                "account_token to VeriSwarmClient (this endpoint does not "
                "accept API keys)",
                code="ACCOUNT_TOKEN_REQUIRED",
            )
        return method(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


@dataclass(slots=True)
class VeriSwarmClient:
    """VeriSwarm Python SDK — trust scoring, event ingestion, and agent management.

    Usage:
        client = VeriSwarmClient(base_url="https://api.veriswarm.ai", api_key="vsk_...")
        decision = client.check_decision(agent_id="agt_123", action_type="post_message")

    ``account_token`` is an account session token sent as
    ``x-account-access-token``. Account-administration methods (team,
    workspaces, notifications, Passport, Vault export, ...) call routes that
    accept only a session token and raise ``VeriSwarmClientError`` with
    ``code="ACCOUNT_TOKEN_REQUIRED"`` when it is not configured.
    """
    base_url: str
    api_key: str | None = None
    timeout_seconds: float = 15
    secrets_detection: bool = False
    account_token: str | None = field(default=None, repr=False)
    _tripwire: "SecretTripwire | None" = field(default=None, init=False, repr=False)
    _tripwire_retry_at: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.base_url:
            raise ValueError("base_url is required")
        if not self.api_key and not self.account_token:
            raise ValueError("api_key or account_token is required")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive, finite number")
        self.base_url = self.base_url.rstrip("/")
        # Reject non-https base_url. The SDK ships x-api-key on every
        # request; an http base_url would transmit it in plaintext where
        # any MITM (or compromised local proxy) can harvest it. Local
        # development against http://localhost is the only acceptable
        # exception; explicit and narrow. (Audit 2026-05-08 CRIT-SDK-1.)
        from urllib.parse import urlparse
        parsed = urlparse(self.base_url)
        if parsed.scheme != "https":
            allow_http_dev = (
                parsed.scheme == "http"
                and parsed.hostname in ("localhost", "127.0.0.1", "::1")
            )
            if not allow_http_dev:
                raise ValueError(
                    f"base_url must be https:// (got {parsed.scheme!r}). "
                    "Only http://localhost is permitted as a dev escape hatch."
                )

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
        return self._request(f"/v1/public/agents/{_path(agent_id)}")

    def get_agent_scores(self, agent_id: str) -> dict[str, Any]:
        """Get an agent's current trust scores."""
        return self._request(f"/v1/public/agents/{_path(agent_id)}/scores/current")

    def get_agent_score_history(self, agent_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Get an agent's score history (last N snapshots)."""
        return self._get(f"/v1/public/agents/{_path(agent_id)}/scores/history", query={"limit": limit})

    def get_agent_score_breakdown(self, agent_id: str) -> dict[str, Any]:
        """Get detailed score breakdown with contributing factors."""
        return self._request(f"/v1/public/agents/{_path(agent_id)}/scores/breakdown")

    def get_agent_flags(self, agent_id: str) -> list[dict[str, Any]]:
        """Get active moderation flags for an agent."""
        return self._request(f"/v1/public/agents/{_path(agent_id)}/flags")

    def appeal_flag(self, agent_id: str, flag_id: int) -> dict[str, Any]:
        """Appeal a moderation flag for review."""
        return self._request(
            f"/v1/public/agents/{_path(agent_id)}/flags/{_path(flag_id)}/appeal",
            method="POST",
        )

    def get_agent_manifests(self, agent_id: str) -> list[dict[str, Any]]:
        """Get agent capability manifests (public)."""
        return self._request(f"/v1/public/agents/{_path(agent_id)}/manifests")

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

    def get_secret_rules(self) -> dict[str, Any]:
        """Fetch the client-tripwire secret-rules manifest."""
        return self._request("/v1/suite/guard/secret-rules", method="GET")

    def guard_outbound_text(
        self,
        text: str,
        *,
        agent_id: str | None = None,
        session_id: str | None = None,
    ) -> str:
        """Tokenize-when-online / redact-when-offline outbound text.

        No-op unless ``secrets_detection`` is enabled. On a prefix hit the
        authoritative tokenize endpoint is tried first; any failure (or a
        surviving prefix span) falls back to a non-recoverable local
        redaction (fail-closed).
        """
        if not self.secrets_detection or not isinstance(text, str) or not text:
            return text
        tripwire = self._refresh_tripwire_if_due()
        if not tripwire.scan(text):
            return text
        try:
            result = self.tokenize_pii(
                text=text, agent_id=agent_id, session_id=session_id
            )
            guarded = text
            if isinstance(result, dict) and result.get("tokens_created", 0) > 0:
                guarded = result.get("tokenized_text") or text
            # Belt-and-suspenders: the PII tokenizer is not a secret detector,
            # so re-scan and locally redact any provider-prefix span it left.
            if tripwire.scan(guarded):
                guarded = tripwire.redact_offline(guarded)
            return guarded
        except Exception:
            return tripwire.redact_offline(text)

    def _refresh_tripwire_if_due(self) -> SecretTripwire:
        """Load the tripwire on first use; if only built-in rules are active
        (fetch failed or manifest invalid), retry once the interval passes
        instead of keeping the fallback forever."""
        current = self._tripwire
        due = time.monotonic() >= self._tripwire_retry_at
        if current is not None and (current.source == "remote" or not due):
            return current
        fresh = ensure_tripwire(fetch_manifest=self.get_secret_rules)
        if fresh.source != "remote":
            self._tripwire_retry_at = time.monotonic() + _TRIPWIRE_RETRY_SECONDS
        self._tripwire = fresh
        return fresh

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

    @_requires_account_token
    def get_scoring_profile(self) -> dict[str, Any]:
        """Get the current tenant's scoring profile."""
        return self._get("/v1/suite/scoring/profile")

    @_requires_account_token
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
        return self._get(f"/v1/public/agents/{_path(agent_id)}/timeline", query={"limit": limit})

    # --- Agent API Keys ---

    def get_agent_api_keys(self, agent_id: str) -> list[dict[str, Any]]:
        """List API keys for an agent."""
        return self._get(f"/v1/public/agents/{_path(agent_id)}/api-keys")

    def rotate_agent_api_key(self, agent_id: str) -> dict[str, Any]:
        """Rotate (regenerate) an agent's API key."""
        return self._post(f"/v1/public/agents/{_path(agent_id)}/api-keys/rotate")

    def revoke_agent_api_key(self, agent_id: str, key_id: str) -> dict[str, Any]:
        """Revoke a specific agent API key."""
        return self._post(f"/v1/public/agents/{_path(agent_id)}/api-keys/{_path(key_id)}/revoke")

    # --- Guard PII Sessions ---

    def get_pii_session(self, session_id: str) -> dict[str, Any]:
        """Get details of a PII tokenization session."""
        return self._get(f"/v1/suite/guard/pii/sessions/{_path(session_id)}")

    @_requires_account_token
    def revoke_pii_session(self, session_id: str) -> dict[str, Any]:
        """Revoke (delete) a PII tokenization session and all its tokens."""
        return self._request(f"/v1/suite/guard/pii/sessions/{_path(session_id)}", method="DELETE")

    # --- Guard Policies ---

    def list_guard_policies(self) -> list[dict[str, Any]]:
        """List all Guard policies for the workspace."""
        return self._get("/v1/suite/guard/policies")

    def create_guard_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        """Create a new Guard policy rule."""
        return self._post("/v1/suite/guard/policies", policy)

    def update_guard_policy(
        self,
        policy_id: int,
        updates: dict[str, Any] | None = None,
        *,
        is_active: bool | None = None,
    ) -> dict[str, Any]:
        """Activate or deactivate a Guard policy rule (``is_active``)."""
        active = is_active if is_active is not None else (updates or {}).get("is_active")
        if not isinstance(active, bool):
            raise ValueError("update_guard_policy requires is_active=True/False")
        return self._request(
            f"/v1/suite/guard/policies/{_path(policy_id)}",
            method="PATCH",
            query={"is_active": active},
        )

    def delete_guard_policy(self, policy_id: int) -> dict[str, Any]:
        """Delete a Guard policy rule."""
        return self._request(f"/v1/suite/guard/policies/{_path(policy_id)}", method="DELETE")

    # --- Guard Kill Switch ---

    def kill_agent(self, agent_id: str, *, reason: str) -> dict[str, Any]:
        """Activate the kill switch for an agent, blocking all trust decisions."""
        return self._post(f"/v1/suite/guard/kill/{_path(agent_id)}", {"reason": reason})

    def unkill_agent(self, agent_id: str) -> dict[str, Any]:
        """Deactivate the kill switch for an agent."""
        return self._post(f"/v1/suite/guard/unkill/{_path(agent_id)}")

    # --- Guard Findings ---

    def list_guard_findings(self, *, agent_id: str | None = None) -> list[dict[str, Any]]:
        """List Guard security findings, optionally filtered by agent."""
        return self._get("/v1/suite/guard/findings", query={"agent_id": agent_id or None})

    @_requires_account_token
    def update_guard_finding(
        self,
        finding_id: int,
        updates: dict[str, Any] | None = None,
        *,
        new_status: str | None = None,
    ) -> dict[str, Any]:
        """Set a Guard finding's status: open, false_positive, mitigated, or resolved."""
        given = updates or {}
        value = new_status or given.get("new_status") or given.get("status")
        if not isinstance(value, str) or not value:
            raise ValueError("update_guard_finding requires new_status")
        return self._request(
            f"/v1/suite/guard/findings/{_path(finding_id)}",
            method="PATCH",
            query={"new_status": value},
        )

    # --- Passport Delegations ---

    @_requires_account_token
    def create_delegation(self, delegation: dict[str, Any]) -> dict[str, Any]:
        """Create a new Passport delegation grant."""
        return self._post("/v1/suite/passport/delegations", delegation)

    @_requires_account_token
    def list_delegations(self) -> list[dict[str, Any]]:
        """List active Passport delegations."""
        return self._get("/v1/suite/passport/delegations")

    @_requires_account_token
    def revoke_delegation(self, delegation_id: int) -> dict[str, Any]:
        """Revoke a Passport delegation."""
        return self._request(f"/v1/suite/passport/delegations/{_path(delegation_id)}", method="DELETE")

    # --- Passport Verification ---

    @_requires_account_token
    def verify_agent_identity(self, agent_id: str) -> dict[str, Any]:
        """Mark an agent as identity-verified in Passport."""
        return self._post(f"/v1/suite/passport/verify/{_path(agent_id)}")

    # --- Passport Manifests ---

    @_requires_account_token
    def create_manifest(self, agent_id: str, manifest: dict[str, Any]) -> dict[str, Any]:
        """Create or update an agent capability manifest."""
        return self._post(f"/v1/suite/passport/manifests/{_path(agent_id)}", manifest)

    @_requires_account_token
    def get_manifests(self, agent_id: str) -> list[dict[str, Any]]:
        """Get agent capability manifests from Passport."""
        return self._get(f"/v1/suite/passport/manifests/{_path(agent_id)}")

    # --- Vault ---

    def query_vault_ledger(self, *, agent_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        """Query the immutable Vault audit ledger."""
        return self._get(
            "/v1/suite/vault/ledger", query={"limit": limit, "agent_id": agent_id or None}
        )

    def verify_vault_chain(self, *, limit: int = 100) -> dict[str, Any]:
        """Verify hash-chain integrity of the Vault ledger."""
        return self._get("/v1/suite/vault/verify", query={"limit": limit})

    @_requires_account_token
    def export_vault(self, *, export_type: str = "json") -> dict[str, Any]:
        """Create a Vault export job."""
        return self._post("/v1/suite/vault/export", {"export_type": export_type})

    @_requires_account_token
    def get_vault_export_status(self, job_id: str) -> dict[str, Any]:
        """Check the status of a Vault export job."""
        return self._get(f"/v1/suite/vault/export/{_path(job_id)}")

    # --- Notifications ---

    @_requires_account_token
    def list_notifications(self) -> list[dict[str, Any]]:
        """List notifications for the current workspace."""
        return self._get("/v1/suite/notifications")

    @_requires_account_token
    def mark_notification_read(self, notification_id: int) -> dict[str, Any]:
        """Mark a single notification as read."""
        return self._post(f"/v1/suite/notifications/{_path(notification_id)}/read")

    @_requires_account_token
    def mark_all_notifications_read(self) -> dict[str, Any]:
        """Mark all notifications as read."""
        return self._post("/v1/suite/notifications/read-all")

    # --- IP Allowlist ---

    @_requires_account_token
    def get_ip_allowlist(self) -> dict[str, Any]:
        """Get the current IP allowlist for the workspace."""
        return self._get("/v1/public/providers/ip-allowlist")

    @_requires_account_token
    def set_ip_allowlist(
        self,
        *,
        cidrs: list[str] | str | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Set the IP allowlist for the workspace.

        The server stores a comma-separated CIDR string and treats an empty
        one as "disable", so an empty list is refused unless
        ``enabled=False`` is passed explicitly.
        """
        ip_allowlist = _normalize_cidrs(cidrs) if enabled else ""
        if enabled and not ip_allowlist:
            raise ValueError(
                "set_ip_allowlist: cidrs is empty; pass enabled=False to disable the allowlist"
            )
        return self._post("/v1/public/providers/ip-allowlist", {"ip_allowlist": ip_allowlist})

    # --- Custom Domains ---

    @_requires_account_token
    def get_custom_domain(self) -> dict[str, Any]:
        """Get the custom domain configuration for the workspace."""
        return self._get("/v1/public/providers/custom-domain")

    @_requires_account_token
    def set_custom_domain(self, *, domain: str) -> dict[str, Any]:
        """Set a custom domain for the workspace."""
        return self._post("/v1/public/providers/custom-domain", {"domain": domain})

    @_requires_account_token
    def verify_custom_domain(self) -> dict[str, Any]:
        """Verify DNS configuration for the custom domain."""
        return self._post("/v1/public/providers/custom-domain/verify")

    @_requires_account_token
    def delete_custom_domain(self) -> dict[str, Any]:
        """Remove the custom domain from the workspace."""
        return self._request("/v1/public/providers/custom-domain", method="DELETE")

    # --- Team Management ---

    @_requires_account_token
    def list_team_members(self) -> list[dict[str, Any]]:
        """List team members in the current workspace."""
        return self._get("/v1/public/providers/team")

    @_requires_account_token
    def invite_team_member(self, *, email: str, role: str = "member") -> dict[str, Any]:
        """Invite a new team member to the workspace."""
        return self._post("/v1/public/providers/team/invite", {"email": email, "role": role})

    @_requires_account_token
    def remove_team_member(self, user_id: str) -> dict[str, Any]:
        """Remove a team member from the workspace."""
        return self._request(f"/v1/public/providers/team/{_path(user_id)}", method="DELETE")

    # --- Workspaces ---

    @_requires_account_token
    def list_workspaces(self) -> list[dict[str, Any]]:
        """List workspaces the current user belongs to."""
        return self._get("/v1/public/accounts/workspaces")

    @_requires_account_token
    def switch_workspace(self, tenant_id: str) -> dict[str, Any]:
        """Switch the user's active workspace."""
        return self._post(f"/v1/public/accounts/workspaces/{_path(tenant_id)}/switch")

    # --- Reputation Lookup ---

    def reputation_lookup(
        self, agent_ref: str | None = None, *, slug: str | None = None
    ) -> dict[str, Any]:
        """Look up an agent's shared reputation by reference (email, URL, slug, ...).

        ``slug=`` is accepted as an alias for ``agent_ref``.
        """
        ref = agent_ref if agent_ref is not None else slug
        if not ref:
            raise ValueError("reputation_lookup requires agent_ref")
        return self._get("/v1/public/reputation/lookup", query={"agent_ref": ref})

    # --- Badges ---

    def get_badge_url(
        self,
        agent_slug: str,
        style: str = "compact",
        theme: str = "dark",
    ) -> str:
        """Get the URL for an agent's embeddable trust badge."""
        path = _with_query(f"/v1/badge/{_path(agent_slug)}.svg", {"style": style, "theme": theme})
        return f"{self.base_url}{path}"

    # --- Cortex Workflows ---

    def list_workflows(self, *, is_active: bool | None = None) -> dict[str, Any]:
        """List all Cortex Workflows for the current tenant."""
        return self._get("/v1/workflows", query={"is_active": is_active})

    def get_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Get a workflow's details and recent executions."""
        return self._get(f"/v1/workflows/{_path(workflow_id)}")

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
        return self._request(f"/v1/workflows/{_path(workflow_id)}", method="PUT", body=body)

    def delete_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Delete a workflow."""
        return self._request(f"/v1/workflows/{_path(workflow_id)}", method="DELETE")

    def activate_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Activate a workflow's triggers."""
        return self._post(f"/v1/workflows/{_path(workflow_id)}/activate")

    def deactivate_workflow(self, workflow_id: str) -> dict[str, Any]:
        """Deactivate a workflow's triggers."""
        return self._post(f"/v1/workflows/{_path(workflow_id)}/deactivate")

    def run_workflow(
        self,
        workflow_id: str,
        *,
        inputs: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Manually trigger a workflow execution."""
        return self._post(f"/v1/workflows/{_path(workflow_id)}/run", body={"inputs": inputs or {}})

    def get_execution(self, execution_id: str) -> dict[str, Any]:
        """Get execution details including step-by-step results."""
        return self._get(f"/v1/workflows/executions/{_path(execution_id)}")

    def list_executions(
        self,
        workflow_id: str,
        *,
        status: str | None = None,
    ) -> dict[str, Any]:
        """List executions for a workflow."""
        return self._get(
            f"/v1/workflows/{_path(workflow_id)}/executions", query={"status": status or None}
        )

    def cancel_execution(self, execution_id: str) -> dict[str, Any]:
        """Cancel a running execution."""
        return self._post(f"/v1/workflows/executions/{_path(execution_id)}/cancel")

    def retry_execution(self, execution_id: str) -> dict[str, Any]:
        """Retry a failed execution."""
        return self._post(f"/v1/workflows/executions/{_path(execution_id)}/retry")

    @_requires_account_token
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
            f"/v1/workflows/executions/{_path(execution_id)}/steps/{_path(step_id)}/approve",
            body=body,
        )

    def list_workflow_templates(self) -> dict[str, Any]:
        """List available workflow templates."""
        return self._get("/v1/workflows/templates")

    def deploy_template(self, template_id: str) -> dict[str, Any]:
        """Deploy a workflow template as a new workflow."""
        return self._post(f"/v1/workflows/templates/{_path(template_id)}/deploy")

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
        return self._get(f"/v1/compliance/{_path(framework_id)}")

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
        return self._get(f"/v1/policies/{_path(policy_id)}")

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
        return self._request(f"/v1/policies/{_path(policy_id)}", method="PUT", body=body)

    def delete_cedar_policy(self, policy_id: str) -> dict[str, Any]:
        """Soft-delete a Cedar policy (sets is_active=False)."""
        return self._request(f"/v1/policies/{_path(policy_id)}", method="DELETE")

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
        return self._post(
            f"/v1/analytics/sre/circuit-breakers/{_path(provider)}/{_path(model)}/reset"
        )

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
        return self._get("/v1/analytics/context/dashboard", query={"days": days})

    def get_context_topics(self, *, days: int = 30, limit: int = 20) -> dict[str, Any]:
        """Event topic distribution and trending categories."""
        return self._get("/v1/analytics/context/topics", query={"days": days, "limit": limit})

    def get_context_quality(self) -> dict[str, Any]:
        """Knowledge base coverage, event health, per-agent breakdown."""
        return self._get("/v1/analytics/context/quality")

    def get_context_gaps(self, *, days: int = 30) -> dict[str, Any]:
        """Detect agents with high failure rates and low knowledge base coverage."""
        return self._get("/v1/analytics/context/gaps", query={"days": days})

    # --- Guard Extensions: MCP Scanner + Cross-Model Verification ---

    def scan_mcp_tools(self, tools: list[dict[str, Any]]) -> dict[str, Any]:
        """Scan MCP tool definitions for security risks (pre-deploy audit).

        Checks for tool poisoning, typosquatting, schema manipulation,
        rug-pull patterns, prompt injection, and excessive permissions.
        Returns a structured report with verdict (pass/warn/fail).
        """
        return self._post("/v1/suite/guard/scan-mcp", body={"tools": tools})

    def scan_ci(self, files: list[dict[str, Any]]) -> dict[str, Any]:
        """Scan CI workflow YAML + Dockerfiles for secret-exfiltration risk.

        Each file is ``{"path": str, "content"?: str, "diff"?: str}``: pass
        ``content`` (full file at head) for Layer 1 vulnerable-config checks and
        ``diff`` (unified diff hunks) for Layer 2 exfil-pattern checks. Returns a
        structured report with ``findings``, ``highest_severity``, ``blocked``
        (derived from the tenant's GuardPolicy enforcement level), and
        ``enforcement_level``.
        """
        return self._post("/v1/suite/guard/scan-ci", body={"files": files})

    def scan_session_turn(
        self,
        session_id: str,
        turn_index: int,
        *,
        user_text: str = "",
        agent_text: str = "",
        system_prompt: str = "",
        agent_id: str | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        """Score one conversation turn for multi-turn exfiltration risk (Guard Session Sentry).

        Sends the turn to POST /v1/suite/guard/scan-session. Returns the scan
        report; check ``blocked`` to decide whether to suppress the agent's
        response, and ``enabled`` to see whether Session Sentry is active for
        your platform/plan.

        When the platform flag is off the response shape is
        ``{session_id, enabled: false, blocked: false, session_score: 0.0,
        highest_severity: "info", contributions: []}``.
        """
        body: dict[str, Any] = {
            "session_id": session_id,
            "turn_index": turn_index,
            "user_text": user_text,
            "agent_text": agent_text,
            "system_prompt": system_prompt,
        }
        if agent_id is not None:
            body["agent_id"] = agent_id
        if actor_id is not None:
            body["actor_id"] = actor_id
        return self._post("/v1/suite/guard/scan-session", body=body)

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

    # --- Operator approval queue (/v1/approvals) ---

    def create_approval(
        self,
        *,
        agent_id: str | None = None,
        requested_action: dict[str, Any] | None = None,
        ttl_seconds: int = 24 * 3600,
    ) -> dict[str, Any]:
        """Submit a new approval request to the operator queue.

        agent_id: agent the request is on behalf of; omit for system-initiated reviews.
        requested_action: structured description of what's being approved.
        ttl_seconds: how long the request stays pending before expiring (60s..30d).
        """
        body: dict[str, Any] = {
            "requested_action": requested_action or {},
            "ttl_seconds": ttl_seconds,
        }
        if agent_id is not None:
            body["agent_id"] = agent_id
        return self._post("/v1/approvals", body=body)

    def list_approvals(
        self,
        *,
        state: str = "pending",
        agent_id: str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        """List approval requests for the authenticated tenant.

        state: one of "pending", "approved", "rejected", "expired", "all".
        """
        return self._get(
            "/v1/approvals", query={"state": state, "limit": limit, "agent_id": agent_id}
        )

    def get_approval(self, approval_id: str) -> dict[str, Any]:
        """Get a single approval request."""
        return self._get(f"/v1/approvals/{_path(approval_id)}")

    @_requires_account_token
    def approve_approval(
        self, approval_id: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        """Approve a pending approval request.

        Requires an account session token (operator role).
        """
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/approvals/{_path(approval_id)}/approve", body=body)

    @_requires_account_token
    def reject_approval(
        self, approval_id: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        """Reject a pending approval request.

        Requires an account session token (operator role).
        """
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/approvals/{_path(approval_id)}/reject", body=body)

    # --- A2A Protocol (catalog, agent cards, tasks) ---

    def list_a2a_catalog(self) -> dict[str, Any]:
        """List the tenant's trust-ranked A2A agent catalog.

        Returns agents in descending trust-score order, excluding any
        agent currently in the kill-switch state.
        """
        return self._get("/v1/a2a/catalog")

    def get_a2a_agent_card(self, agent_id: str) -> dict[str, Any]:
        """Get an A2A agent card.

        The card includes the `x-veriswarm-trust` extension and — when
        keys are provisioned — the `x-veriswarm-transport` extension
        carrying the agent's Ed25519 public key.
        """
        return self._get(f"/v1/a2a/{_path(agent_id)}/card")

    def submit_a2a_task(
        self,
        agent_id: str,
        *,
        requesting_agent_id: str,
        messages: list[dict[str, Any]],
        signature: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Submit a task to an agent via the A2A protocol.

        agent_id: receiving agent (`agt_*`).
        requesting_agent_id: caller's agent id (`agt_*`).
        messages: A2A-shaped message list.
        signature: optional Ed25519 signature envelope
            ``{"key_id": ..., "signature": ..., "algo": "ed25519"}``.

        Raises HTTP 403 if the receiving agent is killed, paused, or stopped.
        """
        body: dict[str, Any] = {
            "requesting_agent_id": requesting_agent_id,
            "messages": messages,
        }
        if signature is not None:
            body["signature"] = signature
        return self._post(f"/v1/a2a/{_path(agent_id)}/tasks", body=body)

    def get_a2a_task(self, agent_id: str, task_id: str) -> dict[str, Any]:
        """Get the status + result of an A2A task."""
        return self._get(f"/v1/a2a/{_path(agent_id)}/tasks/{_path(task_id)}")

    def cancel_a2a_task(self, agent_id: str, task_id: str) -> dict[str, Any]:
        """Cancel an in-flight A2A task. No-op if already terminated."""
        return self._post(
            f"/v1/a2a/{_path(agent_id)}/tasks/{_path(task_id)}/cancel"
        )

    # --- A2A Transport (Ed25519 signing) ---

    def provision_a2a_keys(self, agent_id: str) -> dict[str, Any]:
        """Provision Ed25519 transport keys for an agent. Returns the public key.

        After provisioning, the agent's public_key appears in agent cards under
        x-veriswarm-transport. Inter-agent messages can then be signed.
        """
        return self._post(f"/v1/a2a/{_path(agent_id)}/keys")

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
        return self._get(f"/v1/content/provenance/{_path(content_hash)}")

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
        return self._get(f"/v1/agents/{_path(agent_id)}/attributes")

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
            f"/v1/agents/{_path(agent_id)}/attributes",
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

    @_requires_account_token
    def approve_jit_grant(self, grant_id: str) -> dict[str, Any]:
        """Approve a pending JIT grant (requires account session token)."""
        return self._post(f"/v1/passport/jit/{_path(grant_id)}/approve")

    @_requires_account_token
    def deny_jit_grant(self, grant_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """Deny a pending JIT grant."""
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/passport/jit/{_path(grant_id)}/deny", body=body)

    def revoke_jit_grant(self, grant_id: str, *, reason: str | None = None) -> dict[str, Any]:
        """Revoke an approved JIT grant immediately."""
        body: dict[str, Any] = {}
        if reason is not None:
            body["reason"] = reason
        return self._post(f"/v1/passport/jit/{_path(grant_id)}/revoke", body=body)

    def issue_jit_token(self, grant_id: str) -> dict[str, Any]:
        """Issue the ES256 JIT token for an approved grant.

        Only callable once per grant — subsequent calls fail. Returns a dict
        containing ``token`` (the signed JWT) and ``expires_at``.
        """
        return self._post(f"/v1/passport/jit/{_path(grant_id)}/token")

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
        return self._get(
            "/v1/passport/jit/grants",
            query={"limit": limit, "agent_id": agent_id or None, "status": status or None},
        )

    def get_jit_grant(self, grant_id: str) -> dict[str, Any]:
        """Get a single JIT grant by id."""
        return self._get(f"/v1/passport/jit/grants/{_path(grant_id)}")

    # --- Governance: Anomalies, Discovery, Credential Vault, Compliance Scheduling, Reputation ---

    def list_anomalies(self, *, agent_id: str | None = None, limit: int = 50) -> dict[str, Any]:
        """List behavioral anomalies detected for the tenant."""
        return self._get(
            "/v1/governance/anomalies", query={"limit": limit, "agent_id": agent_id or None}
        )

    @_requires_account_token
    def run_shadow_discovery(self) -> dict[str, Any]:
        """Trigger a shadow-agent discovery scan."""
        return self._post("/v1/governance/discovery/scan")

    def list_discovered_agents(self, *, status: str | None = None) -> dict[str, Any]:
        """List discovered shadow agents, optionally filtered by status."""
        return self._get("/v1/governance/discovery", query={"status": status or None})

    @_requires_account_token
    def dismiss_discovered_agent(self, discovery_id: int) -> dict[str, Any]:
        """Dismiss a discovered shadow agent."""
        return self._post(f"/v1/governance/discovery/{_path(discovery_id)}/dismiss")

    @_requires_account_token
    def store_credential(
        self,
        *,
        name: str,
        credential_type: str,
        value: str,
        agent_id: str | None = None,
        min_trust_score: int = 0,
        rotation_interval_hours: int | None = None,
    ) -> dict[str, Any]:
        """Store an encrypted credential in the governance vault."""
        return self._post(
            "/v1/governance/credentials",
            {
                "name": name,
                "credential_type": credential_type,
                "value": value,
                "agent_id": agent_id,
                "min_trust_score": min_trust_score,
                "rotation_interval_hours": rotation_interval_hours,
            },
        )

    def checkout_credential(self, *, credential_name: str, agent_id: str) -> dict[str, Any]:
        """Check out a credential for an agent (trust-score gated, audit-logged)."""
        return self._post(
            "/v1/governance/credentials/checkout",
            {"credential_name": credential_name, "agent_id": agent_id},
        )

    def list_credentials(self) -> dict[str, Any]:
        """List stored credentials (names/metadata only — never values)."""
        return self._get("/v1/governance/credentials")

    @_requires_account_token
    def revoke_credential(self, credential_id: int) -> dict[str, Any]:
        """Revoke a stored credential by id."""
        return self._request(f"/v1/governance/credentials/{_path(credential_id)}", method="DELETE")

    def get_credential_checkout_history(
        self,
        *,
        credential_id: int | None = None,
        agent_id: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Get credential checkout audit history."""
        return self._get(
            "/v1/governance/credentials/history",
            query={"limit": limit, "credential_id": credential_id, "agent_id": agent_id or None},
        )

    @_requires_account_token
    def get_compliance_schedule(self) -> dict[str, Any]:
        """Get the scheduled compliance report delivery config."""
        return self._get("/v1/governance/compliance/schedule")

    @_requires_account_token
    def set_compliance_schedule(
        self,
        *,
        framework: str,
        email: str,
        frequency: str = "monthly",
    ) -> dict[str, Any]:
        """Configure scheduled compliance report delivery (eu-ai-act, soc2, iso42001, hipaa)."""
        return self._post(
            "/v1/governance/compliance/schedule",
            {"framework": framework, "frequency": frequency, "email": email},
        )

    @_requires_account_token
    def delete_compliance_schedule(self) -> dict[str, Any]:
        """Remove the scheduled compliance report delivery."""
        return self._request("/v1/governance/compliance/schedule", method="DELETE")

    def issue_reputation_passport(self, agent_id: str) -> dict[str, Any]:
        """Issue a signed Reputation Passport (W3C VC) for an agent."""
        return self._post(f"/v1/governance/passport/{_path(agent_id)}")

    def get_agent_reputation(self, agent_id: str) -> dict[str, Any]:
        """Get decay-weighted cross-provider reputation for an agent."""
        return self._get(f"/v1/governance/reputation/{_path(agent_id)}")

    # --- Internal ---

    def _get(self, path: str, *, query: dict[str, Any] | None = None) -> Any:
        """Convenience wrapper for GET requests."""
        return self._request(path, method="GET", query=query)

    def _post(self, path: str, body: Any = None) -> Any:
        """Convenience wrapper for POST requests."""
        return self._request(path, method="POST", body=body)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
        }
        if self.api_key:
            headers["x-api-key"] = self.api_key
        if self.account_token:
            headers["x-account-access-token"] = self.account_token
        return headers

    def _request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: Any = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        encoded = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            f"{self.base_url}{_with_query(path, query)}",
            data=encoded,
            method=method,
            headers=self._headers(),
        )
        status, raw_bytes = self._send(request)
        # Cap the read at 10 MiB. A compromised or MITM'd endpoint
        # returning a multi-hundred-MB body would otherwise OOM the
        # customer's process. Real API responses are well under this cap.
        if len(raw_bytes) > _MAX_RESPONSE_BYTES:
            raise VeriSwarmClientError(
                f"VeriSwarm response exceeded {_MAX_RESPONSE_BYTES} bytes",
                status=status,
                code="RESPONSE_TOO_LARGE",
            )
        if not raw_bytes:
            return {}
        try:
            return json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise VeriSwarmClientError(
                "VeriSwarm API returned invalid JSON", status=status, code="INVALID_RESPONSE"
            ) from exc

    def _send(self, request: Request) -> tuple[int, bytes]:
        """Perform the request; every transport failure becomes VeriSwarmClientError."""
        try:
            with _OPENER.open(request, timeout=self.timeout_seconds) as response:
                raw_bytes = response.read(_MAX_RESPONSE_BYTES + 1)
                return getattr(response, "status", 200), raw_bytes
        except HTTPError as exc:
            # Cap embedded details. Some logging frameworks emit
            # exception messages to structured aggregators; an unbounded
            # server response embedded here can leak request context
            # into customer log pipelines. (Audit 2026-05-08 MED-SDK-1.)
            details = ""
            try:
                raw_details = exc.read(4096).decode("utf-8", errors="replace")
                details = raw_details[:500]
            except Exception:
                details = str(exc)[:500]
            raise VeriSwarmClientError(
                f"VeriSwarm API {exc.code}: {details}", status=exc.code
            ) from exc
        except URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise self._timeout_error() from exc
            raise VeriSwarmClientError(
                f"VeriSwarm request failed: {exc.reason}", code="NETWORK_ERROR"
            ) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise self._timeout_error() from exc
        except (OSError, HTTPException) as exc:
            raise VeriSwarmClientError(
                f"VeriSwarm request failed: {exc}", code="NETWORK_ERROR"
            ) from exc

    def _timeout_error(self) -> VeriSwarmClientError:
        return VeriSwarmClientError(
            f"VeriSwarm request timed out after {self.timeout_seconds}s", code="TIMEOUT"
        )
