"""Platform status tools for VeriSwarm MCP."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import call_api, safe_error_response


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def platform_status() -> str:
        """Check VeriSwarm platform health, uptime, and active feature flags."""
        try:
            result = await call_api(client.get, "/v1/public/status")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="platform_status")

    @server.tool()
    async def get_scoring_profile() -> str:
        """Get the current workspace's scoring profile and weight configuration.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = await call_api(client.get, "/v1/suite/scoring/profile")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_scoring_profile")

    @server.tool()
    async def set_scoring_profile(profile_code: str, weight_overrides: str = "") -> str:
        """Set the workspace's scoring profile.

        Requires session auth (x-account-access-token). Not available with API key only.

        profile_code: one of 'general', 'high_security', 'community', 'enterprise', 'minimal'
        weight_overrides: optional JSON string of custom weight overrides
        """
        try:
            body: dict = {"profile_code": profile_code}
            if weight_overrides:
                body["weight_overrides"] = json.loads(weight_overrides)
            result = await call_api(client.post, "/v1/suite/scoring/profile", json=body)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="set_scoring_profile")

    @server.tool()
    async def list_notifications(limit: int = 20) -> str:
        """List recent notifications for the workspace.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = await call_api(client.get, "/v1/suite/notifications", params={"limit": limit})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="list_notifications")

    @server.tool()
    async def get_ip_allowlist() -> str:
        """Get the current IP allowlist configuration for the workspace.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = await call_api(client.get, "/v1/public/providers/ip-allowlist")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_ip_allowlist")

    @server.tool()
    async def set_ip_allowlist(cidrs: str, enabled: bool = True) -> str:
        """Set the IP allowlist for the workspace.

        Requires session auth (x-account-access-token). Not available with API key only.

        cidrs: comma-separated list of CIDR ranges, e.g. '10.0.0.0/8,192.168.1.0/24'
        enabled: whether to enable the allowlist (default True)
        """
        try:
            cidr_str = ",".join(c.strip() for c in cidrs.split(",") if c.strip())
            if not enabled:
                cidr_str = ""
            result = await call_api(client.post, "/v1/public/providers/ip-allowlist", json={
                "ip_allowlist": cidr_str,
            })
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="set_ip_allowlist")

    @server.tool()
    async def get_custom_domain() -> str:
        """Get the custom domain configuration for the workspace.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = await call_api(client.get, "/v1/public/providers/custom-domain")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_custom_domain")

    @server.tool()
    async def set_custom_domain(domain: str) -> str:
        """Set a custom domain for the workspace.

        Requires session auth (x-account-access-token). Not available with API key only.

        domain: the custom domain, e.g. 'trust.mycompany.com'
        """
        try:
            result = await call_api(client.post, "/v1/public/providers/custom-domain", json={"domain": domain})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="set_custom_domain")

    @server.tool()
    async def list_team_members() -> str:
        """List team members in the current workspace.

        Requires session auth (x-account-access-token). Not available with API key only."""
        try:
            result = await call_api(client.get, "/v1/public/providers/team")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="list_team_members")

    @server.tool()
    async def invite_team_member(email: str, role: str = "member") -> str:
        """Invite a new team member to the workspace.

        Requires session auth (x-account-access-token). Not available with API key only.

        email: the email address to invite
        role: 'admin' or 'member' (default 'member')
        """
        try:
            result = await call_api(client.post, "/v1/public/providers/team/invite", json={
                "email": email,
                "role": role,
            })
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="invite_team_member")
