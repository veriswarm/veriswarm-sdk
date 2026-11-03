"""Account session-token auth: header wiring and local fail-fast for session-only routes."""
from __future__ import annotations

import pytest

from veriswarm import VeriSwarmClient, VeriSwarmClientError
from veriswarm.client import _StripAuthRedirectHandler

BASE = "https://api.test"

# Every method whose server route accepts ONLY x-account-access-token.
ACCOUNT_ONLY = {
    "get_scoring_profile": lambda c: c.get_scoring_profile(),
    "set_scoring_profile": lambda c: c.set_scoring_profile("general"),
    "list_notifications": lambda c: c.list_notifications(),
    "mark_notification_read": lambda c: c.mark_notification_read(1),
    "mark_all_notifications_read": lambda c: c.mark_all_notifications_read(),
    "get_ip_allowlist": lambda c: c.get_ip_allowlist(),
    "set_ip_allowlist": lambda c: c.set_ip_allowlist(cidrs=["10.0.0.0/8"]),
    "get_custom_domain": lambda c: c.get_custom_domain(),
    "set_custom_domain": lambda c: c.set_custom_domain(domain="agents.example.com"),
    "verify_custom_domain": lambda c: c.verify_custom_domain(),
    "delete_custom_domain": lambda c: c.delete_custom_domain(),
    "list_team_members": lambda c: c.list_team_members(),
    "invite_team_member": lambda c: c.invite_team_member(email="a@example.com"),
    "remove_team_member": lambda c: c.remove_team_member("usr_1"),
    "list_workspaces": lambda c: c.list_workspaces(),
    "switch_workspace": lambda c: c.switch_workspace("ten_1"),
    "approve_approval": lambda c: c.approve_approval("apr_1"),
    "reject_approval": lambda c: c.reject_approval("apr_1"),
    "approve_jit_grant": lambda c: c.approve_jit_grant("jit_1"),
    "deny_jit_grant": lambda c: c.deny_jit_grant("jit_1"),
    "approve_step": lambda c: c.approve_step("exe_1", "step_1"),
    "store_credential": lambda c: c.store_credential(name="n", credential_type="api_key", value="v"),
    "revoke_credential": lambda c: c.revoke_credential(1),
    "run_shadow_discovery": lambda c: c.run_shadow_discovery(),
    "dismiss_discovered_agent": lambda c: c.dismiss_discovered_agent(1),
    "get_compliance_schedule": lambda c: c.get_compliance_schedule(),
    "set_compliance_schedule": lambda c: c.set_compliance_schedule(framework="eu-ai-act", email="a@example.com"),
    "delete_compliance_schedule": lambda c: c.delete_compliance_schedule(),
    "verify_agent_identity": lambda c: c.verify_agent_identity("agt_1"),
    "create_manifest": lambda c: c.create_manifest("agt_1", {"version": "1.0"}),
    "get_manifests": lambda c: c.get_manifests("agt_1"),
    "create_delegation": lambda c: c.create_delegation({"grantee_agent_id": "agt_2", "scopes": ["x"]}),
    "list_delegations": lambda c: c.list_delegations(),
    "revoke_delegation": lambda c: c.revoke_delegation(1),
    "export_vault": lambda c: c.export_vault(),
    "get_vault_export_status": lambda c: c.get_vault_export_status("job_1"),
    "revoke_pii_session": lambda c: c.revoke_pii_session("pii_1"),
    "update_guard_finding": lambda c: c.update_guard_finding(1, {"new_status": "resolved"}),
}

SCOPED_KEY_OR_SESSION = {
    "kill_agent": lambda c: c.kill_agent("agt_1", reason="compromised"),
    "unkill_agent": lambda c: c.unkill_agent("agt_1"),
    "list_guard_policies": lambda c: c.list_guard_policies(),
    "create_guard_policy": lambda c: c.create_guard_policy({"name": "p"}),
    "update_guard_policy": lambda c: c.update_guard_policy(1, {"is_active": False}),
    "delete_guard_policy": lambda c: c.delete_guard_policy(1),
}


def test_account_token_alone_is_a_valid_credential():
    c = VeriSwarmClient(base_url=BASE, account_token="acct_tok")
    assert c.account_token == "acct_tok"


def test_requires_at_least_one_credential():
    with pytest.raises(ValueError, match="api_key or account_token"):
        VeriSwarmClient(base_url=BASE)


def test_refuses_account_token_over_plain_http():
    with pytest.raises(ValueError, match="https"):
        VeriSwarmClient(base_url="http://api.test", account_token="t")


def test_positional_api_key_still_works():
    c = VeriSwarmClient(BASE, "vsk_x")
    assert c.api_key == "vsk_x"


@pytest.mark.parametrize("name", sorted(ACCOUNT_ONLY))
def test_account_only_methods_fail_locally_without_token(name, recorder):
    c = VeriSwarmClient(base_url=BASE, api_key="vsk_x")
    with pytest.raises(VeriSwarmClientError) as info:
        ACCOUNT_ONLY[name](c)
    assert info.value.code == "ACCOUNT_TOKEN_REQUIRED"
    assert name in str(info.value)
    assert "account_token" in str(info.value)
    assert recorder.requests == []


@pytest.mark.parametrize("name", sorted(ACCOUNT_ONLY))
def test_account_only_methods_send_session_header(name, recorder):
    c = VeriSwarmClient(base_url=BASE, account_token="acct_tok")
    ACCOUNT_ONLY[name](c)
    assert recorder.header("x-account-access-token") == "acct_tok"
    assert recorder.header("x-api-key") is None


@pytest.mark.parametrize("name", sorted(SCOPED_KEY_OR_SESSION))
def test_kill_and_policy_methods_send_api_key_without_local_error(name, recorder):
    c = VeriSwarmClient(base_url=BASE, api_key="vsk_x")
    SCOPED_KEY_OR_SESSION[name](c)
    assert recorder.header("x-api-key") == "vsk_x"
    assert recorder.header("x-account-access-token") is None


@pytest.mark.parametrize("name", sorted(SCOPED_KEY_OR_SESSION))
def test_kill_and_policy_methods_send_both_credentials(name, recorder):
    c = VeriSwarmClient(base_url=BASE, api_key="vsk_x", account_token="acct_tok")
    SCOPED_KEY_OR_SESSION[name](c)
    assert recorder.header("x-api-key") == "vsk_x"
    assert recorder.header("x-account-access-token") == "acct_tok"


def test_redirect_handler_strips_session_token():
    from urllib.request import Request

    handler = _StripAuthRedirectHandler()
    req = Request(
        "https://api.test/x",
        headers={"x-api-key": "k", "x-account-access-token": "t", "Accept": "a"},
    )
    new = handler.redirect_request(req, None, 302, "Found", {}, "https://evil.test/y")
    names = {k.lower() for k in new.headers}
    assert "x-account-access-token" not in names
    assert "x-api-key" not in names
