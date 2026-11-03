"""Request shapes must match the server's route signatures."""
from __future__ import annotations

from urllib.parse import urlsplit

import pytest

from veriswarm import VeriSwarmClient

BASE = "https://api.test"


@pytest.fixture
def client() -> VeriSwarmClient:
    return VeriSwarmClient(base_url=BASE, api_key="vsk_x", account_token="acct")


def test_reputation_lookup_sends_agent_ref(client, recorder):
    client.reputation_lookup("my-agent@example.com")
    assert urlsplit(recorder.url).path == "/v1/public/reputation/lookup"
    assert recorder.query == {"agent_ref": ["my-agent@example.com"]}


def test_reputation_lookup_keeps_slug_keyword_alias(client, recorder):
    client.reputation_lookup(slug="my-agent")
    assert recorder.query == {"agent_ref": ["my-agent"]}


def test_update_guard_policy_sends_is_active_query_without_body(client, recorder):
    client.update_guard_policy(7, is_active=False)
    assert recorder.last.get_method() == "PATCH"
    assert urlsplit(recorder.url).path == "/v1/suite/guard/policies/7"
    assert recorder.query == {"is_active": ["false"]}
    assert recorder.last.data is None


def test_update_guard_policy_accepts_updates_dict(client, recorder):
    client.update_guard_policy(7, {"is_active": True})
    assert recorder.query == {"is_active": ["true"]}


def test_update_guard_policy_rejects_non_boolean(client, recorder):
    with pytest.raises(ValueError, match="is_active"):
        client.update_guard_policy(7, {"enabled": False})
    assert recorder.requests == []


def test_update_guard_finding_sends_new_status_query_without_body(client, recorder):
    client.update_guard_finding(3, new_status="resolved")
    assert recorder.last.get_method() == "PATCH"
    assert urlsplit(recorder.url).path == "/v1/suite/guard/findings/3"
    assert recorder.query == {"new_status": ["resolved"]}
    assert recorder.last.data is None


@pytest.mark.parametrize("updates", [{"new_status": "mitigated"}, {"status": "mitigated"}])
def test_update_guard_finding_accepts_updates_dict(client, recorder, updates):
    client.update_guard_finding(3, updates)
    assert recorder.query == {"new_status": ["mitigated"]}


def test_update_guard_finding_rejects_missing_status(client, recorder):
    with pytest.raises(ValueError, match="new_status"):
        client.update_guard_finding(3, {})
    assert recorder.requests == []


def test_set_ip_allowlist_sends_server_string(client, recorder):
    client.set_ip_allowlist(cidrs=["10.0.0.0/8", " 192.168.1.0/24 "])
    assert recorder.json_body == {"ip_allowlist": "10.0.0.0/8,192.168.1.0/24"}


def test_set_ip_allowlist_accepts_comma_string(client, recorder):
    client.set_ip_allowlist(cidrs="10.0.0.0/8, 172.16.0.0/12")
    assert recorder.json_body == {"ip_allowlist": "10.0.0.0/8,172.16.0.0/12"}


@pytest.mark.parametrize("cidrs", [[], "", " , ", None])
def test_set_ip_allowlist_refuses_empty_list_while_enabled(client, recorder, cidrs):
    with pytest.raises(ValueError, match="enabled=False"):
        client.set_ip_allowlist(cidrs=cidrs)
    assert recorder.requests == []


def test_set_ip_allowlist_disables_only_when_explicit(client, recorder):
    client.set_ip_allowlist(cidrs=["10.0.0.0/8"], enabled=False)
    assert recorder.json_body == {"ip_allowlist": ""}


def test_reputation_lookup_rejects_empty_reference(client, recorder):
    with pytest.raises(ValueError, match="agent_ref"):
        client.reputation_lookup("")
    assert recorder.requests == []
