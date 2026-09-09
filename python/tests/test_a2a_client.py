from __future__ import annotations

from veriswarm.client import VeriSwarmClient


def _client() -> VeriSwarmClient:
    return VeriSwarmClient(base_url="https://example.invalid", api_key="test-key")


def test_a2a_catalog_and_card_use_expected_paths(monkeypatch):
    c = _client()
    captured_paths: list[str] = []

    def fake_get(self, path):
        captured_paths.append(path)
        return {"path": path}

    monkeypatch.setattr(VeriSwarmClient, "_get", fake_get)

    assert c.list_a2a_catalog() == {"path": "/v1/a2a/catalog"}
    assert c.get_a2a_agent_card("agt_../one two") == {
        "path": "/v1/a2a/agt_..%2Fone%20two/card"
    }
    assert captured_paths == [
        "/v1/a2a/catalog",
        "/v1/a2a/agt_..%2Fone%20two/card",
    ]


def test_submit_a2a_task_posts_snake_case_payload_and_omits_signature(monkeypatch):
    c = _client()
    captured: list[tuple[str, dict]] = []
    messages = [{"role": "user", "content": "start"}]

    def fake_post(self, path, body=None):
        captured.append((path, body or {}))
        return {"id": "a2a_task_1", "status": "submitted"}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)

    result = c.submit_a2a_task(
        "agt_receiver",
        requesting_agent_id="agt_sender",
        messages=messages,
    )

    assert result["id"] == "a2a_task_1"
    assert captured == [
        (
            "/v1/a2a/agt_receiver/tasks",
            {
                "requesting_agent_id": "agt_sender",
                "messages": messages,
            },
        )
    ]
    assert "signature" not in captured[0][1]


def test_submit_a2a_task_includes_signature_when_provided(monkeypatch):
    c = _client()
    captured: list[tuple[str, dict]] = []
    messages = [{"role": "user", "content": "signed task"}]
    signature = {"key_id": "key_1", "signature": "sig", "algo": "ed25519"}

    def fake_post(self, path, body=None):
        captured.append((path, body or {}))
        return {"id": "a2a_task_2", "status": "submitted"}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)

    c.submit_a2a_task(
        "agt_receiver",
        requesting_agent_id="agt_sender",
        messages=messages,
        signature=signature,
    )

    assert captured[0] == (
        "/v1/a2a/agt_receiver/tasks",
        {
            "requesting_agent_id": "agt_sender",
            "messages": messages,
            "signature": signature,
        },
    )


def test_get_and_cancel_a2a_task_encode_path_components(monkeypatch):
    c = _client()
    get_paths: list[str] = []
    post_paths: list[str] = []

    def fake_get(self, path):
        get_paths.append(path)
        return {"path": path}

    def fake_post(self, path, body=None):
        post_paths.append(path)
        return {"path": path, "status": "canceled"}

    monkeypatch.setattr(VeriSwarmClient, "_get", fake_get)
    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)

    c.get_a2a_task("agt/receiver", "a2a task/1")
    c.cancel_a2a_task("agt/receiver", "a2a task/1")

    encoded_task_path = "/v1/a2a/agt%2Freceiver/tasks/a2a%20task%2F1"
    assert get_paths == [encoded_task_path]
    assert post_paths == [f"{encoded_task_path}/cancel"]


def test_provision_a2a_keys_encodes_agent_id(monkeypatch):
    c = _client()
    captured_paths: list[str] = []

    def fake_post(self, path, body=None):
        captured_paths.append(path)
        return {"public_key": "pub"}

    monkeypatch.setattr(VeriSwarmClient, "_post", fake_post)

    assert c.provision_a2a_keys("agt/key owner") == {"public_key": "pub"}
    assert captured_paths == ["/v1/a2a/agt%2Fkey%20owner/keys"]
