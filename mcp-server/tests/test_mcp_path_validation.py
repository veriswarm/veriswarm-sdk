import asyncio
import json
from unittest.mock import patch

from veriswarm_mcp.client import VeriSwarmAPIClient
from veriswarm_mcp.tools import agents, compliance_and_sre, passport, runtime, workflows


def _get_tools(module, client):
    captured = {}

    class FakeServer:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn

            return deco

    module.register(FakeServer(), client)
    return captured


def _client():
    return VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")


def test_passport_verify_identity_rejects_route_escape_before_posting():
    client = _client()
    tools = _get_tools(passport, client)

    with patch.object(client, "post", side_effect=AssertionError("post called")) as post:
        out = asyncio.run(tools["verify_identity"]("../../guard/unkill/agt_victim"))

    parsed = json.loads(out)
    assert parsed["type"] == "ToolValidationError"
    post.assert_not_called()


def test_workflow_template_id_is_single_quoted_path_segment():
    client = _client()
    tools = _get_tools(workflows, client)

    with patch.object(client, "post", return_value={"ok": True}) as post:
        out = asyncio.run(tools["deploy_template"]("builtin:content-pipeline-v2"))

    assert json.loads(out) == {"ok": True}
    post.assert_called_once_with(
        "/v1/workflows/templates/builtin%3Acontent-pipeline-v2/deploy"
    )


def test_workflow_template_id_rejects_dot_dot_segment():
    client = _client()
    tools = _get_tools(workflows, client)

    with patch.object(client, "post", side_effect=AssertionError("post called")) as post:
        out = asyncio.run(tools["deploy_template"](".."))

    parsed = json.loads(out)
    assert parsed["type"] == "ToolValidationError"
    post.assert_not_called()


def test_sre_provider_model_are_single_quoted_path_segments():
    client = _client()
    tools = _get_tools(compliance_and_sre, client)

    with patch.object(client, "post", return_value={"ok": True}) as post:
        out = asyncio.run(tools["reset_circuit_breaker"]("openai", "family/model"))

    assert json.loads(out) == {"ok": True}
    post.assert_called_once_with(
        "/v1/analytics/sre/circuit-breakers/openai/family%2Fmodel/reset"
    )


def test_abac_set_agent_attributes_rejects_route_escape_before_putting():
    client = _client()
    tools = _get_tools(compliance_and_sre, client)

    with patch.object(client, "put", side_effect=AssertionError("put called")) as put:
        out = asyncio.run(tools["set_agent_attributes"]("../../guard/unkill/agt_victim", "{}"))

    parsed = json.loads(out)
    assert parsed["type"] == "ToolValidationError"
    put.assert_not_called()


def test_agent_lookup_rejects_route_escape_before_getting():
    client = _client()
    tools = _get_tools(agents, client)

    with patch.object(client, "get", side_effect=AssertionError("get called")) as get:
        out = asyncio.run(tools["get_agent"]("../suite/guard/kill/agt_victim"))

    parsed = json.loads(out)
    assert parsed["type"] == "ToolValidationError"
    get.assert_not_called()


def test_runtime_agent_analytics_rejects_route_escape_before_getting():
    client = _client()
    tools = _get_tools(runtime, client)

    with patch.object(client, "get", side_effect=AssertionError("get called")) as get:
        out = asyncio.run(tools["get_agent_analytics"]("../guard/kill/agt_victim"))

    parsed = json.loads(out)
    assert parsed["type"] == "ToolValidationError"
    get.assert_not_called()
