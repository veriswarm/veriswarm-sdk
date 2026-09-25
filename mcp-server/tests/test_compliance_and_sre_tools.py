import asyncio
import json
from unittest.mock import patch

from veriswarm_mcp.client import VeriSwarmAPIClient
from veriswarm_mcp.tools import compliance_and_sre


def _get_tools(client):
    captured = {}

    class FakeServer:
        def tool(self):
            def deco(fn):
                captured[fn.__name__] = fn
                return fn

            return deco

    compliance_and_sre.register(FakeServer(), client)
    return captured


def test_provision_a2a_keys_posts_to_validated_agent_path():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    tools = _get_tools(client)

    with patch.object(client, "post", return_value={"public_key": "pub"}) as post:
        out = asyncio.run(tools["provision_a2a_keys"]("agt_valid-1"))

    assert json.loads(out) == {"public_key": "pub"}
    post.assert_called_once_with("/v1/a2a/agt_valid-1/keys")


def test_provision_a2a_keys_rejects_path_escape_before_posting():
    client = VeriSwarmAPIClient("https://api.veriswarm.ai", api_key="k")
    tools = _get_tools(client)

    with patch.object(client, "post", side_effect=AssertionError("post called")) as post:
        out = asyncio.run(tools["provision_a2a_keys"]("../admin"))

    parsed = json.loads(out)
    assert "error" in parsed
    assert parsed["type"] == "ToolValidationError"
    post.assert_not_called()
