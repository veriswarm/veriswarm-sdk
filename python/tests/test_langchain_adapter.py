"""Tests for VeriSwarm LangChain adapter."""
import sys
import os
import uuid
from unittest.mock import MagicMock, patch
import pytest

# Ensure the sdk-python package root is on sys.path so that
# `veriswarm_client` and `adapters` are importable without installation.
_SDK_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SDK_ROOT not in sys.path:
    sys.path.insert(0, _SDK_ROOT)


def test_handler_instantiation():
    """Handler can be created with required params."""
    from adapters.langchain import VeriSwarmCallbackHandler
    handler = VeriSwarmCallbackHandler(api_key="test", agent_id="agt_test")
    assert handler.agent_id == "agt_test"
    assert handler.enforce is False


def test_on_tool_end_reports_event():
    """on_tool_end calls ingest_event with tool.call.success."""
    from adapters.langchain import VeriSwarmCallbackHandler
    handler = VeriSwarmCallbackHandler(api_key="test", agent_id="agt_test")
    handler._client = MagicMock()

    run_id = uuid.uuid4()
    handler._active_tools[str(run_id)] = 1000.0

    with patch("time.monotonic", return_value=1001.5):
        handler.on_tool_end("result", run_id=run_id, name="search")

    handler._client.ingest_event.assert_called_once()
    call_kwargs = handler._client.ingest_event.call_args
    assert call_kwargs[1]["event_type"] == "tool.call.success" or call_kwargs.kwargs.get("event_type") == "tool.call.success"


def test_on_tool_error_reports_failure():
    """on_tool_error calls ingest_event with tool.call.failure."""
    from adapters.langchain import VeriSwarmCallbackHandler
    handler = VeriSwarmCallbackHandler(api_key="test", agent_id="agt_test")
    handler._client = MagicMock()

    run_id = uuid.uuid4()
    handler.on_tool_error(ValueError("bad"), run_id=run_id, name="search")

    handler._client.ingest_event.assert_called_once()


def test_event_reporting_never_raises():
    """Event reporting failures are swallowed."""
    from adapters.langchain import VeriSwarmCallbackHandler
    handler = VeriSwarmCallbackHandler(api_key="test", agent_id="agt_test")
    handler._client = MagicMock()
    handler._client.ingest_event.side_effect = Exception("network error")

    # Should not raise
    handler._report_event("tool.call.success", {"tool_name": "test"})


def test_enforce_mode_blocks_denied():
    """Enforcement mode raises PermissionError on deny."""
    from adapters.langchain import VeriSwarmCallbackHandler
    handler = VeriSwarmCallbackHandler(api_key="test", agent_id="agt_test", enforce=True, on_deny="raise")
    handler._client = MagicMock()
    handler._client.check_decision.return_value = {"decision": "deny", "reason_code": "restricted"}

    with pytest.raises(PermissionError, match="denied"):
        handler.on_tool_start({"name": "dangerous_tool"}, "input", run_id=uuid.uuid4())
