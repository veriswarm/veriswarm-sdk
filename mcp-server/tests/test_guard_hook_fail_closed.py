from __future__ import annotations

import importlib
import io
import json
import sys

import pytest

GH = "ghp_" + "A" * 36


def _reload_hook(monkeypatch, *, enabled: bool, api_key: str = "test-key"):
    if api_key:
        monkeypatch.setenv("VERISWARM_API_KEY", api_key)
    else:
        monkeypatch.delenv("VERISWARM_API_KEY", raising=False)
    monkeypatch.setenv(
        "GUARD_SECRETS_DETECTION", "1" if enabled else ""
    )
    monkeypatch.delenv("VERISWARM_API_URL", raising=False)
    import veriswarm_mcp.hooks.guard_hook as gh

    return importlib.reload(gh)


def test_prefix_hit_redacts_when_tokenize_fails(monkeypatch):
    gh = _reload_hook(monkeypatch, enabled=True)
    monkeypatch.setattr(gh, "_tokenize", lambda text: None)
    out = gh.apply_secret_tripwire("token " + GH)
    assert out == "token [VS:GITHUB_TOKEN:offline]"


def test_no_hit_passthrough(monkeypatch):
    gh = _reload_hook(monkeypatch, enabled=True)
    monkeypatch.setattr(gh, "_tokenize", lambda text: None)
    clean = "the quick brown fox jumps"
    assert gh.apply_secret_tripwire(clean) == clean


def test_disabled_is_passthrough(monkeypatch):
    gh = _reload_hook(monkeypatch, enabled=False)
    monkeypatch.setattr(gh, "_tokenize", lambda text: None)
    assert gh.apply_secret_tripwire("token " + GH) == "token " + GH


def test_prefix_hit_uses_tokenize_when_online(monkeypatch):
    gh = _reload_hook(monkeypatch, enabled=True)

    def _ok(text):
        return {
            "tokens_created": 1,
            "tokenized_text": "token [VS_TOKEN_1]",
            "token_manifest": [{"type": "GITHUB_TOKEN"}],
        }

    monkeypatch.setattr(gh, "_tokenize", _ok)
    out = gh.apply_secret_tripwire("token " + GH)
    assert out == "token [VS_TOKEN_1]"


def test_pre_tool_redacts_secret_without_api_key(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HOME", str(tmp_path))
    gh = _reload_hook(monkeypatch, enabled=True, api_key="")
    monkeypatch.setattr(gh, "_tokenize", lambda text: None)

    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "mcp__github__create_issue",
        "tool_input": {"body": "token " + GH},
    }
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    with pytest.raises(SystemExit) as exc:
        gh.main()

    assert exc.value.code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["hookSpecificOutput"]["updatedInput"]["body"] == (
        "token [VS:GITHUB_TOKEN:offline]"
    )


def test_pre_tool_use_redacts_nested_tool_arguments(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, enabled=True)
    monkeypatch.setattr(gh, "_tokenize", lambda text: None)

    event = {
        "tool_name": "mcp__vault__write_secret",
        "tool_input": {
            "headers": {"authorization": "Bearer " + GH},
            "payloads": [{"token": GH}],
            "unchanged": "safe",
        },
    }

    with pytest.raises(SystemExit) as exc:
        gh.handle_pre_tool_use(event)

    assert exc.value.code == 0
    output = json.loads(capsys.readouterr().out)
    updated = output["hookSpecificOutput"]["updatedInput"]
    assert updated["headers"]["authorization"] == "Bearer [VS:GITHUB_TOKEN:offline]"
    assert updated["payloads"][0]["token"] == "[VS:GITHUB_TOKEN:offline]"
    assert updated["unchanged"] == "safe"


def test_guard_hook_disables_api_calls_for_external_http(monkeypatch):
    monkeypatch.setenv("VERISWARM_API_URL", "http://api.veriswarm.ai")
    monkeypatch.setenv("VERISWARM_API_KEY", "key123")

    import veriswarm_mcp.hooks.guard_hook as gh

    gh = importlib.reload(gh)
    assert gh.API_URL == ""
    assert gh.API_KEY == ""


def test_guard_hook_allows_localhost_http_for_dev(monkeypatch):
    monkeypatch.setenv("VERISWARM_API_URL", "http://localhost:8000/")
    monkeypatch.setenv("VERISWARM_API_KEY", "key123")

    import veriswarm_mcp.hooks.guard_hook as gh

    gh = importlib.reload(gh)
    assert gh.API_URL == "http://localhost:8000"
    assert gh.API_KEY == "key123"


def test_activity_reporter_drops_keys_for_external_http(monkeypatch, tmp_path):
    # Isolate from a developer's real ~/.veriswarm/env, which _load_config()
    # falls back to whenever the agent key is unset.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VERISWARM_API_URL", "http://api.veriswarm.ai")
    monkeypatch.setenv("VERISWARM_API_KEY", "key123")
    monkeypatch.delenv("VERISWARM_AGENT_KEY", raising=False)

    import veriswarm_mcp.hooks.activity_reporter as ar

    api_url, api_key, _agent_id, agent_key = ar._load_config()
    assert api_url == ""
    assert api_key == ""
    assert agent_key == ""


def test_activity_reporter_allows_localhost_http_for_dev(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VERISWARM_API_URL", "http://127.0.0.1:8787/")
    monkeypatch.setenv("VERISWARM_API_KEY", "key123")
    monkeypatch.delenv("VERISWARM_AGENT_KEY", raising=False)

    import veriswarm_mcp.hooks.activity_reporter as ar

    api_url, api_key, _agent_id, _agent_key = ar._load_config()
    assert api_url == "http://127.0.0.1:8787"
    assert api_key == "key123"
