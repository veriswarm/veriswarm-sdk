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
