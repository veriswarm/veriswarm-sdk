"""PreToolUse PII tokenization fails closed.

When the PII scan of MCP tool arguments cannot complete (API error,
malformed response, stalled server, exhausted time budget), the tool call
is blocked (exit 2, reason on stderr) instead of running with raw PII.
GUARD_PII_FAIL_OPEN=1 restores the old pass-through behaviour.
"""
from __future__ import annotations

import json
import time

import pytest

from test_guard_hook_contract import (  # noqa: F401 — stalling_api is a fixture
    BUDGET,
    GH,
    _event,
    _output,
    _reload_hook,
    _run_main,
    _timed_main,
    stalling_api,
)

PII_ARGS = {"body": "contact a@b.com please"}


class _Resp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._body


def _assert_blocked(code, capsys):
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out.strip() == ""  # no updatedInput: the call does not run
    assert "PII" in captured.err
    assert "GUARD_PII_FAIL_OPEN" in captured.err
    assert "a@b.com" not in captured.err


def test_blocks_when_api_returns_an_error(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh.httpx, "post", lambda *a, **k: _Resp(500, {"detail": "boom"}))

    _assert_blocked(_run_main(gh, monkeypatch, _event("PreToolUse", tool_input=PII_ARGS)), capsys)


def test_blocks_when_api_is_unreachable(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)

    def _down(*a, **k):
        raise gh.httpx.ConnectError("refused")

    monkeypatch.setattr(gh.httpx, "post", _down)

    _assert_blocked(_run_main(gh, monkeypatch, _event("PreToolUse", tool_input=PII_ARGS)), capsys)


@pytest.mark.parametrize("body", [
    ["not", "a", "dict"],
    {"tokens_created": "1"},
    {"tokens_created": 1},  # no tokenized_text
])
def test_blocks_on_malformed_tokenize_response(monkeypatch, capsys, body):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh.httpx, "post", lambda *a, **k: _Resp(200, body))

    _assert_blocked(_run_main(gh, monkeypatch, _event("PreToolUse", tool_input=PII_ARGS)), capsys)


def test_blocks_when_budget_is_exhausted(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "HOOK_BUDGET_SECONDS", gh.MIN_API_BUDGET / 2)

    def _no_api(*a, **k):
        raise AssertionError("API called with no budget left")

    monkeypatch.setattr(gh, "_post_within", _no_api)

    _assert_blocked(_run_main(gh, monkeypatch, _event("PreToolUse", tool_input=PII_ARGS)), capsys)


def test_blocks_within_budget_when_api_stalls(monkeypatch, capsys, stalling_api):
    gh = _reload_hook(monkeypatch)
    fields = {"secret": "token " + GH, **{f"f{i}": f"value number {i}" for i in range(5)}}

    code, elapsed = _timed_main(gh, monkeypatch, _event("PreToolUse", tool_input=fields))

    assert elapsed < BUDGET + 0.5
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out.strip() == ""
    assert GH not in captured.err


def test_fail_open_opt_out_lets_the_call_proceed_with_secrets_redacted(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False, env={"GUARD_PII_FAIL_OPEN": "1"})
    monkeypatch.setattr(gh.httpx, "post", lambda *a, **k: _Resp(500, {}))

    args = {"body": "contact a@b.com please", "key": "token " + GH}
    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input=args))

    captured = capsys.readouterr()
    assert code == 0
    updated = json.loads(captured.out)["hookSpecificOutput"]["updatedInput"]
    assert updated == {"body": "contact a@b.com please", "key": "token [VS:GITHUB_TOKEN:offline]"}
    assert "GUARD_PII_FAIL_OPEN" in captured.err  # visible notice that PII went unscanned


def test_fail_open_is_off_by_default(monkeypatch):
    gh = _reload_hook(monkeypatch)
    assert gh.PII_FAIL_OPEN is False


def test_without_api_key_pii_scan_is_not_attempted(monkeypatch, capsys):
    """No API key means PII scanning is not configured (same as PostToolUse);
    secrets are still redacted locally."""
    gh = _reload_hook(monkeypatch, api_key="")

    def _no_network(*a, **k):
        raise AssertionError("network call")

    monkeypatch.setattr(gh.httpx, "post", _no_network)

    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"body": "a@b.com", "k": GH}))

    assert code == 0
    assert _output(capsys)["hookSpecificOutput"]["updatedInput"] == {
        "body": "a@b.com", "k": "[VS:GITHUB_TOKEN:offline]",
    }


def test_successful_scan_still_tokenizes(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)

    def _post(url, json=None, headers=None, timeout=None):
        text = json["text"]
        if "a@b.com" not in text:
            return _Resp(200, {"tokens_created": 0})
        return _Resp(200, {
            "tokens_created": 1,
            "tokenized_text": text.replace("a@b.com", "[VS:EMAIL:abc]"),
            "token_manifest": [{"type": "EMAIL"}],
        })

    monkeypatch.setattr(gh.httpx, "post", _post)

    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input=PII_ARGS))

    assert code == 0
    assert _output(capsys)["hookSpecificOutput"]["updatedInput"] == {"body": "contact [VS:EMAIL:abc] please"}
