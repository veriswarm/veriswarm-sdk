"""Guard hook behaviour against the real Claude Code hook contract.

Event shapes follow the Claude Code hooks reference: common fields
(session_id, transcript_path, cwd, permission_mode, hook_event_name),
PreToolUse `tool_input`, PostToolUse `tool_response`, and decision output
under `hookSpecificOutput` with `hookEventName`.
"""
from __future__ import annotations

import importlib
import io
import json
import sys

import pytest

GH = "ghp_" + "A" * 36

PII_RESULT = {
    "tokens_created": 1,
    "tokenized_text": "contact [VS:EMAIL:abc123]",
    "token_manifest": [{"type": "EMAIL"}],
}


def _fake_pii_tokenizer(text, **k):
    """Behaves like the real tokenizer: only strings containing PII change."""
    if "a@b.com" not in text:
        return None
    return dict(PII_RESULT, tokenized_text=text.replace("a@b.com", "[VS:EMAIL:abc123]"))


def _reload_hook(
    monkeypatch, *, secrets: bool = True, api_key: str = "test-key",
    exempt: str | None = None, env: dict | None = None,
):
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)
    if api_key:
        monkeypatch.setenv("VERISWARM_API_KEY", api_key)
    monkeypatch.setenv("GUARD_SECRETS_DETECTION", "1" if secrets else "")
    if exempt is not None:
        monkeypatch.setenv("GUARD_PII_EXEMPT_PREFIXES", exempt)
    import veriswarm_mcp.hooks.guard_hook as gh

    gh = importlib.reload(gh)
    monkeypatch.setattr(gh, "log_pii_detected", lambda *a, **k: None)
    monkeypatch.setattr(gh, "log_session_start", lambda *a, **k: None)
    return gh


def _event(hook: str, tool_name="mcp__github__create_issue", **fields) -> dict:
    base = {
        "session_id": "sess-123",
        "transcript_path": "/tmp/transcript.jsonl",
        "cwd": "/work",
        "permission_mode": "default",
        "hook_event_name": hook,
        "tool_name": tool_name,
        "tool_use_id": "toolu_01ABC",
    }
    base.update(fields)
    return base


def _run_main(gh, monkeypatch, stdin) -> int:
    if isinstance(stdin, bytes):
        stream = io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")
    else:
        stream = io.StringIO(stdin if isinstance(stdin, str) else json.dumps(stdin))
    monkeypatch.setattr(sys, "stdin", stream)
    with pytest.raises(SystemExit) as exc:
        gh.main()
    return exc.value.code or 0


def _output(capsys) -> dict | None:
    out = capsys.readouterr().out.strip()
    return json.loads(out) if out else None


# ── PreToolUse decision shape ────────────────────────────────────────

def test_pre_tool_use_modifies_input_without_auto_approving(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "_tokenize", _fake_pii_tokenizer)

    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"body": "contact a@b.com"}))

    out = _output(capsys)["hookSpecificOutput"]
    assert code == 0
    assert out["hookEventName"] == "PreToolUse"
    assert out["updatedInput"] == {"body": "contact [VS:EMAIL:abc123]"}
    # "allow" would skip the user's permission prompt for the call.
    assert out.get("permissionDecision") != "allow"
    assert out["permissionDecision"] == "ask"


# ── Fail-closed after a secret is found ──────────────────────────────

def test_secret_still_redacted_when_pii_manifest_is_malformed(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)
    # Tokenizer "succeeds" but returns a manifest entry without "type".
    monkeypatch.setattr(
        gh, "_tokenize",
        lambda text, **k: {"tokens_created": 1, "tokenized_text": text, "token_manifest": [{}]},
    )

    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"body": "token " + GH}))

    assert code == 0
    updated = _output(capsys)["hookSpecificOutput"]["updatedInput"]
    assert updated["body"] == "token [VS:GITHUB_TOKEN:offline]"


def test_secret_still_redacted_when_pii_tokenizer_raises(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)
    calls = {"n": 0}

    def _tokenize(text, **k):
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("tokenizer exploded")
        return None

    monkeypatch.setattr(gh, "_tokenize", _tokenize)

    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"body": "token " + GH}))

    assert code == 0
    assert _output(capsys)["hookSpecificOutput"]["updatedInput"]["body"] == "token [VS:GITHUB_TOKEN:offline]"


def test_secrets_in_dict_keys_are_redacted(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)
    monkeypatch.setattr(gh, "_tokenize", lambda text, **k: None)

    event = _event("PreToolUse", tool_input={GH: "v", "outer": {"inner": {GH: [GH]}}})
    code = _run_main(gh, monkeypatch, event)

    assert code == 0
    updated = _output(capsys)["hookSpecificOutput"]["updatedInput"]
    assert GH not in json.dumps(updated)
    assert updated["[VS:GITHUB_TOKEN:offline]"] == "v"
    assert updated["outer"]["inner"]["[VS:GITHUB_TOKEN:offline]"] == ["[VS:GITHUB_TOKEN:offline]"]


# ── Malformed stdin ──────────────────────────────────────────────────

@pytest.mark.parametrize("stdin", [
    "[]",
    "null",
    "not json",
    {"hook_event_name": "PreToolUse", "tool_name": None, "tool_input": {"a": "hello"}},
    {"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y", "tool_input": "a string"},
    {"hook_event_name": None},
    {"hook_event_name": "PostToolUse", "tool_name": None, "tool_response": "x" * 10},
    b"\xff\xfe{not utf-8",
])
def test_malformed_stdin_exits_zero_without_output(monkeypatch, capsys, stdin):
    gh = _reload_hook(monkeypatch)
    monkeypatch.setattr(gh, "_tokenize", lambda text, **k: None)

    assert _run_main(gh, monkeypatch, stdin) == 0
    assert _output(capsys) is None


@pytest.mark.parametrize("stdin", [
    b"\xff\xfe" + json.dumps({"tool_input": {"body": GH}}).encode(),
    {"hook_event_name": "PreToolUse", "tool_name": None, "tool_input": {"body": GH}},
    {"hook_event_name": "PreToolUse", "tool_name": "mcp__x__y", "tool_input": "raw " + GH},
])
def test_malformed_stdin_carrying_a_secret_is_blocked(monkeypatch, capsys, stdin):
    gh = _reload_hook(monkeypatch)
    monkeypatch.setattr(gh, "_tokenize", lambda text, **k: None)

    assert _run_main(gh, monkeypatch, stdin) == 2
    assert GH not in capsys.readouterr().err


def test_unexpected_crash_with_secret_blocks(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)

    def _boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(gh, "_guard_strings", _boom)

    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"body": "token " + GH}))

    assert code == 2


# ── Overall deadline ─────────────────────────────────────────────────

def test_total_api_time_is_bounded_by_the_hook_deadline(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    clock = {"now": 1000.0}
    monkeypatch.setattr(gh.time, "monotonic", lambda: clock["now"])
    timeouts = []

    def _slow_post(url, json=None, headers=None, timeout=None):
        timeouts.append(timeout)
        clock["now"] += timeout  # every call runs to its timeout
        raise gh.httpx.TimeoutException("slow")

    monkeypatch.setattr(gh.httpx, "post", _slow_post)

    fields = {f"f{i}": f"value number {i}" for i in range(40)}
    code = _run_main(gh, monkeypatch, _event("PreToolUse", tool_input=fields))

    assert code == 0
    assert sum(timeouts) <= gh.HOOK_BUDGET_SECONDS
    assert gh.HOOK_BUDGET_SECONDS < 10  # hook entries are installed with timeout: 10


# ── PostToolUse contract ─────────────────────────────────────────────

@pytest.mark.parametrize("field", ["tool_response", "tool_result"])
def test_post_tool_use_replaces_output_with_tokenized_values(monkeypatch, capsys, field):
    gh = _reload_hook(monkeypatch)
    monkeypatch.setattr(gh, "_tokenize_strict", _fake_pii_tokenizer)
    response = {"content": [{"type": "text", "text": "mail a@b.com now"}], "isError": False}

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_input={"q": "x"}, **{field: response}))

    assert code == 0
    out = _output(capsys)
    assert "additionalContext" not in out
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PostToolUse"
    assert hso["updatedToolOutput"] == {
        "content": [{"type": "text", "text": "mail [VS:EMAIL:abc123] now"}], "isError": False,
    }
    assert "PII" in hso["additionalContext"]


def test_post_tool_use_without_pii_leaves_output_alone(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)
    monkeypatch.setattr(gh, "_tokenize_strict", _fake_pii_tokenizer)

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_response="nothing personal here"))

    assert code == 0
    assert _output(capsys) is None


@pytest.mark.parametrize("response", ["contact a@b.com please", [{"type": "text", "text": "a@b.com"}]])
def test_post_tool_use_withholds_output_when_pii_scan_cannot_complete(monkeypatch, capsys, response):
    gh = _reload_hook(monkeypatch)

    def _unavailable(text, **k):
        raise gh.ScanUnavailable("down")

    monkeypatch.setattr(gh, "_tokenize_strict", _unavailable)

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_response=response))

    assert code == 0
    raw = json.dumps(_output(capsys))
    assert "a@b.com" not in raw
    assert "withheld" in raw


def test_post_tool_use_withholds_on_malformed_tokenize_response(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"tokens_created": 2, "token_manifest": [{}, "x"]}  # no tokenized_text

    monkeypatch.setattr(gh.httpx, "post", lambda *a, **k: _Resp())

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_response="contact a@b.com please"))

    assert code == 0
    assert "withheld" in json.dumps(_output(capsys))


def test_post_tool_use_redacts_secrets_offline_without_api(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, api_key="")

    def _no_network(*a, **k):
        raise AssertionError("network call")

    monkeypatch.setattr(gh.httpx, "post", _no_network)

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_response={"token": "key " + GH}))

    assert code == 0
    assert _output(capsys)["hookSpecificOutput"]["updatedToolOutput"] == {
        "token": "key [VS:GITHUB_TOKEN:offline]",
    }


# ── PII exemption (opt-in) ───────────────────────────────────────────

def test_no_tools_are_pii_exempt_by_default(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "_tokenize", _fake_pii_tokenizer)

    _run_main(gh, monkeypatch, _event("PreToolUse", tool_name="mcp__notes__save", tool_input={"body": "contact a@b.com"}))

    assert gh.PII_EXEMPT_PREFIXES == ()
    assert _output(capsys)["hookSpecificOutput"]["updatedInput"]["body"] == "contact [VS:EMAIL:abc123]"


def test_exempt_tool_skips_pii_but_still_redacts_secrets(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, exempt=" mcp__mystore__ , ")
    calls = []

    def _tokenize(text, **k):
        calls.append(text)
        return None

    monkeypatch.setattr(gh, "_tokenize", _tokenize)

    event = _event(
        "PreToolUse", tool_name="mcp__mystore__save",
        tool_input={"note": "Alice Smith, alice@example.com", "key": "token " + GH},
    )
    code = _run_main(gh, monkeypatch, event)

    assert code == 0
    updated = _output(capsys)["hookSpecificOutput"]["updatedInput"]
    assert updated["note"] == "Alice Smith, alice@example.com"
    assert updated["key"] == "token [VS:GITHUB_TOKEN:offline]"
    # Only the secret-bearing value reached the tokenizer (tripwire path).
    assert calls == ["token " + GH]


def test_exempt_tool_gets_no_post_tool_use_pii_warning(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, exempt="mcp__mystore__")
    monkeypatch.setattr(gh, "_tokenize", lambda text, **k: dict(PII_RESULT))

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_name="mcp__mystore__get", tool_response="a@b.com here"))

    assert code == 0
    assert _output(capsys) is None


# ── Session id from the hook payload ─────────────────────────────────

def test_session_start_uses_payload_session_id(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)
    seen = {}
    monkeypatch.setattr(gh, "log_session_start", lambda **kw: seen.update(kw))

    _run_main(gh, monkeypatch, _event("SessionStart", source="startup"))

    assert seen["session_id"] == "sess-123"


# ── UserPromptSubmit ─────────────────────────────────────────────────

def _prompt_event(prompt):
    return _event("UserPromptSubmit", tool_name=None, prompt=prompt)


def test_prompt_with_secret_is_always_blocked_without_echoing_it(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False, api_key="")

    code = _run_main(gh, monkeypatch, _prompt_event("deploy with " + GH))

    out = _output(capsys)
    assert code == 0
    assert out["decision"] == "block"
    assert "secret" in out["reason"]
    assert out["hookSpecificOutput"] == {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": True}
    assert GH not in json.dumps(out)


def test_prompt_blocked_when_secret_tripwire_unavailable(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False, api_key="")
    monkeypatch.setattr(gh, "_get_tripwire", lambda: None)

    _run_main(gh, monkeypatch, _prompt_event("hello there"))

    assert _output(capsys)["decision"] == "block"


def test_prompt_with_pii_is_blocked_by_default(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "_tokenize_strict", _fake_pii_tokenizer)

    _run_main(gh, monkeypatch, _prompt_event("email a@b.com about it"))

    out = _output(capsys)
    assert out["decision"] == "block"
    assert "EMAIL" in out["reason"]
    assert "a@b.com" not in json.dumps(out)


def test_prompt_pii_allowed_when_blocking_turned_off(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False, env={"GUARD_BLOCK_PROMPT_PII": "0"})

    def _not_called(text, **k):
        raise AssertionError("PII scan should be skipped")

    monkeypatch.setattr(gh, "_tokenize_strict", _not_called)

    assert _run_main(gh, monkeypatch, _prompt_event("email a@b.com about it")) == 0
    assert _output(capsys) is None


def test_clean_prompt_passes_silently(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "_tokenize_strict", _fake_pii_tokenizer)

    assert _run_main(gh, monkeypatch, _prompt_event("refactor the parser")) == 0
    assert _output(capsys) is None


def test_prompt_pii_scan_failure_warns_but_does_not_block(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)

    def _unavailable(text, **k):
        raise gh.ScanUnavailable("down")

    monkeypatch.setattr(gh, "_tokenize_strict", _unavailable)

    _run_main(gh, monkeypatch, _prompt_event("email a@b.com about it"))

    out = _output(capsys)
    assert "decision" not in out
    assert "could not complete" in out["systemMessage"]


# ── Hard wall-clock deadline against a server that really stalls ─────

import http.server
import threading
import time


class _TricklingHandler(http.server.BaseHTTPRequestHandler):
    """Sends headers, then one body byte every 0.2s: each read finishes well
    inside httpx's per-read timeout, so only a wall-clock limit stops it."""

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "100")
        self.end_headers()
        try:
            for _ in range(100):
                self.wfile.write(b" ")
                self.wfile.flush()
                time.sleep(0.2)
        except OSError:
            pass

    def log_message(self, *args):
        pass


@pytest.fixture
def stalling_api(monkeypatch):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TricklingHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("VERISWARM_API_URL", f"http://127.0.0.1:{server.server_address[1]}")
    yield
    server.shutdown()


BUDGET = 1.5


def _timed_main(gh, monkeypatch, event):
    monkeypatch.setattr(gh, "HOOK_BUDGET_SECONDS", BUDGET)
    monkeypatch.setattr(gh, "API_TIMEOUT", 1.0)
    start = time.monotonic()
    code = _run_main(gh, monkeypatch, event)
    return code, time.monotonic() - start


def test_pre_tool_use_finishes_within_budget_and_redacts_offline(monkeypatch, capsys, stalling_api):
    gh = _reload_hook(monkeypatch)
    fields = {"secret": "token " + GH, **{f"f{i}": f"value number {i}" for i in range(5)}}

    code, elapsed = _timed_main(gh, monkeypatch, _event("PreToolUse", tool_input=fields))

    assert code == 0
    assert elapsed < BUDGET + 0.5
    updated = _output(capsys)["hookSpecificOutput"]["updatedInput"]
    assert updated["secret"] == "token [VS:GITHUB_TOKEN:offline]"


def test_post_tool_use_withholds_within_budget_when_api_stalls(monkeypatch, capsys, stalling_api):
    gh = _reload_hook(monkeypatch)

    code, elapsed = _timed_main(gh, monkeypatch, _event("PostToolUse", tool_response="contact a@b.com please"))

    assert code == 0
    assert elapsed < BUDGET + 0.5
    assert "withheld" in json.dumps(_output(capsys))


def test_prompt_check_finishes_within_budget_when_api_stalls(monkeypatch, capsys, stalling_api):
    gh = _reload_hook(monkeypatch, secrets=False)

    code, elapsed = _timed_main(gh, monkeypatch, _prompt_event("email a@b.com about it"))

    assert code == 0
    assert elapsed < BUDGET + 0.5
    assert "systemMessage" in _output(capsys)


def test_tripwire_skips_api_when_budget_is_low(monkeypatch):
    gh = _reload_hook(monkeypatch)
    monkeypatch.setattr(gh, "_deadline", time.monotonic() + gh.MIN_API_BUDGET / 2)

    def _no_api(*a, **k):
        raise AssertionError("API called with no budget left")

    monkeypatch.setattr(gh, "_post_within", _no_api)

    assert gh.apply_secret_tripwire("token " + GH) == "token [VS:GITHUB_TOKEN:offline]"


# ── Round 2: always-on secret redaction, crash fail-closed, no fork ──

def test_secrets_redacted_in_tool_input_even_with_detection_off(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "_tokenize", lambda text, **k: None)

    _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"body": "token " + GH}))

    assert _output(capsys)["hookSpecificOutput"]["updatedInput"]["body"] == "token [VS:GITHUB_TOKEN:offline]"


def test_secrets_redacted_in_tool_output_even_with_detection_off(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False, api_key="")

    _run_main(gh, monkeypatch, _event("PostToolUse", tool_response="key " + GH))

    assert _output(capsys)["hookSpecificOutput"]["updatedToolOutput"] == "key [VS:GITHUB_TOKEN:offline]"


def test_detection_flag_only_controls_the_api_tokenize_step(monkeypatch):
    gh = _reload_hook(monkeypatch, secrets=False)

    def _no_api(text, **k):
        raise AssertionError("API tokenize used with detection off")

    monkeypatch.setattr(gh, "_tokenize", _no_api)

    assert gh.apply_secret_tripwire("token " + GH) == "token [VS:GITHUB_TOKEN:offline]"


def test_unparseable_stdin_with_secret_blocks_with_detection_off(monkeypatch):
    gh = _reload_hook(monkeypatch, secrets=False)

    assert _run_main(gh, monkeypatch, b"\xff\xfe" + GH.encode()) == 2


def test_post_tool_use_crash_inside_handler_withholds_output(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)

    def _boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(gh, "_guard_strings", _boom)

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_response="key " + GH))

    assert code == 0
    raw = json.dumps(_output(capsys))
    assert GH not in raw
    assert "withheld" in raw


def test_post_tool_use_crash_outside_handler_withholds_output(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)

    def _boom(*a, **k):
        raise RuntimeError("bug")

    monkeypatch.setattr(gh, "handle_post_tool_use", _boom)

    code = _run_main(gh, monkeypatch, _event("PostToolUse", tool_response=[{"type": "text", "text": "key " + GH}]))

    assert code == 0
    out = _output(capsys)["hookSpecificOutput"]
    assert out["hookEventName"] == "PostToolUse"
    assert "withheld" in json.dumps(out["updatedToolOutput"])
    assert GH not in json.dumps(out)


def test_post_tool_use_budget_leaves_headroom(monkeypatch):
    gh = _reload_hook(monkeypatch)
    assert gh.HOOK_BUDGET_SECONDS <= 6.0


class _RaisingTripwire:
    def scan(self, text):
        raise RuntimeError("tripwire bug")


def test_prompt_tripwire_error_blocks_without_echoing_prompt(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch, secrets=False)
    monkeypatch.setattr(gh, "_get_tripwire", lambda: _RaisingTripwire())

    code = _run_main(gh, monkeypatch, _prompt_event("my private prompt text"))

    out = _output(capsys)
    assert code == 0
    assert out["decision"] == "block"
    assert out["hookSpecificOutput"]["suppressOriginalPrompt"] is True
    assert "my private prompt text" not in json.dumps(out)


def test_foreground_run_surfaces_pending_reporter_warnings(monkeypatch, capsys):
    gh = _reload_hook(monkeypatch)
    import activity_reporter as reporter  # the sibling module guard_hook imports
    reporter._warn("Activity upload: dropped 3 event(s) the API rejected as invalid (HTTP 400/413/422).")

    _run_main(gh, monkeypatch, _event("PreToolUse", tool_input={"q": "x"}))

    assert "dropped 3" in capsys.readouterr().err


def test_timed_out_request_thread_prevents_fork(monkeypatch, stalling_api):
    gh = _reload_hook(monkeypatch)
    import activity_reporter as reporter

    with pytest.raises(gh.ScanUnavailable):
        gh._post_within(gh.API_URL + "/v1/suite/guard/pii/tokenize", {"text": "x"}, 0.3)

    def _no_fork():
        raise AssertionError("forked while a request thread was alive")

    monkeypatch.setattr(reporter.os, "fork", _no_fork)
    reporter.maybe_flush(reporter.FLUSH_THRESHOLD)
