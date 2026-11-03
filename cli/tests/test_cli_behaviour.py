"""CLI behaviour tests with a stubbed API (no network)."""
from __future__ import annotations

import io
import json
import subprocess
import urllib.error
from urllib.parse import quote

import pytest

from veriswarm_cli import client, main as cli


class FakeApi:
    def __init__(self, responder=None):
        self.calls = []
        self.responder = responder or (lambda path, **kw: {})

    def __call__(self, path, *, method="GET", body=None, timeout=15):
        self.calls.append((path, method, body))
        result = self.responder(path, method=method, body=body)
        if isinstance(result, BaseException):
            raise result
        return result


def run(monkeypatch, argv, api=None, stdin=None):
    api = api or FakeApi()
    monkeypatch.setattr(cli, "api_request", api)
    monkeypatch.setattr("sys.argv", ["veriswarm", *argv])
    if stdin is not None:
        monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    try:
        cli.main()
        return 0, api
    except SystemExit as exc:
        return exc.code, api


BREAKDOWN = {
    "policy_tier": "tier_2",
    "scores": {"identity": 90, "risk": 5, "reliability": 80, "autonomy": 70, "composite_trust": 84},
}


def test_status_does_not_depend_on_removed_suite_flags(monkeypatch, capsys):
    api = FakeApi(lambda p, **k: {"api_version": "1.2", "release_date": "2026-01-01", "deprecation_date": None})
    code, _ = run(monkeypatch, ["status"], api)
    out = capsys.readouterr().out
    assert code in (0, None)
    assert "1.2" in out
    assert "Guard" not in out and "disabled" not in out


def test_score_prints_real_composite(monkeypatch, capsys):
    code, api = run(monkeypatch, ["score", "agt_1"], FakeApi(lambda p, **k: BREAKDOWN))
    out = capsys.readouterr().out
    assert code in (0, None)
    assert api.calls[0][0] == "/v1/public/agents/agt_1/scores/breakdown"
    assert "84" in out and "tier_2" in out


def test_score_without_composite_exits_nonzero(monkeypatch, capsys):
    code, _ = run(monkeypatch, ["score", "agt_1"], FakeApi(lambda p, **k: {"status": "unscored"}))
    assert code not in (0, None)


def test_user_values_are_url_encoded(monkeypatch):
    weird = "a/b?x=1&y#z"
    _, api = run(monkeypatch, ["score", weird], FakeApi(lambda p, **k: BREAKDOWN))
    assert api.calls[0][0] == f"/v1/public/agents/{quote(weird, safe='')}/scores/breakdown"
    _, api = run(monkeypatch, ["reputation", weird], FakeApi(lambda p, **k: {"status": "no_history"}))
    assert api.calls[0][0] == f"/v1/public/reputation/lookup?agent_ref={quote(weird, safe='')}"
    _, api = run(monkeypatch, ["test", weird], FakeApi(lambda p, **k: {"readiness_score": 90}))
    assert api.calls[0][0] == f"/v1/agents/test/{quote(weird, safe='')}"


def test_compliance_encodes_framework_and_rejects_bad_days(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _, api = run(monkeypatch, ["compliance", "a/b"], FakeApi(lambda p, **k: {"framework": "x"}))
    assert api.calls[0][0] == "/v1/agents/compliance/a%2Fb?days=90"
    code, _ = run(monkeypatch, ["compliance", "soc2", "--days", "many"])
    assert code not in (0, None)


@pytest.mark.parametrize("decision,expected_ok", [("allow", True), ("review", True), ("deny", False)])
def test_decision_exit_code(monkeypatch, decision, expected_ok):
    code, _ = run(monkeypatch, ["decision", "agt_1", "deploy"], FakeApi(lambda p, **k: {"decision": decision}))
    assert (code in (0, None)) is expected_ok


def test_decision_unrecognised_response_exits_nonzero(monkeypatch):
    code, _ = run(monkeypatch, ["decision", "agt_1", "deploy"], FakeApi(lambda p, **k: {}))
    assert code not in (0, None)


def test_events_stream_exits_nonzero_if_any_event_failed(monkeypatch):
    def responder(path, method, body):
        return SystemExit("API error 500") if body["event_id"] == "bad" else {"event_id": body["event_id"]}

    lines = (
        json.dumps({"event_id": "ok", "agent_id": "a", "event_type": "t"}) + "\n"
        + json.dumps({"event_id": "bad", "agent_id": "a", "event_type": "t"}) + "\n"
        + "not json\n"
    )
    code, _ = run(monkeypatch, ["events", "stream"], FakeApi(responder), stdin=lines)
    assert code not in (0, None)


def test_events_stream_all_ok_exits_zero(monkeypatch):
    line = json.dumps({"agent_id": "a", "event_type": "t"}) + "\n"
    code, _ = run(monkeypatch, ["events", "stream"], FakeApi(lambda p, **k: {"event_id": "x"}), stdin=line)
    assert code in (0, None)


def test_unknown_events_subcommand_exits_nonzero(monkeypatch):
    code, _ = run(monkeypatch, ["events", "bogus"])
    assert code not in (0, None)


def test_unknown_command_exits_nonzero(monkeypatch):
    code, _ = run(monkeypatch, ["bogus"])
    assert code not in (0, None)


@pytest.mark.parametrize("argv", [
    ["events", "send", "{not json"],
    ["events", "send", "[1,2]"],
    ["compliance", "soc2", "--days", "x"],
    ["scan", "hi", "--type", "bogus"],
])
def test_bad_input_is_clean_error_not_traceback(monkeypatch, capsys, argv):
    code, _ = run(monkeypatch, argv)
    assert code not in (0, None)
    assert "Traceback" not in capsys.readouterr().err


def test_main_converts_unexpected_value_errors_to_clean_exit(monkeypatch, capsys):
    code, _ = run(monkeypatch, ["score", "a"], FakeApi(lambda p, **k: ValueError("boom")))
    assert code not in (0, None)
    assert "Traceback" not in capsys.readouterr().err


# ── client ──
def test_broken_config_file_is_clean_error(monkeypatch, tmp_path):
    cfg = tmp_path / ".veriswarm"
    cfg.mkdir()
    (cfg / "config.json").write_text("{broken")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("VERISWARM_API_KEY", raising=False)
    monkeypatch.delenv("VERISWARM_API_URL", raising=False)
    with pytest.raises(SystemExit) as exc:
        client.get_config()
    assert "config" in str(exc.value).lower()


class _Resp:
    def __init__(self, body): self.body = body
    def read(self): return self.body
    def __enter__(self): return self
    def __exit__(self, *a): return False


class _Opener:
    def __init__(self, result): self.result = result
    def open(self, req, timeout=None):
        if isinstance(self.result, BaseException):
            raise self.result
        return _Resp(self.result)


@pytest.mark.parametrize("result", [b"<html>502</html>", b"[1]", TimeoutError("timed out"), ConnectionResetError("reset")])
def test_api_request_bad_responses_exit_cleanly(monkeypatch, result):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("VERISWARM_API_URL", "https://api.veriswarm.ai")
    monkeypatch.setattr(client, "_OPENER", _Opener(result))
    with pytest.raises(SystemExit):
        client.api_request("/x")


# ── scan-ci ──
def git_missing(monkeypatch):
    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 128, stdout="", stderr="fatal: bad revision")
    monkeypatch.setattr(subprocess, "run", fake_run)


CLEAN_CI = {"findings": [], "highest_severity": "none", "blocked": False}


def test_scan_ci_missing_path_exits_nonzero_but_scans_others(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    code, api = run(monkeypatch, ["scan-ci", "Dockerfile", "missing.yml"], FakeApi(lambda p, **k: CLEAN_CI))
    assert code not in (0, None)
    assert "missing.yml" in capsys.readouterr().err
    assert len(api.calls) == 1


def test_scan_ci_unreachable_base_ref_warns_and_exits_nonzero(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    git_missing(monkeypatch)
    code, _ = run(monkeypatch, ["scan-ci", "Dockerfile", "--base", "nope"], FakeApi(lambda p, **k: CLEAN_CI))
    assert code not in (0, None)
    assert "base" in capsys.readouterr().err.lower()


def test_scan_ci_clean_exits_zero(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    code, _ = run(monkeypatch, ["scan-ci", "Dockerfile"], FakeApi(lambda p, **k: CLEAN_CI))
    assert code in (0, None)


def test_scan_ci_malformed_response_exits_nonzero(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM x\n")
    code, _ = run(monkeypatch, ["scan-ci", "Dockerfile"], FakeApi(lambda p, **k: {"ok": 1}))
    assert code not in (0, None)
