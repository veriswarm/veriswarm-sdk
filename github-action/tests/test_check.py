from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ACTION_PATH = Path(__file__).resolve().parents[1] / "check.py"
SPEC = importlib.util.spec_from_file_location("veriswarm_action_check", ACTION_PATH)
assert SPEC is not None and SPEC.loader is not None
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


@pytest.fixture(autouse=True)
def reset_action_state(monkeypatch):
    check.failures.clear()
    check.summary_lines.clear()
    monkeypatch.setattr(check, "CI_SCAN_PATHS", "")
    monkeypatch.setattr(check, "FAIL_ON_CI_EXFIL", True)
    monkeypatch.delenv("GITHUB_BASE_REF", raising=False)


def test_check_ci_exfil_posts_only_safe_workspace_files(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "repo"
    workflow_dir = workspace / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "ci.yml"
    workflow.write_text("name: CI\n", encoding="utf-8")
    (workspace / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (workspace / "cert.pem").write_text("private key\n", encoding="utf-8")
    outside = tmp_path / "outside.yml"
    outside.write_text("name: outside\n", encoding="utf-8")

    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setattr(
        check,
        "CI_SCAN_PATHS",
        ".github/workflows/*.yml,.env,*.pem,../outside.yml",
    )
    calls = []

    def fake_api_request(path, method="GET", body=None):
        calls.append((path, method, body))
        return {"findings": [], "highest_severity": "none", "blocked": False}

    monkeypatch.setattr(check, "api_request", fake_api_request)

    check.check_ci_exfil()

    assert calls == [
        (
            "/v1/suite/guard/scan-ci",
            "POST",
            {
                "files": [
                    {
                        "path": ".github/workflows/ci.yml",
                        "content": "name: CI\n",
                    }
                ]
            },
        )
    ]
    assert "Skipped 3 CI file(s)" in capsys.readouterr().out


def test_check_ci_exfil_includes_base_diff_and_caps_file_content(
    tmp_path, monkeypatch
):
    workspace = tmp_path / "repo"
    workspace.mkdir()
    dockerfile = workspace / "Dockerfile"
    dockerfile.write_text("0123456789abcdef", encoding="utf-8")

    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    monkeypatch.setattr(check, "CI_SCAN_PATHS", "Dockerfile")
    monkeypatch.setattr(check, "_MAX_CI_FILE_BYTES", 12)
    diff_calls = []

    def fake_git_diff(path, base_ref):
        diff_calls.append((path, base_ref))
        return "+RUN curl https://example.invalid\n"

    captured_body = {}

    def fake_api_request(path, method="GET", body=None):
        captured_body.update(body or {})
        return {"findings": [], "highest_severity": "none", "blocked": False}

    monkeypatch.setattr(check, "_git_diff_for", fake_git_diff)
    monkeypatch.setattr(check, "api_request", fake_api_request)

    check.check_ci_exfil()

    assert diff_calls == [("Dockerfile", "main")]
    assert captured_body == {
        "files": [
            {
                "path": "Dockerfile",
                "content": "0123456789ab",
                "diff": "+RUN curl https://example.invalid\n",
            }
        ]
    }


def test_check_ci_exfil_records_outputs_and_failure_when_api_blocks(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "repo"
    workflow_dir = workspace / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "ci.yml").write_text("name: CI\n", encoding="utf-8")

    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.setattr(check, "CI_SCAN_PATHS", ".github/workflows/*.yml")
    outputs = []

    def fake_set_output(name, value):
        outputs.append((name, value))

    def fake_api_request(path, method="GET", body=None):
        return {
            "blocked": True,
            "highest_severity": "high",
            "enforcement_level": "block",
            "findings": [
                {
                    "severity": "high",
                    "path": ".github/workflows/ci.yml",
                    "line": 7,
                    "check": "secret_egress",
                    "recommendation": "Move network egress away from secrets.",
                    "evidence": "SHOULD_NOT_BE_LOGGED",
                }
            ],
        }

    monkeypatch.setattr(check, "set_output", fake_set_output)
    monkeypatch.setattr(check, "api_request", fake_api_request)

    check.check_ci_exfil()

    assert outputs == [
        ("ci-exfil-blocked", "true"),
        ("ci-exfil-highest-severity", "high"),
        ("ci-exfil-findings", "1"),
    ]
    assert check.failures == [
        "CI secret-exfiltration scan blocked the build "
        "(highest severity: high, enforcement: block)"
    ]
    assert len(check.summary_lines) == 1
    assert "**1 finding(s)**, highest **high**" in check.summary_lines[0]
    assert "(enforcement: block, blocked: True)" in check.summary_lines[0]
    out = capsys.readouterr().out
    assert "secret_egress" in out
    assert "SHOULD_NOT_BE_LOGGED" not in out
