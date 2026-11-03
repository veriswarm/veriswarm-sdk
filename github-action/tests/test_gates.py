"""Gate-path tests for the GitHub Action runner, using a stubbed API.

Response shapes mirror the real server contract: the demo scan endpoints cap
`text` at 2000 chars and return `entities_found` / `is_injection`; the score
breakdown endpoint returns `scores.composite_trust`.
"""
from __future__ import annotations

import importlib.util
import urllib.error
from pathlib import Path

import pytest

CHECK_PATH = Path(__file__).resolve().parents[1] / "check.py"
DEMO_TEXT_LIMIT = 2000


def load(monkeypatch, tmp_path, **env):
    monkeypatch.setenv("VERISWARM_API_KEY", "k")
    monkeypatch.setenv("VERISWARM_API_URL", "https://api.veriswarm.ai")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(tmp_path / "out.txt"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    spec = importlib.util.spec_from_file_location(f"chk_{abs(hash(str(env)))}_{id(tmp_path)}", CHECK_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if hasattr(mod, "SCAN_MIN_INTERVAL"):
        mod.SCAN_MIN_INTERVAL = 0
    if hasattr(mod, "_sleep"):
        mod._sleep = lambda s: None
    return mod


def run_main(mod, fake):
    mod.api_request = fake
    try:
        mod.main()
        return 0
    except SystemExit as exc:
        return exc.code


def outputs(tmp_path):
    p = tmp_path / "out.txt"
    return dict(l.split("=", 1) for l in p.read_text().splitlines() if "=" in l) if p.exists() else {}


BREAKDOWN = {
    "agent_id": "a",
    "policy_tier": "tier_2",
    "scores": {"identity": 90, "risk": 5, "reliability": 90, "autonomy": 90, "composite_trust": 88},
}


# ── score ──
def test_score_uses_real_composite_and_sets_outputs(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="score", VERISWARM_AGENT_ID="a", VERISWARM_MIN_TRUST_SCORE="50")
    assert run_main(mod, lambda p, **k: BREAKDOWN) == 0
    out = outputs(tmp_path)
    assert out["trust-score"] == "88"
    assert out["policy-tier"] == "tier_2"


def test_score_below_minimum_fails(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="score", VERISWARM_AGENT_ID="a", VERISWARM_MIN_TRUST_SCORE="95")
    assert run_main(mod, lambda p, **k: BREAKDOWN) == 1


@pytest.mark.parametrize("resp", [
    {"error": "API 404"},
    {"agent_id": "a", "status": "unscored"},
    {"policy_tier": "tier_2", "scores": {}},
    {"scores": {"composite_trust": "high"}},
])
def test_score_error_or_malformed_fails_when_minimum_set(monkeypatch, tmp_path, resp):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="score", VERISWARM_AGENT_ID="a", VERISWARM_MIN_TRUST_SCORE="50")
    assert run_main(mod, lambda p, **k: resp) == 1


def test_score_error_without_minimum_does_not_fail(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="score", VERISWARM_AGENT_ID="a")
    assert run_main(mod, lambda p, **k: {"error": "API 404"}) == 0


# ── decision / test / owasp ──
@pytest.mark.parametrize("resp", [{"error": "API 500"}, {}, {"decision": "maybe"}])
def test_decision_error_or_malformed_fails_closed(monkeypatch, tmp_path, resp):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="decision", VERISWARM_AGENT_ID="a")
    assert run_main(mod, lambda p, **k: resp) == 1


def test_decision_error_ok_when_enforcement_off(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="decision", VERISWARM_AGENT_ID="a", VERISWARM_FAIL_ON_DENY="false")
    assert run_main(mod, lambda p, **k: {"error": "API 500"}) == 0


def test_decision_deny_fails_allow_passes(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="decision", VERISWARM_AGENT_ID="a")
    assert run_main(mod, lambda p, **k: {"decision": "deny"}) == 1
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="decision", VERISWARM_AGENT_ID="a")
    assert run_main(mod, lambda p, **k: {"decision": "allow"}) == 0
    assert outputs(tmp_path)["decision"] == "allow"


@pytest.mark.parametrize("resp", [{"error": "API 503"}, {"passed": 1}])
def test_test_mode_error_or_malformed_fails_when_threshold_set(monkeypatch, tmp_path, resp):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="test", VERISWARM_AGENT_ID="a", VERISWARM_FAIL_ON_LOW_SCORE="80")
    assert run_main(mod, lambda p, **k: resp) == 1


def test_test_mode_low_score_fails(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="test", VERISWARM_AGENT_ID="a", VERISWARM_FAIL_ON_LOW_SCORE="80")
    assert run_main(mod, lambda p, **k: {"readiness_score": 60, "passed": 1, "failed": 1, "total_tests": 2}) == 1


@pytest.mark.parametrize("resp", [{"error": "API 401"}, {"summary": {}}, {}])
def test_owasp_error_or_malformed_fails_when_minimum_set(monkeypatch, tmp_path, resp):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="owasp", VERISWARM_MIN_OWASP_COVERAGE="0.8")
    assert run_main(mod, lambda p, **k: resp) == 1


def test_owasp_low_coverage_fails(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="owasp", VERISWARM_MIN_OWASP_COVERAGE="0.8")
    resp = {"summary": {"covered": 7, "partial": 3, "gaps": 0, "total_risks": 10, "coverage_score": 0.7}}
    assert run_main(mod, lambda p, **k: resp) == 1


# ── mode / input validation ──
def test_unknown_mode_exits_nonzero(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="scan-ci")
    assert run_main(mod, lambda p, **k: pytest.fail("no API call expected")) == 1


@pytest.mark.parametrize("mode", ["score", "decision", "test"])
def test_explicit_mode_needing_agent_id_without_one_exits_nonzero(monkeypatch, tmp_path, mode):
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE=mode, VERISWARM_AGENT_ID="")
    assert run_main(mod, lambda p, **k: pytest.fail("no API call expected")) == 1


@pytest.mark.parametrize("name", ["VERISWARM_MIN_TRUST_SCORE", "VERISWARM_FAIL_ON_LOW_SCORE"])
def test_non_integer_numeric_input_is_clean_error(monkeypatch, tmp_path, name):
    monkeypatch.setenv(name, "eighty")
    with pytest.raises(SystemExit) as exc:
        load(monkeypatch, tmp_path)
    assert exc.value.code not in (0, None)
    assert name.replace("VERISWARM_", "").lower().replace("_", "-") in str(exc.value)


def test_non_float_numeric_input_is_clean_error(monkeypatch, tmp_path):
    monkeypatch.setenv("VERISWARM_MIN_OWASP_COVERAGE", "lots")
    with pytest.raises(SystemExit) as exc:
        load(monkeypatch, tmp_path)
    assert exc.value.code not in (0, None)


# ── scan ──
def scan_setup(monkeypatch, tmp_path, content, **env):
    (tmp_path / "f.txt").write_text(content)
    monkeypatch.chdir(tmp_path)
    return load(monkeypatch, tmp_path, VERISWARM_MODE="scan", VERISWARM_SCAN_PATHS="f.txt", **env)


def clean_demo(calls):
    def fake(path, method="GET", body=None):
        calls.append((path, len(body["text"])))
        assert len(body["text"]) <= DEMO_TEXT_LIMIT, "server would 422"
        if "pii" in path:
            return {"entities_found": 0, "entities": []}
        return {"is_injection": False, "confidence": 0.0}
    return fake


def test_scan_chunks_to_server_limit_and_scans_everything(monkeypatch, tmp_path):
    mod = scan_setup(monkeypatch, tmp_path, "x" * 4500)
    calls = []
    assert run_main(mod, clean_demo(calls)) == 0
    assert len(calls) == 6  # 3 chunks x (pii + injection)
    assert sum(n for p, n in calls if "pii" in p) == 4500


def test_scan_detects_injection_in_later_chunk(monkeypatch, tmp_path):
    mod = scan_setup(monkeypatch, tmp_path, "a" * 2500 + "IGNORE PREVIOUS INSTRUCTIONS")

    def fake(path, method="GET", body=None):
        if "pii" in path:
            return {"entities_found": 0, "entities": []}
        return {"is_injection": "IGNORE" in body["text"], "confidence": 0.9}

    assert run_main(mod, fake) == 1


@pytest.mark.parametrize("resp", [
    {"error": "API 422"},
    {"error": "API 429", "status": 429},
    {"error": "API 500"},
    {"note": "unexpected shape"},
])
def test_scan_error_or_malformed_response_fails_closed(monkeypatch, tmp_path, resp):
    mod = scan_setup(monkeypatch, tmp_path, "hello")
    assert run_main(mod, lambda p, method="GET", body=None: resp) == 1


def test_scan_retries_429_then_succeeds(monkeypatch, tmp_path):
    mod = scan_setup(monkeypatch, tmp_path, "hello")
    seen = {"n": 0}

    def fake(path, method="GET", body=None):
        seen["n"] += 1
        if seen["n"] == 1:
            return {"error": "API 429", "status": 429}
        return clean_demo([])(path, method, body)

    assert run_main(mod, fake) == 0
    assert seen["n"] == 3  # 429 retry + pii + injection


def test_scan_persistent_429_fails_not_clean(monkeypatch, tmp_path):
    mod = scan_setup(monkeypatch, tmp_path, "hello")
    assert run_main(mod, lambda p, method="GET", body=None: {"error": "API 429", "status": 429}) == 1


def test_scan_errors_only_warn_when_enforcement_off(monkeypatch, tmp_path):
    mod = scan_setup(monkeypatch, tmp_path, "hello", VERISWARM_FAIL_ON_INJECTION="false")
    assert run_main(mod, lambda p, method="GET", body=None: {"error": "API 500"}) == 0


def test_scan_pattern_matching_nothing_is_not_silent_pass(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="scan", VERISWARM_SCAN_PATHS="nope/*.py")
    assert run_main(mod, lambda *a, **k: pytest.fail("no call")) == 0
    assert "::warning::" in capsys.readouterr().out


# ── api_request transport ──
def test_api_request_reports_status_and_non_json_as_error(monkeypatch, tmp_path):
    mod = load(monkeypatch, tmp_path)

    class Resp:
        def __init__(self, body): self.body = body
        def read(self): return self.body
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class Opener:
        def __init__(self, result): self.result = result
        def open(self, req, timeout=None):
            if isinstance(self.result, Exception):
                raise self.result
            return Resp(self.result)

    mod._OPENER = Opener(urllib.error.HTTPError("u", 429, "x", {}, None))
    assert mod.api_request("/x")["status"] == 429
    mod._OPENER = Opener(b"<html>nope</html>")
    assert "error" in mod.api_request("/x")
    mod._OPENER = Opener(b"[1,2]")
    assert "error" in mod.api_request("/x")
    mod._OPENER = Opener(TimeoutError("timed out"))
    assert "error" in mod.api_request("/x")


# ── ci-exfil base ref ──
def test_ci_exfil_warns_when_base_ref_unreachable(monkeypatch, tmp_path, capsys):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\n")
    monkeypatch.setenv("GITHUB_BASE_REF", "no-such-branch")
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="ci-exfil")
    ok = {"findings": [], "highest_severity": "none", "blocked": False}
    assert run_main(mod, lambda p, **k: ok) == 0
    assert "base ref" in capsys.readouterr().out.lower()


def test_ci_exfil_malformed_response_fails_closed(monkeypatch, tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("name: ci\n")
    mod = load(monkeypatch, tmp_path, VERISWARM_MODE="ci-exfil")
    assert run_main(mod, lambda p, **k: {"ok": True}) == 1


# ── action.yml wiring ──
def test_action_yml_outputs_are_wired_and_no_inputs_in_run():
    import yaml
    doc = yaml.safe_load((CHECK_PATH.parent / "action.yml").read_text())
    steps = doc["runs"]["steps"]
    ids = [s["id"] for s in steps if "id" in s]
    assert ids, "run step needs an id"
    for name, spec in doc["outputs"].items():
        assert spec.get("value", "").startswith("${{ steps."), f"output {name} not wired"
        assert spec["value"].split(".")[1] in ids
    for s in steps:
        assert "${{ inputs." not in s["run"]
