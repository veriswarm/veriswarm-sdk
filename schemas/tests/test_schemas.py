"""Validate API-shaped payloads against the published JSON Schemas."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> dict:
    return json.loads((ROOT / name).read_text())


def validator(name: str) -> Draft202012Validator:
    schema = load(name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


# ── agent_event: mirrors the API's EventIngest model ──
def test_event_with_free_form_source_type_and_no_payload_is_valid():
    v = validator("agent_event.schema.json")
    event = {
        "event_id": "cli-1",
        "agent_id": "agt_1",
        "source_type": "cli",
        "event_type": "task.completed",
        "occurred_at": "2026-01-01T00:00:00+00:00",
    }
    assert list(v.iter_errors(event)) == []


def test_event_requires_core_fields():
    v = validator("agent_event.schema.json")
    assert list(v.iter_errors({"event_id": "x"}))


# ── score_snapshot: mirrors GET /v1/public/agents/{id}/scores/current ──
CURRENT_SCORES = {
    "identity": {"score": 90, "confidence": 0.9},
    "risk": {"score": 5, "confidence": 0.9, "band": "low"},
    "reliability": {"score": 80, "confidence": 0.9},
    "autonomy": {"score": 80, "confidence": 0.9, "label": "agent_operated"},
    "policy_tier": "tier_2",
    "explanations": ["Identity score is 90."],
}


def test_real_current_scores_response_is_valid():
    v = validator("score_snapshot.schema.json")
    assert list(v.iter_errors(CURRENT_SCORES)) == []


def test_current_scores_with_calibration_is_valid():
    v = validator("score_snapshot.schema.json")
    payload = {**CURRENT_SCORES, "calibration": {"score": 70, "confidence": 0.8}}
    assert list(v.iter_errors(payload)) == []


@pytest.mark.parametrize("label", ["agent_operated", "human_assisted", "unclear"])
def test_autonomy_labels_match_engine(label):
    v = validator("score_snapshot.schema.json")
    payload = {**CURRENT_SCORES, "autonomy": {"score": 50, "confidence": 0.5, "label": label}}
    assert list(v.iter_errors(payload)) == []


def test_score_snapshot_rejects_unknown_tier():
    v = validator("score_snapshot.schema.json")
    assert list(v.iter_errors({**CURRENT_SCORES, "policy_tier": "tier_9"}))


# ── workflow: every step type the server accepts ──
STEP_TYPES = [
    "llm", "adapter", "condition", "transform", "wait", "human_review", "webhook_out",
    "guard_scan", "score", "knowledge", "vault_log", "web_search", "platform_query",
    "send_email", "a2a",
]


def test_workflow_schema_lists_all_server_step_types():
    enum = load("workflow-schema.json")["$defs"]["StepDefinition"]["properties"]["type"]["enum"]
    assert enum == STEP_TYPES


def test_workflow_using_new_step_types_is_valid():
    v = validator("workflow-schema.json")
    wf = {
        "name": "ops",
        "trigger": {"type": "manual"},
        "steps": [
            {"id": "q", "name": "Query", "type": "platform_query", "query_type": "tenant_overview"},
            {"id": "m", "name": "Mail", "type": "send_email", "depends_on": ["q"]},
            {"id": "a", "name": "A2A", "type": "a2a", "depends_on": ["m"]},
        ],
        "budget": {"max_duration_minutes": 4000},
    }
    assert list(v.iter_errors(wf)) == []


def test_workflow_rejects_unknown_step_type():
    v = validator("workflow-schema.json")
    wf = {"name": "x", "trigger": {"type": "manual"}, "steps": [{"id": "a", "name": "A", "type": "bogus"}]}
    assert list(v.iter_errors(wf))


# ── package wiring ──
def test_package_main_exists_and_lists_every_schema():
    pkg = json.loads((ROOT / "package.json").read_text())
    main = ROOT / pkg["main"]
    assert main.is_file(), f"package.json main {pkg['main']} does not exist"
    text = main.read_text()
    for name in ("agent_event", "agent_profile", "score_snapshot", "workflow-schema"):
        assert name in text
    assert pkg["main"] in pkg["files"] or "*.js" in pkg["files"]


def test_agent_profile_schema_is_valid():
    validator("agent_profile.schema.json")
