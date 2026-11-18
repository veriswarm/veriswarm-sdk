"""Tests for validate_schemas.py. Run: python -m pytest scripts/test_validate_schemas.py"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).with_name("validate_schemas.py")
BASIC_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["name"],
    "properties": {"name": {"type": "string"}},
    "additionalProperties": False,
}


def load_script():
    spec = importlib.util.spec_from_file_location("validate_schemas_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value))


def use_temp_schema_root(monkeypatch, tmp_path):
    module = load_script()
    schemas = tmp_path / "schemas"
    schemas.mkdir()
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(module, "SCHEMAS", schemas)
    return module, schemas


def test_main_returns_error_when_no_schemas_found(monkeypatch, tmp_path, capsys):
    module, schemas = use_temp_schema_root(monkeypatch, tmp_path)
    write_json(schemas / "package.json", {"name": "@veriswarm/schemas"})

    assert module.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "no schemas found" in captured.err


def test_main_accepts_valid_schema_and_matching_fixtures(monkeypatch, tmp_path, capsys):
    module, schemas = use_temp_schema_root(monkeypatch, tmp_path)
    write_json(schemas / "thing.schema.json", BASIC_SCHEMA)
    write_json(schemas / "fixtures/thing/valid/ok.json", {"name": "demo"})
    write_json(schemas / "fixtures/thing/invalid/missing_name.json", {})

    assert module.main() == 0

    captured = capsys.readouterr()
    assert captured.out == "ok thing.schema.json\n"
    assert captured.err == ""


def test_main_reports_invalid_schema_definition(monkeypatch, tmp_path, capsys):
    module, schemas = use_temp_schema_root(monkeypatch, tmp_path)
    write_json(schemas / "broken.schema.json", {"$schema": BASIC_SCHEMA["$schema"], "type": 42})

    assert module.main() == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "::error::broken.schema.json:" in captured.err


def test_main_reports_valid_fixture_that_does_not_validate(monkeypatch, tmp_path, capsys):
    module, schemas = use_temp_schema_root(monkeypatch, tmp_path)
    write_json(schemas / "thing.schema.json", BASIC_SCHEMA)
    write_json(schemas / "fixtures/thing/valid/missing_name.json", {})

    assert module.main() == 1

    captured = capsys.readouterr()
    assert "ok thing.schema.json" in captured.out
    assert "::error::schemas/fixtures/thing/valid/missing_name.json: expected valid" in captured.err


def test_main_reports_invalid_fixture_that_validates(monkeypatch, tmp_path, capsys):
    module, schemas = use_temp_schema_root(monkeypatch, tmp_path)
    write_json(schemas / "thing.schema.json", BASIC_SCHEMA)
    write_json(schemas / "fixtures/thing/invalid/valid_payload.json", {"name": "demo"})

    assert module.main() == 1

    captured = capsys.readouterr()
    assert "ok thing.schema.json" in captured.out
    assert "::error::schemas/fixtures/thing/invalid/valid_payload.json: expected invalid" in captured.err
