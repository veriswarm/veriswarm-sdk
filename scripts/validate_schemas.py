#!/usr/bin/env python3
"""Check that every schemas/*.json is a valid JSON Schema (per its $schema
dialect, default 2020-12), and that any fixtures validate. Requires `jsonschema`.

Fixtures (optional): schemas/fixtures/<schema-stem>/valid/*.json must validate
and schemas/fixtures/<schema-stem>/invalid/*.json must be rejected.
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"


def main() -> int:
    errors = []
    files = sorted(p for p in SCHEMAS.glob("*.json") if p.name != "package.json")
    if not files:
        print("no schemas found", file=sys.stderr)
        return 1
    for path in files:
        try:
            schema = json.loads(path.read_text())
            cls = validator_for(schema, default=Draft202012Validator)
            cls.check_schema(schema)
        except Exception as exc:  # noqa: BLE001 - report every bad schema
            errors.append(f"{path.name}: {exc}")
            continue
        stem = path.name.removesuffix(".schema.json").removesuffix(".json")
        for kind, should_pass in (("valid", True), ("invalid", False)):
            for fx in sorted((SCHEMAS / "fixtures" / stem / kind).glob("*.json")):
                ok = cls(schema).is_valid(json.loads(fx.read_text()))
                if ok != should_pass:
                    errors.append(f"{fx.relative_to(ROOT)}: expected {kind}")
        print(f"ok {path.name}")
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
