"""Client secret tripwire (Python SDK).

Mirror of the TS/Node tripwire. Consumes the generated manifest — never the
main-repo ``secret_rules.py`` (separate public package). Prefix hit + online →
escalate to the tokenize endpoint; prefix hit + offline → local fail-closed
redaction to ``[VS:<ENTITY_TYPE>:offline]``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


@dataclass(frozen=True)
class SecretHit:
    start: int
    end: int
    value: str
    entity_type: str
    rule_name: str


# entity_type is interpolated into the ``[VS:<ENTITY_TYPE>:offline]``
# redaction marker, so it is restricted to a safe identifier alphabet.
_ENTITY_TYPE_RE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_MAX_PATTERN_LENGTH = 1000


class SecretTripwire:
    def __init__(self, manifest: dict[str, Any], *, source: str = "builtin") -> None:
        self.version: str = manifest["version"]
        # "remote" when a fetched manifest was merged in; "builtin" when only
        # the vendored rules are active (no fetch, failed fetch, or invalid
        # manifest).
        self.source = source
        self._compiled: list[tuple[re.Pattern[str], dict[str, str]]] = [
            (re.compile(rule["prefix_pattern"]), rule) for rule in manifest["rules"]
        ]

    def scan(self, text: str) -> list[SecretHit]:
        if not isinstance(text, str) or not text:
            return []
        hits: list[SecretHit] = []
        for compiled, rule in self._compiled:
            for m in compiled.finditer(text):
                if not m.group(0):
                    continue
                hits.append(
                    SecretHit(
                        m.start(),
                        m.end(),
                        m.group(0),
                        rule["entity_type"],
                        rule["name"],
                    )
                )
        return hits

    def redact_offline(self, text: str) -> str:
        hits = sorted(self.scan(text), key=lambda h: h.start)
        chosen: list[SecretHit] = []
        cursor = -1
        for h in hits:
            if h.start >= cursor:
                chosen.append(h)
                cursor = h.end
        out = text
        for h in reversed(chosen):
            out = out[: h.start] + f"[VS:{h.entity_type}:offline]" + out[h.end :]
        return out


_VENDORED = Path(__file__).resolve().parent / "secret_rules_manifest.json"


def load_vendored_manifest() -> dict[str, Any]:
    return json.loads(_VENDORED.read_text(encoding="utf-8"))


def is_valid_rule(rule: Any) -> bool:
    """True when a fetched rule is well-formed and its pattern compiles."""
    if not isinstance(rule, dict):
        return False
    name = rule.get("name")
    entity_type = rule.get("entity_type")
    pattern = rule.get("prefix_pattern")
    if not isinstance(name, str) or not name:
        return False
    if not isinstance(entity_type, str) or not _ENTITY_TYPE_RE.fullmatch(entity_type):
        return False
    if not isinstance(pattern, str) or not pattern or len(pattern) > _MAX_PATTERN_LENGTH:
        return False
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def merge_manifests(vendored: dict[str, Any], fetched: dict[str, Any]) -> dict[str, Any]:
    """Built-in rules plus every valid fetched rule.

    Fetched rules can only add coverage: built-ins are always kept, and a
    fetched rule identical to an existing one is skipped.
    """
    seen = {(r["name"], r["prefix_pattern"]) for r in vendored["rules"]}
    rules = list(vendored["rules"])
    for rule in fetched["rules"]:
        if not is_valid_rule(rule):
            continue
        key = (rule["name"], rule["prefix_pattern"])
        if key in seen:
            continue
        seen.add(key)
        rules.append(
            {
                "name": rule["name"],
                "entity_type": rule["entity_type"],
                "prefix_pattern": rule["prefix_pattern"],
            }
        )
    version = fetched.get("version")
    if not isinstance(version, str) or not version:
        version = vendored["version"]
    return {"version": version, "rules": rules}


def ensure_tripwire(
    fetch_manifest: Callable[[], dict[str, Any]] | None = None,
) -> SecretTripwire:
    vendored = load_vendored_manifest()
    if fetch_manifest is None:
        return SecretTripwire(vendored)
    try:
        fetched = fetch_manifest()
    except Exception:
        return SecretTripwire(vendored)  # offline — the caller retries later
    if not isinstance(fetched, dict) or not isinstance(fetched.get("rules"), list):
        return SecretTripwire(vendored)
    return SecretTripwire(merge_manifests(vendored, fetched), source="remote")
