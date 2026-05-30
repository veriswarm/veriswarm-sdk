"""Client secret tripwire (MCP server).

The MCP hook is a short-lived subprocess invoked per tool call. To avoid
per-call network latency it uses the vendored manifest only — the freshness
fetch other surfaces perform at init is intentionally omitted here. Detection
shape is identical to the other surfaces (same generated manifest).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SecretHit:
    start: int
    end: int
    value: str
    entity_type: str
    rule_name: str


class SecretTripwire:
    def __init__(self, manifest: dict[str, Any]) -> None:
        self.version: str = manifest["version"]
        self._compiled = [
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
                        m.start(), m.end(), m.group(0), rule["entity_type"], rule["name"]
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
