from __future__ import annotations

from veriswarm_mcp.secret_tripwire import SecretTripwire, load_vendored_manifest

GH = "ghp_" + "A" * 36
MANIFEST = {
    "version": "sha256:test",
    "rules": [
        {
            "name": "github_pat",
            "entity_type": "GITHUB_TOKEN",
            "prefix_pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        }
    ],
}


def test_scan_and_redact():
    tw = SecretTripwire(MANIFEST)
    assert tw.scan(f"x {GH}")[0].entity_type == "GITHUB_TOKEN"
    assert tw.redact_offline(GH) == "[VS:GITHUB_TOKEN:offline]"


def test_vendored_manifest_loads():
    m = load_vendored_manifest()
    assert m["version"].startswith("sha256:")
    assert any(r["name"] == "github_pat" for r in m["rules"])
