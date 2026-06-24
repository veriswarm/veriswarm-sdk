from __future__ import annotations

from veriswarm.secret_tripwire import (
    SecretTripwire,
    ensure_tripwire,
    load_vendored_manifest,
)

GH = "ghp_" + "A" * 36
MANIFEST = {
    "version": "sha256:test",
    "rules": [
        {
            "name": "github_pat",
            "entity_type": "GITHUB_TOKEN",
            "prefix_pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
        },
        {
            "name": "aws_access_key",
            "entity_type": "AWS_KEY",
            "prefix_pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        },
    ],
}


def test_scan_detects_prefix_secret():
    tw = SecretTripwire(MANIFEST)
    hits = tw.scan(f"token {GH} end")
    assert len(hits) == 1
    assert hits[0].entity_type == "GITHUB_TOKEN"
    assert hits[0].value == GH


def test_scan_clean_text():
    tw = SecretTripwire(MANIFEST)
    assert tw.scan("nothing here") == []


def test_redact_offline_fail_closed():
    tw = SecretTripwire(MANIFEST)
    assert tw.redact_offline(f"a {GH} b") == "a [VS:GITHUB_TOKEN:offline] b"


def test_redact_offline_multiple_spans():
    tw = SecretTripwire(MANIFEST)
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    assert tw.redact_offline(f"{GH} mid {aws}") == (
        "[VS:GITHUB_TOKEN:offline] mid [VS:AWS_KEY:offline]"
    )


def test_load_vendored_manifest():
    m = load_vendored_manifest()
    assert m["version"].startswith("sha256:")
    assert any(r["name"] == "github_pat" for r in m["rules"])


def test_ensure_tripwire_falls_back_when_fetched_manifest_has_no_rules():
    tw = ensure_tripwire(fetch_manifest=lambda: {"version": "sha256:empty", "rules": []})

    assert tw.version.startswith("sha256:")
    assert tw.scan(GH)
