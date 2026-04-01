#!/usr/bin/env python3
"""VeriSwarm Trust Check — GitHub Action runner.

Runs trust score checks, security tests, PII scans, and injection scans
against AI agents in CI. Zero external dependencies.
"""
from __future__ import annotations

import glob
import json
import os
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ── Config ───────────────────────────────────────────────────────────────

API_URL = os.environ.get("VERISWARM_API_URL", "https://api.veriswarm.ai").rstrip("/")
API_KEY = os.environ.get("VERISWARM_API_KEY", "")
AGENT_ID = os.environ.get("VERISWARM_AGENT_ID", "")
MODE = os.environ.get("VERISWARM_MODE", "all")
SCAN_PATHS = os.environ.get("VERISWARM_SCAN_PATHS", "")
ACTION_TYPE = os.environ.get("VERISWARM_ACTION_TYPE", "deploy")
FAIL_ON_DENY = os.environ.get("VERISWARM_FAIL_ON_DENY", "true").lower() == "true"
FAIL_ON_INJECTION = os.environ.get("VERISWARM_FAIL_ON_INJECTION", "true").lower() == "true"
FAIL_ON_LOW_SCORE = int(os.environ.get("VERISWARM_FAIL_ON_LOW_SCORE", "0"))
MIN_TRUST_SCORE = int(os.environ.get("VERISWARM_MIN_TRUST_SCORE", "0"))

GITHUB_OUTPUT = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY", "")


def api_request(path: str, method: str = "GET", body: dict | None = None) -> dict:
    encoded = None if body is None else json.dumps(body).encode("utf-8")
    req = Request(
        f"{API_URL}{path}", data=encoded, method=method,
        headers={"Content-Type": "application/json", "x-api-key": API_KEY},
    )
    try:
        with urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:200]
        print(f"::warning::VeriSwarm API error {exc.code}: {detail}")
        return {"error": f"API {exc.code}"}
    except URLError as exc:
        print(f"::warning::VeriSwarm connection failed: {exc.reason}")
        return {"error": str(exc.reason)}


def set_output(name: str, value: str):
    if GITHUB_OUTPUT:
        with open(GITHUB_OUTPUT, "a") as f:
            f.write(f"{name}={value}\n")


def append_summary(md: str):
    if GITHUB_STEP_SUMMARY:
        with open(GITHUB_STEP_SUMMARY, "a") as f:
            f.write(md + "\n")


# ── Checks ───────────────────────────────────────────────────────────────

failures = []
summary_lines = []


def check_score():
    if not AGENT_ID:
        print("::notice::Skipping score check (no agent-id provided)")
        return

    print(f"Checking trust score for {AGENT_ID}...")
    result = api_request(f"/v1/public/agents/{AGENT_ID}/scores/current")

    if "error" in result:
        print(f"::warning::Score check failed: {result['error']}")
        return

    scores = result.get("scores", {})
    tier = result.get("policy_tier", "unknown")
    composite = scores.get("composite_trust", 0)

    set_output("trust-score", str(composite))
    set_output("policy-tier", tier)

    line = f"Trust Score: **{composite}** | Tier: **{tier}** | Identity: {scores.get('identity', '?')} | Risk: {scores.get('risk', '?')} | Reliability: {scores.get('reliability', '?')}"
    summary_lines.append(line)
    print(f"  Score: {composite} | Tier: {tier}")

    if MIN_TRUST_SCORE > 0 and composite < MIN_TRUST_SCORE:
        msg = f"Trust score {composite} is below minimum {MIN_TRUST_SCORE}"
        failures.append(msg)
        print(f"::error::{msg}")


def check_decision():
    if not AGENT_ID:
        return

    print(f"Checking trust decision for {AGENT_ID} / {ACTION_TYPE}...")
    result = api_request("/v1/decisions/check", method="POST", body={
        "agent_id": AGENT_ID, "action_type": ACTION_TYPE,
    })

    if "error" in result:
        return

    decision = result.get("decision", "unknown")
    set_output("decision", decision)

    emoji = "✅" if decision == "allow" else "⚠️" if decision == "review" else "❌"
    line = f"Decision: {emoji} **{decision.upper()}** for action `{ACTION_TYPE}`"
    summary_lines.append(line)
    print(f"  Decision: {decision}")

    if FAIL_ON_DENY and decision == "deny":
        msg = f"Trust decision is DENY for action '{ACTION_TYPE}'"
        failures.append(msg)
        print(f"::error::{msg}")


def check_test():
    if not AGENT_ID:
        return

    print(f"Running security tests against {AGENT_ID}...")
    result = api_request(f"/v1/agents/test/{AGENT_ID}", method="POST", body={})

    if "error" in result:
        return

    readiness = result.get("readiness_score", 0)
    passed = result.get("passed", 0)
    failed = result.get("failed", 0)
    total = result.get("total_tests", 0)

    set_output("readiness-score", str(readiness))

    emoji = "✅" if readiness >= 80 else "⚠️" if readiness >= 50 else "❌"
    line = f"Security Tests: {emoji} **{readiness}/100** ({passed}/{total} passed, {failed} failed)"
    summary_lines.append(line)
    print(f"  Readiness: {readiness}/100 | Passed: {passed} | Failed: {failed}")

    if FAIL_ON_LOW_SCORE > 0 and readiness < FAIL_ON_LOW_SCORE:
        msg = f"Security readiness score {readiness} is below threshold {FAIL_ON_LOW_SCORE}"
        failures.append(msg)
        print(f"::error::{msg}")

    # Show failed tests in annotations
    for r in result.get("results", []):
        if r.get("status") == "fail":
            print(f"::warning::Security test failed: {r['name']} — expected: {r.get('expected', '?')[:80]}")


def check_scan():
    files_to_scan = []

    if SCAN_PATHS:
        for pattern in SCAN_PATHS.split(","):
            files_to_scan.extend(glob.glob(pattern.strip(), recursive=True))

    if not files_to_scan:
        print("::notice::No files to scan (set scan-paths to enable PII/injection scanning)")
        return

    print(f"Scanning {len(files_to_scan)} files for PII and injection patterns...")

    total_pii = 0
    total_injection = 0

    for filepath in files_to_scan[:50]:  # Cap at 50 files
        try:
            with open(filepath) as f:
                content = f.read()[:5000]  # Cap at 5KB per file
        except Exception:
            continue

        if not content.strip():
            continue

        # PII scan
        result = api_request("/v1/demo/pii-scan", method="POST", body={"text": content})
        entities = result.get("entities_found", 0)
        if entities > 0:
            total_pii += entities
            for e in result.get("entities", []):
                print(f"::warning file={filepath}::PII detected: {e['type']} (confidence: {e.get('score', 0):.0%})")

        # Injection scan
        result = api_request("/v1/demo/injection-scan", method="POST", body={"text": content})
        if result.get("is_injection"):
            total_injection += 1
            print(f"::error file={filepath}::Prompt injection pattern detected (confidence: {result.get('confidence', 0):.0%})")

    set_output("pii-found", str(total_pii > 0).lower())
    set_output("injection-found", str(total_injection > 0).lower())

    if total_pii > 0:
        summary_lines.append(f"PII Scan: ⚠️ **{total_pii} entities** found across {len(files_to_scan)} files")
    else:
        summary_lines.append(f"PII Scan: ✅ Clean ({len(files_to_scan)} files scanned)")

    if total_injection > 0:
        summary_lines.append(f"Injection Scan: ❌ **{total_injection} files** contain injection patterns")
        if FAIL_ON_INJECTION:
            failures.append(f"Prompt injection detected in {total_injection} file(s)")
    else:
        summary_lines.append(f"Injection Scan: ✅ Clean")


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    if not API_KEY:
        print("::error::VERISWARM_API_KEY is not set. Add it as a GitHub secret.")
        sys.exit(1)

    print("🐝 VeriSwarm Trust Check")
    print(f"   API: {API_URL}")
    print(f"   Agent: {AGENT_ID or '(none)'}")
    print(f"   Mode: {MODE}")
    print()

    modes = [MODE] if MODE != "all" else ["score", "decision", "test", "scan"]

    for mode in modes:
        if mode == "score":
            check_score()
        elif mode == "decision":
            check_decision()
        elif mode == "test":
            check_test()
        elif mode == "scan":
            check_scan()

    # Write summary
    summary_md = "## 🐝 VeriSwarm Trust Check\n\n"
    if summary_lines:
        summary_md += "\n".join(f"- {line}" for line in summary_lines) + "\n"
    if failures:
        summary_md += f"\n### ❌ {len(failures)} check(s) failed\n\n"
        summary_md += "\n".join(f"- {f}" for f in failures) + "\n"
    else:
        summary_md += "\n### ✅ All checks passed\n"

    set_output("summary", summary_md.replace("\n", "%0A"))
    append_summary(summary_md)

    if failures:
        print(f"\n❌ {len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("\n✅ All VeriSwarm checks passed")


if __name__ == "__main__":
    main()
