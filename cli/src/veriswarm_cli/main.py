"""VeriSwarm CLI — trust scoring, event ingestion, agent testing, and Guard scanning.

Usage:
    veriswarm init                          Configure API key and endpoint
    veriswarm status                        Check platform status and connection
    veriswarm score <agent_id>              Get an agent's current trust scores
    veriswarm decision <agent_id> <action>  Check a trust decision
    veriswarm events send <json>            Send a single event
    veriswarm events stream                 Stream events from stdin (one JSON per line)
    veriswarm test <agent_id>               Run security test suite against an agent
    veriswarm scan <text>                   Scan text for PII or prompt injection
    veriswarm reputation <agent_ref>        Look up cross-provider reputation
    veriswarm compliance <framework>        Generate a compliance report
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

from . import __version__
from .client import api_request, get_config


def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return

    if args[0] in ("-v", "--version", "version"):
        print(f"veriswarm-cli {__version__}")
        return

    cmd = args[0]
    rest = args[1:]

    commands = {
        "init": cmd_init,
        "status": cmd_status,
        "score": cmd_score,
        "decision": cmd_decision,
        "events": cmd_events,
        "test": cmd_test,
        "scan": cmd_scan,
        "reputation": cmd_reputation,
        "compliance": cmd_compliance,
    }

    handler = commands.get(cmd)
    if not handler:
        print(f"Unknown command: {cmd}")
        print(f"Run 'veriswarm help' for usage.")
        sys.exit(1)

    handler(rest)


# ── init ─────────────────────────────────────────────────────────────────

def cmd_init(args: list[str]):
    """Configure API key and endpoint."""
    config_dir = os.path.expanduser("~/.veriswarm")
    config_path = os.path.join(config_dir, "config.json")

    # Load existing config
    config = {}
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)

    api_url = input(f"API URL [{config.get('api_url', 'https://api.veriswarm.ai')}]: ").strip()
    if not api_url:
        api_url = config.get("api_url", "https://api.veriswarm.ai")

    api_key = input("API Key: ").strip()
    if not api_key:
        api_key = config.get("api_key", "")

    if not api_key:
        print("API key is required. Get one at https://veriswarm.ai/account?tab=settings")
        sys.exit(1)

    os.makedirs(config_dir, exist_ok=True)
    config["api_url"] = api_url
    config["api_key"] = api_key

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    os.chmod(config_path, 0o600)

    print(f"Config saved to {config_path}")
    print(f"API URL: {api_url}")
    print(f"API Key: {api_key[:8]}...")


# ── status ───────────────────────────────────────────────────────────────

def cmd_status(args: list[str]):
    """Check platform status and connection."""
    base_url, api_key = get_config()
    print(f"API URL:  {base_url}")
    print(f"API Key:  {api_key[:8]}..." if api_key else "API Key:  (not set)")

    try:
        result = api_request("/v1/public/meta/version")
        print(f"Status:   connected")
        print(f"Version:  {result.get('api_version', '?')}")
        print(f"Release:  {result.get('release_date', '?')}")
        flags = result.get("suite_flags", {})
        print(f"Guard:    {'enabled' if flags.get('guard_enabled') else 'disabled'}")
        print(f"Passport: {'enabled' if flags.get('passport_enabled') else 'disabled'}")
        print(f"Vault:    {'enabled' if flags.get('vault_enabled') else 'disabled'}")
    except SystemExit as e:
        print(f"Status:   disconnected ({e})")


# ── score ────────────────────────────────────────────────────────────────

def cmd_score(args: list[str]):
    """Get an agent's current trust scores."""
    if not args:
        print("Usage: veriswarm score <agent_id>")
        sys.exit(1)

    agent_id = args[0]
    result = api_request(f"/v1/public/agents/{agent_id}/scores/current")

    scores = result.get("scores", {})
    print(f"Agent:       {agent_id}")
    print(f"Tier:        {result.get('policy_tier', '?')}")
    print(f"Identity:    {scores.get('identity', '?')}")
    print(f"Risk:        {scores.get('risk', '?')}")
    print(f"Reliability: {scores.get('reliability', '?')}")
    print(f"Autonomy:    {scores.get('autonomy', '?')}")
    print(f"Composite:   {scores.get('composite_trust', '?')}")


# ── decision ─────────────────────────────────────────────────────────────

def cmd_decision(args: list[str]):
    """Check a trust decision before a sensitive action."""
    if len(args) < 2:
        print("Usage: veriswarm decision <agent_id> <action_type> [resource_type]")
        sys.exit(1)

    agent_id, action_type = args[0], args[1]
    resource_type = args[2] if len(args) > 2 else None

    body = {"agent_id": agent_id, "action_type": action_type}
    if resource_type:
        body["resource_type"] = resource_type

    result = api_request("/v1/decisions/check", method="POST", body=body)

    decision = result.get("decision", "?")
    color = "\033[92m" if decision == "allow" else "\033[93m" if decision == "review" else "\033[91m"
    reset = "\033[0m"

    print(f"Agent:    {agent_id}")
    print(f"Action:   {action_type}")
    print(f"Decision: {color}{decision.upper()}{reset}")
    print(f"Tier:     {result.get('policy_tier', '?')}")
    if result.get("reason_code"):
        print(f"Reason:   {result['reason_code']}")


# ── events ───────────────────────────────────────────────────────────────

def cmd_events(args: list[str]):
    """Send events to VeriSwarm."""
    if not args:
        print("Usage: veriswarm events send '<json>' | veriswarm events stream")
        sys.exit(1)

    subcmd = args[0]

    if subcmd == "send":
        if len(args) < 2:
            print("Usage: veriswarm events send '<json>'")
            sys.exit(1)
        event = json.loads(args[1])
        # Add defaults
        if "occurred_at" not in event:
            event["occurred_at"] = datetime.now(timezone.utc).isoformat()
        if "event_id" not in event:
            import uuid
            event["event_id"] = f"cli-{uuid.uuid4().hex[:16]}"
        if "source_type" not in event:
            event["source_type"] = "cli"

        result = api_request("/v1/events", method="POST", body=event)
        print(f"Event ingested: {result.get('event_id', '?')}")

    elif subcmd == "stream":
        print("Streaming events from stdin (one JSON per line, Ctrl+C to stop)...")
        count = 0
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                if "occurred_at" not in event:
                    event["occurred_at"] = datetime.now(timezone.utc).isoformat()
                if "event_id" not in event:
                    import uuid
                    event["event_id"] = f"cli-{uuid.uuid4().hex[:16]}"
                if "source_type" not in event:
                    event["source_type"] = "cli"
                api_request("/v1/events", method="POST", body=event)
                count += 1
                print(f"  [{count}] {event.get('event_type', '?')} for {event.get('agent_id', '?')}")
            except (json.JSONDecodeError, SystemExit) as e:
                print(f"  Error: {e}", file=sys.stderr)
        print(f"Done. {count} events sent.")

    else:
        print(f"Unknown events subcommand: {subcmd}")
        print("Usage: veriswarm events send '<json>' | veriswarm events stream")


# ── test ─────────────────────────────────────────────────────────────────

def cmd_test(args: list[str]):
    """Run security test suite against an agent."""
    if not args:
        print("Usage: veriswarm test <agent_id> [--category <cat>]")
        sys.exit(1)

    agent_id = args[0]
    categories = None
    if "--category" in args:
        idx = args.index("--category")
        if idx + 1 < len(args):
            categories = [args[idx + 1]]

    body = {}
    if categories:
        body["categories"] = categories

    print(f"Running security tests against {agent_id}...")
    result = api_request(f"/v1/agents/test/{agent_id}", method="POST", body=body)

    score = result.get("readiness_score", 0)
    color = "\033[92m" if score >= 80 else "\033[93m" if score >= 50 else "\033[91m"
    reset = "\033[0m"

    print(f"\nSecurity Readiness Score: {color}{score}/100{reset}")
    print(f"Total: {result.get('total_tests', 0)} | Passed: {result.get('passed', 0)} | Failed: {result.get('failed', 0)}")

    by_cat = result.get("by_category", {})
    if by_cat:
        print("\nBy category:")
        for cat, data in by_cat.items():
            cat_label = cat.replace("_", " ").title()
            status = "\033[92mPASS\033[0m" if data["failed"] == 0 else "\033[91mFAIL\033[0m"
            print(f"  {cat_label:30s} {data['passed']}/{data['total']} {status}")

    # Show failures
    failures = [r for r in result.get("results", []) if r.get("status") == "fail"]
    if failures:
        print(f"\nFailed tests ({len(failures)}):")
        for f in failures:
            print(f"  \033[91m✗\033[0m {f['name']}")
            print(f"    Expected: {f['expected'][:80]}")
            if f.get("actual"):
                print(f"    Got:      {f['actual'][:80]}")


# ── scan ─────────────────────────────────────────────────────────────────

def cmd_scan(args: list[str]):
    """Scan text for PII or prompt injection."""
    if not args:
        print("Usage: veriswarm scan '<text>' [--type pii|injection]")
        sys.exit(1)

    text = args[0]
    scan_type = "both"
    if "--type" in args:
        idx = args.index("--type")
        if idx + 1 < len(args):
            scan_type = args[idx + 1]

    if scan_type in ("pii", "both"):
        print("PII Scan:")
        result = api_request("/v1/demo/pii-scan", method="POST", body={"text": text})
        entities = result.get("entities", [])
        if entities:
            for e in entities:
                print(f"  \033[91m{e['type']}\033[0m (confidence: {e.get('score', 0):.0%})")
            print(f"\nTokenized:\n  {result.get('tokenized_text', text)}")
        else:
            print("  \033[92mNo PII detected\033[0m")

    if scan_type in ("injection", "both"):
        if scan_type == "both":
            print()
        print("Injection Scan:")
        result = api_request("/v1/demo/injection-scan", method="POST", body={"text": text})
        if result.get("is_injection"):
            print(f"  \033[91mINJECTION DETECTED\033[0m (confidence: {result.get('confidence', 0):.0%})")
            for p in result.get("patterns_matched", []):
                print(f"  Pattern: {p}")
        else:
            print("  \033[92mClean\033[0m")


# ── reputation ───────────────────────────────────────────────────────────

def cmd_reputation(args: list[str]):
    """Look up an agent's cross-provider reputation."""
    if not args:
        print("Usage: veriswarm reputation <agent_ref>")
        sys.exit(1)

    agent_ref = args[0]
    result = api_request(f"/v1/public/reputation/lookup?agent_ref={agent_ref}")

    if result.get("status") == "no_history":
        print(f"No reputation data found for: {agent_ref}")
    else:
        band = result.get("risk_band", "?")
        color = "\033[92m" if band == "low" else "\033[93m" if band == "medium" else "\033[91m"
        reset = "\033[0m"
        print(f"Agent:    {agent_ref}")
        print(f"Risk:     {color}{band.upper()}{reset}")
        print(f"Reports:  {result.get('report_count', 0)}")


# ── compliance ───────────────────────────────────────────────────────────

def cmd_compliance(args: list[str]):
    """Generate a compliance report."""
    if not args:
        print("Usage: veriswarm compliance <framework> [--days N]")
        print("Frameworks: eu-ai-act, soc2, iso42001, hipaa")
        sys.exit(1)

    framework = args[0]
    days = 90
    if "--days" in args:
        idx = args.index("--days")
        if idx + 1 < len(args):
            days = int(args[idx + 1])

    print(f"Generating {framework} report (last {days} days)...")
    result = api_request(f"/v1/agents/compliance/{framework}?days={days}")

    # Save to file
    filename = f"veriswarm-{framework}-{datetime.now().strftime('%Y%m%d')}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Report saved: {filename}")
    print(f"Framework: {result.get('framework', framework)}")
    if result.get("title"):
        print(f"Title: {result['title']}")


if __name__ == "__main__":
    main()
