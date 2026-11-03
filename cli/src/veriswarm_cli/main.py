"""VeriSwarm CLI — trust scoring, event ingestion, agent testing, and Guard scanning.

Usage:
    veriswarm init                          Configure API key and endpoint
    veriswarm status                        Check platform status and connection
    veriswarm score <agent_id>              Get an agent's trust scores and composite trust score
    veriswarm decision <agent_id> <action>  Check a trust decision (exit 2 on deny, 1 on error)
    veriswarm events send <json>            Send a single event
    veriswarm events stream                 Stream events from stdin (one JSON per line)
    veriswarm test <agent_id>               Run security test suite against an agent
    veriswarm scan <text>                   Scan text for PII or prompt injection
    veriswarm scan-ci <path>...             Scan CI YAML/Dockerfiles for secret exfiltration
    veriswarm reputation <agent_ref>        Look up cross-provider reputation
    veriswarm compliance <framework>        Generate a compliance report

The composite trust score is the server's composite_trust (0-100) from
GET /v1/public/agents/{id}/scores/breakdown: a profile-weighted blend of the
identity, inverted risk, reliability and autonomy scores (plus calibration when
the agent's profile uses it).

Exit codes: 0 success; 1 error or invalid input; 2 trust decision is "deny".
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import quote

from . import __version__
from .client import api_request, get_config, validate_api_url


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
        "scan-ci": cmd_scan_ci,
        "reputation": cmd_reputation,
        "compliance": cmd_compliance,
    }

    handler = commands.get(cmd)
    if not handler:
        print(f"Unknown command: {cmd}")
        print(f"Run 'veriswarm help' for usage.")
        sys.exit(1)

    try:
        handler(rest)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)
    except (ValueError, OSError, EOFError, KeyError, TypeError, AttributeError) as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)


def _die(message: str, code: int = 1):
    print(message, file=sys.stderr)
    sys.exit(code)


def _int_flag(args: list[str], flag: str, default: int) -> int:
    if flag not in args:
        return default
    idx = args.index(flag)
    if idx + 1 >= len(args):
        _die(f"{flag} requires a value")
    try:
        return int(args[idx + 1])
    except ValueError:
        _die(f"{flag} must be an integer (got {args[idx + 1]!r})")


def _parse_event(raw: str) -> dict:
    try:
        event = json.loads(raw)
    except json.JSONDecodeError as exc:
        _die(f"Event is not valid JSON: {exc}")
    if not isinstance(event, dict):
        _die("Event must be a JSON object")
    return event


def _with_event_defaults(event: dict) -> dict:
    import uuid

    event = dict(event)
    event.setdefault("occurred_at", datetime.now(timezone.utc).isoformat())
    event.setdefault("event_id", f"cli-{uuid.uuid4().hex[:16]}")
    event.setdefault("source_type", "cli")
    return event


# ── init ─────────────────────────────────────────────────────────────────

def cmd_init(args: list[str]):
    """Configure API key and endpoint."""
    config_dir = os.path.expanduser("~/.veriswarm")
    config_path = os.path.join(config_dir, "config.json")

    # Load existing config
    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                config = json.load(f)
        except (OSError, ValueError) as exc:
            _die(f"Could not read existing config {config_path}: {exc}")
        if not isinstance(config, dict):
            _die(f"Config file {config_path} must contain a JSON object")

    api_url = input(f"API URL [{config.get('api_url', 'https://api.veriswarm.ai')}]: ").strip()
    if not api_url:
        api_url = config.get("api_url", "https://api.veriswarm.ai")

    api_key = input("API Key: ").strip()
    if not api_key:
        api_key = config.get("api_key", "")

    if not api_key:
        print("API key is required. Get one at https://veriswarm.ai/account?tab=settings")
        sys.exit(1)

    api_url = validate_api_url(api_url, field_name="API URL")

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
    except SystemExit as e:
        print(f"Status:   disconnected ({e})")
        sys.exit(1)


# ── score ────────────────────────────────────────────────────────────────

def cmd_score(args: list[str]):
    """Get an agent's trust scores, including the composite trust score."""
    if not args:
        _die("Usage: veriswarm score <agent_id>")

    agent_id = args[0]
    result = api_request(f"/v1/public/agents/{quote(agent_id, safe='')}/scores/breakdown")

    scores = result.get("scores")
    composite = scores.get("composite_trust") if isinstance(scores, dict) else None
    if isinstance(composite, bool) or not isinstance(composite, (int, float)):
        reason = result.get("message") or result.get("status") or "no composite_trust in response"
        _die(f"No trust score available for {agent_id}: {reason}")

    print(f"Agent:       {agent_id}")
    print(f"Tier:        {result.get('policy_tier', '?')}")
    print(f"Identity:    {scores.get('identity', '?')}")
    print(f"Risk:        {scores.get('risk', '?')}")
    print(f"Reliability: {scores.get('reliability', '?')}")
    print(f"Autonomy:    {scores.get('autonomy', '?')}")
    print(f"Composite:   {composite}")


# ── decision ─────────────────────────────────────────────────────────────

def cmd_decision(args: list[str]):
    """Check a trust decision before a sensitive action."""
    if len(args) < 2:
        _die("Usage: veriswarm decision <agent_id> <action_type> [resource_type]")

    agent_id, action_type = args[0], args[1]
    resource_type = args[2] if len(args) > 2 else None

    body = {"agent_id": agent_id, "action_type": action_type}
    if resource_type:
        body["resource_type"] = resource_type

    result = api_request("/v1/decisions/check", method="POST", body=body)

    decision = result.get("decision")
    if decision not in ("allow", "review", "deny"):
        _die(f"Unrecognised decision in response: {decision!r}")
    color = "\033[92m" if decision == "allow" else "\033[93m" if decision == "review" else "\033[91m"
    reset = "\033[0m"

    print(f"Agent:    {agent_id}")
    print(f"Action:   {action_type}")
    print(f"Decision: {color}{decision.upper()}{reset}")
    print(f"Tier:     {result.get('policy_tier', '?')}")
    if result.get("reason_code"):
        print(f"Reason:   {result['reason_code']}")
    if decision == "deny":
        sys.exit(2)


# ── events ───────────────────────────────────────────────────────────────

def cmd_events(args: list[str]):
    """Send events to VeriSwarm."""
    if not args:
        _die("Usage: veriswarm events send '<json>' | veriswarm events stream")

    subcmd = args[0]

    if subcmd == "send":
        if len(args) < 2:
            _die("Usage: veriswarm events send '<json>'")
        event = _with_event_defaults(_parse_event(args[1]))
        result = api_request("/v1/events", method="POST", body=event)
        print(f"Event ingested: {result.get('event_id', '?')}")

    elif subcmd == "stream":
        print("Streaming events from stdin (one JSON per line, Ctrl+C to stop)...")
        count = 0
        failed = 0
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = _with_event_defaults(_parse_event(line))
                api_request("/v1/events", method="POST", body=event)
            except SystemExit as e:
                failed += 1
                print(f"  Error: {e}", file=sys.stderr)
                continue
            count += 1
            print(f"  [{count}] {event.get('event_type', '?')} for {event.get('agent_id', '?')}")
        print(f"Done. {count} events sent, {failed} failed.")
        if failed:
            sys.exit(1)

    else:
        _die(f"Unknown events subcommand: {subcmd}\nUsage: veriswarm events send '<json>' | veriswarm events stream")


# ── test ─────────────────────────────────────────────────────────────────

def cmd_test(args: list[str]):
    """Run security test suite against an agent."""
    if not args:
        _die("Usage: veriswarm test <agent_id> [--category <cat>]")

    agent_id = args[0]
    categories = None
    if "--category" in args:
        idx = args.index("--category")
        if idx + 1 >= len(args):
            _die("--category requires a value")
        categories = [args[idx + 1]]

    body = {}
    if categories:
        body["categories"] = categories

    print(f"Running security tests against {agent_id}...")
    result = api_request(f"/v1/agents/test/{quote(agent_id, safe='')}", method="POST", body=body)

    score = result.get("readiness_score")
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        _die("Security test response had no numeric readiness_score")
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
        _die("Usage: veriswarm scan '<text>' [--type pii|injection]")

    text = args[0]
    scan_type = "both"
    if "--type" in args:
        idx = args.index("--type")
        if idx + 1 >= len(args):
            _die("--type requires a value")
        scan_type = args[idx + 1]
    if scan_type not in ("pii", "injection", "both"):
        _die(f"--type must be pii, injection or both (got {scan_type!r})")

    if scan_type in ("pii", "both"):
        print("PII Scan:")
        result = api_request("/v1/demo/pii-scan", method="POST", body={"text": text})
        if not isinstance(result.get("entities_found"), int):
            _die("PII scan returned an unexpected response")
        entities = result.get("entities", [])
        if entities:
            for e in entities:
                print(f"  \033[91m{e.get('type', '?')}\033[0m (confidence: {e.get('score', 0):.0%})")
            print(f"\nTokenized:\n  {result.get('tokenized_text', text)}")
        else:
            print("  \033[92mNo PII detected\033[0m")

    if scan_type in ("injection", "both"):
        if scan_type == "both":
            print()
        print("Injection Scan:")
        result = api_request("/v1/demo/injection-scan", method="POST", body={"text": text})
        if not isinstance(result.get("is_injection"), bool):
            _die("Injection scan returned an unexpected response")
        if result.get("is_injection"):
            print(f"  \033[91mINJECTION DETECTED\033[0m (confidence: {result.get('confidence', 0):.0%})")
            for p in result.get("patterns_matched", []):
                print(f"  Pattern: {p}")
        else:
            print("  \033[92mClean\033[0m")


# ── scan-ci ──────────────────────────────────────────────────────────────

_CI_MAX_FILE_BYTES = 200_000  # matches the API's CiScanFile content/diff cap
_CI_SEVERITY_COLOR = {
    "critical": "\033[91m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[90m",
    "info": "\033[90m",
}


class BaseRefUnreachable(Exception):
    """The --base ref could not be diffed against."""


def _ci_git_diff(path: str, base_ref: str) -> str | None:
    """Unified diff of `path` vs `base_ref` for Layer 2 checks.

    Returns None when the file is unchanged; raises BaseRefUnreachable when
    the ref cannot be resolved (typo, shallow clone).
    """
    import subprocess

    reachable = False
    for base in (f"origin/{base_ref}", base_ref):
        try:
            out = subprocess.run(
                ["git", "diff", f"{base}...HEAD", "--", path],
                capture_output=True, text=True, timeout=20,
            )
        except Exception:
            continue
        if out.returncode == 0:
            reachable = True
            if out.stdout.strip():
                return out.stdout[:_CI_MAX_FILE_BYTES]
    if not reachable:
        raise BaseRefUnreachable(base_ref)
    return None


def cmd_scan_ci(args: list[str]):
    """Scan CI workflow YAML + Dockerfiles for secret-exfiltration risk.

    Each path's full content drives Layer 1 vulnerable-config checks. Pass
    --base <ref> to also compute a git diff per file for Layer 2
    exfil-pattern checks (network egress next to a secret/env reference in
    added lines).

    Exit codes: 1 when the API returns blocked=true, when the response is
    malformed, or when the scan was incomplete (a given path does not exist
    or is unreadable, or the --base ref cannot be resolved so the Layer 2
    diff checks were skipped). The scan still runs on what is available.
    """
    base_ref = None
    if "--base" in args:
        idx = args.index("--base")
        if idx + 1 >= len(args):
            _die("--base requires a ref")
        base_ref = args[idx + 1]
        args = args[:idx] + args[idx + 2:]

    unknown = [a for a in args if a.startswith("--")]
    if unknown:
        _die(f"Unknown option: {unknown[0]}")
    paths = list(args)
    if not paths:
        _die("Usage: veriswarm scan-ci <path>... [--base <ref>]\n  e.g. veriswarm scan-ci .github/workflows/ci.yml Dockerfile --base main")

    # Expand any literal globs the shell didn't (e.g. quoted patterns).
    import glob as _glob

    incomplete = False
    expanded: list[str] = []
    seen: set[str] = set()
    for p in paths:
        hits = _glob.glob(p, recursive=True)
        files = [h for h in hits if os.path.isfile(h)]
        if not files:
            print(f"WARNING: path does not exist or is not a file: {p}", file=sys.stderr)
            incomplete = True
        for h in files:
            real = os.path.realpath(h)
            if real not in seen:
                seen.add(real)
                expanded.append(h)

    files: list[dict] = []
    base_unreachable = False
    for p in expanded[:200]:  # API caps at 200 files
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                content = f.read()[:_CI_MAX_FILE_BYTES]
        except OSError as exc:
            print(f"WARNING: skipping {p}: {exc}", file=sys.stderr)
            incomplete = True
            continue
        entry: dict = {"path": p, "content": content}
        if base_ref and not base_unreachable:
            try:
                diff = _ci_git_diff(p, base_ref)
            except BaseRefUnreachable:
                base_unreachable = True
                incomplete = True
                print(
                    f"WARNING: base ref '{base_ref}' is not reachable; diff-based "
                    "exfil checks (Layer 2) were SKIPPED. Fetch the ref or check for typos.",
                    file=sys.stderr,
                )
                diff = None
            if diff:
                entry["diff"] = diff
        files.append(entry)
    if len(expanded) > 200:
        print(f"WARNING: {len(expanded) - 200} file(s) beyond the 200-file limit were not scanned", file=sys.stderr)
        incomplete = True

    if not files:
        _die("No readable files to scan.")

    print(f"Scanning {len(files)} file(s) for secret-exfiltration risk...")
    result = api_request("/v1/suite/guard/scan-ci", method="POST", body={"files": files})
    if not isinstance(result.get("findings"), list) or "blocked" not in result:
        _die("CI scan returned an unexpected response")

    findings = result.get("findings", [])
    highest = result.get("highest_severity", "none")
    blocked = bool(result.get("blocked"))
    enforcement = result.get("enforcement_level") or "default"
    reset = "\033[0m"

    if findings:
        print()
        for fnd in findings:
            sev = fnd.get("severity", "info")
            color = _CI_SEVERITY_COLOR.get(sev, "")
            loc = fnd.get("path", "?")
            line = fnd.get("line")
            where = f"{loc}:{line}" if line else loc
            print(f"  {color}[{sev.upper()}]{reset} {fnd.get('check', '?')}  ({fnd.get('layer', '?')})  {where}")
            if fnd.get("recommendation"):
                print(f"      → {fnd['recommendation']}")
    else:
        print(f"  \033[92mClean — no exfiltration patterns detected\033[0m")

    hi_color = _CI_SEVERITY_COLOR.get(highest, "")
    block_color = "\033[91m" if blocked else "\033[92m"
    print()
    print(f"Findings:    {len(findings)}")
    print(f"Highest:     {hi_color}{highest}{reset}")
    print(f"Enforcement: {enforcement}")
    print(f"Blocked:     {block_color}{str(blocked).upper()}{reset}")

    if blocked:
        sys.exit(1)
    if incomplete:
        print("Scan incomplete (see warnings above).", file=sys.stderr)
        sys.exit(1)


# ── reputation ───────────────────────────────────────────────────────────

def cmd_reputation(args: list[str]):
    """Look up an agent's cross-provider reputation."""
    if not args:
        _die("Usage: veriswarm reputation <agent_ref>")

    agent_ref = args[0]
    result = api_request(f"/v1/public/reputation/lookup?agent_ref={quote(agent_ref, safe='')}")

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
        _die("Usage: veriswarm compliance <framework> [--days N]\nFrameworks: eu-ai-act, soc2, iso42001, hipaa")

    framework = args[0]
    days = _int_flag(args, "--days", 90)
    if days < 1:
        _die("--days must be a positive integer")

    print(f"Generating {framework} report (last {days} days)...")
    result = api_request(f"/v1/agents/compliance/{quote(framework, safe='')}?days={days}")

    # Save to file
    safe_framework = "".join(c if c.isalnum() or c in "-_" else "_" for c in framework)
    filename = f"veriswarm-{safe_framework}-{datetime.now().strftime('%Y%m%d')}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Report saved: {filename}")
    print(f"Framework: {result.get('framework', framework)}")
    if result.get("title"):
        print(f"Title: {result['title']}")


if __name__ == "__main__":
    main()
