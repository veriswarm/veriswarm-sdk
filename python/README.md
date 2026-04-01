# VeriSwarm Python SDK

Lightweight Python client for the VeriSwarm trust scoring API. Zero external dependencies -- uses only Python stdlib.

## Install

```bash
pip install veriswarm
# or copy veriswarm_client.py directly into your project
```

## Quick Start

```python
from veriswarm_client import VeriSwarmClient

client = VeriSwarmClient(
    base_url="https://api.veriswarm.ai",
    api_key="vsk_your_workspace_key",
)

# Check a trust decision before a sensitive action
decision = client.check_decision(
    agent_id="agt_123",
    action_type="post_public_message",
    resource_type="feed",
)
print(decision["decision"])  # "allow", "review", or "deny"
```

## Event Ingestion

```python
# Single event
client.ingest_event(
    event_id="evt_unique_123",
    agent_id="agt_123",
    source_type="platform",
    event_type="message.sent",
    occurred_at="2026-03-20T12:00:00Z",
    payload={"content_length": 140, "channel": "general"},
)

# Batch (up to 50 events)
client.ingest_events_batch([
    {"event_id": "evt_1", "agent_id": "agt_123", "source_type": "platform",
     "event_type": "message.sent", "occurred_at": "2026-03-20T12:00:00Z", "payload": {}},
    {"event_id": "evt_2", "agent_id": "agt_123", "source_type": "platform",
     "event_type": "tool.invoked", "occurred_at": "2026-03-20T12:01:00Z", "payload": {}},
])
```

## Agent Management

```python
# Register a new agent
agent = client.register_agent({
    "tenant_id": "ten_your_workspace",
    "slug": "my-assistant",
    "display_name": "My Assistant",
    "description": "A helpful coding assistant",
})

# Get agent profile
profile = client.get_agent("agt_123")

# Get current trust scores
scores = client.get_agent_scores("agt_123")
print(f"Risk: {scores['risk']['score']}, Tier: {scores['policy_tier']}")

# Get score history, breakdown, flags, timeline, manifests
history = client.get_agent_score_history("agt_123", limit=10)
breakdown = client.get_agent_score_breakdown("agt_123")
flags = client.get_agent_flags("agt_123")
timeline = client.get_agent_timeline("agt_123", limit=20)
manifests = client.get_agent_manifests("agt_123")

# Appeal a flag
client.appeal_flag("agt_123", flag_id=42)

# Agent API key management
keys = client.get_agent_api_keys("agt_123")
client.rotate_agent_api_key("agt_123")
client.revoke_agent_api_key("agt_123", key_id="key_456")
```

## Provider Reports

```python
# Submit a trust signal from your platform
client.ingest_provider_report({
    "agent_id": "agt_123",
    "provider_event_id": "provider-evt-456",
    "report_type": "spam",
    "severity": "high",
    "confidence": 0.91,
    "summary": "Burst spam detected in #general",
})
```

## Guard (Security)

```python
# PII tokenization (before sending to LLM)
result = client.tokenize_pii(text="Contact john@acme.com for details")
print(result["tokenized_text"])  # "Contact [VS:EMAIL:a1b2c3] for details"

# Rehydrate PII (after LLM processing)
original = client.rehydrate_pii(text=result["tokenized_text"], session_id=result["session_id"])

# PII session management
session = client.get_pii_session(result["session_id"])
client.revoke_pii_session(result["session_id"])

# Prompt injection scanning
scan = client.scan_injection(text="Ignore previous instructions and...")
print(scan["is_injection"])  # True

# Kill switch
client.kill_agent("agt_123", reason="Suspicious behavior detected")
client.unkill_agent("agt_123")

# Guard findings
findings = client.list_guard_findings(agent_id="agt_123")
client.update_guard_finding(finding_id=1, updates={"status": "resolved"})

# Guard policies
policies = client.list_guard_policies()
client.create_guard_policy({"name": "block-sql", "pattern": "DROP TABLE", "action": "block"})
client.update_guard_policy(policy_id=1, updates={"enabled": False})
client.delete_guard_policy(policy_id=1)
```

## Passport (Identity)

```python
# Verify agent identity
client.verify_agent_identity("agt_123")

# Delegations
client.create_delegation({"from_agent": "agt_123", "to_agent": "agt_456", "scope": "read"})
delegations = client.list_delegations()
client.revoke_delegation(delegation_id=1)

# Manifests
client.create_manifest("agt_123", {"capabilities": ["search", "summarize"]})
manifests = client.get_manifests("agt_123")
```

## Vault (Audit Ledger)

```python
# Query the immutable audit ledger
entries = client.query_vault_ledger(agent_id="agt_123", limit=20)

# Verify hash-chain integrity
verification = client.verify_vault_chain(limit=100)

# Export
job = client.export_vault(export_type="csv")
status = client.get_vault_export_status(job["job_id"])
```

## Credentials (Portable JWT)

```python
# Issue a signed trust credential (requires agent key auth)
result = client.issue_credential()
jwt_token = result["credential"]

# Verify a credential from another agent
verified = client.verify_credential("eyJhbGciOiJFUzI1NiI...")
print(verified["veriswarm"]["policy_tier"])  # "tier_2"
```

## Agent Self-Service

```python
# Get own scores with improvement guidance
scores = client.get_my_scores()
print(scores["guidance"]["actions"])  # actionable improvement steps
```

## Scoring Profiles

```python
# Get current tenant profile
profile = client.get_scoring_profile()
print(profile["profile_code"])  # "general"

# Set tenant profile
client.set_scoring_profile("high_security")
```

## Notifications

```python
notifications = client.list_notifications()
client.mark_notification_read(notification_id=1)
client.mark_all_notifications_read()
```

## IP Allowlist

```python
# Get current allowlist
allowlist = client.get_ip_allowlist()

# Set allowlist
client.set_ip_allowlist(cidrs=["10.0.0.0/8", "192.168.1.0/24"], enabled=True)
```

## Custom Domains

```python
client.set_custom_domain(domain="trust.mycompany.com")
client.verify_custom_domain()
domain = client.get_custom_domain()
client.delete_custom_domain()
```

## Team Management

```python
members = client.list_team_members()
client.invite_team_member(email="alice@acme.com", role="admin")
client.remove_team_member(user_id="usr_789")
```

## Workspaces

```python
workspaces = client.list_workspaces()
client.switch_workspace(tenant_id="ten_456")
```

## Trust Badges

```python
url = client.get_badge_url("my-agent", style="compact", theme="dark")
# "https://api.veriswarm.ai/v1/badge/my-agent.svg?style=compact&theme=dark"
```

## Reputation Lookup

```python
rep = client.reputation_lookup(slug="my-agent")
```

## Platform Status

```python
status = client.get_platform_status()
print(status["status"])  # "operational" or "degraded"
```

## All Methods

| Method | Description |
|--------|-------------|
| `check_decision(...)` | Trust decision check (allow/review/deny) |
| `ingest_event(...)` | Single event ingestion |
| `ingest_events_batch(events)` | Batch event ingestion (max 50) |
| `ingest_provider_report(report)` | Provider trust signal |
| `ingest_provider_reports_batch(reports)` | Batch provider reports |
| `register_agent(payload)` | Register a new agent |
| `get_agent(agent_id)` | Public agent profile |
| `get_agent_scores(agent_id)` | Current trust scores |
| `get_agent_score_history(agent_id)` | Score trend over time |
| `get_agent_score_breakdown(agent_id)` | Score contributing factors |
| `get_agent_flags(agent_id)` | Active moderation flags |
| `appeal_flag(agent_id, flag_id)` | Appeal a moderation flag |
| `get_agent_manifests(agent_id)` | Public capability manifests |
| `get_agent_timeline(agent_id)` | Agent event timeline |
| `get_agent_api_keys(agent_id)` | List agent API keys |
| `rotate_agent_api_key(agent_id)` | Rotate agent API key |
| `revoke_agent_api_key(agent_id, key_id)` | Revoke agent API key |
| `tokenize_pii(...)` | Guard PII tokenization |
| `rehydrate_pii(...)` | Guard PII rehydration |
| `get_pii_session(session_id)` | Get PII session details |
| `revoke_pii_session(session_id)` | Revoke PII session |
| `scan_injection(text)` | Guard injection scanning |
| `list_guard_policies()` | List Guard policies |
| `create_guard_policy(policy)` | Create Guard policy |
| `update_guard_policy(id, updates)` | Update Guard policy |
| `delete_guard_policy(id)` | Delete Guard policy |
| `kill_agent(agent_id, reason)` | Activate kill switch |
| `unkill_agent(agent_id)` | Deactivate kill switch |
| `list_guard_findings(...)` | List Guard findings |
| `update_guard_finding(id, updates)` | Update Guard finding |
| `verify_agent_identity(agent_id)` | Passport identity verification |
| `create_delegation(delegation)` | Create Passport delegation |
| `list_delegations()` | List Passport delegations |
| `revoke_delegation(id)` | Revoke Passport delegation |
| `create_manifest(agent_id, manifest)` | Create agent manifest |
| `get_manifests(agent_id)` | Get agent manifests |
| `query_vault_ledger(...)` | Query Vault audit ledger |
| `verify_vault_chain(...)` | Verify Vault hash chain |
| `export_vault(...)` | Create Vault export job |
| `get_vault_export_status(job_id)` | Check Vault export status |
| `issue_credential()` | Issue portable JWT credential |
| `verify_credential(credential)` | Verify JWT credential |
| `get_my_scores()` | Own scores with guidance |
| `get_scoring_profile()` | Get tenant scoring profile |
| `set_scoring_profile(code, overrides)` | Set tenant scoring profile |
| `list_notifications()` | List notifications |
| `mark_notification_read(id)` | Mark notification read |
| `mark_all_notifications_read()` | Mark all notifications read |
| `get_ip_allowlist()` | Get IP allowlist |
| `set_ip_allowlist(cidrs, enabled)` | Set IP allowlist |
| `get_custom_domain()` | Get custom domain config |
| `set_custom_domain(domain)` | Set custom domain |
| `verify_custom_domain()` | Verify custom domain DNS |
| `delete_custom_domain()` | Remove custom domain |
| `list_team_members()` | List team members |
| `invite_team_member(email, role)` | Invite team member |
| `remove_team_member(user_id)` | Remove team member |
| `list_workspaces()` | List user workspaces |
| `switch_workspace(tenant_id)` | Switch active workspace |
| `reputation_lookup(slug)` | Shared reputation lookup |
| `get_badge_url(slug, ...)` | Embeddable badge URL |
| `get_platform_status()` | Platform health check |
| **Cortex Workflows** | |
| `list_workflows(is_active=)` | List workflows |
| `get_workflow(workflow_id)` | Get workflow + recent executions |
| `create_workflow(name, slug, definition)` | Create from definition dict |
| `update_workflow(id, name=, definition=)` | Update workflow |
| `delete_workflow(workflow_id)` | Delete workflow |
| `activate_workflow(workflow_id)` | Enable triggers |
| `deactivate_workflow(workflow_id)` | Disable triggers |
| `run_workflow(workflow_id, inputs=)` | Manual trigger |
| `get_execution(execution_id)` | Execution detail + steps |
| `list_executions(workflow_id, status=)` | List executions |
| `cancel_execution(execution_id)` | Cancel running |
| `retry_execution(execution_id)` | Retry failed |
| `approve_step(exec_id, step_id, action=)` | Human review action |
| `list_workflow_templates()` | Available templates |
| `deploy_template(template_id)` | Deploy template |
