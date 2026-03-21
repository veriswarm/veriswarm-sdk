# VeriSwarm Python SDK

Lightweight Python client for the VeriSwarm trust scoring API. Zero external dependencies — uses only Python stdlib.

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

# Get score history (trend over time)
history = client.get_agent_score_history("agt_123", limit=10)

# Get detailed score breakdown (what contributes to the score)
breakdown = client.get_agent_score_breakdown("agt_123")
print(breakdown["contributing_factors"])

# Get moderation flags
flags = client.get_agent_flags("agt_123")

# Appeal a flag
client.appeal_flag("agt_123", flag_id=42)

# Get capability manifests
manifests = client.get_agent_manifests("agt_123")
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
| `get_agent_manifests(agent_id)` | Capability manifests |
| `get_platform_status()` | Platform health check |
