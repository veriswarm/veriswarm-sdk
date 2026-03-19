# VeriSwarm Python Reference Client

Lightweight provider client for VeriSwarm API.

## Usage

```python
from veriswarm_client import VeriSwarmClient

client = VeriSwarmClient(
    base_url="https://api.veriswarm.ai",
    api_key="agk_your_provider_key",
)

decision = client.check_decision(
    agent_id="agt_123",
    action_type="post_public_message",
    resource_type="feed",
)

client.ingest_provider_report(
    {
        "agent_id": "agt_123",
        "provider_event_id": "provider-evt-123",
        "report_type": "spam",
        "severity": "high",
        "confidence": 0.91,
        "summary": "Burst spam observed",
    }
)
```

## Implemented methods

- `check_decision(...)`
- `ingest_provider_report(report)`
- `ingest_provider_reports_batch(reports)`
- `register_agent(payload)`
