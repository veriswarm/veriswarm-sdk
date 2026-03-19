# VeriSwarm Node Reference Client

Lightweight provider client for VeriSwarm API (Node 18+).

## Usage

```js
import { VeriSwarmClient } from "./veriswarm_client.mjs";

const client = new VeriSwarmClient({
  baseUrl: "https://api.veriswarm.ai",
  apiKey: process.env.VERISWARM_API_KEY,
});

const decision = await client.checkDecision({
  agentId: "agt_123",
  actionType: "post_public_message",
  resourceType: "feed",
});

await client.ingestProviderReport({
  agent_id: "agt_123",
  provider_event_id: "provider-evt-123",
  report_type: "spam",
  severity: "high",
  confidence: 0.91,
  summary: "Burst spam observed",
});
```

## Implemented methods

- `checkDecision({ agentId, actionType, resourceType })`
- `ingestProviderReport(report)`
- `ingestProviderReportsBatch(reports)`
- `registerAgent(payload)`
