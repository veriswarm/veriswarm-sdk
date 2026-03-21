# VeriSwarm Node.js SDK

Lightweight Node.js client for the VeriSwarm trust scoring API. Zero dependencies — uses native `fetch` (Node.js 18+).

## Install

```bash
npm install @veriswarm/sdk
# or copy veriswarm_client.mjs directly into your project
```

## Quick Start

```javascript
import { VeriSwarmClient } from "@veriswarm/sdk";

const client = new VeriSwarmClient({
  baseUrl: "https://api.veriswarm.ai",
  apiKey: "vsk_your_workspace_key",
});

// Check a trust decision before a sensitive action
const decision = await client.checkDecision({
  agentId: "agt_123",
  actionType: "post_public_message",
  resourceType: "feed",
});
console.log(decision.decision); // "allow", "review", or "deny"
```

## Event Ingestion

```javascript
// Single event
await client.ingestEvent({
  eventId: "evt_unique_123",
  agentId: "agt_123",
  sourceType: "platform",
  eventType: "message.sent",
  occurredAt: new Date().toISOString(),
  payload: { contentLength: 140, channel: "general" },
});

// Batch (up to 50 events)
await client.ingestEventsBatch([
  { event_id: "evt_1", agent_id: "agt_123", source_type: "platform",
    event_type: "message.sent", occurred_at: new Date().toISOString(), payload: {} },
  { event_id: "evt_2", agent_id: "agt_123", source_type: "platform",
    event_type: "tool.invoked", occurred_at: new Date().toISOString(), payload: {} },
]);
```

## Agent Management

```javascript
// Register a new agent
const agent = await client.registerAgent({
  tenant_id: "ten_your_workspace",
  slug: "my-assistant",
  display_name: "My Assistant",
  description: "A helpful coding assistant",
});

// Get agent profile
const profile = await client.getAgent("agt_123");

// Get current trust scores
const scores = await client.getAgentScores("agt_123");
console.log(`Risk: ${scores.risk.score}, Tier: ${scores.policy_tier}`);

// Get score history (trend over time)
const history = await client.getAgentScoreHistory("agt_123", { limit: 10 });

// Get detailed score breakdown
const breakdown = await client.getAgentScoreBreakdown("agt_123");
console.log(breakdown.contributing_factors);

// Get moderation flags
const flags = await client.getAgentFlags("agt_123");

// Appeal a flag
await client.appealFlag("agt_123", 42);

// Get capability manifests
const manifests = await client.getAgentManifests("agt_123");
```

## Provider Reports

```javascript
// Submit a trust signal from your platform
await client.ingestProviderReport({
  agent_id: "agt_123",
  provider_event_id: "provider-evt-456",
  report_type: "spam",
  severity: "high",
  confidence: 0.91,
  summary: "Burst spam detected in #general",
});
```

## Platform Status

```javascript
const status = await client.getPlatformStatus();
console.log(status.status); // "operational" or "degraded"
```

## All Methods

| Method | Description |
|--------|-------------|
| `checkDecision(...)` | Trust decision check (allow/review/deny) |
| `ingestEvent(...)` | Single event ingestion |
| `ingestEventsBatch(events)` | Batch event ingestion (max 50) |
| `ingestProviderReport(report)` | Provider trust signal |
| `ingestProviderReportsBatch(reports)` | Batch provider reports |
| `registerAgent(payload)` | Register a new agent |
| `getAgent(agentId)` | Public agent profile |
| `getAgentScores(agentId)` | Current trust scores |
| `getAgentScoreHistory(agentId)` | Score trend over time |
| `getAgentScoreBreakdown(agentId)` | Score contributing factors |
| `getAgentFlags(agentId)` | Active moderation flags |
| `appealFlag(agentId, flagId)` | Appeal a moderation flag |
| `getAgentManifests(agentId)` | Capability manifests |
| `getPlatformStatus()` | Platform health check |
