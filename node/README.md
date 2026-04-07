# VeriSwarm Node.js SDK

Lightweight Node.js client for the VeriSwarm trust scoring API. Zero dependencies -- uses native `fetch` (Node.js 18+).

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
]);
```

## Agent Management

```javascript
// Register a new agent
const agent = await client.registerAgent({
  tenant_id: "ten_your_workspace",
  slug: "my-assistant",
  display_name: "My Assistant",
});

// Get agent profile, scores, history, breakdown, flags, timeline
const profile = await client.getAgent("agt_123");
const scores = await client.getAgentScores("agt_123");
const history = await client.getAgentScoreHistory("agt_123", { limit: 10 });
const breakdown = await client.getAgentScoreBreakdown("agt_123");
const flags = await client.getAgentFlags("agt_123");
const timeline = await client.getAgentTimeline("agt_123", { limit: 20 });
const manifests = await client.getAgentManifests("agt_123");

// Appeal a flag
await client.appealFlag("agt_123", 42);

// Agent API key management
const keys = await client.getAgentApiKeys("agt_123");
await client.rotateAgentApiKey("agt_123");
await client.revokeAgentApiKey("agt_123", "key_456");
```

## Guard (Security)

```javascript
// PII tokenization
const result = await client.tokenizePii({ text: "Contact john@acme.com" });
const original = await client.rehydratePii({ text: result.tokenized_text, sessionId: result.session_id });

// PII session management
const session = await client.getPiiSession(result.session_id);
await client.revokePiiSession(result.session_id);

// Injection scanning
const scan = await client.scanInjection({ text: "Ignore previous instructions..." });

// Kill switch
await client.killAgent("agt_123", "Suspicious behavior");
await client.unkillAgent("agt_123");

// Guard findings
const findings = await client.listGuardFindings("agt_123");
await client.updateGuardFinding(1, { status: "resolved" });

// Guard policies
const policies = await client.listGuardPolicies();
await client.createGuardPolicy({ name: "block-sql", pattern: "DROP TABLE", action: "block" });
await client.updateGuardPolicy(1, { enabled: false });
await client.deleteGuardPolicy(1);
```

## Passport (Identity)

```javascript
// Verify agent identity
await client.verifyAgentIdentity("agt_123");

// Delegations
await client.createDelegation({ from_agent: "agt_123", to_agent: "agt_456", scope: "read" });
const delegations = await client.listDelegations();
await client.revokeDelegation(1);

// Manifests
await client.createManifest("agt_123", { capabilities: ["search", "summarize"] });
const manifests = await client.getManifests("agt_123");
```

## Vault (Audit Ledger)

```javascript
const entries = await client.queryVaultLedger({ agentId: "agt_123", limit: 20 });
const verification = await client.verifyVaultChain({ limit: 100 });
const job = await client.exportVault({ exportType: "csv" });
const status = await client.getVaultExportStatus(job.job_id);
```

## Portable Credentials

```javascript
const result = await client.issueCredential();
const verified = await client.verifyCredential("eyJhbGciOiJFUzI1NiI...");
```

## Scoring Profiles

```javascript
const profile = await client.getScoringProfile();
await client.setScoringProfile("high_security");
await client.setScoringProfile("high_security", { risk: { secret_hygiene_failures: 0.40 } });
```

## Notifications

```javascript
const notifications = await client.listNotifications();
await client.markNotificationRead(1);
await client.markAllNotificationsRead();
```

## IP Allowlist

```javascript
const allowlist = await client.getIpAllowlist();
await client.setIpAllowlist({ cidrs: ["10.0.0.0/8"], enabled: true });
```

## Custom Domains

```javascript
await client.setCustomDomain("trust.mycompany.com");
await client.verifyCustomDomain();
const domain = await client.getCustomDomain();
await client.deleteCustomDomain();
```

## Team Management

```javascript
const members = await client.listTeamMembers();
await client.inviteTeamMember({ email: "alice@acme.com", role: "admin" });
await client.removeTeamMember("usr_789");
```

## Workspaces

```javascript
const workspaces = await client.listWorkspaces();
await client.switchWorkspace("ten_456");
```

## Trust Badges

```javascript
const url = client.getBadgeUrl("my-agent", { style: "card", theme: "dark" });
```

## Reputation Lookup

```javascript
const rep = await client.reputationLookup("my-agent");
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
| `getAgentManifests(agentId)` | Public capability manifests |
| `getAgentTimeline(agentId)` | Agent event timeline |
| `getAgentApiKeys(agentId)` | List agent API keys |
| `rotateAgentApiKey(agentId)` | Rotate agent API key |
| `revokeAgentApiKey(agentId, keyId)` | Revoke agent API key |
| `tokenizePii(...)` | Guard PII tokenization |
| `rehydratePii(...)` | Guard PII rehydration |
| `getPiiSession(sessionId)` | Get PII session details |
| `revokePiiSession(sessionId)` | Revoke PII session |
| `scanInjection({ text })` | Guard injection scanning |
| `listGuardPolicies()` | List Guard policies |
| `createGuardPolicy(policy)` | Create Guard policy |
| `updateGuardPolicy(id, updates)` | Update Guard policy |
| `deleteGuardPolicy(id)` | Delete Guard policy |
| `killAgent(agentId, reason)` | Activate kill switch |
| `unkillAgent(agentId)` | Deactivate kill switch |
| `listGuardFindings(agentId?)` | List Guard findings |
| `updateGuardFinding(id, updates)` | Update Guard finding |
| `verifyAgentIdentity(agentId)` | Passport identity verification |
| `createDelegation(delegation)` | Create Passport delegation |
| `listDelegations()` | List Passport delegations |
| `revokeDelegation(id)` | Revoke Passport delegation |
| `createManifest(agentId, manifest)` | Create agent manifest |
| `getManifests(agentId)` | Get agent manifests |
| `queryVaultLedger(...)` | Query Vault audit ledger |
| `verifyVaultChain(...)` | Verify Vault hash chain |
| `exportVault(...)` | Create Vault export job |
| `getVaultExportStatus(jobId)` | Check Vault export status |
| `issueCredential()` | Issue portable JWT credential |
| `verifyCredential(credential)` | Verify JWT credential |
| `getMyScores()` | Own scores with guidance |
| `getScoringProfile()` | Get tenant scoring profile |
| `setScoringProfile(code, overrides?)` | Set tenant scoring profile |
| `listNotifications()` | List notifications |
| `markNotificationRead(id)` | Mark notification read |
| `markAllNotificationsRead()` | Mark all notifications read |
| `getIpAllowlist()` | Get IP allowlist |
| `setIpAllowlist({ cidrs, enabled })` | Set IP allowlist |
| `getCustomDomain()` | Get custom domain config |
| `setCustomDomain(domain)` | Set custom domain |
| `verifyCustomDomain()` | Verify custom domain DNS |
| `deleteCustomDomain()` | Remove custom domain |
| `listTeamMembers()` | List team members |
| `inviteTeamMember({ email, role })` | Invite team member |
| `removeTeamMember(userId)` | Remove team member |
| `listWorkspaces()` | List user workspaces |
| `switchWorkspace(tenantId)` | Switch active workspace |
| `reputationLookup(slug)` | Shared reputation lookup |
| `getBadgeUrl(slug, options?)` | Embeddable badge URL |
| `getPlatformStatus()` | Platform health check |
| **Cortex Workflows** | |
| `listWorkflows({ isActive? })` | List workflows |
| `getWorkflow(workflowId)` | Get workflow + recent executions |
| `createWorkflow({ name, slug, definition })` | Create from definition |
| `updateWorkflow(workflowId, updates)` | Update workflow |
| `deleteWorkflow(workflowId)` | Delete workflow |
| `activateWorkflow(workflowId)` | Enable triggers |
| `deactivateWorkflow(workflowId)` | Disable triggers |
| `runWorkflow(workflowId, { inputs? })` | Manual trigger |
| `getExecution(executionId)` | Execution detail + steps |
| `listExecutions(workflowId, { status? })` | List executions |
| `cancelExecution(executionId)` | Cancel running |
| `retryExecution(executionId)` | Retry failed |
| `approveStep(execId, stepId, { action })` | Human review action |
| `listWorkflowTemplates()` | Available templates |
| `deployTemplate(templateId)` | Deploy template |
| **Compliance** | |
| `getOwaspAttestation()` | OWASP Agentic AI Top 10 (2026) per-tenant coverage report |
| `listComplianceFrameworks()` | List supported frameworks |
| `getComplianceReport(frameworkId)` | EU AI Act / NIST AI RMF / ISO 42001 reports |
| **Cedar Policies** | |
| `listCedarPolicies()` | List active Cedar policies |
| `createCedarPolicy({ name, policyText })` | Create policy (Max+) |
| `getCedarPolicy(policyId)` | Get policy with full text |
| `updateCedarPolicy(policyId, updates)` | Update policy (versions bumped) |
| `deleteCedarPolicy(policyId)` | Soft-delete policy |
| `validateCedarPolicy(policyText)` | Validate Cedar syntax |
| `testCedarPolicy({ policyText, ... })` | Dry-run policy against test input |
| **SRE: Circuit Breakers + SLOs** | |
| `getSreDashboard()` | Combined SRE dashboard |
| `getCircuitBreakers()` | Provider circuit breaker states |
| `resetCircuitBreaker(provider, model)` | Manually close a breaker |
| `getErrorBudget()` | SLO error budget status |
| `getSloConfig()` | Get SLO targets |
| `updateSloConfig({ ... })` | Update availability/latency targets |
| **Context Governance** | |
| `getContextDashboard({ days })` | Topics + quality + gaps |
| `getContextTopics({ days, limit })` | Event topic distribution |
| `getContextQuality()` | KB coverage + per-agent health |
| `getContextGaps({ days })` | Detect knowledge-gap agents |
| **Guard Extensions** | |
| `scanMcpTools(tools)` | Pre-deploy MCP tool scanner (6 checks) |
| `verifyResponse({ prompt, response })` | Cross-model verification (ASI06 defense) |
| **A2A Transport** | |
| `provisionA2aKeys(agentId)` | Provision Ed25519 keys for inter-agent signing |
