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

## Authentication

The client accepts three credentials; pass whichever your integration has:

| Option | Header | Use for |
|--------|--------|---------|
| `apiKey` | `x-api-key` | Workspace API key (`vsk_...`) — trust checks, events, Guard scans, workflows, analytics |
| `agentKey` | `x-agent-api-key` | Individual agent key (`vak_...`) — agent self-service (`getMyScores`, `issueCredential`) |
| `accountToken` | `x-account-access-token` | Account session token — account administration |

Some endpoints accept **only** an account session token: team and workspace
management, notifications, IP allowlist, custom domain, scoring profile,
approval approve/reject, JIT approve/deny, workflow step approval, governance
credential store/revoke, shadow-discovery scan/dismiss, compliance schedule,
Passport verify/manifests/delegations, Vault export, Guard finding updates, and
PII session revocation. Calling one of these without `accountToken` throws a
`VeriSwarmError` with `code === "ACCOUNT_TOKEN_REQUIRED"` before any request
is sent.

Kill switch (`killAgent`/`unkillAgent`) and Guard policy CRUD send the API key
(an API key needs the matching Guard scope on the server) and the account
token too when one is configured.

```javascript
const admin = new VeriSwarmClient({
  baseUrl: "https://api.veriswarm.ai",
  apiKey: "vsk_your_workspace_key",
  accountToken: process.env.VERISWARM_ACCOUNT_TOKEN,
});
```

Like API keys, the account token is only ever sent over `https://` (plain
`http://` is allowed for `localhost`, `127.0.0.1`, and `[::1]` only).

## Errors

Every failure is a `VeriSwarmError` (exported from the package) with:

- `status` — HTTP status when a response arrived, otherwise `null`
- `code` — local failure class: `ACCOUNT_TOKEN_REQUIRED`, `TIMEOUT`,
  `NETWORK_ERROR`, `RESPONSE_TOO_LARGE` (bodies are capped at 10 MiB), or
  `INVALID_RESPONSE`
- `payload` — the parsed error body, for API errors (kept off the message so
  it never lands in logs by accident)

```javascript
import { VeriSwarmClient, VeriSwarmError } from "@veriswarm/sdk";

try {
  await client.getAgent("agt_123");
} catch (err) {
  if (err instanceof VeriSwarmError && err.status === 404) {
    // not found
  }
}
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
await client.updateGuardFinding(1, { newStatus: "resolved" }); // open | false_positive | mitigated | resolved

// Guard policies
const policies = await client.listGuardPolicies();
await client.createGuardPolicy({ name: "block-sql", pattern: "DROP TABLE", action: "block" });
await client.updateGuardPolicy(1, { isActive: false });
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

## Manifest signing

Sign a Passport manifest's content (`version`, `capabilities`, `required_tools`, `ai_disclosure`, `principal_ref`) with Ed25519 so the VeriSwarm API can verify it on `createManifest`. VeriSwarm issues the Ed25519 signing key via `POST /v1/suite/passport/webbotauth/keys` and returns the private key **exactly once** — VeriSwarm never stores it. Submit the resulting `signature` and `signing_kid` alongside the manifest fields when creating the manifest.

```javascript
import { signManifest } from "@veriswarm/sdk/manifest-signing.mjs";

const { signature, signing_kid } = signManifest({
  version: "1.0",
  capabilities: ["calendar.read", "email.send"],
  required_tools: ["calendar"],
  ai_disclosure: "You are chatting with an AI assistant operated by Acme Corp.",
  principal_ref: { type: "organization", name: "Acme Corp", identifier: "acme-001" },
  privateKeyPem: process.env.WEBBOTAUTH_PRIVATE_KEY_PEM,
  kid: "key_abc123", // returned alongside the private key at issuance
});

await client.createManifest("agt_123", {
  version: "1.0",
  capabilities: ["calendar.read", "email.send"],
  required_tools: ["calendar"],
  ai_disclosure: "You are chatting with an AI assistant operated by Acme Corp.",
  principal_ref: { type: "organization", name: "Acme Corp", identifier: "acme-001" },
  signature,
  signing_kid,
});
```

The signature covers the canonical JSON of those five fields exactly as the server serializes them — object keys sorted recursively, no whitespace — so `signManifest` must be called with the same field values you send to `createManifest`.

## Web Bot Auth (signed agents)

Sign outbound HTTP requests per the IETF Web Bot Auth profile (RFC 9421 HTTP Message Signatures with Ed25519), so your agent is cryptographically identifiable at the edge (e.g. Cloudflare, Google). VeriSwarm issues the Ed25519 key pair via `POST /v1/suite/passport/webbotauth/keys` and returns the private key **exactly once** in that response — VeriSwarm never stores it. Save it somewhere durable (secret manager, env var) immediately; there is no way to retrieve it again later.

```javascript
import { WebBotAuthSigner } from "@veriswarm/sdk/webbotauth.mjs";

const signer = new WebBotAuthSigner({
  privateKeyPem: process.env.WEBBOTAUTH_PRIVATE_KEY_PEM,
  keyId: "key_abc123", // returned alongside the private key at issuance
});

// Option 1: get the three headers and attach them yourself
const headers = signer.signRequest({ url: "https://target.example/api/data" });
// { "Signature-Agent": ..., "Signature-Input": ..., "Signature": ... }

// Option 2: signed fetch() wrapper
const response = await signer.fetch("https://target.example/api/data", { method: "GET" });
```

Being listed in VeriSwarm's signature directory is VeriSwarm's own verification claim about the key. Being honored as a signed agent by a given edge provider (e.g. Cloudflare) is a separate matter: it additionally requires VeriSwarm's one-time agent-operator registration with that provider, plus ongoing per-agent behavioral compliance (respecting `robots.txt`, keeping request rates reasonable). Signing requests does not itself guarantee bypassing blocks or guaranteed access to any site.

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
await client.setIpAllowlist({ cidrs: ["10.0.0.0/8"] });
await client.setIpAllowlist({ enabled: false }); // disable explicitly; an empty cidrs list is refused
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
const rep = await client.reputationLookup("my-agent"); // email, URL, slug, or other reference
```

## OpenAI-Compatible LLM Proxy

VeriSwarm runs an OpenAI-wire-compatible proxy at `/v1/proxy/chat/completions` and `/v1/proxy/models`. Every request flows through Guard scanning, the LLM router (cost / complexity / fallback policy), and a Vault audit entry before it reaches the chosen provider — and the response wire shape matches `openai.chat.completions.create(...)` byte-for-byte.

So the recommended integration is to keep using the OpenAI SDK and just point its `baseURL` at VeriSwarm:

```javascript
import OpenAI from "openai";

const openai = new OpenAI({
  baseURL: "https://api.veriswarm.ai/v1/proxy",
  apiKey: process.env.VERISWARM_API_KEY,
});

// Streaming and non-streaming both work; chat.completions, models, etc.
const completion = await openai.chat.completions.create({
  model: "claude-sonnet-4-6",  // or any model your router policy allows
  messages: [{ role: "user", content: "What's the trust score for agt_42?" }],
});
```

Use this SDK (`@veriswarm/sdk`) for trust, Guard, Passport, Vault, A2A, approvals, compliance — the surfaces the OpenAI SDK doesn't speak.

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
| `updateGuardPolicy(id, { isActive })` | Activate/deactivate Guard policy |
| `deleteGuardPolicy(id)` | Delete Guard policy |
| `killAgent(agentId, reason)` | Activate kill switch |
| `unkillAgent(agentId)` | Deactivate kill switch |
| `listGuardFindings(agentId?)` | List Guard findings |
| `updateGuardFinding(id, { newStatus })` | Set Guard finding status |
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
| `setIpAllowlist({ cidrs, enabled })` | Set IP allowlist (`enabled: false` disables) |
| `getCustomDomain()` | Get custom domain config |
| `setCustomDomain(domain)` | Set custom domain |
| `verifyCustomDomain()` | Verify custom domain DNS |
| `deleteCustomDomain()` | Remove custom domain |
| `listTeamMembers()` | List team members |
| `inviteTeamMember({ email, role })` | Invite team member |
| `removeTeamMember(userId)` | Remove team member |
| `listWorkspaces()` | List user workspaces |
| `switchWorkspace(tenantId)` | Switch active workspace |
| `reputationLookup(agentRef)` | Shared reputation lookup |
| `getBadgeUrl(slug, options?)` | Embeddable badge URL |
| `getPlatformStatus()` | Platform health check |
| **Web Bot Auth** (`webbotauth.mjs`, separate entry point) | |
| `new WebBotAuthSigner({ privateKeyPem, keyId, signatureAgent? })` | Construct a signer from an issued Ed25519 key |
| `signer.signRequest({ url, created?, expiresInSeconds?, nonce? })` | Returns `{ "Signature-Agent", "Signature-Input", "Signature" }` |
| `signer.fetch(url, init?)` | Signed `fetch()` wrapper |
| `buildSignatureBase({ authority, signatureAgent, created, expires, keyid, nonce?, tag? })` | Low-level RFC 9421 signature base builder |
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
| `scanCi(files)` | CI/CD secret-exfiltration scanner (workflow YAML + Dockerfiles) |
| `scanSessionTurn(sessionId, turnIndex, opts?)` | Multi-turn exfiltration risk scoring (Guard Session Sentry) |
| `verifyResponse({ prompt, response })` | Cross-model verification (ASI06 defense) |
| **A2A Transport** | |
| `provisionA2aKeys(agentId)` | Provision Ed25519 keys for inter-agent signing |
| **Content Provenance (EU AI Act Art. 50)** | |
| `labelContent({ content, agentId?, model? })` | Generate signed manifest for AI-generated content |
| `getContentProvenance(contentHash)` | Public lookup by SHA-256 content hash |
| `verifyContent({ manifest, content? })` | Verify signature + optional content match |
| **ABAC: Agent Attributes** | |
| `getAgentAttributes(agentId)` | Read tenant-defined Cedar attributes |
| `setAgentAttributes(agentId, attributes)` | Replace agent attributes (Cedar-compatible types) |
| **Passport JIT (Just-in-Time Access)** | |
| `requestJitGrant({ agentId, actionType, ... })` | Request ephemeral access grant |
| `approveJitGrant(grantId)` | Approve pending grant (session auth) |
| `denyJitGrant(grantId, { reason? })` | Deny pending grant |
| `revokeJitGrant(grantId, { reason? })` | Revoke approved grant immediately |
| `issueJitToken(grantId)` | Issue ES256 JIT token (one-time) |
| `verifyJitToken({ token, expectedAction?, expectedResourceId? })` | Verify JIT token at use-time (public) |
| `listJitGrants({ agentId?, status? })` | List grants for the tenant |
| `getJitGrant(grantId)` | Get a single grant by id |
| **A2A Protocol** | |
| `listA2aCatalog()` | Trust-ranked agent catalog (excludes killed) |
| `getA2aAgentCard(agentId)` | A2A card with `x-veriswarm-trust` (+ `x-veriswarm-transport`) extension |
| `submitA2aTask(agentId, { requestingAgentId, messages, signature? })` | Submit task to an agent |
| `getA2aTask(agentId, taskId)` | Task status + result |
| `cancelA2aTask(agentId, taskId)` | Cancel an in-flight task |
| **Operator Approval Queue** | |
| `createApproval({ agentId?, requestedAction?, ttlSeconds? })` | Submit approval request |
| `listApprovals({ state?, agentId?, limit? })` | List requests (pending/approved/rejected/expired/all) |
| `getApproval(approvalId)` | Fetch one request |
| `approveApproval(approvalId, { reason? })` | Approve (operator session) |
| `rejectApproval(approvalId, { reason? })` | Reject (operator session) |
