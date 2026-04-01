# VeriSwarm Trust Check — GitHub Action

Run trust score checks, security tests, PII scans, and injection scans against your AI agents in CI.

## Quick Start

```yaml
name: Trust Check
on: [push, pull_request]

jobs:
  veriswarm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: veriswarm/trust-check@v1
        with:
          api-key: ${{ secrets.VERISWARM_API_KEY }}
          agent-id: "agt_your_agent"
```

## What It Checks

| Check | Description | Fails when |
|-------|-------------|------------|
| **Trust Score** | Current agent trust score | Below `min-trust-score` |
| **Decision** | Trust decision for an action | Decision is `deny` |
| **Security Tests** | 33 adversarial tests | Readiness score below `fail-on-low-score` |
| **PII Scan** | Scan files for personal data | PII found in scanned files |
| **Injection Scan** | Scan files for injection patterns | Injection detected |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | | VeriSwarm API key (use GitHub secret) |
| `agent-id` | No | | Agent ID for score/test/decision checks |
| `mode` | No | `all` | `score`, `test`, `scan`, `decision`, or `all` |
| `scan-paths` | No | | Glob for files to scan (e.g., `**/*.py`) |
| `fail-on-deny` | No | `true` | Fail if trust decision is deny |
| `fail-on-injection` | No | `true` | Fail if injection detected |
| `fail-on-low-score` | No | `0` | Min security readiness score (0=disabled) |
| `min-trust-score` | No | `0` | Min composite trust score (0=disabled) |

## Examples

### Score check only

```yaml
- uses: veriswarm/trust-check@v1
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    agent-id: "agt_my_agent"
    mode: score
    min-trust-score: 60
```

### PII scan on Python files

```yaml
- uses: veriswarm/trust-check@v1
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    mode: scan
    scan-paths: "**/*.py,**/*.txt,**/*.md"
```

### Security tests with threshold

```yaml
- uses: veriswarm/trust-check@v1
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    agent-id: "agt_my_agent"
    mode: test
    fail-on-low-score: 70
```

### Full check on deploy

```yaml
- uses: veriswarm/trust-check@v1
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    agent-id: "agt_production"
    action-type: deploy
    fail-on-deny: true
    min-trust-score: 70
    fail-on-low-score: 80
```

## Outputs

| Output | Description |
|--------|-------------|
| `trust-score` | Composite trust score |
| `policy-tier` | Policy tier (allow/review/deny) |
| `decision` | Trust decision for the action |
| `readiness-score` | Security test readiness (0-100) |
| `pii-found` | Whether PII was found |
| `injection-found` | Whether injection was found |
| `summary` | Markdown summary of all checks |
