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
| **OWASP Attestation** | OWASP Agentic AI Top 10 (2026) coverage | Coverage score below `min-owasp-coverage` |
| **Compliance** | One or more framework attestations (19 frameworks available — EU AI Act, NIST AI RMF, ISO 42001, NAIC, NYDFS, SEC §206, CFPB ECOA, OCC SR 11-7, ABA, FRCP, CA SB 243 et al.) | Worst per-framework pass ratio below `min-compliance-pass-ratio`, or a control returns `warn` while `fail-on-compliance-warn` is true |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api-key` | Yes | | VeriSwarm API key (use GitHub secret) |
| `agent-id` | No | | Agent ID for score/test/decision checks |
| `mode` | No | `all` | `score`, `test`, `scan`, `decision`, `owasp`, `compliance`, or `all` |
| `scan-paths` | No | | Glob for files to scan (e.g., `**/*.py`) |
| `fail-on-deny` | No | `true` | Fail if trust decision is deny |
| `fail-on-injection` | No | `true` | Fail if injection detected |
| `fail-on-low-score` | No | `0` | Min security readiness score (0=disabled) |
| `min-trust-score` | No | `0` | Min composite trust score (0=disabled) |
| `min-owasp-coverage` | No | `0` | Min OWASP coverage score (0.0–1.0, 0=disabled) |
| `frameworks` | No | `eu-ai-act,nist-ai-rmf,iso-42001` | Comma-separated framework slugs for `compliance` mode, or `all` to evaluate every framework returned by `GET /v1/compliance/frameworks` |
| `min-compliance-pass-ratio` | No | `0` | Min per-framework pass ratio (0.0–1.0, 0=disabled). Applies to the worst framework in the list. |
| `fail-on-compliance-warn` | No | `false` | Fail if any control's status is `warn` (default: only `fail` blocks the gate) |

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

### Compliance gate — block releases when an attestation regresses

```yaml
- uses: veriswarm/trust-check@v1
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    mode: compliance
    # Pick frameworks that match your buyer base. Use `all` to evaluate
    # every framework returned by GET /v1/compliance/frameworks.
    frameworks: "eu-ai-act,nydfs-part-500,sec-section-206"
    # 0.9 = at most 10% of controls may regress before the build fails.
    min-compliance-pass-ratio: 0.9
    fail-on-compliance-warn: false
```

### OWASP-only gate

```yaml
- uses: veriswarm/trust-check@v1
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    mode: owasp
    min-owasp-coverage: 0.9
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
