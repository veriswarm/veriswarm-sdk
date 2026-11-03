# VeriSwarm Trust Check — GitHub Action

Run trust score checks, security tests, PII scans, and injection scans against your AI agents in CI.

## Quick Start

The action lives in this repository's `github-action/` directory, so reference it by that path. Pin a commit SHA instead of `@main` for reproducible, tamper-resistant CI.

```yaml
name: Trust Check
on: [push, pull_request]

jobs:
  veriswarm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: veriswarm/veriswarm-sdk/github-action@main
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
| `mode` | No | `all` | `score`, `test`, `scan`, `decision`, `owasp`, `compliance`, `ci-exfil`, or `all`. An unknown mode fails the run. `score`, `test` and `decision` fail the run if `agent-id` is empty; `all` skips them in that case. |
| `scan-paths` | No | | Glob for files to scan (e.g., `**/*.py`) |
| `fail-on-deny` | No | `true` | Fail if trust decision is deny |
| `fail-on-injection` | No | `true` | Fail if injection detected |
| `fail-on-pii` | No | `true` | Fail if PII is detected in scanned files |
| `fail-on-low-score` | No | `0` | Min security readiness score (0=disabled) |
| `min-trust-score` | No | `0` | Min composite trust score, 0-100 (0=disabled). See "Trust score" below. |
| `min-owasp-coverage` | No | `0` | Min OWASP coverage score (0.0–1.0, 0=disabled) |
| `frameworks` | No | `eu-ai-act,nist-ai-rmf,iso-42001` | Comma-separated framework slugs for `compliance` mode, or `all` to evaluate every framework returned by `GET /v1/compliance/frameworks` |
| `min-compliance-pass-ratio` | No | `0` | Min per-framework pass ratio (0.0–1.0, 0=disabled). Applies to the worst framework in the list. |
| `fail-on-compliance-warn` | No | `false` | Fail if any control's status is `warn` (default: only `fail` blocks the gate) |

## Examples

### Score check only

```yaml
- uses: veriswarm/veriswarm-sdk/github-action@main
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    agent-id: "agt_my_agent"
    mode: score
    min-trust-score: 60
```

### PII scan on Python files

```yaml
- uses: veriswarm/veriswarm-sdk/github-action@main
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    mode: scan
    scan-paths: "**/*.py,**/*.txt,**/*.md"
```

### Security tests with threshold

```yaml
- uses: veriswarm/veriswarm-sdk/github-action@main
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    agent-id: "agt_my_agent"
    mode: test
    fail-on-low-score: 70
```

### Full check on deploy

```yaml
- uses: veriswarm/veriswarm-sdk/github-action@main
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
- uses: veriswarm/veriswarm-sdk/github-action@main
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
- uses: veriswarm/veriswarm-sdk/github-action@main
  with:
    api-key: ${{ secrets.VERISWARM_API_KEY }}
    mode: owasp
    min-owasp-coverage: 0.9
```

## Outputs

| Output | Description |
|--------|-------------|
| `trust-score` | Composite trust score |
| `policy-tier` | Policy tier (`tier_0` ... `tier_3`, `tier_x`) |
| `decision` | Trust decision for the action |
| `readiness-score` | Security test readiness (0-100) |
| `pii-found` | Whether PII was found |
| `pii-count` | Number of distinct PII entities found |
| `injection-found` | Whether injection was found |
| `summary` | Markdown summary of all checks |

Every output is set only when the corresponding check ran and produced a valid result.

## Trust score

`min-trust-score` gates on the server's composite trust score (`composite_trust`), read from
`GET /v1/public/agents/{id}/scores/breakdown` as `scores.composite_trust` (0-100). It is the
profile-weighted blend of the identity, (inverted) risk, reliability and autonomy scores, plus calibration
when the agent's scoring profile uses it. The Action also prints the individual dimension scores. If the
agent has no score yet, or the response has no numeric composite, the check cannot be evaluated.

## Failing closed

When an enforcement input is set, a check that cannot be evaluated fails the run instead of passing:

| Check | Enforced when | Fails on |
|-------|---------------|----------|
| score | `min-trust-score` > 0 | API error, missing/non-numeric composite, or below minimum |
| decision | `fail-on-deny` is true (default) | API error, unrecognised decision, or `deny` |
| test | `fail-on-low-score` > 0 | API error, missing readiness score, or below threshold |
| owasp | `min-owasp-coverage` > 0 | API error, missing coverage score, or below minimum |
| scan | `fail-on-injection` / `fail-on-pii` are true (default) | PII found (`fail-on-pii`), injection found (`fail-on-injection`), or, if either is on, any scan request that errored, was rate limited past retries, returned an unexpected shape, or any file that could not be fully scanned |
| ci-exfil | `fail-on-ci-exfil` is true (default) | API error, malformed response, or `blocked` |

With the enforcement input off, the same problems are logged as warnings only.

Numeric inputs must be valid numbers; anything else stops the run with a clear error.

### Scan mode limits

The scan endpoints accept at most 2000 characters per request and 30 requests per minute. The Action splits
each file into chunks of at most 2000 characters (consecutive chunks overlap by 200 so a phrase cannot hide on a boundary), paces requests, and backs off on HTTP 429; a request that
is still rate limited after retries is a failure, never "clean". Only the first 20,000 characters of each file
and the first 50 matched files are scanned; anything beyond that is reported and counts as an incomplete scan.
Files matching a sensitive-name denylist (`.env`, keys, `.git/`) or outside the workspace are skipped.

### ci-exfil mode

Scans workflow YAML and Dockerfiles. On pull requests it also sends a per-file diff against the base branch;
if the base ref is not reachable (a shallow checkout), the Action logs a warning and skips the diff checks.
Use `fetch-depth: 0` on `actions/checkout` to enable them.
