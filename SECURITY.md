# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the VeriSwarm SDKs or MCP server, please report it responsibly.

**Email:** security@veriswarm.ai

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected package(s) and version(s)
- Impact assessment

**Do NOT** open a public GitHub issue for security vulnerabilities.

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix for critical issues**: Within 7 days
- **Fix for non-critical issues**: Within 30 days

## Scope

This policy covers:
- `@veriswarm/sdk` (Node.js SDK)
- `veriswarm` (Python SDK)
- `veriswarm-mcp` (MCP Server)
- `@veriswarm/openclaw-plugin` (OpenClaw plugin)
- `@veriswarm/schemas` (JSON schemas)
- `veriswarm-action` (GitHub Action)
- LangChain adapter (`veriswarm[langchain]`)

For vulnerabilities in the VeriSwarm platform itself (API, web dashboard, infrastructure), please email security@veriswarm.ai directly.

## Security Posture

Security-relevant features of the VeriSwarm platform:

- **Authentication:** Argon2id password hashing, ES256 JWT credentials, Ed25519 inter-agent message signing, MFA with TOTP and recovery codes
- **Tenant isolation:** per-tenant scoping enforced at the database query level on every endpoint
- **Rate limiting:** per-IP and per-tenant limits on all authenticated routes
- **IP allowlists:** optional per-tenant CIDR-based allowlist enforced via global middleware
- **Encryption at rest:** Fernet/AES-256 for PII tokenization and BYOK API keys
- **Encryption in transit:** TLS 1.3 enforced
- **Supply chain:** Ed25519-signed agent template exports, SHA-256 pinned Docker base images
- **Defense in depth:** hash-chained audit ledger (Vault), cross-model verification for memory poisoning, three-state circuit breakers per LLM provider

## Supported Versions

We provide security updates for the latest minor version of each package. Older versions are not supported.

| Package | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Best effort |
| Older versions | No |

## Disclosure

We follow coordinated disclosure. We will credit reporters in release notes unless they prefer anonymity. We do not currently offer a bug bounty program.
