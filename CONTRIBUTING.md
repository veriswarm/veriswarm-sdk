# Contributing to VeriSwarm SDKs

Thank you for your interest in contributing. These SDKs are the public interface to the VeriSwarm platform, so we value correctness, simplicity, and backward compatibility.

## How to Contribute

### Bug Reports

Open a [GitHub issue](https://github.com/veriswarm/veriswarm-sdk/issues) with:
- Which package is affected (Node SDK, Python SDK, or MCP server)
- Steps to reproduce
- Expected vs. actual behavior
- Your environment (OS, runtime version, package version)

### Feature Requests

Open an issue describing:
- What you're trying to accomplish
- Why the current API doesn't support it
- Your suggested approach (if any)

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Ensure existing behavior is preserved (no breaking changes without discussion)
5. Submit a PR with a clear description

### Guidelines

- **Zero dependencies**: The Node and Python SDKs have zero runtime dependencies. Keep it that way. The MCP server depends on `mcp` and `httpx` only.
- **Backward compatibility**: Do not change existing method signatures. Add new methods instead.
- **Keep it simple**: These are thin API clients, not frameworks. Business logic belongs in the VeriSwarm platform, not in the SDKs.
- **Match the style**: Follow the existing code patterns. The Node SDK uses native `fetch` and ES modules. The Python SDK uses `urllib`. The MCP server uses `httpx`.
- **Test your changes**: Add tests for new functionality. Run existing tests to verify nothing breaks.

### Running Tests

```bash
# Python SDK
cd python && python3 -m pytest tests/ -v

# MCP Server
cd mcp-server && pip install -e ".[dev]" && python3 -m pytest tests/ -v

# Node SDK
cd node && node --test test/
```

## Code of Conduct

This project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Be respectful and constructive.

## Questions?

- Platform docs: https://veriswarm.ai/docs
- API reference: https://veriswarm.ai/docs/api
- Support: support@veriswarm.ai
