"""validate_api_url guards every URL the MCP server sends credentials to."""
from __future__ import annotations

import pytest

from veriswarm_mcp.url_security import validate_api_url


@pytest.mark.parametrize(
    "url",
    [
        "https://api.veriswarm.ai@attacker.example",
        "https://user:pass@api.veriswarm.ai",
        "http://localhost@attacker.example",
    ],
)
def test_rejects_userinfo_that_redirects_auth_headers(url):
    with pytest.raises(ValueError, match="must not contain credentials"):
        validate_api_url(url)


@pytest.mark.parametrize("url", ["https://:443/v1", "https:///v1"])
def test_rejects_url_without_host(url):
    with pytest.raises(ValueError):
        validate_api_url(url)


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://api.veriswarm.ai/", "https://api.veriswarm.ai"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("http://[::1]:8000", "http://[::1]:8000"),
    ],
)
def test_accepts_https_and_local_http(url, expected):
    assert validate_api_url(url) == expected
