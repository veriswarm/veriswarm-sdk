from __future__ import annotations

from urllib.request import Request

import pytest

from veriswarm.client import VeriSwarmClient, _StripAuthRedirectHandler


def test_base_url_normalizes_trailing_slash():
    client = VeriSwarmClient(base_url="https://api.veriswarm.ai///", api_key="k")

    assert client.base_url == "https://api.veriswarm.ai"


def test_base_url_rejects_external_http():
    with pytest.raises(ValueError, match="base_url must be https://"):
        VeriSwarmClient(base_url="http://api.veriswarm.ai", api_key="k")


@pytest.mark.parametrize(
    "base_url",
    [
        "api.veriswarm.ai",
        "https:/api.veriswarm.ai",
        "https:///v1",
    ],
)
def test_base_url_rejects_non_absolute_urls(base_url):
    with pytest.raises(ValueError, match="base_url must be an absolute URL"):
        VeriSwarmClient(base_url=base_url, api_key="k")


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:8000/",
        "http://127.0.0.1:8000/",
        "http://[::1]:8000/",
    ],
)
def test_base_url_allows_localhost_http_for_development(base_url):
    client = VeriSwarmClient(base_url=base_url, api_key="k")

    assert client.base_url == base_url.rstrip("/")


def test_redirect_handler_strips_credentials_from_followed_redirects():
    request = Request(
        "https://api.veriswarm.ai/v1/events",
        headers={
            "Content-Type": "application/json",
            "x-api-key": "secret-key",
            "Authorization": "Bearer secret-token",
        },
    )

    redirected = _StripAuthRedirectHandler().redirect_request(
        request,
        fp=None,
        code=302,
        msg="Found",
        headers={},
        newurl="https://attacker.example/collect",
    )

    assert redirected is not None
    redirected_headers = {
        key.lower(): value for key, value in redirected.headers.items()
    }
    assert "x-api-key" not in redirected_headers
    assert "authorization" not in redirected_headers
    assert redirected.full_url == "https://attacker.example/collect"
