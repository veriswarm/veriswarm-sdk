import pytest

from veriswarm.client import VeriSwarmClient


def test_client_rejects_userinfo_base_url():
    with pytest.raises(ValueError, match="base_url must not include username or password"):
        VeriSwarmClient(
            base_url="https://api.veriswarm.ai@attacker.example",
            api_key="vsk_test",
        )


def test_client_rejects_non_absolute_base_url():
    with pytest.raises(ValueError, match="base_url must be an absolute URL"):
        VeriSwarmClient(base_url="https:api.veriswarm.ai", api_key="vsk_test")
