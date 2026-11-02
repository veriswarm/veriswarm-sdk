"""Every public module must import from an installed package.

Regression guard: in 0.5.0 the shared GuardMixin still imported the pre-0.3
top-level ``veriswarm_client`` module, so the Claude Agent SDK, CrewAI,
OpenAI Agents, and decorator adapters all failed with ModuleNotFoundError on a
plain ``pip install veriswarm``. Only the LangChain adapter had tests, and it
doesn't use the mixin, so nothing caught it.
"""

import importlib
from importlib import metadata

import pytest

# Adapters whose framework imports are lazy, so they must import with no extras.
ADAPTER_MODULES = [
    "veriswarm.adapters.guard_mixin",
    "veriswarm.adapters.claude_sdk",
    "veriswarm.adapters.crewai",
    "veriswarm.adapters.openai_agents",
    "veriswarm.adapters.decorator",
]


@pytest.mark.parametrize("module", ADAPTER_MODULES)
def test_adapter_module_imports(module):
    importlib.import_module(module)


def test_guard_mixin_uses_the_packaged_client():
    from veriswarm.adapters import guard_mixin
    from veriswarm.client import VeriSwarmClient, VeriSwarmClientError

    assert guard_mixin.VeriSwarmClient is VeriSwarmClient
    assert guard_mixin.VeriSwarmClientError is VeriSwarmClientError


def test_version_matches_package_metadata():
    import veriswarm

    assert veriswarm.__version__ == metadata.version("veriswarm")
