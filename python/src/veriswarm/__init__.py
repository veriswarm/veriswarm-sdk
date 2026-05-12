"""VeriSwarm Python SDK — trust scoring, event ingestion, and agent management.

Usage:
    from veriswarm import VeriSwarmClient

    client = VeriSwarmClient(
        base_url="https://api.veriswarm.ai",
        api_key="vsk_your_workspace_key",
    )
    decision = client.check_decision(
        agent_id="agt_123",
        action_type="post_message",
    )
"""
from veriswarm.client import VeriSwarmClient, VeriSwarmClientError

__version__ = "0.3.0"

__all__ = [
    "VeriSwarmClient",
    "VeriSwarmClientError",
    "__version__",
]
