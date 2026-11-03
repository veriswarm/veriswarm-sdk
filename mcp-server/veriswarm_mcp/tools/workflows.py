"""Cortex Workflows tools for VeriSwarm MCP."""
from __future__ import annotations

import json

from mcp.server.fastmcp import FastMCP

from ..client import VeriSwarmAPIClient
from ._shared import call_api, safe_error_response, safe_id


def register(server: FastMCP, client: VeriSwarmAPIClient) -> None:
    @server.tool()
    async def list_workflows(is_active: bool | None = None) -> str:
        """List all Cortex Workflows for the current tenant.

        is_active: optional filter — true for active only, false for inactive only
        """
        try:
            params: dict = {}
            if is_active is not None:
                params["is_active"] = str(is_active).lower()
            result = await call_api(client.get, "/v1/workflows", params=params)
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="list_workflows")

    @server.tool()
    async def get_workflow(workflow_id: str) -> str:
        """Get details of a specific workflow including recent executions.

        workflow_id: the workflow ID (starts with wf_)
        """
        try:
            workflow_id = safe_id(workflow_id, "workflow_id")
            result = await call_api(client.get, f"/v1/workflows/{workflow_id}")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_workflow")

    @server.tool()
    async def create_workflow(name: str, slug: str, definition: str, description: str = "") -> str:
        """Create a new Cortex Workflow from a JSON definition.

        name: display name for the workflow
        slug: URL-safe identifier (lowercase, hyphens ok)
        definition: the full workflow definition as a JSON string
        description: optional description of what the workflow does
        """
        try:
            defn = json.loads(definition)
            result = await call_api(client.post, "/v1/workflows", json={
                "name": name,
                "slug": slug,
                "description": description,
                "definition": defn,
            })
            return json.dumps(result, indent=2)
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON in definition"})
        except Exception as exc:
            return safe_error_response(exc, context="create_workflow")

    @server.tool()
    async def run_workflow(workflow_id: str) -> str:
        """Manually trigger a workflow execution.

        workflow_id: the workflow ID to run
        """
        try:
            workflow_id = safe_id(workflow_id, "workflow_id")
            result = await call_api(client.post, f"/v1/workflows/{workflow_id}/run", json={})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="run_workflow")

    @server.tool()
    async def get_execution(execution_id: str) -> str:
        """Get the status and step-by-step results of a workflow execution.

        execution_id: the execution ID (starts with wfx_)
        """
        try:
            execution_id = safe_id(execution_id, "execution_id")
            result = await call_api(client.get, f"/v1/workflows/executions/{execution_id}")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="get_execution")

    @server.tool()
    async def activate_workflow(workflow_id: str) -> str:
        """Activate a workflow so its triggers (schedule/event/webhook) start firing.

        workflow_id: the workflow ID to activate
        """
        try:
            workflow_id = safe_id(workflow_id, "workflow_id")
            result = await call_api(client.post, f"/v1/workflows/{workflow_id}/activate")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="activate_workflow")

    @server.tool()
    async def deactivate_workflow(workflow_id: str) -> str:
        """Deactivate a workflow, stopping all triggers.

        workflow_id: the workflow ID to deactivate
        """
        try:
            workflow_id = safe_id(workflow_id, "workflow_id")
            result = await call_api(client.post, f"/v1/workflows/{workflow_id}/deactivate")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="deactivate_workflow")

    @server.tool()
    async def list_workflow_templates() -> str:
        """List available workflow templates (both built-in and custom)."""
        try:
            result = await call_api(client.get, "/v1/workflows/templates")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="list_workflow_templates")

    @server.tool()
    async def deploy_template(template_id: str) -> str:
        """Deploy a workflow template as a new workflow in your workspace.

        template_id: the template ID (e.g., "builtin:content-pipeline-v2" or a custom template ID)
        """
        try:
            template_id = safe_id(template_id, "template_id")
            result = await call_api(client.post, f"/v1/workflows/templates/{template_id}/deploy")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="deploy_template")

    @server.tool()
    async def workflow_stats(days: int = 30) -> str:
        """Get workflow usage statistics: execution counts, success rates, and LLM costs.

        days: time period in days (default 30, max 90)
        """
        try:
            result = await call_api(client.get, "/v1/workflows/stats", params={"days": days})
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="workflow_stats")

    @server.tool()
    async def cancel_workflow_execution(execution_id: str) -> str:
        """Cancel a running or paused workflow execution.

        execution_id: the execution ID to cancel (starts with wfx_)
        """
        try:
            execution_id = safe_id(execution_id, "execution_id")
            result = await call_api(client.post, f"/v1/workflows/executions/{execution_id}/cancel")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="cancel_workflow_execution")

    @server.tool()
    async def retry_workflow_execution(execution_id: str) -> str:
        """Retry a failed workflow execution from where it left off.

        execution_id: the execution ID to retry (starts with wfx_)
        """
        try:
            execution_id = safe_id(execution_id, "execution_id")
            result = await call_api(client.post, f"/v1/workflows/executions/{execution_id}/retry")
            return json.dumps(result, indent=2)
        except Exception as exc:
            return safe_error_response(exc, context="retry_workflow_execution")
