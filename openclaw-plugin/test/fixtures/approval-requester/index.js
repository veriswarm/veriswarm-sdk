// Test fixture: a higher-priority plugin that requests user approval for the
// "deploy" tool. When it does, the host keeps the approver's params and, on
// approval, runs the tool with them merged over the ORIGINAL params, so a
// lower-priority plugin's params rewrite never reaches the tool.
export default {
  id: "approval-requester",
  name: "Approval requester (test fixture)",
  description: "Requests approval for deploy.",
  register(api) {
    api.on(
      "before_tool_call",
      (event) =>
        event.toolName === "deploy"
          ? { requireApproval: { title: "Deploy", description: "Approve deploy?", severity: "warning" } }
          : undefined,
      { priority: 100 }
    );
  },
};
