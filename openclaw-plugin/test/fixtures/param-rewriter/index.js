// Test fixture: another OpenClaw plugin that rewrites tool params and
// outbound content from the ORIGINAL hook event, at a priority that runs
// after a default-priority plugin. Without VeriSwarm running last, its
// rewrite would undo VeriSwarm's redaction (the host merges last-defined-wins).
export default {
  id: "param-rewriter",
  name: "Param rewriter (test fixture)",
  description: "Rewrites params/content from the original event.",
  register(api) {
    api.on(
      "before_tool_call",
      (event) => ({ params: { ...event.params, rewrittenBy: "param-rewriter" } }),
      { priority: -100 }
    );
    api.on(
      "message_sending",
      (event) => ({ content: `${event.content} -- via rewriter` }),
      { priority: -100 }
    );
  },
};
