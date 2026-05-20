"""VeriSwarm Guard adapters for AI agent frameworks.

Each adapter wraps tool execution with Guard protection:
- PII tokenization (strip personal data before LLM sees it)
- Policy enforcement (block disallowed tool calls)
- Prompt injection scanning (detect injection in tool outputs)
- Audit logging (record everything to VeriSwarm Vault)

Available adapters (install the matching extras for each):
    guard_mixin     — Base mixin for building custom adapters
    langchain       — LangChain callback handler  (pip install veriswarm[langchain])
    crewai          — CrewAI tool wrapper          (pip install veriswarm[crewai])
    openai_agents   — OpenAI Agents SDK wrapper    (pip install veriswarm[openai-agents])
    claude_sdk      — Claude Agent SDK wrapper     (pip install veriswarm[claude-sdk])
    decorator       — @guard_protected for any Python function
"""
