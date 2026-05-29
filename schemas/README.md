# Shared Schemas

JSON schemas and typed contracts shared between API, workers, and web.

## Current contents
- `agent_event.schema.json` — Agent behavioral event format (24 standardized event types, incl. `agent.confidence_reported` + `agent.task_outcome` for calibration)
- `agent_profile.schema.json` — Agent registration and profile data
- `score_snapshot.schema.json` — Trust score snapshot (identity, risk, reliability, autonomy, calibration). Calibration is the fifth dimension and is optional/nullable (absent for cold-start agents).
- `workflow-schema.json` — Cortex Workflows YAML/JSON definition schema (11 step types, triggers, budget config)
