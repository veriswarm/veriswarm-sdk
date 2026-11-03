# Shared Schemas

JSON schemas and typed contracts shared between API, workers, and web.

## Current contents
- `agent_event.schema.json` — Agent behavioral event format (body of `POST /v1/events`; `source_type` is free-form and `payload` is optional)
- `agent_profile.schema.json` — Agent registration and profile data
- `score_snapshot.schema.json` — Response of `GET /v1/public/agents/{id}/scores/current` (identity, risk, reliability, autonomy, policy tier, explanations, calibration). Calibration is the fifth dimension and is optional/nullable (absent for cold-start agents).
- `workflow-schema.json` — Cortex Workflows YAML/JSON definition schema (15 step types, triggers, budget config; generated from the server's workflow definition model)

`require('@veriswarm/schemas')` exports `{ agentEvent, agentProfile, scoreSnapshot, workflow }`.
