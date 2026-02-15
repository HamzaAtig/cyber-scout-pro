# Architecture

## Components

- Spring Boot app (single deployable)
- Camunda 7 engine + webapps (Cockpit/Tasklist/Admin)
- Decision tables (DMN) to keep deterministic control over what checks are allowed
- PostgreSQL (dev via Docker Compose) for:
  - Camunda history/runtime persistence
  - Cyber-Scout findings and observations (schema `cyberscout.*`)
- Local LLM integration is planned (Ollama), but checks must remain evidence-based.

## Key Design Principles

- Local-first (0 external calls)
- Guardrails-first (policy, budgets, idempotence, kill switch)
- Evidence-first (store HTTP observations and link findings to evidence)
- Deterministic governance (DMN and explicit allowlists)

## Data Model (high level)

- `cyberscout.audit_campaign`: campaign metadata + status
- `cyberscout.attack_attempt`: idempotence key + per-target budgeting
- `cyberscout.scan_run`: a run under a campaign for a base URL
- `cyberscout.scan_finding`: findings with OWASP standard + confidence
- `cyberscout.http_observation`: raw observations from active probes (headers, excerpt, timings)
