# Cyber-Scout Pro

Java 21/Maven baseline for Cyber-Scout Pro with Camunda + DMN + guardrails.

## Stack

- Java 21
- Maven
- Spring Boot
- Camunda 7
- DMN decision table
- Local policy guardrails

## Run

Default profile (H2 in-memory):

```bash
mvn spring-boot:run
```

One-command demo (Docker target + PostgreSQL + report):

```bash
./scripts/demo.sh
```

Local PostgreSQL dev profile (Docker auto-start + Flyway migrations):

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres
```

Local PostgreSQL + local LLM (Ollama via Spring AI):

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres,local-ollama
```

If Docker was previously started with a stale container configuration, recreate once:

```bash
docker compose down
docker compose up -d
```

Camunda web apps:
- [http://localhost:8080/camunda/app/welcome/default/](http://localhost:8080/camunda/app/welcome/default/)
- default credentials: `demo` / `demo`

## Test

```bash
mvn test
```

## Docs

- Documentation index: `docs/README.md`
- Usage scenarios: `docs/USAGE_SCENARIOS.md`
- Configuration/profiles: `docs/CONFIGURATION.md`
- Workflow (BPMN/DMN): `docs/WORKFLOW.md`

## Core assets

- BPMN process: `/src/main/resources/bpmn/cyber-scout-audit.bpmn`
- DMN matrix: `/src/main/resources/dmn/define-strategy.dmn`
- Guardrail evaluator API: `POST /api/policy/evaluate`
- Docker local DB: `/docker-compose.yml`
- Flyway SQL migrations: `/src/main/resources/db/migration`

## Governance Controls (local-postgres)

- Global kill switch:
  - `GET /api/control/kill-switch`
  - `POST /api/control/kill-switch` with body `{"enabled":true}`
- Campaign controls:
  - `GET /api/campaigns/{campaignId}/status`
  - `POST /api/campaigns/{campaignId}/stop`

When `local-postgres` profile is active, execution guardrails add:
- campaign status check (`RUNNING` required)
- request budget per target
- idempotence key to block duplicate attack attempts

## Process Control API

- Start Cyber Scout process:
  - `POST /api/processes/cyber-scout/start`
  - body example: `{"campaignId":1,"baseUrl":"http://localhost:8080"}`
- Stop a running instance:
  - `POST /api/processes/instances/{instanceId}/stop`
  - body example: `{"reason":"Manual stop"}`

## Reporting API (local-postgres)

- List scan runs for a campaign:
  - `GET /api/reports/scan-runs?campaignId=1`
- JSON report for a scan run:
  - `GET /api/reports/scan-runs/{scanRunId}`
- HTML report for a scan run:
  - `GET /api/reports/scan-runs/{scanRunId}.html`

## Attack-Level Checks (local-postgres only)

When running with profile `local-postgres`, `cyberscout.attack.enabled=true` enables additional bounded checks:

- OpenAPI authz smoke test (secured endpoints returning 2xx without auth)
- OpenAPI type-mismatch validation (5xx or verbose errors on type mismatch)
