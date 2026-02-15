# Usage Scenarios

This document provides simplified, practical scenarios for running Cyber-Scout Pro locally and understanding outputs.

## Scenario 1: Quick Demo (H2, No Persistence)

Goal: run the workflow and Camunda UI quickly without PostgreSQL persistence.

1. Start the app:

```bash
mvn spring-boot:run
```

2. Open Camunda webapps:

- `http://localhost:8080/camunda/app/welcome/default/`
- Credentials: `demo / demo`

3. Start a scan (target URL):

- `POST /api/processes/cyber-scout/start`
- Body:

```json
{"campaignId":1,"baseUrl":"http://localhost:8080"}
```

What you get:

- A running process instance visible in Cockpit
- No persisted scan report (H2 profile is for quick demo)

## Scenario 1b: One-Command Demo (Docker Target + PostgreSQL)

Goal: run a reproducible end-to-end demo with a local target and a persisted HTML report.

This starts:

- PostgreSQL (Docker, for persistence)
- a local demo target (WireMock) on `http://localhost:18080`
- Cyber-Scout Pro (Spring Boot) on `http://localhost:8080`

Run:

```bash
./scripts/demo.sh
```

Stop containers:

```bash
./scripts/demo-stop.sh
```

Outputs:

- HTML report URL printed by the script
- Camunda Cockpit for live execution

## Scenario 2: Dev Local (PostgreSQL + Persistence + Recon Active)

Goal: store runs/findings/observations and generate a report.

1. Start with the local profile:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres
```

2. Start a scan:

- `POST /api/processes/cyber-scout/start`
- Body:

```json
{"campaignId":1,"baseUrl":"http://target.local:8080"}
```

3. Read results:

- List runs:
  - `GET /api/reports/scan-runs?campaignId=1`
- JSON report:
  - `GET /api/reports/scan-runs/{scanRunId}`
- HTML report:
  - `GET /api/reports/scan-runs/{scanRunId}.html`

What you get:

- `scan_run` lifecycle: `RUNNING` -> `FINISHED`
- `scan_finding`: OWASP standard/category + confidence + evidence
- `http_observation`: HTTP status/timing/headers + response excerpt

## Scenario 3: Choosing Test Types (DMN-driven)

Goal: decide which check families are allowed based on recon facts.

How it works:

1. Recon sets variables:
   - `apiLikely`
   - `hasOpenApi`
   - `hasActuator`
   - `hasH2Console`

2. DMN decision `selectChecks` outputs:
   - `enabledCheckFamilies` (list)

Families currently used:

- `SECURITY_HEADERS`
- `OPENAPI_PROBE`
- `ACTUATOR_PROBE`
- `RATELIMIT_PROBE`
- `OPENAPI_AUTHZ_SMOKE`
- `OPENAPI_TYPE_VALIDATION`

Where to edit the selection:

- `src/main/resources/dmn/select-checks.dmn`

Where to observe the selection:

- Camunda Cockpit process variables: `enabledCheckFamilies`

## Scenario 4: Attack-Level Checks (Bounded, local-postgres only)

Goal: enable additional evidence-driven checks that are closer to pentest testing, but still bounded and reproducible.

Activation:

- Only enabled in `local-postgres` profile:
  - `cyberscout.attack.enabled=true`

What it adds:

- OpenAPI authz smoke test:
  - if OpenAPI indicates `security` for an operation and it returns `2xx` without auth, it raises a high severity finding
- OpenAPI type-mismatch validation:
  - if a type-mismatched JSON input causes `5xx` or verbose error leaks, it raises findings

Outputs:

- Findings and their HTTP evidence appear in the scan report (`.html` or JSON)

## Scenario 5: Stop Controls (Safety)

Goal: stop tests quickly if needed.

Global kill switch:

- `GET /api/control/kill-switch`
- `POST /api/control/kill-switch` body:

```json
{"enabled":true}
```

Stop a campaign:

- `POST /api/campaigns/{campaignId}/stop`

Stop a running process instance:

- `POST /api/processes/instances/{instanceId}/stop`
- Body (optional):

```json
{"reason":"Manual stop"}
```

## Scenario 6: Local LLM Assistance (Ollama + Spring AI)

Goal: keep the scan local-only, but let a local LLM suggest bounded **robustness test** JSON bodies for JSON endpoints.

Prereqs:

- Ollama running locally (`http://localhost:11434`)
- A model pulled locally (default `mistral`): `ollama pull mistral`

Run:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres,local-ollama
```

What changes:

- Camunda step “Generate Custom Payload” uses Ollama via Spring AI and expects strict JSON-only output.
- If the model output is invalid (not JSON / unusable), the BPMN error `INVALID_LLM_FORMAT` is raised and the workflow falls back to `FormatRepairDelegate`.
- `ExecuteAttackDelegate` uses the generated payloads (bounded) for JSON robustness probes, still subject to policy + governance budgets.
