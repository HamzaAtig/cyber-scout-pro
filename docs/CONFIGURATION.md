# Configuration

## Profiles

- Default: in-memory H2, scanning persistence disabled
- `local-postgres`: Docker Postgres + Flyway enabled, governance + scan persistence enabled
- `local-ollama`: Ollama + Spring AI enabled for **robustness payload generation** (local-only)

Run:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres
```

Run with persistence + local LLM:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres,local-ollama
```

Requirements for `local-ollama`:

- Ollama running locally on `http://localhost:11434`
- A model pulled locally (default `mistral`): `ollama pull mistral`

Key env vars:

- `OLLAMA_BASE_URL` (default `http://localhost:11434`)
- `CS_AI_MODEL` (default `mistral`)
- `CS_AI_TEMPERATURE` (default `0.2`)

If the model returns invalid/non-JSON output, the workflow triggers `INVALID_LLM_FORMAT` and falls back to a small deterministic payload set.

## Governance

- Kill switch: `GET/POST /api/control/kill-switch`
- Campaign stop: `POST /api/campaigns/{id}/stop`

## Scanning

Properties under `cyberscout.scan.*`:

- `enabled`: store scan runs/findings/observations
- `default-standard`: `OWASP_TOP10_2025` (default), `OWASP_TOP10_2021`, `OWASP_API_TOP10_2023`
- `active-probing-enabled`: enables bounded GET/HEAD probes
- `active-probing-max-requests`: global cap per recon phase
- `rate-limit-probe-requests`: bounded count for the API4 probe

## Policy (Allowlist)

Properties under `cyberscout.policy.*`:

- allowed hosts/ports/methods
- allowed path prefixes
- payload/request budgets
