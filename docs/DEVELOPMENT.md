# Development

## Build

```bash
mvn test
```

## Run

H2 default:

```bash
mvn spring-boot:run
```

Local PostgreSQL:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local-postgres
```

## Useful URLs

- Camunda webapps: `http://localhost:8080/camunda/app/welcome/default/`
- Reporting:
  - `GET /api/reports/scan-runs?campaignId=1`
  - `GET /api/reports/scan-runs/{scanRunId}.html`

## Extending Checks

Add checks as small, evidence-driven modules:

- input: recon variables + base URL + allowed families
- output: findings with OWASP standard + confidence + evidence
- persist: store findings and observations in `cyberscout.*`
