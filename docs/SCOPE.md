# Scope And Safety

## Purpose

Cyber-Scout Pro is a local-first security audit orchestrator intended to help with structured testing and reporting.
It is designed for authorized security assessments only.

## Non-Goals

- Not a DDoS/DoS tool. The project must not include features meant to degrade or take down targets.
- Not a worm/exploitation framework.
- Not a scanner that phones home. The system is designed for 0 external calls.

## Operating Rules

- Always require explicit target scope (base URL) and enforce allowlists (hosts, ports, methods, path prefixes).
- Enforce budgets:
  - request budget per target
  - bounded retries
  - idempotence (prevent duplicate attempts)
- Always keep a kill switch and campaign stop controls available.
- Prefer safe probes and evidence-based findings over speculative "LLM guesses".

## "Active Probing" Definition

Active probing means low-impact, bounded HTTP requests (GET/HEAD) to validate exposure or misconfiguration.
It must be:

- single-threaded or tightly rate-limited
- capped by strict request counts
- stoppable via kill switch/campaign stop

## Adoption

Recommended environments:

- Local development: Docker PostgreSQL + Flyway
- Internal network: same principles, but with tightened allowlists and auth enabled for control endpoints

Production-like usage should set:

- `camunda.bpm.database.schema-update=false`
- governance enabled
- active probing disabled unless explicitly approved
