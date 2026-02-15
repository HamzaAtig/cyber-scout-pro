# Roadmap

## Short Term

- Make `ExecuteAttackDelegate` a real HTTP executor (still safe-by-default).
- Persist structured evidence for each check:
  - request metadata
  - response headers
  - response excerpt
  - timing
- Add campaign creation/start API (avoid hardcoded campaign id assumptions).

## Medium Term

- Expand check catalogue:
  - auth/session checks (safe)
  - access control smoke tests (requires explicit scope and opt-in)
  - SSRF preconditions (no exploitation)
- Add export formats:
  - JSON bundle
  - HTML report with grouping, evidence snippets, and remediation guidance

## Long Term

- Offline vulnerability database ingestion (OSV/NVD) for CVE matching.
- Local LLM integration for hypothesis generation (strict schema + evidence gating).
