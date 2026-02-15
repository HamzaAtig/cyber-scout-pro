# Workflow (Camunda)

## Current BPMN

Process key: `cyberScoutAuditProcess`

High-level flow:

1. Identify Attack Surface
   - URL reconnaissance (headers fingerprint + endpoint candidates)
   - outputs:
     - `targetList` (collection)
     - `hasOpenApi`, `hasActuator`, `hasH2Console`, `apiLikely`

2. Select Checks (DMN)
   - decision: `selectChecks`
   - output: `enabledCheckFamilies` (list)

3. Run Recon Checks
   - executes enabled families (bounded active probes)
   - persists findings + observations (if `scanRunId` exists and scanning enabled)
   - sets `reconFindingCount`

4. Parallel Assault (multi-instance)
   - placeholder for deeper checks (still partially simulated)

5. Finish Scan Run
   - marks `scan_run` as `FINISHED` when persistence is enabled

## Retry Policy

Service tasks are marked `asyncBefore=true` with bounded retry cycles (e.g. `R3/PT10S`).
This prevents infinite retries and makes failures visible in Cockpit.
