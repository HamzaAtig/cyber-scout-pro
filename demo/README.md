# Demo Target (Local)

This folder contains a **local demo target** used to exercise Cyber-Scout Pro in a reproducible way.

It is implemented as a WireMock container with fixed stubs:

- an OpenAPI document at `/v3/api-docs`
- a few endpoints that intentionally return responses that trigger findings

Nothing here is intended to be "realistic vulnerabilities"; it is a deterministic lab for the POC.

Start the demo target via:

```bash
docker compose -f docker-compose.demo.yml up -d
```

It listens on `http://localhost:18080`.

