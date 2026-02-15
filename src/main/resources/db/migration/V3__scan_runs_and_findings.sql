CREATE TABLE IF NOT EXISTS cyberscout.scan_run (
    id BIGSERIAL PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES cyberscout.audit_campaign(id) ON DELETE CASCADE,
    base_url VARCHAR(512) NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL DEFAULT 'RUNNING'
);

CREATE TABLE IF NOT EXISTS cyberscout.http_observation (
    id BIGSERIAL PRIMARY KEY,
    scan_run_id BIGINT NOT NULL REFERENCES cyberscout.scan_run(id) ON DELETE CASCADE,
    method VARCHAR(10) NOT NULL,
    url VARCHAR(1024) NOT NULL,
    status_code INTEGER,
    duration_ms INTEGER,
    response_headers TEXT,
    response_body_excerpt TEXT,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cyberscout.scan_finding (
    id BIGSERIAL PRIMARY KEY,
    scan_run_id BIGINT NOT NULL REFERENCES cyberscout.scan_run(id) ON DELETE CASCADE,
    owasp_id VARCHAR(10) NOT NULL,
    check_id VARCHAR(80) NOT NULL,
    target VARCHAR(1024) NOT NULL,
    severity VARCHAR(10) NOT NULL,
    confidence NUMERIC(3,2) NOT NULL,
    title VARCHAR(200) NOT NULL,
    evidence_json TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_run_campaign ON cyberscout.scan_run(campaign_id);
CREATE INDEX IF NOT EXISTS idx_finding_scan_run ON cyberscout.scan_finding(scan_run_id);
