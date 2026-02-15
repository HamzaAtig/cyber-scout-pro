CREATE SCHEMA IF NOT EXISTS cyberscout;

CREATE TABLE IF NOT EXISTS cyberscout.audit_campaign (
    id BIGSERIAL PRIMARY KEY,
    campaign_name VARCHAR(120) NOT NULL,
    scope_description TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(80) NOT NULL DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS cyberscout.attack_finding (
    id BIGSERIAL PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES cyberscout.audit_campaign(id) ON DELETE CASCADE,
    target_path VARCHAR(255) NOT NULL,
    strategy VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    evidence TEXT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO cyberscout.audit_campaign (campaign_name, scope_description, created_by)
VALUES ('Bootstrap Local Campaign', 'Initial local database bootstrap for Cyber-Scout Pro', 'flyway')
ON CONFLICT DO NOTHING;
