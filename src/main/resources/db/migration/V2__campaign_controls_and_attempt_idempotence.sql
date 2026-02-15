ALTER TABLE cyberscout.audit_campaign
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'RUNNING';

ALTER TABLE cyberscout.audit_campaign
    ADD COLUMN IF NOT EXISTS stopped_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS cyberscout.attack_attempt (
    id BIGSERIAL PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES cyberscout.audit_campaign(id) ON DELETE CASCADE,
    target_path VARCHAR(255) NOT NULL,
    http_method VARCHAR(10) NOT NULL,
    strategy VARCHAR(120) NOT NULL,
    attack_key CHAR(64) NOT NULL,
    payload_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_attack_attempt_campaign_key UNIQUE (campaign_id, attack_key)
);

UPDATE cyberscout.audit_campaign
SET status = 'RUNNING'
WHERE status IS NULL;
