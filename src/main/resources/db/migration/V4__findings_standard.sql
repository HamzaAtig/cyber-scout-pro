ALTER TABLE cyberscout.scan_finding
    ADD COLUMN IF NOT EXISTS owasp_standard VARCHAR(40) NOT NULL DEFAULT 'OWASP_TOP10_2021';

UPDATE cyberscout.scan_finding
SET owasp_standard = 'OWASP_TOP10_2021'
WHERE owasp_standard IS NULL;

CREATE INDEX IF NOT EXISTS idx_finding_standard ON cyberscout.scan_finding(owasp_standard);
