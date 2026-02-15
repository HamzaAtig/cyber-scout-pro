package org.hat.cyberscout.governance;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class GovernanceService {

    private final GovernanceProperties properties;
    private final GlobalKillSwitchService killSwitchService;
    private final JdbcTemplate jdbcTemplate;

    public GovernanceService(
            GovernanceProperties properties,
            GlobalKillSwitchService killSwitchService,
            JdbcTemplate jdbcTemplate
    ) {
        this.properties = properties;
        this.killSwitchService = killSwitchService;
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean isGovernanceEnabled() {
        return properties.isEnabled();
    }

    @Transactional
    public GovernanceDecision evaluateAndRecordExecution(
            Long campaignId,
            String targetPath,
            String httpMethod,
            String strategy,
            List<String> payloads,
            int maxRequestsPerTarget
    ) {
        List<String> reasons = new ArrayList<>();
        if (killSwitchService.isEnabled()) {
            reasons.add("Global kill switch is enabled");
            return new GovernanceDecision(false, reasons);
        }

        if (!properties.isEnabled()) {
            return new GovernanceDecision(true, List.of());
        }

        if (campaignId == null) {
            reasons.add("Missing campaign id");
            return new GovernanceDecision(false, reasons);
        }

        try {
            Optional<String> campaignStatus = getCampaignStatus(campaignId);
            if (campaignStatus.isEmpty()) {
                reasons.add("Campaign not found: " + campaignId);
                return new GovernanceDecision(false, reasons);
            }
            if (!"RUNNING".equalsIgnoreCase(campaignStatus.get())) {
                reasons.add("Campaign is not running: " + campaignStatus.get());
                return new GovernanceDecision(false, reasons);
            }

            String key = attackKey(campaignId, targetPath, httpMethod, strategy, payloads);
            try {
                jdbcTemplate.update("""
                    INSERT INTO cyberscout.attack_attempt
                    (campaign_id, target_path, http_method, strategy, attack_key, payload_count, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                        campaignId,
                        targetPath,
                        httpMethod,
                        strategy,
                        key,
                        payloads == null ? 0 : payloads.size(),
                        OffsetDateTime.now()
                );
            } catch (DuplicateKeyException duplicateKeyException) {
                reasons.add("Duplicate attack attempt blocked by idempotence key");
                return new GovernanceDecision(false, reasons);
            }

            Integer currentRequests = jdbcTemplate.queryForObject("""
                SELECT COUNT(*)
                FROM cyberscout.attack_attempt
                WHERE campaign_id = ? AND target_path = ?
                """, Integer.class, campaignId, targetPath);

            int requestCount = currentRequests == null ? 0 : currentRequests;
            if (requestCount > maxRequestsPerTarget) {
                jdbcTemplate.update("""
                    DELETE FROM cyberscout.attack_attempt
                    WHERE campaign_id = ? AND attack_key = ?
                    """, campaignId, key);
                reasons.add("Request budget exceeded for target " + targetPath);
                return new GovernanceDecision(false, reasons);
            }

            return new GovernanceDecision(true, List.of());
        } catch (DataAccessException exception) {
            reasons.add("Governance database check failed: " + exception.getMostSpecificCause().getMessage());
            return new GovernanceDecision(false, reasons);
        }
    }

    @Transactional(readOnly = true)
    public Optional<String> getCampaignStatus(long campaignId) {
        List<String> statuses = jdbcTemplate.query("""
            SELECT status
            FROM cyberscout.audit_campaign
            WHERE id = ?
            """, (rs, rowNum) -> rs.getString("status"), campaignId);
        return statuses.stream().findFirst();
    }

    @Transactional
    public boolean stopCampaign(long campaignId) {
        if (!properties.isEnabled()) {
            return false;
        }
        int updated = jdbcTemplate.update("""
            UPDATE cyberscout.audit_campaign
            SET status = 'STOPPED', stopped_at = ?
            WHERE id = ? AND status <> 'STOPPED'
            """, OffsetDateTime.now(), campaignId);
        return updated > 0;
    }

    private String attackKey(
            long campaignId,
            String targetPath,
            String httpMethod,
            String strategy,
            List<String> payloads
    ) {
        String payloadMaterial = payloads == null ? "" : String.join("||", payloads);
        String raw = campaignId + "|"
                + normalized(targetPath) + "|"
                + normalized(httpMethod) + "|"
                + normalized(strategy) + "|"
                + payloadMaterial;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private String normalized(String value) {
        if (value == null) {
            return "";
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }
}
