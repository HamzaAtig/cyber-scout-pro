package org.hat.cyberscout.scan.persist;

import java.net.URI;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import org.hat.cyberscout.scan.model.Finding;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

@Repository
public class ScanRunRepository {

    private final ScanPersistenceProperties properties;
    private final JdbcTemplate jdbcTemplate;

    public ScanRunRepository(ScanPersistenceProperties properties, JdbcTemplate jdbcTemplate) {
        this.properties = properties;
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean isEnabled() {
        return properties.isEnabled();
    }

    @Transactional
    public Optional<Long> createRun(long campaignId, URI baseUri) {
        if (!properties.isEnabled()) {
            return Optional.empty();
        }
        try {
            Long id = jdbcTemplate.queryForObject("""
                INSERT INTO cyberscout.scan_run (campaign_id, base_url, started_at, status)
                VALUES (?, ?, ?, 'RUNNING')
                RETURNING id
                """, Long.class, campaignId, baseUri.toString(), OffsetDateTime.now());
            return Optional.ofNullable(id);
        } catch (DataAccessException e) {
            return Optional.empty();
        }
    }

    @Transactional
    public void finishRun(long scanRunId, String status) {
        if (!properties.isEnabled()) {
            return;
        }
        jdbcTemplate.update("""
            UPDATE cyberscout.scan_run
            SET finished_at = ?, status = ?
            WHERE id = ?
            """, OffsetDateTime.now(), status, scanRunId);
    }

    @Transactional
    public void insertFinding(long scanRunId, Finding finding) {
        if (!properties.isEnabled()) {
            return;
        }
        jdbcTemplate.update("""
            INSERT INTO cyberscout.scan_finding
            (scan_run_id, owasp_standard, owasp_id, check_id, target, severity, confidence, title, evidence_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                scanRunId,
                finding.owasp().standard().name(),
                finding.owasp().id(),
                finding.checkId(),
                finding.target(),
                finding.severity().name(),
                finding.confidence(),
                finding.title(),
                finding.evidenceJson(),
                OffsetDateTime.now()
        );
    }

    @Transactional
    public void insertObservation(long scanRunId, String method, String url, Integer statusCode, Integer durationMs, String headers, String bodyExcerpt) {
        if (!properties.isEnabled()) {
            return;
        }
        jdbcTemplate.update("""
            INSERT INTO cyberscout.http_observation
            (scan_run_id, method, url, status_code, duration_ms, response_headers, response_body_excerpt, observed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                scanRunId,
                method,
                url,
                statusCode,
                durationMs,
                headers,
                bodyExcerpt,
                OffsetDateTime.now()
        );
    }

    @Transactional(readOnly = true)
    public Optional<Long> latestRunIdForCampaign(long campaignId) {
        if (!properties.isEnabled()) {
            return Optional.empty();
        }
        List<Long> ids = jdbcTemplate.query("""
            SELECT id
            FROM cyberscout.scan_run
            WHERE campaign_id = ?
            ORDER BY started_at DESC
            LIMIT 1
            """, (rs, rowNum) -> rs.getLong("id"), campaignId);
        return ids.stream().findFirst();
    }

    @Transactional(readOnly = true)
    public Optional<String> runBaseUrl(long scanRunId) {
        if (!properties.isEnabled()) {
            return Optional.empty();
        }
        List<String> urls = jdbcTemplate.query("""
            SELECT base_url
            FROM cyberscout.scan_run
            WHERE id = ?
            """, new SingleStringMapper("base_url"), scanRunId);
        return urls.stream().findFirst();
    }

    private static final class SingleStringMapper implements RowMapper<String> {
        private final String column;

        private SingleStringMapper(String column) {
            this.column = column;
        }

        @Override
        public String mapRow(ResultSet rs, int rowNum) throws SQLException {
            return rs.getString(column);
        }
    }
}
