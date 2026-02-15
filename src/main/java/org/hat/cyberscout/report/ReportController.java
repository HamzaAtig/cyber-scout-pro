package org.hat.cyberscout.report;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private final JdbcTemplate jdbcTemplate;

    public ReportController(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/scan-runs")
    public List<ScanRunRow> listRuns(@RequestParam long campaignId) {
        return jdbcTemplate.query("""
            SELECT id, campaign_id, base_url, started_at, finished_at, status
            FROM cyberscout.scan_run
            WHERE campaign_id = ?
            ORDER BY started_at DESC
            """, new ScanRunMapper(), campaignId);
    }

    @GetMapping("/scan-runs/{scanRunId}")
    public ResponseEntity<ScanRunReport> runReport(@PathVariable long scanRunId) {
        List<ScanRunRow> run = jdbcTemplate.query("""
            SELECT id, campaign_id, base_url, started_at, finished_at, status
            FROM cyberscout.scan_run
            WHERE id = ?
            """, new ScanRunMapper(), scanRunId);
        if (run.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        List<FindingRow> findings = jdbcTemplate.query("""
            SELECT owasp_standard, owasp_id, check_id, target, severity, confidence, title, evidence_json, created_at
            FROM cyberscout.scan_finding
            WHERE scan_run_id = ?
            ORDER BY created_at ASC
            """, new FindingMapper(), scanRunId);

        List<ObservationRow> observations = jdbcTemplate.query("""
            SELECT method, url, status_code, duration_ms, response_headers, response_body_excerpt, observed_at
            FROM cyberscout.http_observation
            WHERE scan_run_id = ?
            ORDER BY observed_at ASC
            """, new ObservationMapper(), scanRunId);

        Map<String, Long> findingCounts = findings.stream()
                .collect(java.util.stream.Collectors.groupingBy(FindingRow::severity, java.util.stream.Collectors.counting()));

        return ResponseEntity.ok(new ScanRunReport(run.get(0), findings, observations, findingCounts));
    }

    @GetMapping(value = "/scan-runs/{scanRunId}.html", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> runReportHtml(@PathVariable long scanRunId) {
        ResponseEntity<ScanRunReport> report = runReport(scanRunId);
        if (!report.getStatusCode().is2xxSuccessful() || report.getBody() == null) {
            return ResponseEntity.status(report.getStatusCode()).body("<h1>Not found</h1>");
        }
        ScanRunReport r = report.getBody();

        StringBuilder html = new StringBuilder();
        html.append("<!doctype html><html><head><meta charset=\"utf-8\"/>");
        html.append("<title>Cyber-Scout Scan Report</title>");
        html.append("<style>body{font-family:ui-sans-serif,system-ui,Segoe UI,Roboto,Helvetica,Arial;max-width:980px;margin:24px auto;padding:0 12px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px;font-size:14px}th{background:#f6f6f6;text-align:left}code{background:#f2f2f2;padding:2px 4px;border-radius:4px}</style>");
        html.append("</head><body>");

        html.append("<h1>Cyber-Scout Pro Report</h1>");
        html.append("<p><b>ScanRun</b> #").append(r.run().id()).append(" | <b>Campaign</b> #").append(r.run().campaignId()).append("</p>");
        html.append("<p><b>Base URL</b>: <code>").append(escape(r.run().baseUrl())).append("</code></p>");
        html.append("<p><b>Status</b>: ").append(escape(r.run().status())).append("</p>");

        html.append("<h2>Findings (").append(r.findings().size()).append(")</h2>");
        html.append("<table><thead><tr><th>Severity</th><th>Standard</th><th>ID</th><th>Check</th><th>Title</th><th>Target</th><th>Confidence</th></tr></thead><tbody>");
        for (FindingRow f : r.findings()) {
            html.append("<tr>")
                    .append("<td>").append(escape(f.severity())).append("</td>")
                    .append("<td>").append(escape(f.owaspStandard())).append("</td>")
                    .append("<td>").append(escape(f.owaspId())).append("</td>")
                    .append("<td>").append(escape(f.checkId())).append("</td>")
                    .append("<td>").append(escape(f.title())).append("</td>")
                    .append("<td><code>").append(escape(f.target())).append("</code></td>")
                    .append("<td>").append(f.confidence()).append("</td>")
                    .append("</tr>");
        }
        html.append("</tbody></table>");

        html.append("<h2>HTTP Observations (").append(r.observations().size()).append(")</h2>");
        html.append("<table><thead><tr><th>When</th><th>Method</th><th>Status</th><th>Duration(ms)</th><th>URL</th></tr></thead><tbody>");
        for (ObservationRow o : r.observations()) {
            html.append("<tr>")
                    .append("<td>").append(o.observedAt() == null ? "" : escape(o.observedAt().toString())).append("</td>")
                    .append("<td>").append(escape(o.method())).append("</td>")
                    .append("<td>").append(o.statusCode() == null ? "" : o.statusCode()).append("</td>")
                    .append("<td>").append(o.durationMs() == null ? "" : o.durationMs()).append("</td>")
                    .append("<td><code>").append(escape(o.url())).append("</code></td>")
                    .append("</tr>");
        }
        html.append("</tbody></table>");

        html.append("</body></html>");
        return ResponseEntity.ok(html.toString());
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    public record ScanRunRow(long id, long campaignId, String baseUrl, OffsetDateTime startedAt, OffsetDateTime finishedAt, String status) {
    }

    public record FindingRow(
            String owaspStandard,
            String owaspId,
            String checkId,
            String target,
            String severity,
            double confidence,
            String title,
            String evidenceJson,
            OffsetDateTime createdAt
    ) {
    }

    public record ObservationRow(
            String method,
            String url,
            Integer statusCode,
            Integer durationMs,
            String responseHeaders,
            String responseBodyExcerpt,
            OffsetDateTime observedAt
    ) {
    }

    public record ScanRunReport(ScanRunRow run, List<FindingRow> findings, List<ObservationRow> observations, Map<String, Long> findingCounts) {
    }

    private static final class ScanRunMapper implements RowMapper<ScanRunRow> {
        @Override
        public ScanRunRow mapRow(ResultSet rs, int rowNum) throws SQLException {
            return new ScanRunRow(
                    rs.getLong("id"),
                    rs.getLong("campaign_id"),
                    rs.getString("base_url"),
                    rs.getObject("started_at", OffsetDateTime.class),
                    rs.getObject("finished_at", OffsetDateTime.class),
                    rs.getString("status")
            );
        }
    }

    private static final class FindingMapper implements RowMapper<FindingRow> {
        @Override
        public FindingRow mapRow(ResultSet rs, int rowNum) throws SQLException {
            return new FindingRow(
                    rs.getString("owasp_standard"),
                    rs.getString("owasp_id"),
                    rs.getString("check_id"),
                    rs.getString("target"),
                    rs.getString("severity"),
                    rs.getDouble("confidence"),
                    rs.getString("title"),
                    rs.getString("evidence_json"),
                    rs.getObject("created_at", OffsetDateTime.class)
            );
        }
    }

    private static final class ObservationMapper implements RowMapper<ObservationRow> {
        @Override
        public ObservationRow mapRow(ResultSet rs, int rowNum) throws SQLException {
            return new ObservationRow(
                    rs.getString("method"),
                    rs.getString("url"),
                    (Integer) rs.getObject("status_code"),
                    (Integer) rs.getObject("duration_ms"),
                    rs.getString("response_headers"),
                    rs.getString("response_body_excerpt"),
                    rs.getObject("observed_at", OffsetDateTime.class)
            );
        }
    }
}

