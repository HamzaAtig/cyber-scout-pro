package org.hat.cyberscout.scan.model;

public record Finding(
        OwaspCategory owasp,
        String checkId,
        String target,
        Severity severity,
        double confidence,
        String title,
        String evidenceJson
) {
}
