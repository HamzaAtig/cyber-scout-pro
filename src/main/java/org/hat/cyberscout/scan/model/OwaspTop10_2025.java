package org.hat.cyberscout.scan.model;

public enum OwaspTop10_2025 implements OwaspCategory {
    A01("A01", "Broken Access Control"),
    A02("A02", "Security Misconfiguration"),
    A03("A03", "Injection"),
    A04("A04", "Insecure Design"),
    A05("A05", "Vulnerable and Outdated Components"),
    A06("A06", "Identification and Authentication Failures"),
    A07("A07", "Software and Data Integrity Failures"),
    A08("A08", "Security Logging and Monitoring Failures"),
    A09("A09", "Server-Side Request Forgery (SSRF)"),
    A10("A10", "Cryptographic Failures");

    private final String id;
    private final String title;

    OwaspTop10_2025(String id, String title) {
        this.id = id;
        this.title = title;
    }

    @Override
    public OwaspStandard standard() {
        return OwaspStandard.OWASP_TOP10_2025;
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public String title() {
        return title;
    }
}

