package org.hat.cyberscout.scan.model;

public enum Owasp2021 implements OwaspCategory {
    A01("A01", "Broken Access Control"),
    A02("A02", "Cryptographic Failures"),
    A03("A03", "Injection"),
    A04("A04", "Insecure Design"),
    A05("A05", "Security Misconfiguration"),
    A06("A06", "Vulnerable and Outdated Components"),
    A07("A07", "Identification and Authentication Failures"),
    A08("A08", "Software and Data Integrity Failures"),
    A09("A09", "Security Logging and Monitoring Failures"),
    A10("A10", "Server-Side Request Forgery (SSRF)");

    private final String id;
    private final String title;

    Owasp2021(String id, String title) {
        this.id = id;
        this.title = title;
    }

    public String id() {
        return id;
    }

    public String title() {
        return title;
    }

    @Override
    public OwaspStandard standard() {
        return OwaspStandard.OWASP_TOP10_2021;
    }
}
