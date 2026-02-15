package org.hat.cyberscout.scan.model;

public enum OwaspApiTop10_2023 implements OwaspCategory {
    API1("API1", "Broken Object Level Authorization"),
    API2("API2", "Broken Authentication"),
    API3("API3", "Broken Object Property Level Authorization"),
    API4("API4", "Unrestricted Resource Consumption"),
    API5("API5", "Broken Function Level Authorization"),
    API6("API6", "Unrestricted Access to Sensitive Business Flows"),
    API7("API7", "Server-Side Request Forgery"),
    API8("API8", "Security Misconfiguration"),
    API9("API9", "Improper Inventory Management"),
    API10("API10", "Unsafe Consumption of APIs");

    private final String id;
    private final String title;

    OwaspApiTop10_2023(String id, String title) {
        this.id = id;
        this.title = title;
    }

    @Override
    public OwaspStandard standard() {
        return OwaspStandard.OWASP_API_TOP10_2023;
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

