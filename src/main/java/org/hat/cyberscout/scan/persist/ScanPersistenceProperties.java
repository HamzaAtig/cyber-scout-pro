package org.hat.cyberscout.scan.persist;

import org.hat.cyberscout.scan.model.OwaspStandard;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "cyberscout.scan")
public class ScanPersistenceProperties {

    private boolean enabled = false;
    private OwaspStandard defaultStandard = OwaspStandard.OWASP_TOP10_2025;

    // "Active probing" means low-impact HTTP checks (GET/HEAD) that validate exposure.
    // This is intentionally not a load-test or DoS simulation.
    private boolean activeProbingEnabled = false;
    private int activeProbingMaxRequests = 25;
    private int rateLimitProbeRequests = 15;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public OwaspStandard getDefaultStandard() {
        return defaultStandard;
    }

    public void setDefaultStandard(OwaspStandard defaultStandard) {
        this.defaultStandard = defaultStandard;
    }

    public boolean isActiveProbingEnabled() {
        return activeProbingEnabled;
    }

    public void setActiveProbingEnabled(boolean activeProbingEnabled) {
        this.activeProbingEnabled = activeProbingEnabled;
    }

    public int getActiveProbingMaxRequests() {
        return activeProbingMaxRequests;
    }

    public void setActiveProbingMaxRequests(int activeProbingMaxRequests) {
        this.activeProbingMaxRequests = activeProbingMaxRequests;
    }

    public int getRateLimitProbeRequests() {
        return rateLimitProbeRequests;
    }

    public void setRateLimitProbeRequests(int rateLimitProbeRequests) {
        this.rateLimitProbeRequests = rateLimitProbeRequests;
    }
}
