package org.hat.cyberscout.governance;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "cyberscout.governance")
public class GovernanceProperties {

    private boolean enabled = false;
    private boolean killSwitchDefault = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isKillSwitchDefault() {
        return killSwitchDefault;
    }

    public void setKillSwitchDefault(boolean killSwitchDefault) {
        this.killSwitchDefault = killSwitchDefault;
    }
}
