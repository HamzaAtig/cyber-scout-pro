package org.hat.cyberscout.attack;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "cyberscout.attack")
public class AttackProperties {

    // Safe-by-default: disabled unless explicitly enabled in a dev profile.
    private boolean enabled = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}

