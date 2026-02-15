package org.hat.cyberscout.governance;

import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.stereotype.Service;

@Service
public class GlobalKillSwitchService {

    private final AtomicBoolean enabled;

    public GlobalKillSwitchService(GovernanceProperties properties) {
        this.enabled = new AtomicBoolean(properties.isKillSwitchDefault());
    }

    public boolean isEnabled() {
        return enabled.get();
    }

    public boolean setEnabled(boolean value) {
        enabled.set(value);
        return enabled.get();
    }
}
