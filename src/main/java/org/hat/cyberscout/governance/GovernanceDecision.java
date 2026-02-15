package org.hat.cyberscout.governance;

import java.util.List;

public record GovernanceDecision(boolean allowed, List<String> reasons) {
}
