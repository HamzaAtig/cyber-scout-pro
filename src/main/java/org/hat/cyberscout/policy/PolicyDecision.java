package org.hat.cyberscout.policy;

import java.util.List;

public record PolicyDecision(boolean allowed, List<String> reasons) {
}
