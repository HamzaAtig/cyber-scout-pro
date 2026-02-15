package org.hat.cyberscout.recon;

import java.util.Map;

public record TechFingerprint(
        String serverHeader,
        String poweredByHeader,
        boolean hasHsts,
        boolean hasCsp,
        boolean hasXFrameOptions,
        boolean hasXContentTypeOptions,
        Map<String, String> rawHeaders
) {
}

