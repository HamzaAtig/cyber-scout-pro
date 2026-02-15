package org.hat.cyberscout.util;

import java.net.URI;
import java.net.URISyntaxException;

public final class UrlUtils {

    private UrlUtils() {
    }

    public static URI parseBaseUrl(String baseUrl) {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        try {
            URI uri = new URI(baseUrl.trim());
            if (uri.getScheme() == null || (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme()))) {
                throw new IllegalArgumentException("baseUrl must start with http:// or https://");
            }
            if (uri.getHost() == null || uri.getHost().isBlank()) {
                throw new IllegalArgumentException("baseUrl host is required");
            }
            // Normalize to origin (no query/fragment)
            return new URI(uri.getScheme(), null, uri.getHost(), effectivePort(uri), null, null, null);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid baseUrl: " + baseUrl, e);
        }
    }

    public static int effectivePort(URI uri) {
        if (uri.getPort() != -1) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }
}

