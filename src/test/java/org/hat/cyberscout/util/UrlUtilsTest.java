package org.hat.cyberscout.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import org.junit.jupiter.api.Test;

class UrlUtilsTest {

    @Test
    void parseBaseUrl_shouldNormalizeToOrigin() {
        URI uri = UrlUtils.parseBaseUrl("http://example.local:8080/some/path?x=1#frag");
        assertThat(uri.toString()).isEqualTo("http://example.local:8080");
    }

    @Test
    void parseBaseUrl_shouldRejectMissingScheme() {
        assertThatThrownBy(() -> UrlUtils.parseBaseUrl("example.local"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void effectivePort_shouldDefaultTo80or443() {
        assertThat(UrlUtils.effectivePort(URI.create("http://localhost"))).isEqualTo(80);
        assertThat(UrlUtils.effectivePort(URI.create("https://localhost"))).isEqualTo(443);
    }
}

