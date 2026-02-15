package org.hat.cyberscout.http;

import java.net.URI;

public interface HttpProber {
    HttpProbeResult probe(Long scanRunId, URI baseUri, String path, String method);

    default HttpProbeResult probeJson(Long scanRunId, URI baseUri, String path, String method, String jsonBody) {
        // Optional operation; implementations may override for real JSON execution.
        return probe(scanRunId, baseUri, path, method);
    }
}
