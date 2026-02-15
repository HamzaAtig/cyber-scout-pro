package org.hat.cyberscout.recon;

import java.net.URI;
import java.util.List;

public record ReconResult(URI baseUri, TechFingerprint fingerprint, List<EndpointCandidate> endpoints) {
}

