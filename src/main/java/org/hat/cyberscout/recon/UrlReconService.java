package org.hat.cyberscout.recon;

import static java.util.stream.Collectors.toMap;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.hat.cyberscout.util.UrlUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class UrlReconService {

    private static final Logger log = LoggerFactory.getLogger(UrlReconService.class);

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    public UrlReconService(ObjectMapper objectMapper) {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(Redirect.NEVER)
                .build();
        this.objectMapper = objectMapper;
    }

    public ReconResult recon(String baseUrl) {
        URI baseUri = UrlUtils.parseBaseUrl(baseUrl);

        TechFingerprint fingerprint = fingerprint(baseUri);
        List<EndpointCandidate> endpoints = new ArrayList<>();

        // Common endpoints (safe discovery only)
        Set<String> candidates = new LinkedHashSet<>();
        candidates.add("/");
        candidates.add("/robots.txt");
        candidates.add("/sitemap.xml");
        candidates.add("/.well-known/security.txt");
        candidates.add("/swagger-ui");
        candidates.add("/swagger-ui/");
        candidates.add("/v3/api-docs");
        candidates.add("/v3/api-docs/");
        candidates.add("/openapi.json");
        candidates.add("/actuator");
        candidates.add("/actuator/health");
        candidates.add("/graphql");
        candidates.add("/login");
        candidates.add("/admin");
        candidates.add("/h2-console");

        // Crawl a tiny bit from home page to discover same-origin links (depth 1).
        candidates.addAll(extractSameOriginLinks(baseUri.resolve("/"), 30));

        // If OpenAPI is present, use it to enumerate paths/methods.
        endpoints.addAll(openApiEndpointsIfPresent(baseUri));

        // Add HTTP GET candidates that we haven't already covered via OpenAPI.
        Set<String> already = new HashSet<>();
        for (EndpointCandidate e : endpoints) {
            already.add(e.path() + "|" + e.method());
        }
        for (String path : candidates) {
            String key = path + "|GET";
            if (already.contains(key)) {
                continue;
            }
            endpoints.add(new EndpointCandidate(path, "GET", techHintFromPath(path, fingerprint)));
        }

        // Keep it bounded for now.
        if (endpoints.size() > 80) {
            endpoints = endpoints.subList(0, 80);
        }

        return new ReconResult(baseUri, fingerprint, endpoints);
    }

    private TechFingerprint fingerprint(URI baseUri) {
        try {
            HttpResponse<Void> resp = httpClient.send(
                    HttpRequest.newBuilder(baseUri.resolve("/"))
                            .timeout(Duration.ofSeconds(8))
                            .method("HEAD", HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.discarding()
            );

            Map<String, String> headers = resp.headers().map().entrySet().stream()
                    .collect(toMap(
                            e -> e.getKey().toLowerCase(Locale.ROOT),
                            e -> String.join(",", e.getValue()),
                            (a, b) -> a
                    ));

            boolean hsts = headers.containsKey("strict-transport-security");
            boolean csp = headers.containsKey("content-security-policy");
            boolean xfo = headers.containsKey("x-frame-options");
            boolean xcto = headers.containsKey("x-content-type-options");

            return new TechFingerprint(
                    headers.get("server"),
                    headers.get("x-powered-by"),
                    hsts,
                    csp,
                    xfo,
                    xcto,
                    headers
            );
        } catch (Exception e) {
            log.warn("Fingerprint HEAD failed for {}: {}", baseUri, e.getMessage());
            return new TechFingerprint(null, null, false, false, false, false, Map.of());
        }
    }

    private List<EndpointCandidate> openApiEndpointsIfPresent(URI baseUri) {
        List<EndpointCandidate> endpoints = new ArrayList<>();
        Optional<JsonNode> doc = tryGetJson(baseUri.resolve("/v3/api-docs"));
        if (doc.isEmpty()) {
            doc = tryGetJson(baseUri.resolve("/openapi.json"));
        }
        if (doc.isEmpty()) {
            return endpoints;
        }

        JsonNode paths = doc.get().get("paths");
        if (paths == null || !paths.isObject()) {
            return endpoints;
        }

        paths.fieldNames().forEachRemaining(path -> {
            JsonNode methods = paths.get(path);
            if (methods == null || !methods.isObject()) {
                return;
            }
            methods.fieldNames().forEachRemaining(method -> {
                String m = method.toUpperCase(Locale.ROOT);
                if (!Set.of("GET", "POST", "PUT", "PATCH", "DELETE").contains(m)) {
                    return;
                }
                endpoints.add(new EndpointCandidate(path, m, "OPENAPI"));
            });
        });
        return endpoints;
    }

    private Optional<JsonNode> tryGetJson(URI uri) {
        try {
            HttpResponse<String> resp = httpClient.send(
                    HttpRequest.newBuilder(uri)
                            .timeout(Duration.ofSeconds(10))
                            .GET()
                            .header("Accept", "application/json")
                            .build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            if (resp.statusCode() / 100 != 2) {
                return Optional.empty();
            }
            return Optional.of(objectMapper.readTree(resp.body()));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    private Set<String> extractSameOriginLinks(URI pageUri, int maxLinks) {
        // Deliberately minimal: we only look for href="/...". No JS execution, no forms.
        try {
            HttpResponse<String> resp = httpClient.send(
                    HttpRequest.newBuilder(pageUri)
                            .timeout(Duration.ofSeconds(10))
                            .GET()
                            .header("Accept", "text/html, */*")
                            .build(),
                    HttpResponse.BodyHandlers.ofString()
            );
            if (resp.statusCode() / 100 != 2) {
                return Set.of();
            }
            String body = resp.body();
            Set<String> links = new LinkedHashSet<>();
            int idx = 0;
            while (idx < body.length() && links.size() < maxLinks) {
                int href = body.indexOf("href=\"/", idx);
                if (href < 0) {
                    break;
                }
                int start = href + "href=\"".length();
                int end = body.indexOf("\"", start);
                if (end < 0) {
                    break;
                }
                String raw = body.substring(start, end);
                // Keep path only; drop query/fragment.
                int q = raw.indexOf('?');
                if (q >= 0) raw = raw.substring(0, q);
                int f = raw.indexOf('#');
                if (f >= 0) raw = raw.substring(0, f);
                if (raw.length() > 1 && raw.endsWith("/")) {
                    raw = raw.substring(0, raw.length() - 1);
                }
                if (raw.startsWith("/") && raw.length() <= 255) {
                    links.add(raw);
                }
                idx = end + 1;
            }
            return links;
        } catch (Exception ignored) {
            return Set.of();
        }
    }

    private String techHintFromPath(String path, TechFingerprint fp) {
        if (path == null) {
            return "UNKNOWN";
        }
        if (path.startsWith("/actuator")) {
            return "SPRING_ACTUATOR";
        }
        if (path.startsWith("/v3/api-docs") || path.startsWith("/swagger")) {
            return "OPENAPI";
        }
        if (path.startsWith("/graphql")) {
            return "GRAPHQL";
        }
        if (path.contains("login") || path.contains("auth")) {
            return "AUTH";
        }
        if (fp != null && fp.poweredByHeader() != null && fp.poweredByHeader().toLowerCase(Locale.ROOT).contains("express")) {
            return "NODE_EXPRESS";
        }
        if (fp != null && fp.serverHeader() != null && fp.serverHeader().toLowerCase(Locale.ROOT).contains("nginx")) {
            return "NGINX";
        }
        return "GENERIC";
    }
}

