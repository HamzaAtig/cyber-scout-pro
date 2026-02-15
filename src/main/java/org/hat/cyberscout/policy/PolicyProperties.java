package org.hat.cyberscout.policy;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "cyberscout.policy")
public class PolicyProperties {

    @NotEmpty
    private Set<String> allowedHosts = Set.of("localhost", "127.0.0.1");

    @NotEmpty
    private Set<Integer> allowedPorts = Set.of(80, 443, 8080, 8443);

    @NotEmpty
    private Set<String> allowedMethods = Set.of("GET", "POST", "PUT", "PATCH", "DELETE");

    @NotEmpty
    private List<String> allowedPathPrefixes = List.of("/");

    @Min(1)
    @Max(1000)
    private int maxRequestsPerTarget = 25;

    @Min(1)
    @Max(20)
    private int maxPayloadsPerTarget = 3;

    @Min(1)
    @Max(64)
    private int maxConcurrentAttacks = 4;

    private boolean dryRunOnly = true;

    public Set<String> getAllowedHosts() {
        return allowedHosts;
    }

    public void setAllowedHosts(Set<String> allowedHosts) {
        this.allowedHosts = allowedHosts;
    }

    public Set<Integer> getAllowedPorts() {
        return allowedPorts;
    }

    public void setAllowedPorts(Set<Integer> allowedPorts) {
        this.allowedPorts = allowedPorts;
    }

    public Set<String> getAllowedMethods() {
        return allowedMethods;
    }

    public void setAllowedMethods(Set<String> allowedMethods) {
        this.allowedMethods = allowedMethods;
    }

    public List<String> getAllowedPathPrefixes() {
        return allowedPathPrefixes;
    }

    public void setAllowedPathPrefixes(List<String> allowedPathPrefixes) {
        this.allowedPathPrefixes = allowedPathPrefixes;
    }

    public int getMaxRequestsPerTarget() {
        return maxRequestsPerTarget;
    }

    public void setMaxRequestsPerTarget(int maxRequestsPerTarget) {
        this.maxRequestsPerTarget = maxRequestsPerTarget;
    }

    public int getMaxPayloadsPerTarget() {
        return maxPayloadsPerTarget;
    }

    public void setMaxPayloadsPerTarget(int maxPayloadsPerTarget) {
        this.maxPayloadsPerTarget = maxPayloadsPerTarget;
    }

    public int getMaxConcurrentAttacks() {
        return maxConcurrentAttacks;
    }

    public void setMaxConcurrentAttacks(int maxConcurrentAttacks) {
        this.maxConcurrentAttacks = maxConcurrentAttacks;
    }

    public boolean isDryRunOnly() {
        return dryRunOnly;
    }

    public void setDryRunOnly(boolean dryRunOnly) {
        this.dryRunOnly = dryRunOnly;
    }
}
