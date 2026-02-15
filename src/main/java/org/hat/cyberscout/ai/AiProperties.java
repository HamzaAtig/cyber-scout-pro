package org.hat.cyberscout.ai;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "cyberscout.ai")
public class AiProperties {

    /**
     * Enables local LLM assistance (Ollama via Spring AI). This must remain local-only.
     */
    private boolean enabled = false;

    /**
     * Expected model name (e.g. "mistral", "llama3"). Actual usage depends on Spring AI config.
     */
    @NotBlank
    private String model = "mistral";

    /**
     * Low temperature for reproducible JSON output.
     */
    @Min(0)
    @Max(1)
    private double temperature = 0.2;

    /**
     * Maximum characters accepted from the model response. Larger responses are treated as invalid format.
     */
    @Min(128)
    @Max(200_000)
    private int maxResponseChars = 20_000;

    /**
     * Maximum characters accepted per generated payload.
     */
    @Min(16)
    @Max(20_000)
    private int maxPayloadChars = 2_000;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public double getTemperature() {
        return temperature;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public int getMaxResponseChars() {
        return maxResponseChars;
    }

    public void setMaxResponseChars(int maxResponseChars) {
        this.maxResponseChars = maxResponseChars;
    }

    public int getMaxPayloadChars() {
        return maxPayloadChars;
    }

    public void setMaxPayloadChars(int maxPayloadChars) {
        this.maxPayloadChars = maxPayloadChars;
    }
}

