package org.hat.cyberscout.ai;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class AiPayloadItem {

    private String payload;
    private String purpose;

    public AiPayloadItem() {
    }

    public AiPayloadItem(String payload, String purpose) {
        this.payload = payload;
        this.purpose = purpose;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getPurpose() {
        return purpose;
    }

    public void setPurpose(String purpose) {
        this.purpose = purpose;
    }
}

