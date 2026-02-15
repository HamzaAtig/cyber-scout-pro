package org.hat.cyberscout.control;

import java.util.Optional;
import org.hat.cyberscout.governance.GovernanceService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/campaigns")
public class CampaignController {

    private final GovernanceService governanceService;

    public CampaignController(GovernanceService governanceService) {
        this.governanceService = governanceService;
    }

    @GetMapping("/{campaignId}/status")
    public ResponseEntity<CampaignStatusResponse> status(@PathVariable long campaignId) {
        if (!governanceService.isGovernanceEnabled()) {
            return ResponseEntity.status(501).body(new CampaignStatusResponse(campaignId, "DISABLED"));
        }

        Optional<String> status = governanceService.getCampaignStatus(campaignId);
        return status.map(value -> ResponseEntity.ok(new CampaignStatusResponse(campaignId, value)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/{campaignId}/stop")
    public ResponseEntity<CampaignStatusResponse> stop(@PathVariable long campaignId) {
        if (!governanceService.isGovernanceEnabled()) {
            return ResponseEntity.status(501).body(new CampaignStatusResponse(campaignId, "DISABLED"));
        }

        boolean stopped = governanceService.stopCampaign(campaignId);
        if (!stopped) {
            Optional<String> status = governanceService.getCampaignStatus(campaignId);
            return status.map(value -> ResponseEntity.ok(new CampaignStatusResponse(campaignId, value)))
                    .orElseGet(() -> ResponseEntity.notFound().build());
        }
        return ResponseEntity.ok(new CampaignStatusResponse(campaignId, "STOPPED"));
    }

    public record CampaignStatusResponse(long campaignId, String status) {
    }
}
