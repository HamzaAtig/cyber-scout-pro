package org.hat.cyberscout.control;

import org.hat.cyberscout.governance.GlobalKillSwitchService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/control")
public class KillSwitchController {

    private final GlobalKillSwitchService killSwitchService;

    public KillSwitchController(GlobalKillSwitchService killSwitchService) {
        this.killSwitchService = killSwitchService;
    }

    @GetMapping("/kill-switch")
    public KillSwitchStatus status() {
        return new KillSwitchStatus(killSwitchService.isEnabled());
    }

    @PostMapping("/kill-switch")
    public KillSwitchStatus set(@RequestBody KillSwitchToggleRequest request) {
        return new KillSwitchStatus(killSwitchService.setEnabled(request.enabled()));
    }

    public record KillSwitchToggleRequest(boolean enabled) {
    }

    public record KillSwitchStatus(boolean enabled) {
    }
}
