package org.hat.cyberscout.process;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.camunda.bpm.engine.RepositoryService;
import org.camunda.bpm.engine.RuntimeService;
import org.camunda.bpm.engine.runtime.ProcessInstance;
import org.hat.cyberscout.scan.persist.ScanRunRepository;
import org.hat.cyberscout.util.UrlUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/processes")
@Validated
public class ProcessController {

    public static final String CYBER_SCOUT_PROCESS_KEY = "cyberScoutAuditProcess";

    private final RuntimeService runtimeService;
    private final RepositoryService repositoryService;
    private final ScanRunRepository scanRunRepository;

    public ProcessController(RuntimeService runtimeService, RepositoryService repositoryService, ScanRunRepository scanRunRepository) {
        this.runtimeService = runtimeService;
        this.repositoryService = repositoryService;
        this.scanRunRepository = scanRunRepository;
    }

    @PostMapping("/cyber-scout/start")
    public ResponseEntity<StartProcessResponse> startCyberScout(@RequestBody @Validated StartCyberScoutRequest request) {
        boolean exists = repositoryService.createProcessDefinitionQuery()
                .processDefinitionKey(CYBER_SCOUT_PROCESS_KEY)
                .latestVersion()
                .count() > 0;
        if (!exists) {
            return ResponseEntity.status(500).body(new StartProcessResponse(null, null, CYBER_SCOUT_PROCESS_KEY, "PROCESS_NOT_DEPLOYED"));
        }

        Map<String, Object> variables = new HashMap<>();
        variables.put("campaignId", request.campaignId());
        URI baseUri = UrlUtils.parseBaseUrl(request.baseUrl());
        variables.put("baseUrl", baseUri.toString());
        variables.put("targetHost", baseUri.getHost());
        variables.put("targetPort", UrlUtils.effectivePort(baseUri));

        Long scanRunId = scanRunRepository.createRun(request.campaignId(), baseUri).orElse(null);
        if (scanRunId != null) {
            variables.put("scanRunId", scanRunId);
        }

        if (request.forceInvalidPayload() != null) {
            variables.put("forceInvalidPayload", request.forceInvalidPayload());
        }

        String businessKey = "campaign:" + request.campaignId();
        ProcessInstance instance = runtimeService.startProcessInstanceByKey(CYBER_SCOUT_PROCESS_KEY, businessKey, variables);
        String processDefinitionKey = repositoryService.createProcessDefinitionQuery()
                .processDefinitionId(instance.getProcessDefinitionId())
                .singleResult()
                .getKey();
        return ResponseEntity.ok(new StartProcessResponse(instance.getId(), scanRunId, processDefinitionKey, "STARTED"));
    }

    @PostMapping("/instances/{instanceId}/stop")
    public ResponseEntity<StopProcessResponse> stop(@PathVariable String instanceId, @RequestBody(required = false) StopProcessRequest request) {
        String reason = request != null && request.reason() != null && !request.reason().isBlank()
                ? request.reason()
                : "Stopped via API";

        ProcessInstance existing = runtimeService.createProcessInstanceQuery()
                .processInstanceId(instanceId)
                .singleResult();
        if (existing == null) {
            return ResponseEntity.notFound().build();
        }

        runtimeService.deleteProcessInstance(instanceId, reason);
        return ResponseEntity.ok(new StopProcessResponse(instanceId, "DELETED", reason));
    }

    @GetMapping("/instances/{instanceId}")
    public ResponseEntity<InstanceStatusResponse> status(@PathVariable String instanceId) {
        ProcessInstance existing = runtimeService.createProcessInstanceQuery()
                .processInstanceId(instanceId)
                .singleResult();
        if (existing == null) {
            return ResponseEntity.notFound().build();
        }
        String processDefinitionKey = repositoryService.createProcessDefinitionQuery()
                .processDefinitionId(existing.getProcessDefinitionId())
                .singleResult()
                .getKey();
        return ResponseEntity.ok(new InstanceStatusResponse(instanceId, processDefinitionKey, existing.getBusinessKey()));
    }

    public record StartCyberScoutRequest(
            @NotNull @Min(1) Long campaignId,
            @NotNull String baseUrl,
            Boolean forceInvalidPayload
    ) {
    }

    public record StartProcessResponse(String instanceId, Long scanRunId, String processDefinitionKey, String status) {
    }

    public record StopProcessRequest(String reason) {
    }

    public record StopProcessResponse(String instanceId, String status, String reason) {
    }

    public record InstanceStatusResponse(String instanceId, String processDefinitionKey, String businessKey) {
    }
}
