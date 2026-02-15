package org.hat.cyberscout.openapi;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class OpenApiParserTest {

    @Test
    void shouldMarkSecuredWhenGlobalSecurityPresentAndOperationDoesNotOverride() throws Exception {
        String json = """
            {
              "openapi":"3.0.0",
              "security":[{"bearerAuth":[]}],
              "paths":{
                "/admin":{"get":{"responses":{"200":{"description":"ok"}}}},
                "/public":{"get":{"security":[], "responses":{"200":{"description":"ok"}}}}
              }
            }
            """;
        ObjectMapper om = new ObjectMapper();
        JsonNode root = om.readTree(json);

        List<OpenApiOperation> ops = OpenApiParser.parseOperations(root, 50);

        OpenApiOperation admin = ops.stream().filter(o -> o.path().equals("/admin") && o.method().equals("GET")).findFirst().orElseThrow();
        OpenApiOperation pub = ops.stream().filter(o -> o.path().equals("/public") && o.method().equals("GET")).findFirst().orElseThrow();

        assertThat(admin.secured()).isTrue();
        assertThat(pub.secured()).isFalse(); // overridden by security:[]
    }

    @Test
    void shouldGenerateTypeMismatchBodyForObjectSchema() throws Exception {
        String json = """
            {
              "openapi":"3.0.0",
              "paths":{
                "/items":{"post":{"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"name":{"type":"string"}}}}}},"responses":{"200":{"description":"ok"}}}}
              }
            }
            """;
        ObjectMapper om = new ObjectMapper();
        JsonNode root = om.readTree(json);

        List<OpenApiOperation> ops = OpenApiParser.parseOperations(root, 50);
        OpenApiOperation op = ops.get(0);

        assertThat(op.jsonTypeMismatchBody()).isEqualTo("{\"name\":123}");
    }
}

