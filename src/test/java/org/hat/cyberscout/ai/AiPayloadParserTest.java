package org.hat.cyberscout.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AiPayloadParserTest {

    @Test
    void parsesArrayOfObjects() {
        AiProperties props = new AiProperties();
        AiPayloadParser parser = new AiPayloadParser(new ObjectMapper(), props);

        String json = """
                [
                  {"payload":"{","purpose":"truncated"},
                  {"payload":"{\\"a\\":","purpose":"truncated2"}
                ]
                """;

        List<String> payloads = parser.parsePayloads(json, 3);
        assertEquals(List.of("{", "{\"a\":"), payloads);
    }

    @Test
    void parsesArrayOfStrings() {
        AiProperties props = new AiProperties();
        AiPayloadParser parser = new AiPayloadParser(new ObjectMapper(), props);

        String json = """
                ["{","null","[1,2,]"]
                """;

        List<String> payloads = parser.parsePayloads(json, 5);
        assertEquals(List.of("{", "null", "[1,2,]"), payloads);
    }

    @Test
    void rejectsNonJson() {
        AiProperties props = new AiProperties();
        AiPayloadParser parser = new AiPayloadParser(new ObjectMapper(), props);

        assertThrows(IllegalArgumentException.class, () -> parser.parsePayloads("not json", 3));
    }

    @Test
    void rejectsEmptyResult() {
        AiProperties props = new AiProperties();
        AiPayloadParser parser = new AiPayloadParser(new ObjectMapper(), props);

        String json = """
                [{"payload":"DROP TABLE x","purpose":"bad"}]
                """;

        assertThrows(IllegalArgumentException.class, () -> parser.parsePayloads(json, 3));
    }
}

