package io.mosip.certify.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.*;

public class JsonSchemaDataValidatorTest {

    private final JsonSchemaDataValidator validator = new JsonSchemaDataValidator();
    private final ObjectMapper mapper = new ObjectMapper();

    @SuppressWarnings("unchecked")
    private Map<String, Object> schema(String json) throws Exception {
        return mapper.readValue(json, Map.class);
    }

    private static final String V10 = "{\"type\":\"object\",\"required\":[\"name\",\"dateOfBirth\",\"gender\",\"address\"],"
            + "\"properties\":{\"name\":{\"type\":\"string\"},\"dateOfBirth\":{\"type\":\"string\",\"pattern\":\"^\\\\d{4}-\\\\d{2}-\\\\d{2}$\"},"
            + "\"gender\":{\"type\":\"string\"},\"address\":{\"type\":\"string\"}}}";
    private static final String V11 = V10.replace("\"address\"]", "\"address\",\"email\"]")
            .replace("\"address\":{\"type\":\"string\"}}", "\"address\":{\"type\":\"string\"},\"email\":{\"type\":\"string\"}}");

    private interface Action {
        void run() throws Exception;
    }

    private String code(Action r) {
        try {
            r.run();
            return null;
        } catch (CertifyException e) {
            return e.getErrorCode();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static final String OK10 = "{\"name\":\"A\",\"dateOfBirth\":\"1990-01-02\",\"gender\":\"F\",\"address\":\"X\"}";

    @Test
    public void validData_passes() throws Exception {
        validator.validate(schema(V10), OK10);
    }

    @Test
    public void missingMandatoryAttribute_failsWithoutEchoingValues() throws Exception {
        try {
            validator.validate(schema(V10), "{\"name\":\"SecretName\",\"dateOfBirth\":\"1990-01-02\",\"gender\":\"F\"}");
            fail();
        } catch (CertifyException e) {
            assertEquals(ErrorConstants.SCHEMA_VALIDATION_FAILED, e.getErrorCode());
            assertFalse(e.getMessage().contains("SecretName"));
        }
    }

    @Test
    public void wrongTypeAndPattern_fail() throws Exception {
        Map<String, Object> s = schema(V10);
        assertEquals(ErrorConstants.SCHEMA_VALIDATION_FAILED,
                code(() -> validator.validate(s, OK10.replace("\"A\"", "1"))));
        assertEquals(ErrorConstants.SCHEMA_VALIDATION_FAILED,
                code(() -> validator.validate(s, OK10.replace("1990-01-02", "bad"))));
    }

    @Test
    public void versionsValidateIndependently() throws Exception {
        Map<String, Object> s10 = schema(V10);
        Map<String, Object> s11 = schema(V11);
        validator.validate(s10, OK10);
        assertEquals(ErrorConstants.SCHEMA_VALIDATION_FAILED, code(() -> validator.validate(s11, OK10)));
        validator.validate(s11, OK10.replace("}", ",\"email\":\"a@b.c\"}"));
    }

    @Test
    public void remoteReferenceAndEmptyAndBrokenSchemasAreRejected() throws Exception {
        Map<String, Object> remote = schema("{\"$ref\":\"http://evil.example/s.json\"}");
        Map<String, Object> broken = schema("{\"$ref\":\"#/$defs/missing\"}");
        assertEquals(ErrorConstants.INVALID_SCHEMA_DEFINITION, code(() -> validator.validateDefinition(remote)));
        assertEquals(ErrorConstants.INVALID_SCHEMA_DEFINITION, code(() -> validator.validateDefinition(Map.of())));
        assertEquals(ErrorConstants.INVALID_SCHEMA_DEFINITION, code(() -> validator.validateDefinition(broken)));
    }
}
