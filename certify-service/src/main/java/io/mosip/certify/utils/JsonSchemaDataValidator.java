/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.Error;
import com.networknt.schema.InputFormat;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Validates the data returned by the data provider plugin against the JSON Schema (draft 2020-12) stored with a
 * versioned credential configuration. Uses com.networknt:json-schema-validator rather than a hand-written engine.
 *
 * <p>Safety rules enforced here, independent of the library's defaults:
 * <ul>
 *   <li>Only local references (<code>"$ref": "#/..."</code>) are allowed in a schema. A schema can therefore never
 *       make Certify fetch a remote document while issuing a credential.</li>
 *   <li>Failures report <i>where</i> and <i>which keyword</i> failed, never the offending value, so personal data
 *       is not echoed into error responses or logs.</li>
 * </ul>
 */
@Slf4j
@Component
public class JsonSchemaDataValidator {

    private static final int MAX_SCHEMA_BYTES = 256 * 1024;
    private static final int MAX_REPORTED_ERRORS = 10;

    private final SchemaRegistry schemaRegistry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12);
    private final ObjectMapper objectMapper = new ObjectMapper();
    // Published schemas are immutable, so a compiled schema can be reused for as long as its JSON text is the same.
    private final ConcurrentMap<String, Schema> compiledSchemas = new ConcurrentHashMap<>();

    /**
     * Checks a schema at registration time so that a broken schema is rejected up front instead of failing
     * every issuance later.
     */
    public void validateDefinition(Map<String, Object> schemaDefinition) {
        compile(toJson(schemaDefinition));
    }

    /**
     * @param schemaDefinition the JSON Schema stored with the credential configuration
     * @param dataJson         the data provider output, serialised as JSON
     * @throws CertifyException {@link ErrorConstants#SCHEMA_VALIDATION_FAILED} when the data does not satisfy the schema
     */
    public void validate(Map<String, Object> schemaDefinition, String dataJson) {
        String schemaJson = toJson(schemaDefinition);
        Schema schema = compiledSchemas.get(schemaJson);
        if (schema == null) {
            schema = compile(schemaJson);
            compiledSchemas.putIfAbsent(schemaJson, schema);
        }

        List<Error> errors;
        try {
            errors = schema.validate(dataJson, InputFormat.JSON);
        } catch (RuntimeException e) {
            log.error("Schema validation could not be executed", e);
            throw new CertifyException(ErrorConstants.SCHEMA_VALIDATION_FAILED,
                    "Credential data could not be validated against the schema.");
        }
        if (errors.isEmpty()) {
            return;
        }

        StringBuilder summary = new StringBuilder();
        int reported = 0;
        for (Error error : errors) {
            if (reported == MAX_REPORTED_ERRORS) {
                summary.append("; and ").append(errors.size() - MAX_REPORTED_ERRORS).append(" more");
                break;
            }
            if (reported > 0) {
                summary.append("; ");
            }
            // Location and keyword only (plus the attribute name for 'required'), never the submitted value.
            String location = String.valueOf(error.getInstanceLocation());
            if (location.isEmpty()) {
                location = "$";
            }
            if (error.getProperty() != null) {
                location = location + "/" + error.getProperty();
            }
            summary.append(location).append(" failed '").append(error.getKeyword()).append("'");
            reported++;
        }
        log.warn("Credential data rejected by schema validation: {} violation(s)", errors.size());
        throw new CertifyException(ErrorConstants.SCHEMA_VALIDATION_FAILED,
                "Credential data does not satisfy the credential schema: " + summary);
    }

    private Schema compile(String schemaJson) {
        try {
            Schema schema = schemaRegistry.getSchema(schemaJson);
            schema.initializeValidators();
            return schema;
        } catch (RuntimeException e) {
            log.error("Credential schema could not be compiled", e);
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_DEFINITION,
                    "The validation schema is not a valid JSON Schema (draft 2020-12).");
        }
    }

    private String toJson(Map<String, Object> schemaDefinition) {
        if (schemaDefinition == null || schemaDefinition.isEmpty()) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_DEFINITION, "The validation schema must not be empty.");
        }
        rejectNonLocalReferences(schemaDefinition);
        String json;
        try {
            json = objectMapper.writeValueAsString(schemaDefinition);
        } catch (JsonProcessingException e) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_DEFINITION, "The validation schema is not valid JSON.");
        }
        if (json.length() > MAX_SCHEMA_BYTES) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_DEFINITION,
                    "The validation schema is larger than " + MAX_SCHEMA_BYTES + " characters.");
        }
        return json;
    }

    private void rejectNonLocalReferences(Object node) {
        if (node instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                Object key = entry.getKey();
                Object value = entry.getValue();
                if (("$ref".equals(key) || "$dynamicRef".equals(key)) && value instanceof String reference
                        && !reference.startsWith("#")) {
                    throw new CertifyException(ErrorConstants.INVALID_SCHEMA_DEFINITION,
                            "Only local references (starting with '#') are allowed in a validation schema; found '" + reference + "'.");
                }
                rejectNonLocalReferences(value);
            }
        } else if (node instanceof List<?> list) {
            for (Object element : list) {
                rejectNonLocalReferences(element);
            }
        }
    }
}
