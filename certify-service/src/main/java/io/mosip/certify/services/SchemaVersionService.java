/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.config.SchemaVersioningConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.JsonSchemaDataValidator;
import io.mosip.certify.utils.SchemaVersionCandidate;
import io.mosip.certify.utils.SchemaVersionResolver;
import io.mosip.certify.vcformatters.VCFormatter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static io.mosip.certify.core.constants.Constants.DELIMITER;
import static io.mosip.certify.core.constants.Constants.SCHEMA_VERSION_MARKER;

/**
 * Connects schema versioning to issuance (DataProvider plugin mode):
 * <ol>
 *   <li>{@link #resolveTemplateName} turns a credential request into the template key of the configuration that
 *       must issue it. For an unversioned (legacy) configuration that key is the one Certify has always used.</li>
 *   <li>{@link #validateProvidedData} checks the data provider output against that configuration's JSON Schema.</li>
 * </ol>
 */
@Slf4j
@Service
public class SchemaVersionService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private VCFormatter vcFormatter;

    @Autowired
    private JsonSchemaDataValidator jsonSchemaDataValidator;

    @Autowired
    private SchemaVersioningConfig schemaVersioningConfig;

    /**
     * @param vcRequestDto     the request as built by the issuance service (format, type/context, vct or doctype)
     * @param requestedVersion the schema_version named in the credential request, or null
     * @param tokenScopes      the scopes of the access token
     * @return the template key to use for formatting, signing and validation
     */
    public String resolveTemplateName(VCRequestDto vcRequestDto, String requestedVersion, Collection<String> tokenScopes) {
        String baseTemplateName = io.mosip.certify.utils.CredentialUtils.getTemplateName(vcRequestDto);
        List<CredentialConfig> configs = findConfigsFor(baseTemplateName);

        List<SchemaVersionCandidate> allCandidates = new ArrayList<>();
        Map<SchemaVersionCandidate, CredentialConfig> configByCandidate = new IdentityHashMap<>();
        for (CredentialConfig config : configs) {
            SchemaVersionCandidate candidate = toCandidate(config);
            allCandidates.add(candidate);
            configByCandidate.put(candidate, config);
        }

        // With a single configuration there is nothing to choose between, and the scope has already been matched
        // against it by the caller: keep exactly the pre-versioning behaviour.
        boolean scopeSelectsVersion = configs.size() > 1 && tokenScopes != null;

        SchemaVersionCandidate selected;
        if (requestedVersion != null) {
            selected = SchemaVersionResolver.resolve(allCandidates, requestedVersion, null);
            if (scopeSelectsVersion && !tokenScopes.contains(configByCandidate.get(selected).getScope())) {
                throw new CertifyException(ErrorConstants.SCHEMA_VERSION_SCOPE_MISMATCH,
                        "The access token is not authorised for schema version " + selected.getEffectiveVersion() + " of this credential.");
            }
        } else {
            List<SchemaVersionCandidate> considered = allCandidates;
            if (scopeSelectsVersion) {
                // No version requested: only versions the token's scope authorises are eligible.
                considered = new ArrayList<>();
                for (SchemaVersionCandidate candidate : allCandidates) {
                    if (tokenScopes.contains(configByCandidate.get(candidate).getScope())) {
                        considered.add(candidate);
                    }
                }
                if (considered.isEmpty()) {
                    throw new CertifyException(ErrorConstants.SCHEMA_VERSION_SCOPE_MISMATCH,
                            "The access token is not authorised for any schema version of this credential.");
                }
            }
            selected = SchemaVersionResolver.resolve(considered, null, configuredDefaultFor(configs, baseTemplateName));
        }

        if (selected.isDeprecated()) {
            log.warn("Issuing with deprecated schema version {} of {}", selected.getEffectiveVersion(), selected.getConfigKeyId());
        }
        log.info("Resolved credential configuration {} (schema version {})", selected.getConfigKeyId(),
                selected.isLegacy() ? "unversioned" : selected.getVersion());
        return selected.isLegacy() ? baseTemplateName : baseTemplateName + SCHEMA_VERSION_MARKER + selected.getVersion();
    }

    /**
     * Validates the data returned by the data provider against the JSON Schema of the resolved configuration.
     * A no-op for configurations without a schema, which includes every unversioned configuration.
     */
    public void validateProvidedData(String templateName, String providedDataJson) {
        Map<String, Object> validationSchema = vcFormatter.getValidationSchema(templateName);
        if (validationSchema == null || validationSchema.isEmpty()) {
            return;
        }
        jsonSchemaDataValidator.validate(validationSchema, providedDataJson);
    }

    private List<CredentialConfig> findConfigsFor(String baseTemplateName) {
        String[] parts = baseTemplateName.split(DELIMITER, 3);
        if (parts.length == 2) {
            if (VCFormats.MSO_MDOC.equals(parts[0])) {
                return credentialConfigRepository.findAllByCredentialFormatAndDocType(parts[0], parts[1]);
            }
            if (VCFormats.VC_SD_JWT.equals(parts[0])) {
                return credentialConfigRepository.findAllByCredentialFormatAndSdJwtVct(parts[0], parts[1]);
            }
            return List.of();
        }
        return credentialConfigRepository.findAllByCredentialFormatAndCredentialTypeAndContext(parts[2], parts[0], parts[1]);
    }

    private SchemaVersionCandidate toCandidate(CredentialConfig config) {
        String status;
        if (!Constants.ACTIVE.equals(config.getStatus())) {
            status = Constants.SCHEMA_STATUS_DISABLED; // the pre-existing active/inactive switch still wins
        } else {
            status = config.getSchemaStatus() != null ? config.getSchemaStatus() : Constants.SCHEMA_STATUS_ACTIVE;
        }
        return new SchemaVersionCandidate(config.getCredentialConfigKeyId(), config.getSchemaVersion(), status);
    }

    private String configuredDefaultFor(List<CredentialConfig> configs, String baseTemplateName) {
        Map<String, String> configuredDefaultVersions = schemaVersioningConfig.getDefaultVersions();
        if (configuredDefaultVersions == null || configuredDefaultVersions.isEmpty()) {
            return null;
        }
        String key = configs.stream()
                .map(CredentialConfig::getSchemaId)
                .filter(Objects::nonNull)
                .findFirst()
                .orElseGet(() -> {
                    String[] parts = baseTemplateName.split(DELIMITER, 3);
                    return parts.length == 2 ? parts[1] : parts[0];
                });
        return configuredDefaultVersions.get(key);
    }
}
