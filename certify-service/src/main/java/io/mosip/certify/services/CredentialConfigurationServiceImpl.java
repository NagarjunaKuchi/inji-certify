/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.services;

import com.danubetech.dataintegrity.suites.DataIntegrityProofDataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.constants.VCFormats;
import io.mosip.certify.core.dto.*;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.core.exception.CredentialConfigException;
import io.mosip.certify.core.spi.CredentialConfigurationService;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.CredentialConfigMapper;
import io.mosip.certify.utils.JsonSchemaDataValidator;
import io.mosip.certify.utils.SchemaVersionResolver;
import io.mosip.certify.validators.credentialconfigvalidators.LdpVcCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.MsoMdocCredentialConfigValidator;
import io.mosip.certify.validators.credentialconfigvalidators.SdJwtCredentialConfigValidator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Slf4j
@Component
@Transactional
public class CredentialConfigurationServiceImpl implements CredentialConfigurationService {

    @Autowired
    private CredentialConfigRepository credentialConfigRepository;

    @Autowired
    private CredentialConfigMapper credentialConfigMapper;

    @Autowired
    private JsonSchemaDataValidator jsonSchemaDataValidator;

    @Value("${mosip.certify.domain.url}")
    private String credentialIssuer;

    @Value("${mosip.certify.authorization.url}")
    private String authUrl;

    @Value("${server.servlet.path}")
    private String servletPath;

    @Value("${mosip.certify.plugin-mode}")
    private String pluginMode;

    @Value("#{${mosip.certify.credential-config.issuer.display}}")
    private List<Map<String, String>> issuerDisplay;

    @Value("#{${mosip.certify.data-provider-plugin.credential-status.allowed-status-purposes:{}}}")
    private List<String> allowedCredentialStatusPurposes;

    @Value("#{${mosip.certify.credential-config.cryptographic-binding-methods-supported}}")
    private LinkedHashMap<String, List<String>> cryptographicBindingMethodsSupportedMap;

    @Value("#{${mosip.certify.credential-config.credential-signing-alg-values-supported}}")
    private LinkedHashMap<String, List<String>> credentialSigningAlgValuesSupportedMap;

    @Value("#{${mosip.certify.credential-config.proof-types-supported}}")
    private LinkedHashMap<String, Object> proofTypesSupported;

    @Value("#{${mosip.certify.signature-algo.key-alias-mapper}}")
    private Map<String, List<List<String>>> keyAliasMapper;

    @Value("#{${mosip.certify.credential-config.as-mapping:{}}}")
    private Map<String, String> authorizationServerMapping;


    private static final String CREDENTIAL_CONFIG_CACHE_NAME = "credentialConfig";

    private static final ObjectMapper SCHEMA_COMPARISON_MAPPER = new ObjectMapper();

    @Override
    public CredentialConfigResponse addCredentialConfiguration(CredentialConfigurationDTO credentialConfigurationDTO) {
        validateCredentialConfiguration(credentialConfigurationDTO, true);

        CredentialConfig credentialConfig = credentialConfigMapper.toEntity(credentialConfigurationDTO);
        credentialConfig.setConfigId(UUID.randomUUID().toString());
        credentialConfig.setStatus(Constants.ACTIVE);
        if (credentialConfig.getSchemaVersion() != null) {
            if (credentialConfigurationDTO.getSchemaStatus() != null
                    && !Constants.SCHEMA_STATUS_ACTIVE.equals(credentialConfigurationDTO.getSchemaStatus())) {
                throw new CertifyException(ErrorConstants.INVALID_SCHEMA_STATUS,
                        "A new schema version is always created ACTIVE. Deprecate or disable it with an update once it is published.");
            }
            credentialConfig.setSchemaStatus(Constants.SCHEMA_STATUS_ACTIVE);
        }


        credentialConfig.setCryptographicBindingMethodsSupported(cryptographicBindingMethodsSupportedMap.get(credentialConfig.getCredentialFormat()));
        credentialConfig.setCredentialSigningAlgValuesSupported(Collections.singletonList(credentialConfig.getSignatureCryptoSuite()));
        credentialConfig.setProofTypesSupported(proofTypesSupported);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Added credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    private void validateCredentialConfiguration(CredentialConfigurationDTO credentialConfig, boolean shouldCheckDuplicate) {

        validateSchemaVersioning(credentialConfig);

        if (credentialConfig.getCredentialStatusPurposes() != null && credentialConfig.getCredentialStatusPurposes().size() > 1){
            throw new CertifyException(ErrorConstants.MULTIPLE_STATUS_PURPOSES_NOT_SUPPORTED, "Multiple credential status purposes are not supported. Please specify only one.");
        }

        if (credentialConfig.getCredentialStatusPurposes() != null && !credentialConfig.getCredentialStatusPurposes().isEmpty() && !allowedCredentialStatusPurposes.contains(credentialConfig.getCredentialStatusPurposes().getFirst())) {
            throw new CertifyException(ErrorConstants.INVALID_STATUS_PURPOSE, "Invalid credential status purpose. Allowed values are: " + allowedCredentialStatusPurposes);
        }

        if(pluginMode.equals("DataProvider") && (credentialConfig.getVcTemplate() == null || credentialConfig.getVcTemplate().isEmpty())) {
            throw new CertifyException(ErrorConstants.CREDENTIAL_TEMPLATE_REQUIRED, "A Credential Template is required for issuers using the Data Provider plugin.");
        }

        if(credentialConfig.getQrSettings() == null || credentialConfig.getQrSettings().isEmpty()) {
            if(credentialConfig.getQrSignatureAlgo() != null) {
                throw new CertifyException(ErrorConstants.QR_SIGNATURE_ALGO_NOT_ALLOWED, "QR signature algorithm is not allowed when QR settings are not set.");

            }
        } else {
            String qrSignatureAlgo = credentialConfig.getQrSignatureAlgo();
            if (qrSignatureAlgo != null && !qrSignatureAlgo.isEmpty() && !keyAliasMapper.containsKey(qrSignatureAlgo)) {
                throw new CertifyException(ErrorConstants.INVALID_QR_SIGNING_ALGORITHM, "The algorithm " + qrSignatureAlgo + " is not supported for QR signing. The supported values are: " + keyAliasMapper.keySet());
            }
        }

        switch (credentialConfig.getCredentialFormat()) {
            case VCFormats.LDP_VC:
                if (!LdpVcCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_MANDATORY_FIELDS_MISSING, "Fields context, credentialType, and signatureCryptoSuite are mandatory for the ldp_vc format.");
                }
                if(shouldCheckDuplicate && LdpVcCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.LDP_VC_CONFIG_EXISTS, "Configuration already exists for the specified context and credentialType.");
                }
                validateKeyAliasMapperConfiguration(credentialConfig);
                break;
            case VCFormats.MSO_MDOC:
                if (!MsoMdocCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_MANDATORY_FIELDS_MISSING, "Fields doctype and signatureCryptoSuite are mandatory for the mso_mdoc format.");
                }
                if(shouldCheckDuplicate && MsoMdocCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.MSO_MDOC_CONFIG_EXISTS, "Configuration already exists for the specified doctype.");
                }
                break;
            case VCFormats.VC_SD_JWT:
                if (!SdJwtCredentialConfigValidator.isValidCheck(credentialConfig)) {
                    throw new CertifyException(ErrorConstants.VC_SD_JWT_MANDATORY_FIELDS_MISSING, "Fields vct and signatureAlgo are mandatory for the vc+sd-jwt format.");
                }
                if(shouldCheckDuplicate && SdJwtCredentialConfigValidator.isConfigAlreadyPresent(credentialConfig, credentialConfigRepository)) {
                    throw new CertifyException(ErrorConstants.VC_SD_JWT_CONFIG_EXISTS, "Configuration already exists for the specified vct.");
                }
                break;
            default:
                throw new CertifyException(ErrorConstants.UNSUPPORTED_FORMAT, "Unsupported credential format: " + credentialConfig.getCredentialFormat());
        }
    }

    private void validateSchemaVersioning(CredentialConfigurationDTO credentialConfig) {
        String version = credentialConfig.getSchemaVersion();
        if (version == null) {
            if (credentialConfig.getSchemaId() != null || credentialConfig.getSchemaStatus() != null
                    || credentialConfig.getValidationSchema() != null) {
                throw new CertifyException(ErrorConstants.INVALID_SCHEMA_DEFINITION,
                        "schemaId, schemaStatus and validationSchema can only be set together with schemaVersion.");
            }
            return;
        }
        if (pluginMode.equals("VCIssuance")) {
            throw new CertifyException(ErrorConstants.SCHEMA_VERSION_UNSUPPORTED_IN_PLUGIN_MODE,
                    "Schema versioning is only supported with the DataProvider plugin mode.");
        }
        if (!SchemaVersionResolver.isValidVersion(version)) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_VERSION,
                    "Invalid schemaVersion '" + version + "'. Expected MAJOR.MINOR or MAJOR.MINOR.PATCH.");
        }
        String canonical = SchemaVersionResolver.canonicalize(version);
        if (!canonical.equals(version)) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_VERSION,
                    "schemaVersion must be written in canonical form: use '" + canonical + "' instead of '" + version + "'.");
        }
        if (credentialConfig.getSchemaStatus() != null && !SchemaVersionResolver.isValidStatus(credentialConfig.getSchemaStatus())) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_STATUS,
                    "Invalid schemaStatus. Allowed values: ACTIVE, DEPRECATED, DISABLED.");
        }
        if (credentialConfig.getValidationSchema() != null) {
            jsonSchemaDataValidator.validateDefinition(credentialConfig.getValidationSchema());
        }
    }

    /**
     * Published versions are immutable. Presentation metadata (display, display order, scope, ...) may still be
     * edited, but everything that defines the credential's structure or how it is rendered may not.
     */
    private void assertPublishedDefinitionUnchanged(CredentialConfig existing, CredentialConfigurationDTO requested) {
        List<String> changed = new ArrayList<>();
        if (!Objects.equals(existing.getSchemaId(), requested.getSchemaId())) changed.add("schemaId");
        if (!Objects.equals(existing.getSchemaVersion(), requested.getSchemaVersion())) changed.add("schemaVersion");
        if (!sameJson(existing.getValidationSchema(), requested.getValidationSchema())) changed.add("validationSchema");
        if (!Objects.equals(existing.getVcTemplate(), requested.getVcTemplate())) changed.add("vcTemplate");
        if (!Objects.equals(existing.getCredentialFormat(), requested.getCredentialFormat())) changed.add("credentialFormat");
        if (!Objects.equals(existing.getCredentialType(), credentialConfigMapper.listToCommaSeparatedString(requested.getCredentialTypes()))) changed.add("credentialTypes");
        if (!Objects.equals(existing.getContext(), credentialConfigMapper.listToCommaSeparatedString(requested.getContextURLs()))) changed.add("contextURLs");
        if (!Objects.equals(existing.getSdJwtVct(), requested.getSdJwtVct())) changed.add("sdJwtVct");
        if (!Objects.equals(existing.getDocType(), requested.getDocType())) changed.add("doctype");
        if (!changed.isEmpty()) {
            throw new CertifyException(ErrorConstants.SCHEMA_VERSION_IMMUTABLE,
                    "Schema version " + existing.getSchemaVersion() + " of " + existing.getCredentialConfigKeyId()
                            + " is published and immutable; these fields differ from the stored version: " + String.join(", ", changed)
                            + ". Register a new schema version instead.");
        }
    }

    /** @return the status to store: unchanged when the request names none, otherwise the requested forward transition */
    private String nextSchemaStatus(CredentialConfig existing, String requestedStatus) {
        if (requestedStatus == null) {
            return existing.getSchemaStatus();
        }
        if (!SchemaVersionResolver.isValidStatus(requestedStatus)) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_STATUS, "Invalid schemaStatus. Allowed values: ACTIVE, DEPRECATED, DISABLED.");
        }
        if (!SchemaVersionResolver.isAllowedTransition(existing.getSchemaStatus(), requestedStatus)) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_STATUS_TRANSITION,
                    "schemaStatus cannot move from " + existing.getSchemaStatus() + " to " + requestedStatus
                            + ". Allowed: ACTIVE -> DEPRECATED -> DISABLED (ACTIVE -> DISABLED is also allowed).");
        }
        return requestedStatus;
    }

    /**
     * An existing unversioned configuration may opt in to versioning. It keeps behaving as version 1.0, so that is
     * the only version it can adopt; anything else would silently change what the existing credential is.
     */
    private String adoptSchemaVersioning(CredentialConfigurationDTO requested) {
        if (!Constants.LEGACY_SCHEMA_VERSION.equals(requested.getSchemaVersion())) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_VERSION,
                    "An existing unversioned configuration can only adopt schemaVersion " + Constants.LEGACY_SCHEMA_VERSION
                            + ". Register other versions as new configurations.");
        }
        if (requested.getSchemaStatus() != null && !Constants.SCHEMA_STATUS_ACTIVE.equals(requested.getSchemaStatus())) {
            throw new CertifyException(ErrorConstants.INVALID_SCHEMA_STATUS,
                    "A configuration adopting schema versioning starts ACTIVE.");
        }
        return Constants.SCHEMA_STATUS_ACTIVE;
    }

    private boolean sameJson(Object left, Object right) {
        // Compared as parsed JSON text: valueToTree keeps Integer and Long apart, so an unchanged schema whose
        // numbers were stored as one and submitted as the other would look modified. Fails closed (= "changed").
        try {
            return Objects.equals(SCHEMA_COMPARISON_MAPPER.readTree(SCHEMA_COMPARISON_MAPPER.writeValueAsString(left)),
                    SCHEMA_COMPARISON_MAPPER.readTree(SCHEMA_COMPARISON_MAPPER.writeValueAsString(right)));
        } catch (JsonProcessingException e) {
            return false;
        }
    }

    private void validateKeyAliasMapperConfiguration(CredentialConfigurationDTO credentialConfig) {
        if(pluginMode.equals("VCIssuance")) {
            return;
        }
        String signatureCryptoSuite = credentialConfig.getSignatureCryptoSuite();
        String signatureAlgo = credentialConfig.getSignatureAlgo();

        if(signatureCryptoSuite != null) {
            if(!credentialSigningAlgValuesSupportedMap.containsKey(signatureCryptoSuite)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_CRYPTO_SUITE, "Unsupported signature crypto suite: " + signatureCryptoSuite);
            }

            List<String> signatureAlgos = credentialSigningAlgValuesSupportedMap.get(signatureCryptoSuite);
            if(signatureAlgo == null ) {
                signatureAlgo = signatureAlgos.getFirst();
                credentialConfig.setSignatureAlgo(signatureAlgo);
            } else if(!signatureAlgos.contains(signatureAlgo)) {
                throw new CertifyException(ErrorConstants.UNSUPPORTED_SIGNATURE_ALGO, "Signature algorithm " + signatureAlgo + " is not supported for the crypto suite: " + signatureCryptoSuite);
            }
        }

        List<List<String>> keyAliasList = keyAliasMapper.get(credentialConfig.getSignatureAlgo());
        if (keyAliasList == null || keyAliasList.isEmpty()) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_CONFIG_NOT_FOUND, "No key chooser configuration found for the signature crypto suite: " + credentialConfig.getSignatureCryptoSuite());
        }

        boolean isMatch = keyAliasList.stream()
                .anyMatch(pair ->
                        credentialConfig.getKeyManagerAppId() != null &&
                        pair.getFirst().equals(credentialConfig.getKeyManagerAppId()) &&
                        credentialConfig.getKeyManagerRefId() != null &&
                        pair.getLast().equals(credentialConfig.getKeyManagerRefId()));

        if (!isMatch) {
            throw new CertifyException(ErrorConstants.KEY_CHOOSER_APP_REF_NOT_FOUND, "No matching appId and refId found in the key chooser configuration.");
        }
    }

    @Override
    public CredentialConfigurationDTO getCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_BY_ID, "Configuration not found for the provided ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();
        if(!credentialConfig.getStatus().equals(Constants.ACTIVE)) {
            throw new CertifyException(ErrorConstants.CONFIG_NOT_ACTIVE, "Configuration is inactive.");
        }

        return credentialConfigMapper.toDto(credentialConfig);
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     * The alternative is manual CacheManager.evict() after fetching the object once in this method.
     */
    @Override
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME, key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)", condition = "#credentialConfigKeyId != null")
    public CredentialConfigResponse updateCredentialConfiguration(String credentialConfigKeyId, CredentialConfigurationDTO credentialConfigurationDTO){
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId);

        if(optional.isEmpty()) {
            log.warn("Configuration not found for update with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_UPDATE, "Configuration not found for update with ID: " + credentialConfigKeyId);
        }

        CredentialConfig credentialConfig = optional.get();

        // Schema versioning: a published (versioned) configuration may only change its lifecycle status.
        String schemaStatusToApply = null;
        if (credentialConfig.getSchemaVersion() != null) {
            assertPublishedDefinitionUnchanged(credentialConfig, credentialConfigurationDTO);
            schemaStatusToApply = nextSchemaStatus(credentialConfig, credentialConfigurationDTO.getSchemaStatus());
        } else if (credentialConfigurationDTO.getSchemaVersion() != null) {
            schemaStatusToApply = adoptSchemaVersioning(credentialConfigurationDTO);
        }

        credentialConfigMapper.updateEntityFromDto(credentialConfigurationDTO, credentialConfig);
        if (schemaStatusToApply != null) {
            // The mapper copies the request's (possibly absent) status over the entity's; the checked value wins.
            credentialConfig.setSchemaStatus(schemaStatusToApply);
        }

        validateCredentialConfiguration(credentialConfigMapper.toDto(credentialConfig), false);

        CredentialConfig savedConfig = credentialConfigRepository.save(credentialConfig);
        log.info("Updated credential configuration: {}", savedConfig.getConfigId());

        CredentialConfigResponse credentialConfigResponse = new CredentialConfigResponse();
        credentialConfigResponse.setId(savedConfig.getCredentialConfigKeyId());
        credentialConfigResponse.setStatus(savedConfig.getStatus());

        return credentialConfigResponse;
    }

    /**
     * NOTE: Using @credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#id) will cause
     * an additional database lookup for CredentialConfig by id within the key generator.
     * This is a trade-off for using declarative @CacheEvict on this method signature.
     */
    @Override
    @Transactional
    @CacheEvict(cacheNames = CREDENTIAL_CONFIG_CACHE_NAME,
            key = "@credentialCacheKeyGenerator.generateKeyFromCredentialConfigKeyId(#credentialConfigKeyId)",
            beforeInvocation = true)
    public String deleteCredentialConfigurationById(String credentialConfigKeyId) {
        Optional<CredentialConfig> optional = credentialConfigRepository.findByCredentialConfigKeyId(credentialConfigKeyId) ;

        if(optional.isEmpty()) {
            log.warn("Configuration not found for delete with id: {}", credentialConfigKeyId);
            throw new CredentialConfigException(ErrorConstants.CONFIG_NOT_FOUND_FOR_DELETE, "Configuration not found for delete with ID: " + credentialConfigKeyId);
        }

        if (optional.get().getSchemaVersion() != null) {
            throw new CertifyException(ErrorConstants.SCHEMA_VERSION_IMMUTABLE,
                    "Schema version " + optional.get().getSchemaVersion() + " of " + credentialConfigKeyId
                            + " is published and cannot be deleted. Set its schemaStatus to DISABLED instead.");
        }

        // The object is fetched once here.
        // The @CacheEvict's key SpEL will cause CredentialCacheKeyGenerator to fetch it again.
        credentialConfigRepository.delete(optional.get());
        log.info("Deleted credential configuration: {}", credentialConfigKeyId);
        return credentialConfigKeyId;
    }

    @Override
    public CredentialIssuerMetadataDTO fetchCredentialIssuerMetadata(String version) {
        List<CredentialConfig> credentialConfigList = credentialConfigRepository.findAll()
                .stream()
                .filter(config -> Constants.ACTIVE.equals(config.getStatus()))
                .filter(config -> !Constants.SCHEMA_STATUS_DISABLED.equals(config.getSchemaStatus()))
                .toList();

        return switch (version) {
            case "latest" -> buildMetadataVD13(credentialConfigList, version);
            case "vd12"   -> buildMetadataVD12(credentialConfigList, version);
            case "vd11"   -> buildMetadataVD11(credentialConfigList, version);
            default       -> throw new CertifyException("UNSUPPORTED_METADATA_VERSION", "Unsupported version: " + version);
        };
    }

    private CredentialIssuerMetadataVD13DTO buildMetadataVD13(List<CredentialConfig> credentialConfigList, String version) {
        CredentialIssuerMetadataVD13DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD13DTO();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();

        credentialConfigList.forEach(credentialConfig -> {
            CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
            if (credentialConfig.getSignatureCryptoSuite() != null) {
                dto.setCredentialSigningAlgValuesSupported(
                        credentialSigningAlgValuesSupportedMap.get(credentialConfig.getSignatureCryptoSuite())
                );
            } else {
                dto.setCredentialSigningAlgValuesSupported(
                        Collections.singletonList(credentialConfig.getSignatureAlgo())
                );
            }
            credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), dto);
        });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        populateCommonMetadataFields(credentialIssuerMetadata, version);
        return credentialIssuerMetadata;
    }

    private CredentialIssuerMetadataVD12DTO buildMetadataVD12(List<CredentialConfig> credentialConfigList, String version) {
        CredentialIssuerMetadataVD12DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD12DTO();
        Map<String, CredentialConfigurationSupportedDTO> credentialConfigurationSupportedMap = new HashMap<>();

        credentialConfigList.forEach(credentialConfig -> {
            CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
            dto.setCryptographicSuitesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
            credentialConfigurationSupportedMap.put(credentialConfig.getCredentialConfigKeyId(), dto);
        });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedMap);
        populateCommonMetadataFields(credentialIssuerMetadata, version);
        return credentialIssuerMetadata;
    }

    private CredentialIssuerMetadataVD11DTO buildMetadataVD11(List<CredentialConfig> credentialConfigList, String version) {
        CredentialIssuerMetadataVD11DTO credentialIssuerMetadata = new CredentialIssuerMetadataVD11DTO();
        List<CredentialConfigurationSupportedDTO> credentialConfigurationSupportedList = new ArrayList<>();

        credentialConfigList.forEach(credentialConfig -> {
            CredentialConfigurationSupportedDTO dto = mapToSupportedDTO(credentialConfig);
            dto.setId(credentialConfig.getCredentialConfigKeyId());
            dto.setCryptographicSuitesSupported(credentialConfig.getCredentialSigningAlgValuesSupported());
            credentialConfigurationSupportedList.add(dto);
        });

        credentialIssuerMetadata.setCredentialConfigurationSupportedDTO(credentialConfigurationSupportedList);
        populateCommonMetadataFields(credentialIssuerMetadata, version);
        return credentialIssuerMetadata;
    }

    private void populateCommonMetadataFields(CredentialIssuerMetadataDTO metadata, String version) {
        metadata.setCredentialIssuer(credentialIssuer);
        metadata.setAuthorizationServers(resolveAuthorizationServers());
        metadata.setCredentialEndpoint(buildCredentialEndpoint(version));
        metadata.setDisplay(issuerDisplay);
    }

    private List<String> resolveAuthorizationServers() {
        if (authorizationServerMapping == null || authorizationServerMapping.isEmpty()) {
            return Collections.singletonList(authUrl);
        }
        return authorizationServerMapping.values().stream().distinct().toList();
    }

    private String buildCredentialEndpoint(String version) {
        if ("latest".equals(version)) {
            return credentialIssuer + servletPath + "/issuance/credential";
        }
        return credentialIssuer + servletPath + "/issuance/" + version + "/credential";
    }

    private CredentialConfigurationSupportedDTO mapToSupportedDTO(CredentialConfig credentialConfig) {
        CredentialConfigurationSupportedDTO credentialConfigurationSupported = new CredentialConfigurationSupportedDTO();
        CredentialConfigurationDTO credentialConfigurationDTO = credentialConfigMapper.toDto(credentialConfig);
        credentialConfigurationSupported.setFormat(credentialConfigurationDTO.getCredentialFormat());
        credentialConfigurationSupported.setScope(credentialConfigurationDTO.getScope());
        credentialConfigurationSupported.setCryptographicBindingMethodsSupported(credentialConfig.getCryptographicBindingMethodsSupported());
        credentialConfigurationSupported.setProofTypesSupported(credentialConfig.getProofTypesSupported());
        credentialConfigurationSupported.setDisplay(credentialConfigurationDTO.getMetaDataDisplay());
        credentialConfigurationSupported.setOrder(credentialConfigurationDTO.getDisplayOrder());

        if (VCFormats.LDP_VC.equals(credentialConfig.getCredentialFormat())) {
            CredentialDefinition credentialDefinition = new CredentialDefinition();
            credentialDefinition.setType(credentialConfigurationDTO.getCredentialTypes());
            credentialDefinition.setContext(credentialConfigurationDTO.getContextURLs());
            if (credentialConfig.getCredentialSubject() != null) {
                credentialDefinition.setCredentialSubject(new HashMap<>(credentialConfig.getCredentialSubject()));
            }
            credentialConfigurationSupported.setCredentialDefinition(credentialDefinition);
        } else if (VCFormats.MSO_MDOC.equals(credentialConfig.getCredentialFormat())) {
            if (credentialConfig.getMsoMdocClaims() != null) {
                credentialConfigurationSupported.setClaims(new HashMap<>(new HashMap<>(credentialConfig.getMsoMdocClaims())));
            }
            credentialConfigurationSupported.setDocType(credentialConfig.getDocType());
        } else if (VCFormats.VC_SD_JWT.equals(credentialConfig.getCredentialFormat())) {
            if (credentialConfig.getSdJwtClaims() != null) {
                credentialConfigurationSupported.setClaims(new HashMap<>(credentialConfig.getSdJwtClaims()));
            }
            credentialConfigurationSupported.setVct(credentialConfig.getSdJwtVct());
        }

        return credentialConfigurationSupported;
    }
}