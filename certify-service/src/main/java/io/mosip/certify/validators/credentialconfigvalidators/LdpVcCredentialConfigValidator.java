package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class LdpVcCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getContextURLs() != null && !credentialConfig.getContextURLs().isEmpty()
                && credentialConfig.getCredentialTypes() != null && !credentialConfig.getCredentialTypes().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && credentialConfig.getDocType() == null && credentialConfig.getSdJwtVct() == null
                && credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSdJwtClaims() == null;
    }

    /**
     * A configuration clashes with an existing one that has the same type, context and format AND the same schema
     * version. An unversioned configuration counts as version 1.0.
     */
    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                        CredentialConfigRepository credentialConfigRepository) {
        String format = credentialConfig.getCredentialFormat();
        String types = listToCommaSeparatedString(credentialConfig.getCredentialTypes());
        String contexts = listToCommaSeparatedString(credentialConfig.getContextURLs());
        String version = credentialConfig.getSchemaVersion();

        boolean unversionedExists = credentialConfigRepository
                .findByCredentialFormatAndCredentialTypeAndContext(format, types, contexts).isPresent();
        if (version == null) {
            return unversionedExists || credentialConfigRepository
                    .findByCredentialFormatAndCredentialTypeAndContextAndSchemaVersion(format, types, contexts, Constants.LEGACY_SCHEMA_VERSION).isPresent();
        }
        return credentialConfigRepository
                .findByCredentialFormatAndCredentialTypeAndContextAndSchemaVersion(format, types, contexts, version).isPresent()
                || (Constants.LEGACY_SCHEMA_VERSION.equals(version) && unversionedExists);
    }

    private static String listToCommaSeparatedString(List<String> list) {
        if (list == null || list.isEmpty()) {
            return null;
        }
        return list.stream()
                .sorted()
                .collect(Collectors.joining(","));
    }

}