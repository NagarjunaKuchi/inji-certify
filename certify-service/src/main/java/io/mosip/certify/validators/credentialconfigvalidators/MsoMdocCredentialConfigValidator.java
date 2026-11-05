package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class MsoMdocCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getDocType() != null && !credentialConfig.getDocType().isEmpty()
                && credentialConfig.getSignatureCryptoSuite() != null && !credentialConfig.getSignatureCryptoSuite().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getSdJwtVct() == null && credentialConfig.getCredentialSubjectDefinition() == null
                && credentialConfig.getSdJwtClaims() == null;
    }

    /**
     * A configuration clashes with an existing one that has the same doctype and format AND the same schema version.
     * An unversioned configuration counts as version 1.0.
     */
    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        String format = credentialConfig.getCredentialFormat();
        String docType = credentialConfig.getDocType();
        String version = credentialConfig.getSchemaVersion();

        boolean unversionedExists = credentialConfigRepository.findByCredentialFormatAndDocType(format, docType).isPresent();
        if (version == null) {
            return unversionedExists || credentialConfigRepository
                    .findByCredentialFormatAndDocTypeAndSchemaVersion(format, docType, Constants.LEGACY_SCHEMA_VERSION).isPresent();
        }
        return credentialConfigRepository.findByCredentialFormatAndDocTypeAndSchemaVersion(format, docType, version).isPresent()
                || (Constants.LEGACY_SCHEMA_VERSION.equals(version) && unversionedExists);
    }
}
