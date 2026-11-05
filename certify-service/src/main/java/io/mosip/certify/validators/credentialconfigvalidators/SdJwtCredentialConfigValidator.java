package io.mosip.certify.validators.credentialconfigvalidators;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.dto.CredentialConfigurationDTO;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;

import java.util.Optional;

public class SdJwtCredentialConfigValidator {
    public static boolean isValidCheck(CredentialConfigurationDTO credentialConfig) {
        return credentialConfig.getSdJwtVct() != null && !credentialConfig.getSdJwtVct().isEmpty()
                && credentialConfig.getSignatureAlgo() != null && !credentialConfig.getSignatureAlgo().isEmpty()
                && (credentialConfig.getCredentialTypes() == null || credentialConfig.getCredentialTypes().isEmpty()) && (credentialConfig.getContextURLs() == null || credentialConfig.getContextURLs().isEmpty())
                && credentialConfig.getDocType() == null && credentialConfig.getCredentialSubjectDefinition() == null &&
                credentialConfig.getMsoMdocClaims() == null && credentialConfig.getSignatureCryptoSuite() == null;
    }

    /**
     * A configuration clashes with an existing one that has the same vct and format AND the same schema version.
     * An unversioned configuration counts as version 1.0.
     */
    public static boolean isConfigAlreadyPresent(CredentialConfigurationDTO credentialConfig,
                                                 CredentialConfigRepository credentialConfigRepository) {
        String format = credentialConfig.getCredentialFormat();
        String vct = credentialConfig.getSdJwtVct();
        String version = credentialConfig.getSchemaVersion();

        boolean unversionedExists = credentialConfigRepository.findByCredentialFormatAndSdJwtVct(format, vct).isPresent();
        if (version == null) {
            return unversionedExists || credentialConfigRepository
                    .findByCredentialFormatAndSdJwtVctAndSchemaVersion(format, vct, Constants.LEGACY_SCHEMA_VERSION).isPresent();
        }
        return credentialConfigRepository.findByCredentialFormatAndSdJwtVctAndSchemaVersion(format, vct, version).isPresent()
                || (Constants.LEGACY_SCHEMA_VERSION.equals(version) && unversionedExists);
    }
}
