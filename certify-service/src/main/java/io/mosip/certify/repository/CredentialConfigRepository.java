package io.mosip.certify.repository;

import io.mosip.certify.entity.CredentialConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredentialConfigRepository extends JpaRepository<CredentialConfig, String> {

    /*
     * The three finders below return the UNVERSIONED (legacy) configuration only, i.e. schema_version IS NULL.
     * That is exactly what they returned before schema versioning existed, because every row used to be
     * unversioned. Keeping the filter here (rather than in each caller) means all existing callers keep their
     * behaviour, and an Optional result can never become ambiguous once several versions share one selector.
     * Versioned rows are reached through the *AndSchemaVersion finders and the findAllBy* finders further down.
     */
    @Query("select c from CredentialConfig c where c.credentialFormat = :credentialFormat and c.sdJwtVct = :sdJwtVct and c.schemaVersion is null")
    Optional<CredentialConfig> findByCredentialFormatAndSdJwtVct(@Param("credentialFormat") String credentialFormat,
                                                                 @Param("sdJwtVct") String sdJwtVct);

    @Query("select c from CredentialConfig c where c.credentialFormat = :credentialFormat and c.docType = :docType and c.schemaVersion is null")
    Optional<CredentialConfig> findByCredentialFormatAndDocType(@Param("credentialFormat") String credentialFormat,
                                                                @Param("docType") String docType);

    @Query("select c from CredentialConfig c where c.credentialFormat = :credentialFormat and c.credentialType = :credentialType and c.context = :context and c.schemaVersion is null")
    Optional<CredentialConfig> findByCredentialFormatAndCredentialTypeAndContext(@Param("credentialFormat") String credentialFormat,
                                                                                 @Param("credentialType") String credentialType,
                                                                                 @Param("context") String context);

    Optional<CredentialConfig> findByCredentialConfigKeyId(String credentialConfigKeyID);

    // Versioned lookups: exactly one row per (selector, schema_version), enforced by the unique indexes.
    Optional<CredentialConfig> findByCredentialFormatAndSdJwtVctAndSchemaVersion(String credentialFormat, String sdJwtVct, String schemaVersion);

    Optional<CredentialConfig> findByCredentialFormatAndDocTypeAndSchemaVersion(String credentialFormat, String docType, String schemaVersion);

    Optional<CredentialConfig> findByCredentialFormatAndCredentialTypeAndContextAndSchemaVersion(String credentialFormat, String credentialType,
                                                                                                 String context, String schemaVersion);

    // Every configuration (legacy and versioned, any status) sharing a selector: the input to version resolution.
    List<CredentialConfig> findAllByCredentialFormatAndSdJwtVct(String credentialFormat, String sdJwtVct);

    List<CredentialConfig> findAllByCredentialFormatAndDocType(String credentialFormat, String docType);

    List<CredentialConfig> findAllByCredentialFormatAndCredentialTypeAndContext(String credentialFormat, String credentialType, String context);
}
