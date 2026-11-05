-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config
-- Purpose    : Credential Configuration Table
--
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

CREATE TABLE credential_config (
    credential_config_key_id VARCHAR(2048) NOT NULL UNIQUE,
    config_id VARCHAR(255) NOT NULL,
    status VARCHAR(255),
    vc_template VARCHAR,
    doctype VARCHAR,
    sd_jwt_vct VARCHAR,
    context VARCHAR,
    credential_type VARCHAR,
    credential_format VARCHAR(255) NOT NULL,
    did_url VARCHAR,
    key_manager_app_id VARCHAR(36),
    key_manager_ref_id VARCHAR(128),
    signature_algo VARCHAR(36),
    signature_crypto_suite VARCHAR(128),
    sd_claim VARCHAR,
    display JSONB NOT NULL,
    display_order TEXT[] NOT NULL,
    scope VARCHAR(255) NOT NULL,
    cryptographic_binding_methods_supported TEXT[] NOT NULL,
    credential_signing_alg_values_supported TEXT[] NOT NULL,
    proof_types_supported JSONB NOT NULL,
    credential_subject JSONB,
    mso_mdoc_claims JSONB,
    sd_jwt_claims JSONB,
    plugin_configurations JSONB,
    credential_status_purpose TEXT[],
    qr_settings JSONB,
    qr_signature_algo TEXT,
    schema_id VARCHAR(255),
    schema_version VARCHAR(32),
    schema_status VARCHAR(16),
    validation_schema JSONB,
    cr_dtimes TIMESTAMP NOT NULL,
    upd_dtimes TIMESTAMP,
    CONSTRAINT pk_config_id PRIMARY KEY (config_id),
    CONSTRAINT ck_credential_config_schema_version CHECK (schema_version IS NULL OR schema_version ~ '^[0-9]{1,9}\.[0-9]{1,9}(\.[0-9]{1,9})?$'),
    CONSTRAINT ck_credential_config_schema_status CHECK (schema_status IS NULL OR schema_status IN ('ACTIVE', 'DEPRECATED', 'DISABLED')),
    CONSTRAINT ck_credential_config_schema_pair CHECK ((schema_version IS NULL) = (schema_status IS NULL)),
    CONSTRAINT ck_credential_config_schema_def CHECK (validation_schema IS NULL OR schema_version IS NOT NULL)
);

-- A legacy row (schema_version IS NULL) counts as version 1.0, so it cannot coexist with an explicit 1.0.
CREATE UNIQUE INDEX idx_credential_config_type_context_unique
ON credential_config(credential_type, context, credential_format, (COALESCE(schema_version, '1.0')))
WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
ON credential_config(sd_jwt_vct, credential_format, (COALESCE(schema_version, '1.0')))
WHERE sd_jwt_vct IS NOT NULL and sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
ON credential_config(doctype, credential_format, (COALESCE(schema_version, '1.0')))
WHERE doctype IS NOT NULL and doctype <> '';

CREATE UNIQUE INDEX idx_credential_config_schema_id_version_unique
ON credential_config(schema_id, schema_version)
WHERE schema_id IS NOT NULL AND schema_version IS NOT NULL;

COMMENT ON TABLE credential_config IS 'Credential Config: Contains details of credential configuration.';

COMMENT ON COLUMN credential_config.config_id IS 'Credential Config ID: Unique id assigned to save and identify configuration.';
COMMENT ON COLUMN credential_config.status IS 'Credential Config Status: Status of the credential configuration.';
COMMENT ON COLUMN credential_config.vc_template IS 'VC Template: Template used for the verifiable credential.';
COMMENT ON COLUMN credential_config.doctype IS 'Doc Type: Doc Type specifically for Mdoc VC.';
COMMENT ON COLUMN credential_config.sd_jwt_vct IS 'VCT field: VC Type specifically for SD-JWT VC.';
COMMENT ON COLUMN credential_config.context IS 'Context: Array of context URIs for the credential.';
COMMENT ON COLUMN credential_config.credential_type IS 'Credential Type: Array of credential types supported.';
COMMENT ON COLUMN credential_config.credential_format IS 'Credential Format: Format of the credential (e.g., JWT, JSON-LD).';
COMMENT ON COLUMN credential_config.did_url IS 'DID URL: Decentralized Identifier URL for the issuer.';
COMMENT ON COLUMN credential_config.key_manager_app_id IS 'Key Manager App Id: AppId of the keymanager';
COMMENT ON COLUMN credential_config.key_manager_ref_id IS 'Key Manager Reference Id: RefId of the keymanager';
COMMENT ON COLUMN credential_config.signature_algo IS 'Signature Algorithm: This is for VC signature or proof algorithm';
COMMENT ON COLUMN credential_config.sd_claim IS 'SD Claim: This is a comma separated list for selective disclosure';
COMMENT ON COLUMN credential_config.display IS 'Display: Credential Display object';
COMMENT ON COLUMN credential_config.display_order IS 'Display Order: Array defining the order of display elements.';
COMMENT ON COLUMN credential_config.scope IS 'Scope: Authorization scope for the credential.';
COMMENT ON COLUMN credential_config.cryptographic_binding_methods_supported IS 'Cryptographic Binding Methods: Array of supported binding methods.';
COMMENT ON COLUMN credential_config.credential_signing_alg_values_supported IS 'Credential Signing Algorithms: Array of supported signing algorithms.';
COMMENT ON COLUMN credential_config.proof_types_supported IS 'Proof Types: JSON object containing supported proof types and their configurations.';
COMMENT ON COLUMN credential_config.credential_subject IS 'Credential Subject: JSON object containing subject attributes schema.';
COMMENT ON COLUMN credential_config.mso_mdoc_claims IS 'Mso_mdoc Claims: JSON object containing subject attributes schema specifically for MSO-MDOC VC.';
COMMENT ON COLUMN credential_config.sd_jwt_claims IS 'SdJwt Claims: JSON object containing subject attributes schema specifically for SdJwt VC.';
COMMENT ON COLUMN credential_config.plugin_configurations IS 'Plugin Configurations: Array of JSON objects for plugin configurations.';
COMMENT ON COLUMN credential_config.cr_dtimes IS 'Created DateTime: Date and time when the config was inserted in table.';
COMMENT ON COLUMN credential_config.upd_dtimes IS 'Updated DateTime: Date and time when the config was last updated in table.';
COMMENT ON COLUMN credential_config.schema_id IS 'Schema Id: Optional logical name shared by all versions of one credential schema (e.g. IdentityCredential).';
COMMENT ON COLUMN credential_config.schema_version IS 'Schema Version: MAJOR.MINOR[.PATCH]. NULL for legacy configurations created before schema versioning, which behave as version 1.0.';
COMMENT ON COLUMN credential_config.schema_status IS 'Schema Status: ACTIVE, DEPRECATED or DISABLED. NULL exactly when schema_version is NULL.';
COMMENT ON COLUMN credential_config.validation_schema IS 'Validation Schema: JSON Schema (draft 2020-12) the data provider output must satisfy before the VC template is rendered.';

-- Published (versioned) rows are immutable: their definition cannot change, they cannot be deleted, and their
-- status can only move forward (ACTIVE -> DEPRECATED -> DISABLED). Legacy rows (schema_version IS NULL) are untouched.
CREATE OR REPLACE FUNCTION fn_credential_config_schema_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.schema_version IS NOT NULL THEN
            RAISE EXCEPTION 'credential_config % is a published schema version and cannot be deleted; set schema_status to DISABLED instead', OLD.credential_config_key_id
                USING ERRCODE = '23001';
        END IF;
        RETURN OLD;
    END IF;

    IF OLD.schema_version IS NOT NULL THEN
        IF NEW.schema_id IS DISTINCT FROM OLD.schema_id
           OR NEW.schema_version IS DISTINCT FROM OLD.schema_version
           OR NEW.validation_schema IS DISTINCT FROM OLD.validation_schema
           OR NEW.vc_template IS DISTINCT FROM OLD.vc_template
           OR NEW.credential_format IS DISTINCT FROM OLD.credential_format
           OR NEW.credential_type IS DISTINCT FROM OLD.credential_type
           OR NEW.context IS DISTINCT FROM OLD.context
           OR NEW.sd_jwt_vct IS DISTINCT FROM OLD.sd_jwt_vct
           OR NEW.doctype IS DISTINCT FROM OLD.doctype THEN
            RAISE EXCEPTION 'credential_config % is a published schema version; its definition is immutable. Register a new schema version instead', OLD.credential_config_key_id
                USING ERRCODE = '23001';
        END IF;
        IF NEW.schema_status IS DISTINCT FROM OLD.schema_status
           AND NOT ((OLD.schema_status = 'ACTIVE' AND NEW.schema_status IN ('DEPRECATED', 'DISABLED'))
                 OR (OLD.schema_status = 'DEPRECATED' AND NEW.schema_status = 'DISABLED')) THEN
            RAISE EXCEPTION 'credential_config %: schema_status cannot move from % to %', OLD.credential_config_key_id, OLD.schema_status, NEW.schema_status
                USING ERRCODE = '23001';
        END IF;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_credential_config_schema_guard
BEFORE UPDATE OR DELETE ON credential_config
FOR EACH ROW EXECUTE FUNCTION fn_credential_config_schema_guard();
