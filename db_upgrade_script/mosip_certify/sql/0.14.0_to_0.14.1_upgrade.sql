-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config
-- Purpose    : Credential schema versioning. Adds schema_id, schema_version, schema_status and
--              validation_schema to credential_config. Existing rows are NOT modified: they keep
--              schema_version = NULL and behave exactly as before (effective version 1.0).
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

ALTER TABLE certify.credential_config
    ADD COLUMN IF NOT EXISTS schema_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS schema_version VARCHAR(32),
    ADD COLUMN IF NOT EXISTS schema_status VARCHAR(16),
    ADD COLUMN IF NOT EXISTS validation_schema JSONB;

ALTER TABLE certify.credential_config
    ADD CONSTRAINT ck_credential_config_schema_version CHECK (schema_version IS NULL OR schema_version ~ '^[0-9]{1,9}\.[0-9]{1,9}(\.[0-9]{1,9})?$'),
    ADD CONSTRAINT ck_credential_config_schema_status CHECK (schema_status IS NULL OR schema_status IN ('ACTIVE', 'DEPRECATED', 'DISABLED')),
    ADD CONSTRAINT ck_credential_config_schema_pair CHECK ((schema_version IS NULL) = (schema_status IS NULL)),
    ADD CONSTRAINT ck_credential_config_schema_def CHECK (validation_schema IS NULL OR schema_version IS NOT NULL);

COMMENT ON COLUMN certify.credential_config.schema_id IS 'Schema Id: Optional logical name shared by all versions of one credential schema (e.g. IdentityCredential).';
COMMENT ON COLUMN certify.credential_config.schema_version IS 'Schema Version: MAJOR.MINOR[.PATCH]. NULL for legacy configurations created before schema versioning, which behave as version 1.0.';
COMMENT ON COLUMN certify.credential_config.schema_status IS 'Schema Status: ACTIVE, DEPRECATED or DISABLED. NULL exactly when schema_version is NULL.';
COMMENT ON COLUMN certify.credential_config.validation_schema IS 'Validation Schema: JSON Schema (draft 2020-12) the data provider output must satisfy before the VC template is rendered.';

-- Allow several schema versions of the same credential. A legacy row (schema_version IS NULL) counts as
-- version 1.0, so it cannot coexist with an explicit 1.0. Rows that already satisfy the old indexes satisfy
-- the new ones (all existing rows have schema_version NULL), so this cannot fail on existing data.
DROP INDEX IF EXISTS certify.idx_credential_config_type_context_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_sd_jwt_vct_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_doctype_unique;

CREATE UNIQUE INDEX idx_credential_config_type_context_unique
ON certify.credential_config(credential_type, context, credential_format, (COALESCE(schema_version, '1.0')))
WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
ON certify.credential_config(sd_jwt_vct, credential_format, (COALESCE(schema_version, '1.0')))
WHERE sd_jwt_vct IS NOT NULL AND sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
ON certify.credential_config(doctype, credential_format, (COALESCE(schema_version, '1.0')))
WHERE doctype IS NOT NULL AND doctype <> '';

CREATE UNIQUE INDEX idx_credential_config_schema_id_version_unique
ON certify.credential_config(schema_id, schema_version)
WHERE schema_id IS NOT NULL AND schema_version IS NOT NULL;

-- Published (versioned) rows are immutable: their definition cannot change, they cannot be deleted, and their
-- status can only move forward (ACTIVE -> DEPRECATED -> DISABLED). Legacy rows (schema_version IS NULL) are untouched.
CREATE OR REPLACE FUNCTION certify.fn_credential_config_schema_guard() RETURNS trigger AS $$
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
BEFORE UPDATE OR DELETE ON certify.credential_config
FOR EACH ROW EXECUTE FUNCTION certify.fn_credential_config_schema_guard();
