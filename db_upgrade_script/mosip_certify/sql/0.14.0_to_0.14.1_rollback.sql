-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.
-- -------------------------------------------------------------------------------------------------
-- Database Name: inji_certify
-- Table Name : credential_config
-- Purpose    : Rollback of credential schema versioning (restores the Certify v0.14.0 credential_config).
--
-- Modified Date        Modified By         Comments / Remarks
-- ------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------

-- Refuse to run if versioned rows exist: dropping the columns would silently destroy published schema
-- versions, and the restored (version-less) unique indexes could not hold several versions of one credential.
-- To proceed deliberately: export the rows, DROP TRIGGER trg_credential_config_schema_guard, delete the versioned
-- rows, then re-run this script.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM certify.credential_config WHERE schema_version IS NOT NULL) THEN
        RAISE EXCEPTION 'Rollback aborted: credential_config contains versioned schema rows (schema_version IS NOT NULL). Export and remove them first.';
    END IF;
END
$$;

DROP TRIGGER IF EXISTS trg_credential_config_schema_guard ON certify.credential_config;
DROP FUNCTION IF EXISTS certify.fn_credential_config_schema_guard();

DROP INDEX IF EXISTS certify.idx_credential_config_schema_id_version_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_type_context_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_sd_jwt_vct_unique;
DROP INDEX IF EXISTS certify.idx_credential_config_doctype_unique;

ALTER TABLE certify.credential_config
    DROP CONSTRAINT IF EXISTS ck_credential_config_schema_def,
    DROP CONSTRAINT IF EXISTS ck_credential_config_schema_pair,
    DROP CONSTRAINT IF EXISTS ck_credential_config_schema_status,
    DROP CONSTRAINT IF EXISTS ck_credential_config_schema_version;

ALTER TABLE certify.credential_config
    DROP COLUMN IF EXISTS validation_schema,
    DROP COLUMN IF EXISTS schema_status,
    DROP COLUMN IF EXISTS schema_version,
    DROP COLUMN IF EXISTS schema_id;

CREATE UNIQUE INDEX idx_credential_config_type_context_unique
ON certify.credential_config(credential_type, context, credential_format)
WHERE credential_type IS NOT NULL AND credential_type <> ''
AND context IS NOT NULL AND context <> '';

CREATE UNIQUE INDEX idx_credential_config_sd_jwt_vct_unique
ON certify.credential_config(sd_jwt_vct, credential_format)
WHERE sd_jwt_vct IS NOT NULL AND sd_jwt_vct <> '';

CREATE UNIQUE INDEX idx_credential_config_doctype_unique
ON certify.credential_config(doctype, credential_format)
WHERE doctype IS NOT NULL AND doctype <> '';
