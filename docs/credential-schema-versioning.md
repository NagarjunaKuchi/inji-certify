# Credential schema versioning (inji-certify)

Status: implemented against v0.14.0; **not yet built or run through Maven by the author** – see "Verification status".

## Model
A *schema version* is one `credential_config` row with `schema_version` set. It owns its own attribute mapping
(`credential_subject`/`claims`), VC template and `validation_schema` (JSON Schema draft 2020-12).
Rows with `schema_version IS NULL` are *legacy* and behave exactly as before (effective version `1.0`, no validation).

Template cache key: legacy keys are unchanged; versioned keys get the suffix `#schemaVersion=<v>`.

## Resolution order (DataProvider mode)
1. `schema_version` in the credential request – honoured exactly or rejected (never substituted).
2. `mosip.certify.schema-versioning.default-versions.<schemaId or type/vct/doctype>=<version>` – if it names a missing version the request fails.
3. The legacy (unversioned) configuration, if one exists (keeps existing credentials identical).
4. Highest ACTIVE version.

Unknown version → `SCHEMA_VERSION_NOT_FOUND`; DISABLED → `SCHEMA_VERSION_DISABLED`; DEPRECATED is issuable only when explicit/default and logs a warning.
When several versions share a selector, the token scope must match the chosen row (`SCHEMA_VERSION_SCOPE_MISMATCH`).
VCIssuance plugin mode rejects `schema_version`.

## Lifecycle and immutability
Status moves forward only: ACTIVE → DEPRECATED → DISABLED. Once published, a versioned row's version, selector, template,
mapping and schema cannot change and the row cannot be deleted (enforced in service code and by trigger `trg_credential_config_schema_guard`).
Publish a change as a new version.

## Registering versions (existing endpoint `POST /credential-configurations`)
Add `schemaId`, `schemaVersion` (e.g. `"1.1"`), and `validationSchema` (JSON Schema object) to the usual body. Use a distinct
`credentialConfigKeyId` and `scope` per version. Example validation schema (v1.1 adds `email`):
`{"type":"object","required":["name","dateOfBirth","gender","address","email"],"properties":{"email":{"type":"string"}}}`.
Only local `$ref` (`#...`) is allowed in `validationSchema`. Note: the validator library accepts some malformed keywords at registration
(for example an unknown `type` name), so review schemas before publishing.
Set a version's status via PUT; a PUT on a versioned row must resend the structural fields unchanged.

## Operator rules for verification compatibility
- Verifiers re-canonicalise by fetching `@context` URLs, so every version's JSON-LD context must be published at an immutable, versioned URL and never edited.
- Keep issuer keys/DID documents available while any issued credential remains valid.
- Not verified: the Claim 169 QR mapping in external libraries; test with your verifier before enabling a new version.

## Deployment
1. Back up the DB. 2. Run `db_upgrade_script/mosip_certify/sql/0.14.0_to_0.14.1_upgrade.sql` (the 0.14.1 file name is an assumption; rename to your release).
3. Deploy the new image. Existing rows keep NULL version; no behaviour change. 4. Register new versions.

## Rollback
Run `0.14.0_to_0.14.1_rollback.sql`. It aborts if versioned rows exist (delete/disable them out-of-band first, which requires dropping the trigger deliberately).
Redeploy the previous image afterwards.

## Verification status
Executed: resolver logic and tests (12 JUnit tests + harness), schema validator tests (5 JUnit tests, against a scratch build of networknt 2.0.8 with
some modules stubbed), and the SQL scripts on PostgreSQL 16 (upgrade leaves existing rows identical; constraints, indexes, trigger, rollback).
Not executed: anything needing Spring/Lombok/MapStruct/JPA (service wiring, repository `@Query`s, `SchemaVersionServiceTest`, the updated
`CertifyIssuanceServiceImplTest`). Run `./mvnw -pl certify-service -am test` and `dependency:tree` (check Jackson alignment with networknt).

## Known limitations
Extra indexed query per issuance; admin endpoints may be unauthenticated under some profiles (`ignore-auth-urls`); a disabled-only configuration
yields a generic scope error because metadata hides DISABLED rows; concurrent conflicting status updates may surface the trigger error;
pre-existing mdoc cache-eviction key mismatch left untouched; no list-versions endpoint.
