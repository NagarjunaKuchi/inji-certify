/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

/**
 * Credential schema versioning settings.
 *
 * <pre>
 * # Version used when a credential request names none. Key = the schemaId shared by the credential's versions
 * # (or, for versions without a schemaId, the credential type / vct / doctype). Optional: when absent, an
 * # unversioned configuration is used if one exists, otherwise the highest ACTIVE version.
 * mosip.certify.schema-versioning.default-versions.IdentityCredential=1.1
 * </pre>
 */
@Data
@Component
@ConfigurationProperties(prefix = "mosip.certify.schema-versioning")
public class SchemaVersioningConfig {

    private Map<String, String> defaultVersions = new HashMap<>();
}
