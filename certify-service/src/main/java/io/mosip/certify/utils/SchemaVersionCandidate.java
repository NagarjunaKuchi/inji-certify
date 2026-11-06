/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;

/**
 * Minimal, framework-free view of one credential configuration row as seen by
 * {@link SchemaVersionResolver}. All candidates handed to the resolver share the same credential
 * selector (format + type/context, vct or doctype) and differ only by schema version.
 */
public final class SchemaVersionCandidate {

    private final String configKeyId;
    private final String version;
    private final String status;

    /**
     * @param configKeyId the credential_config_key_id of the row, used for messages and logging
     * @param version     the stored schema_version, or null for a legacy (unversioned) configuration
     * @param status      one of {@link Constants#SCHEMA_STATUS_ACTIVE}, {@link Constants#SCHEMA_STATUS_DEPRECATED},
     *                    {@link Constants#SCHEMA_STATUS_DISABLED}; must not be null
     */
    public SchemaVersionCandidate(String configKeyId, String version, String status) {
        if (status == null) {
            throw new IllegalArgumentException("status must not be null");
        }
        this.configKeyId = configKeyId;
        this.version = version;
        this.status = status;
    }

    public String getConfigKeyId() {
        return configKeyId;
    }

    /** The stored version, null when the configuration predates schema versioning. */
    public String getVersion() {
        return version;
    }

    public String getStatus() {
        return status;
    }

    public boolean isLegacy() {
        return version == null;
    }

    /** The stored version, or {@link Constants#LEGACY_SCHEMA_VERSION} for a legacy configuration. */
    public String getEffectiveVersion() {
        return version != null ? version : Constants.LEGACY_SCHEMA_VERSION;
    }

    public boolean isDisabled() {
        return Constants.SCHEMA_STATUS_DISABLED.equals(status);
    }

    public boolean isDeprecated() {
        return Constants.SCHEMA_STATUS_DEPRECATED.equals(status);
    }

    public boolean isActive() {
        return Constants.SCHEMA_STATUS_ACTIVE.equals(status);
    }

    @Override
    public String toString() {
        return "SchemaVersionCandidate{configKeyId='" + configKeyId + "', version=" + getEffectiveVersion()
                + (isLegacy() ? " (legacy)" : "") + ", status=" + status + "}";
    }
}
