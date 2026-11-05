/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Deterministic schema version selection. Pure logic: no I/O, no Spring, no state.
 *
 * <h3>Resolution order</h3>
 * <ol>
 *   <li><b>Explicit</b> version in the credential request. It is honoured exactly or rejected; it is
 *       never replaced by another version.</li>
 *   <li><b>Configured default</b> for the credential
 *       ({@code mosip.certify.schema-versioning.default-versions}). If it names a version that does not
 *       exist, the request fails rather than falling through to a different version.</li>
 *   <li>The <b>legacy (unversioned) configuration</b>, when one exists. This is what keeps credentials that
 *       were issued before versioning was introduced coming out exactly as before, even after newer
 *       versions are registered next to them.</li>
 *   <li>The <b>highest ACTIVE version</b>.</li>
 * </ol>
 *
 * <h3>Status behaviour</h3>
 * <ul>
 *   <li>{@code ACTIVE}: usable by every step above.</li>
 *   <li>{@code DEPRECATED}: still issuable when requested explicitly or named as the default, but never
 *       chosen by step 4. Callers should log a warning when a deprecated version is returned.</li>
 *   <li>{@code DISABLED}: never issuable; rejected with {@link ErrorConstants#SCHEMA_VERSION_DISABLED}.</li>
 * </ul>
 */
public final class SchemaVersionResolver {

    private static final Pattern VERSION_PATTERN = Pattern.compile(Constants.SCHEMA_VERSION_PATTERN);

    private SchemaVersionResolver() {
    }

    /**
     * @param candidates       every configuration sharing the request's credential selector (any status)
     * @param requestedVersion the version named in the request, or null when the request names none
     * @param configuredDefault the operator-configured default version for this credential, or null
     * @return the selected candidate; never null
     * @throws CertifyException when no usable version can be selected
     */
    public static SchemaVersionCandidate resolve(List<SchemaVersionCandidate> candidates, String requestedVersion,
                                                 String configuredDefault) {
        if (candidates == null || candidates.isEmpty()) {
            // Same error code the template lookup has always used for a missing configuration.
            throw new CertifyException(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND,
                    "Credential configuration not found for the requested credential.");
        }
        assertEffectiveVersionsUnique(candidates);

        if (requestedVersion != null) {
            if (!isValidVersion(requestedVersion)) {
                throw new CertifyException(ErrorConstants.INVALID_SCHEMA_VERSION,
                        "Invalid schema version '" + requestedVersion + "'. Expected MAJOR.MINOR or MAJOR.MINOR.PATCH.");
            }
            SchemaVersionCandidate requested = find(candidates, requestedVersion);
            if (requested == null) {
                throw new CertifyException(ErrorConstants.SCHEMA_VERSION_NOT_FOUND,
                        "Schema version " + requestedVersion + " is not available for this credential. Available versions: "
                                + describeUsableVersions(candidates));
            }
            return requireNotDisabled(requested);
        }

        if (configuredDefault != null) {
            SchemaVersionCandidate configured = find(candidates, configuredDefault);
            if (configured == null) {
                throw new CertifyException(ErrorConstants.SCHEMA_DEFAULT_VERSION_NOT_FOUND,
                        "The configured default schema version " + configuredDefault
                                + " does not exist for this credential. Fix mosip.certify.schema-versioning.default-versions.");
            }
            return requireNotDisabled(configured);
        }

        for (SchemaVersionCandidate candidate : candidates) {
            if (candidate.isLegacy()) {
                return requireNotDisabled(candidate);
            }
        }

        SchemaVersionCandidate latestActive = null;
        for (SchemaVersionCandidate candidate : candidates) {
            if (candidate.isActive()
                    && (latestActive == null || compareVersions(candidate.getEffectiveVersion(), latestActive.getEffectiveVersion()) > 0)) {
                latestActive = candidate;
            }
        }
        if (latestActive == null) {
            throw new CertifyException(ErrorConstants.SCHEMA_NO_ACTIVE_VERSION,
                    "No ACTIVE schema version exists for this credential. Request a version explicitly or activate one.");
        }
        return latestActive;
    }

    public static boolean isValidVersion(String version) {
        return version != null && VERSION_PATTERN.matcher(version).matches();
    }

    public static boolean isValidStatus(String status) {
        return Constants.SCHEMA_STATUS_ACTIVE.equals(status)
                || Constants.SCHEMA_STATUS_DEPRECATED.equals(status)
                || Constants.SCHEMA_STATUS_DISABLED.equals(status);
    }

    /**
     * Lifecycle is forward-only: ACTIVE -> DEPRECATED -> DISABLED (ACTIVE -> DISABLED is also allowed).
     * A version can never be moved back, which prevents a published version from being quietly revived.
     */
    public static boolean isAllowedTransition(String from, String to) {
        if (!isValidStatus(from) || !isValidStatus(to)) {
            return false;
        }
        if (from.equals(to)) {
            return true;
        }
        if (Constants.SCHEMA_STATUS_ACTIVE.equals(from)) {
            return true;
        }
        return Constants.SCHEMA_STATUS_DEPRECATED.equals(from) && Constants.SCHEMA_STATUS_DISABLED.equals(to);
    }

    /**
     * The form in which versions are stored: no leading zeros and no trailing ".0" patch, so that numerically equal
     * versions have exactly one spelling ("1.0.0" and "01.0" both become "1.0"; "1.2.3" is unchanged).
     */
    public static String canonicalize(String version) {
        int[] n = parse(version);
        return n[2] == 0 ? n[0] + "." + n[1] : n[0] + "." + n[1] + "." + n[2];
    }

    /**
     * Numeric, segment-wise comparison; a missing PATCH counts as 0, so "1.0" equals "1.0.0".
     * Both arguments must satisfy {@link #isValidVersion(String)}.
     */
    public static int compareVersions(String a, String b) {
        int[] left = parse(a);
        int[] right = parse(b);
        for (int i = 0; i < 3; i++) {
            int c = Integer.compare(left[i], right[i]);
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    private static int[] parse(String version) {
        if (!isValidVersion(version)) {
            throw new IllegalArgumentException("Not a valid schema version: " + version);
        }
        String[] parts = version.split("\\.");
        int[] numbers = new int[3];
        for (int i = 0; i < parts.length; i++) {
            numbers[i] = Integer.parseInt(parts[i]);
        }
        return numbers;
    }

    private static SchemaVersionCandidate find(List<SchemaVersionCandidate> candidates, String version) {
        if (!isValidVersion(version)) {
            return null;
        }
        for (SchemaVersionCandidate candidate : candidates) {
            if (compareVersions(candidate.getEffectiveVersion(), version) == 0) {
                return candidate;
            }
        }
        return null;
    }

    private static SchemaVersionCandidate requireNotDisabled(SchemaVersionCandidate candidate) {
        if (candidate.isDisabled()) {
            throw new CertifyException(ErrorConstants.SCHEMA_VERSION_DISABLED,
                    "Schema version " + candidate.getEffectiveVersion() + " is disabled and cannot be used to issue credentials.");
        }
        return candidate;
    }

    private static void assertEffectiveVersionsUnique(List<SchemaVersionCandidate> candidates) {
        for (int i = 0; i < candidates.size(); i++) {
            for (int j = i + 1; j < candidates.size(); j++) {
                if (compareVersions(candidates.get(i).getEffectiveVersion(), candidates.get(j).getEffectiveVersion()) == 0) {
                    throw new CertifyException(ErrorConstants.SCHEMA_VERSION_AMBIGUOUS,
                            "More than one configuration resolves to schema version " + candidates.get(i).getEffectiveVersion()
                                    + ": " + candidates.get(i).getConfigKeyId() + ", " + candidates.get(j).getConfigKeyId());
                }
            }
        }
    }

    private static String describeUsableVersions(List<SchemaVersionCandidate> candidates) {
        String usable = candidates.stream()
                .filter(c -> !c.isDisabled())
                .map(SchemaVersionCandidate::getEffectiveVersion)
                .sorted(SchemaVersionResolver::compareVersions)
                .collect(Collectors.joining(", "));
        return usable.isEmpty() ? "none" : usable;
    }
}
