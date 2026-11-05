package io.mosip.certify.utils;

import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class SchemaVersionResolverTest {

    private static SchemaVersionCandidate c(String id, String v, String s) {
        return new SchemaVersionCandidate(id, v, s);
    }

    private static void assertCode(String code, Runnable r) {
        try {
            r.run();
            fail("expected " + code);
        } catch (CertifyException e) {
            assertEquals(code, e.getErrorCode());
        }
    }

    private final SchemaVersionCandidate legacy = c("legacy", null, Constants.SCHEMA_STATUS_ACTIVE);
    private final SchemaVersionCandidate v11 = c("v11", "1.1", Constants.SCHEMA_STATUS_ACTIVE);
    private final SchemaVersionCandidate v20 = c("v20", "2.0", Constants.SCHEMA_STATUS_ACTIVE);

    @Test
    public void legacyOnly_resolvesToLegacy() {
        assertSame(legacy, SchemaVersionResolver.resolve(List.of(legacy), null, null));
    }

    @Test
    public void legacyWinsOverNewerActiveVersionsByDefault() {
        assertSame(legacy, SchemaVersionResolver.resolve(List.of(legacy, v11, v20), null, null));
    }

    @Test
    public void explicitVersionIsHonouredExactly() {
        assertSame(v11, SchemaVersionResolver.resolve(List.of(legacy, v11, v20), "1.1", "2.0"));
        assertSame(legacy, SchemaVersionResolver.resolve(List.of(legacy, v11), "1.0", null));
        assertSame(legacy, SchemaVersionResolver.resolve(List.of(legacy, v11), "1.0.0", null));
    }

    @Test
    public void explicitUnknownOrInvalidIsRejectedNeverSubstituted() {
        assertCode(ErrorConstants.SCHEMA_VERSION_NOT_FOUND, () -> SchemaVersionResolver.resolve(List.of(legacy, v11), "3.0", null));
        assertCode(ErrorConstants.INVALID_SCHEMA_VERSION, () -> SchemaVersionResolver.resolve(List.of(legacy, v11), "v1", null));
    }

    @Test
    public void disabledIsRejectedEvenWhenExplicitOrDefault() {
        SchemaVersionCandidate off = c("off", "1.1", Constants.SCHEMA_STATUS_DISABLED);
        assertCode(ErrorConstants.SCHEMA_VERSION_DISABLED, () -> SchemaVersionResolver.resolve(List.of(legacy, off), "1.1", null));
        assertCode(ErrorConstants.SCHEMA_VERSION_DISABLED, () -> SchemaVersionResolver.resolve(List.of(legacy, off), null, "1.1"));
    }

    @Test
    public void deprecatedIsUsableExplicitlyButNotChosenAutomatically() {
        SchemaVersionCandidate dep = c("dep", "1.0", Constants.SCHEMA_STATUS_DEPRECATED);
        assertSame(dep, SchemaVersionResolver.resolve(List.of(dep, v11), "1.0", null));
        assertSame(v11, SchemaVersionResolver.resolve(List.of(dep, v11), null, null));
    }

    @Test
    public void configuredDefaultUsedAndMissingDefaultFailsWithoutFallthrough() {
        assertSame(v20, SchemaVersionResolver.resolve(List.of(legacy, v11, v20), null, "2.0"));
        assertCode(ErrorConstants.SCHEMA_DEFAULT_VERSION_NOT_FOUND, () -> SchemaVersionResolver.resolve(List.of(legacy, v11), null, "9.9"));
    }

    @Test
    public void latestActiveIsNumericNotLexical() {
        SchemaVersionCandidate a = c("a", "1.9", Constants.SCHEMA_STATUS_ACTIVE);
        SchemaVersionCandidate b = c("b", "1.10", Constants.SCHEMA_STATUS_ACTIVE);
        assertSame(b, SchemaVersionResolver.resolve(List.of(a, b), null, null));
    }

    @Test
    public void noActiveVersionFails() {
        SchemaVersionCandidate dep = c("dep", "1.1", Constants.SCHEMA_STATUS_DEPRECATED);
        assertCode(ErrorConstants.SCHEMA_NO_ACTIVE_VERSION, () -> SchemaVersionResolver.resolve(List.of(dep), null, null));
    }

    @Test
    public void emptyAndAmbiguousCandidates() {
        assertCode(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, () -> SchemaVersionResolver.resolve(List.of(), null, null));
        SchemaVersionCandidate dup = c("dup", "1.0", Constants.SCHEMA_STATUS_ACTIVE);
        assertCode(ErrorConstants.SCHEMA_VERSION_AMBIGUOUS, () -> SchemaVersionResolver.resolve(List.of(legacy, dup), null, null));
    }

    @Test
    public void lifecycleIsForwardOnly() {
        assertTrue(SchemaVersionResolver.isAllowedTransition("ACTIVE", "DEPRECATED"));
        assertTrue(SchemaVersionResolver.isAllowedTransition("DEPRECATED", "DISABLED"));
        assertFalse(SchemaVersionResolver.isAllowedTransition("DEPRECATED", "ACTIVE"));
        assertFalse(SchemaVersionResolver.isAllowedTransition("DISABLED", "ACTIVE"));
        assertFalse(SchemaVersionResolver.isAllowedTransition("ACTIVE", "BOGUS"));
    }

    @Test
    public void canonicalAndValidity() {
        assertEquals("1.0", SchemaVersionResolver.canonicalize("1.0.0"));
        assertEquals("1.2.3", SchemaVersionResolver.canonicalize("1.2.3"));
        assertFalse(SchemaVersionResolver.isValidVersion("1"));
        assertFalse(SchemaVersionResolver.isValidVersion(null));
    }
}
