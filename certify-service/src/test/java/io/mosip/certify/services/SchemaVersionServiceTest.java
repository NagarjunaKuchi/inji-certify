package io.mosip.certify.services;

import io.mosip.certify.api.dto.VCRequestDto;
import io.mosip.certify.config.SchemaVersioningConfig;
import io.mosip.certify.core.constants.Constants;
import io.mosip.certify.core.constants.ErrorConstants;
import io.mosip.certify.core.exception.CertifyException;
import io.mosip.certify.entity.CredentialConfig;
import io.mosip.certify.repository.CredentialConfigRepository;
import io.mosip.certify.utils.JsonSchemaDataValidator;
import io.mosip.certify.vcformatters.VCFormatter;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** NOTE: written without a working Maven build in the authoring environment; run with the module's test suite. */
@RunWith(MockitoJUnitRunner.Silent.class)
public class SchemaVersionServiceTest {

    private static final String BASE = "IdentityCredential,VerifiableCredential::https://www.w3.org/ns/credentials/v2,https://example.org/ctx::ldp_vc";

    @Mock CredentialConfigRepository repository;
    @Mock VCFormatter vcFormatter;
    @Mock JsonSchemaDataValidator validator;
    @Mock SchemaVersioningConfig versioningConfig;
    @InjectMocks SchemaVersionService service;

    private VCRequestDto request;

    @Before
    public void setUp() {
        request = new VCRequestDto();
        request.setFormat("ldp_vc");
        request.setType(List.of("VerifiableCredential", "IdentityCredential"));
        request.setContext(List.of("https://www.w3.org/ns/credentials/v2", "https://example.org/ctx"));
    }

    private CredentialConfig cfg(String id, String version, String schemaStatus, String scope) {
        CredentialConfig c = new CredentialConfig();
        c.setCredentialConfigKeyId(id);
        c.setSchemaVersion(version);
        c.setSchemaStatus(schemaStatus);
        c.setStatus(Constants.ACTIVE);
        c.setScope(scope);
        return c;
    }

    private void given(CredentialConfig... configs) {
        when(repository.findAllByCredentialFormatAndCredentialTypeAndContext(any(), any(), any())).thenReturn(List.of(configs));
    }

    @Test
    public void legacyOnly_returnsUnchangedTemplateKey() {
        given(cfg("legacy", null, null, "id_scope"));
        String key = service.resolveTemplateName(request, null, Set.of("id_scope"));
        assertEquals(io.mosip.certify.utils.CredentialUtils.getTemplateName(request), key);
        assertFalse(key.contains(Constants.SCHEMA_VERSION_MARKER));
    }

    @Test
    public void legacyAndNewer_defaultsToLegacy_explicitSelectsVersion() {
        given(cfg("legacy", null, null, "s0"), cfg("v11", "1.1", "ACTIVE", "s1"), cfg("v20", "2.0", "ACTIVE", "s2"));
        Set<String> all = Set.of("s0", "s1", "s2");
        assertFalse(service.resolveTemplateName(request, null, all).contains(Constants.SCHEMA_VERSION_MARKER));
        assertTrue(service.resolveTemplateName(request, "2.0", all).endsWith("#schemaVersion=2.0"));
    }

    @Test
    public void explicitVersionOutsideTokenScope_isRejected() {
        given(cfg("legacy", null, null, "s0"), cfg("v20", "2.0", "ACTIVE", "s2"));
        try {
            service.resolveTemplateName(request, "2.0", Set.of("s0"));
            fail();
        } catch (CertifyException e) {
            assertEquals(ErrorConstants.SCHEMA_VERSION_SCOPE_MISMATCH, e.getErrorCode());
        }
    }

    @Test
    public void unknownAndDisabledVersions_areRejected() {
        CredentialConfig off = cfg("v11", "1.1", "DISABLED", "s1");
        given(cfg("legacy", null, null, "s0"), off);
        try {
            service.resolveTemplateName(request, "3.0", null);
            fail();
        } catch (CertifyException e) {
            assertEquals(ErrorConstants.SCHEMA_VERSION_NOT_FOUND, e.getErrorCode());
        }
        try {
            service.resolveTemplateName(request, "1.1", null);
            fail();
        } catch (CertifyException e) {
            assertEquals(ErrorConstants.SCHEMA_VERSION_DISABLED, e.getErrorCode());
        }
    }

    @Test
    public void configuredDefault_isUsedWhenNoVersionRequested() {
        CredentialConfig v20 = cfg("v20", "2.0", "ACTIVE", "s2");
        v20.setSchemaId("IdentityCredential");
        given(cfg("legacy", null, null, "s2"), v20);
        when(versioningConfig.getDefaultVersions()).thenReturn(Map.of("IdentityCredential", "2.0"));
        assertTrue(service.resolveTemplateName(request, null, null).endsWith("#schemaVersion=2.0"));
    }

    @Test
    public void noConfiguration_failsWithTemplateNotFound() {
        given();
        try {
            service.resolveTemplateName(request, null, null);
            fail();
        } catch (CertifyException e) {
            assertEquals(ErrorConstants.EXPECTED_TEMPLATE_NOT_FOUND, e.getErrorCode());
        }
    }

    @Test
    public void validateProvidedData_skipsWhenNoSchema_andDelegatesWhenPresent() {
        when(vcFormatter.getValidationSchema("none")).thenReturn(null);
        service.validateProvidedData("none", "{}");
        verifyNoInteractions(validator);

        Map<String, Object> schema = Map.of("type", "object");
        when(vcFormatter.getValidationSchema("v")).thenReturn(schema);
        service.validateProvidedData("v", "{\"a\":1}");
        verify(validator).validate(eq(schema), eq("{\"a\":1}"));
    }
}
