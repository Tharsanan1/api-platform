/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package config

import (
	"testing"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// ============ Fixtures ============
//
// fakeMtlsCertStore (mtls_auth_validator_test.go) already implements the one
// method UpstreamTLSCertificateStore needs (GetCertificateByName) — reused
// here rather than defining a second fake. upstreamCA/clientCA (also from
// that file) cover usage: upstream/client; only usage: identity is new here.

func gatewayIdentityCert(name string) *models.StoredCertificate {
	return &models.StoredCertificate{
		Name: name, Usage: models.CertificateUsageIdentity,
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
	}
}

func expiredGatewayIdentityCert(name string) *models.StoredCertificate {
	return &models.StoredCertificate{
		Name: name, Usage: models.CertificateUsageIdentity,
		NotAfter: time.Now().Add(-24 * time.Hour),
	}
}

// tlsUpstreamDef builds an upstreamDefinitions entry named "partner" with the
// given tls params (nil omits the tls block entirely, matching a definition
// with no mTLS configured at all) and one target per url.
func tlsUpstreamDef(tls map[string]interface{}, urls ...string) api.UpstreamDefinition {
	def := api.UpstreamDefinition{Name: "partner"}
	if tls != nil {
		def.Tls = &tls
	}
	for _, u := range urls {
		def.Upstreams = append(def.Upstreams, struct {
			Url    string `json:"url" yaml:"url"`
			Weight *int   `json:"weight,omitempty" yaml:"weight,omitempty"`
		}{Url: u})
	}
	return def
}

// restAPIWithUpstreamDefs attaches defs to a minimal valid RestAPI, pointing
// upstream.main at the first one by ref. ValidateRestAPI/ResolveWarnings
// never themselves resolve that ref — only Spec.UpstreamDefinitions and
// Spec.Upstream.Main/Sandbox.Tls matter to them — but keeping the ref
// pointed at a real definition keeps these configs realistic.
func restAPIWithUpstreamDefs(defs ...api.UpstreamDefinition) *api.RestAPI {
	cfg := createValidRestAPIConfig()
	cfg.Spec.UpstreamDefinitions = &defs
	if len(defs) > 0 {
		cfg.Spec.Upstream.Main = api.Upstream{Ref: stringPtr(defs[0].Name)}
	}
	return cfg
}

// restAPIWithInlineUpstreamTLS attaches a tls block directly to
// spec.upstream.main (never valid) instead of to an upstreamDefinitions
// entry.
func restAPIWithInlineUpstreamTLS(tls map[string]interface{}) *api.RestAPI {
	cfg := createValidRestAPIConfig()
	cfg.Spec.Upstream.Main.Tls = &tls
	return cfg
}

// ============ ValidateRestAPI: the outbound feature's refusal outline ============
//
// Table mirrors "A tls block that could never work is refused with the
// offending path" in the outbound feature one-for-one.

func TestUpstreamTLSValidator_ValidateRestAPI_RefusalOutline(t *testing.T) {
	store := newFakeMtlsCertStore(
		gatewayIdentityCert("out-identity-a"),
		upstreamCA("out-backend-ca"),
	)
	validator := NewUpstreamTLSValidator(store, false)

	tests := []struct {
		name    string
		def     api.UpstreamDefinition
		field   string
		message string
	}{
		{
			name:    "identity naming a certificate that doesn't exist",
			def:     tlsUpstreamDef(map[string]interface{}{"identity": "out-missing"}, "https://mtls-backend-a:8443"),
			field:   "spec.upstreamDefinitions[0].tls.identity",
			message: "no gateway identity named out-missing exists on this gateway",
		},
		{
			name:    "trustedCAs naming a certificate that doesn't exist",
			def:     tlsUpstreamDef(map[string]interface{}{"trustedCAs": []interface{}{"out-missing-ca"}}, "https://mtls-backend-a:8443"),
			field:   "spec.upstreamDefinitions[0].tls.trustedCAs[0]",
			message: "no certificate named out-missing-ca exists on this gateway",
		},
		{
			name:    "empty trustedCAs list",
			def:     tlsUpstreamDef(map[string]interface{}{"trustedCAs": []interface{}{}}, "https://mtls-backend-a:8443"),
			field:   "spec.upstreamDefinitions[0].tls.trustedCAs",
			message: "omit trustedCAs to use the gateway trust bundle, or list at least one certificate",
		},
		{
			name:    "http target on a definition carrying tls",
			def:     tlsUpstreamDef(map[string]interface{}{"identity": "out-identity-a"}, "http://echo-backend:80"),
			field:   "spec.upstreamDefinitions[0].upstreams[0].url",
			message: "tls is configured but this target is http://; every target of a definition with tls must be https://",
		},
		{
			name:    "unknown tls parameter",
			def:     tlsUpstreamDef(map[string]interface{}{"mode": "strict"}, "https://mtls-backend-a:8443"),
			field:   "spec.upstreamDefinitions[0].tls.mode",
			message: "unknown parameter mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(tt.def))
			if !hasError(errs, tt.field, tt.message) {
				t.Fatalf("expected error field=%q message=%q, got %+v", tt.field, tt.message, errs)
			}
		})
	}
}

func TestUpstreamTLSValidator_ValidateRestAPI_InlineUpstreamTLSRejected(t *testing.T) {
	store := newFakeMtlsCertStore(gatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	errs := validator.ValidateRestAPI(restAPIWithInlineUpstreamTLS(map[string]interface{}{"identity": "out-identity-a"}))
	want := "tls is not supported on an inline upstream; move it to upstreamDefinitions and reference it"
	if !hasError(errs, "spec.upstream.main.tls", want) {
		t.Fatalf("expected error field=%q message=%q, got %+v", "spec.upstream.main.tls", want, errs)
	}
}

// ============ ValidateRestAPI: usage-mismatch and additional cases ============

func TestUpstreamTLSValidator_ValidateRestAPI_TlsEmptyBlock_Valid(t *testing.T) {
	store := newFakeMtlsCertStore()
	validator := NewUpstreamTLSValidator(store, false)

	errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(
		tlsUpstreamDef(map[string]interface{}{}, "https://mtls-backend-a:8443"),
	))
	if len(errs) != 0 {
		t.Fatalf("expected an empty tls block to be valid, got errors: %+v", errs)
	}
}

func TestUpstreamTLSValidator_ValidateRestAPI_IdentityNamingAClientRow_Rejected(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("out-client-authority"), gatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{
		"identity":   "out-client-authority",
		"trustedCAs": []interface{}{"out-identity-a"},
	}, "https://mtls-backend-a:8443")))

	if !hasError(errs, "spec.upstreamDefinitions[0].tls.identity",
		"out-client-authority is not a gateway identity (usage: identity)") {
		t.Fatalf("expected identity-usage-mismatch error, got %+v", errs)
	}
	if !hasError(errs, "spec.upstreamDefinitions[0].tls.trustedCAs[0]",
		"out-identity-a is a gateway identity (usage: identity); trustedCAs takes usage: upstream certificates") {
		t.Fatalf("expected trustedCAs-naming-an-identity error, got %+v", errs)
	}
}

func TestUpstreamTLSValidator_ValidateRestAPI_TrustedCAsNamingAClientRow_Rejected(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("out-client-authority"), gatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{
		"identity":   "out-identity-a",
		"trustedCAs": []interface{}{"out-client-authority"},
	}, "https://mtls-backend-a:8443")))

	want := "out-client-authority is a client authority (usage: client); trustedCAs takes usage: upstream certificates"
	if !hasError(errs, "spec.upstreamDefinitions[0].tls.trustedCAs[0]", want) {
		t.Fatalf("expected error field=%q message=%q, got %+v", "spec.upstreamDefinitions[0].tls.trustedCAs[0]", want, errs)
	}
}

func TestUpstreamTLSValidator_ValidateRestAPI_MixedHttpHttpsTargets_NamesTheHttpOne(t *testing.T) {
	store := newFakeMtlsCertStore(gatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	def := tlsUpstreamDef(map[string]interface{}{"identity": "out-identity-a"},
		"https://mtls-backend-a:8443", "http://echo-backend:80")

	errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(def))

	want := "tls is configured but this target is http://; every target of a definition with tls must be https://"
	// The http:// target is upstreams[1] — the error must name that index,
	// not upstreams[0] (which is https:// and fine).
	if hasError(errs, "spec.upstreamDefinitions[0].upstreams[0].url", want) {
		t.Fatalf("did not expect an error on the https:// target (index 0), got %+v", errs)
	}
	if !hasError(errs, "spec.upstreamDefinitions[0].upstreams[1].url", want) {
		t.Fatalf("expected error naming the http:// target at index 1, got %+v", errs)
	}
}

// ============ ResolveWarnings ============

func TestUpstreamTLSValidator_ResolveWarnings_VerifyHostNameDisabled(t *testing.T) {
	store := newFakeMtlsCertStore(gatewayIdentityCert("out-identity-a"), upstreamCA("out-backend-ca"))
	validator := NewUpstreamTLSValidator(store, false)

	cfg := restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{
		"identity":       "out-identity-a",
		"trustedCAs":     []interface{}{"out-backend-ca"},
		"verifyHostName": false,
	}, "https://mtls-backend-wronghost:8443"))

	warnings := validator.ResolveWarnings(*cfg)
	if !hasWarning(warnings, WarningCodeTLSVerifyHostNameDisabled, "spec.upstreamDefinitions[0].tls.verifyHostName") {
		t.Fatalf("expected %s warning at spec.upstreamDefinitions[0].tls.verifyHostName, got %+v",
			WarningCodeTLSVerifyHostNameDisabled, warnings)
	}
}

func TestUpstreamTLSValidator_ResolveWarnings_VerifyHostNameDefaultTrue_NoWarning(t *testing.T) {
	store := newFakeMtlsCertStore(gatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	cfg := restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{
		"identity": "out-identity-a",
	}, "https://mtls-backend-a:8443"))

	warnings := validator.ResolveWarnings(*cfg)
	if hasWarning(warnings, WarningCodeTLSVerifyHostNameDisabled, "spec.upstreamDefinitions[0].tls.verifyHostName") {
		t.Fatalf("did not expect a verifyHostName warning when unset (defaults true), got %+v", warnings)
	}
}

func TestUpstreamTLSValidator_ResolveWarnings_IdentityExpiredSinceUpload(t *testing.T) {
	store := newFakeMtlsCertStore(expiredGatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	cfg := restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{
		"identity": "out-identity-a",
	}, "https://mtls-backend-a:8443"))

	warnings := validator.ResolveWarnings(*cfg)
	if !hasWarning(warnings, WarningCodeTLSIdentityExpired, "spec.upstreamDefinitions[0].tls.identity") {
		t.Fatalf("expected %s warning at spec.upstreamDefinitions[0].tls.identity, got %+v",
			WarningCodeTLSIdentityExpired, warnings)
	}
}

func TestUpstreamTLSValidator_ResolveWarnings_IdentityNotExpired_NoWarning(t *testing.T) {
	store := newFakeMtlsCertStore(gatewayIdentityCert("out-identity-a"))
	validator := NewUpstreamTLSValidator(store, false)

	cfg := restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{
		"identity": "out-identity-a",
	}, "https://mtls-backend-a:8443"))

	warnings := validator.ResolveWarnings(*cfg)
	if hasWarning(warnings, WarningCodeTLSIdentityExpired, "spec.upstreamDefinitions[0].tls.identity") {
		t.Fatalf("did not expect an identity-expired warning for a not-yet-expired identity, got %+v", warnings)
	}
}

func TestUpstreamTLSValidator_TrustRefusedWhileVerificationDisabled(t *testing.T) {
	store := newFakeMtlsCertStore(gatewayIdentityCert("out-identity-a"), upstreamCA("out-backend-ca"))
	validator := NewUpstreamTLSValidator(store, true)

	for _, tls := range []map[string]interface{}{
		{"trustedCAs": []interface{}{"out-backend-ca"}},
		{"verifyHostName": false},
	} {
		errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(tlsUpstreamDef(tls, "https://mtls-backend-a:8443")))
		if len(errs) == 0 {
			t.Fatalf("expected a refusal for %v while verification is disabled", tls)
		}
		found := false
		for _, e := range errs {
			if e.Field == "spec.upstreamDefinitions[0].tls" && e.Message == "per-upstream trust cannot be enforced while router.upstream.tls.disable_ssl_verification is on" {
				found = true
			}
		}
		if !found {
			t.Errorf("expected the verification-disabled refusal, got %v", errs)
		}
	}

	// An identity alone asks for nothing Envoy cannot honour with verification off.
	if errs := validator.ValidateRestAPI(restAPIWithUpstreamDefs(tlsUpstreamDef(map[string]interface{}{"identity": "out-identity-a"}, "https://mtls-backend-a:8443"))); len(errs) != 0 {
		t.Errorf("an identity alone must deploy while verification is disabled, got %v", errs)
	}
}
