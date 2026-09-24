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
	"fmt"
	"strings"
	"testing"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// ============ Fake certificate store ============

// fakeMtlsCertStore is a minimal, in-memory MtlsAuthCertificateStore for
// tests: no database involved, just the two lookups the validator needs.
type fakeMtlsCertStore struct {
	byUsage map[string][]*models.StoredCertificate
	byName  map[string]*models.StoredCertificate
}

func newFakeMtlsCertStore(certs ...*models.StoredCertificate) *fakeMtlsCertStore {
	s := &fakeMtlsCertStore{
		byUsage: make(map[string][]*models.StoredCertificate),
		byName:  make(map[string]*models.StoredCertificate),
	}
	for _, c := range certs {
		usage := c.Usage
		if usage == "" {
			usage = models.CertificateUsageUpstream
		}
		s.byUsage[usage] = append(s.byUsage[usage], c)
		s.byName[c.Name] = c
	}
	return s
}

func (s *fakeMtlsCertStore) GetCertificateByName(name string) (*models.StoredCertificate, error) {
	c, ok := s.byName[name]
	if !ok {
		return nil, fmt.Errorf("no certificate named %q", name)
	}
	return c, nil
}

func (s *fakeMtlsCertStore) ListCertificatesByUsage(usage string) ([]*models.StoredCertificate, error) {
	return s.byUsage[usage], nil
}

func clientCA(name string) *models.StoredCertificate {
	return &models.StoredCertificate{Name: name, Usage: models.CertificateUsageClient, Role: models.CertificateRoleClient}
}

func relayCA(name string) *models.StoredCertificate {
	return &models.StoredCertificate{Name: name, Usage: models.CertificateUsageClient, Role: models.CertificateRoleRelay}
}

func upstreamCA(name string) *models.StoredCertificate {
	return &models.StoredCertificate{Name: name, Usage: models.CertificateUsageUpstream}
}

// ============ RestAPI builders ============

// mtlsPolicy builds an mtls-auth policy entry with the given params (nil for
// "no params at all", matching an omitted params: block).
func mtlsPolicy(params map[string]interface{}) api.Policy {
	p := api.Policy{Name: MtlsAuthPolicyName, Version: "v1"}
	if params != nil {
		p.Params = &params
	}
	return p
}

func namedPolicy(name string) api.Policy {
	return api.Policy{Name: name, Version: "v1"}
}

// restAPIWithAPILevelPolicies attaches the given policies at API level (spec.policies).
func restAPIWithAPILevelPolicies(policies ...api.Policy) *api.RestAPI {
	cfg := createValidRestAPIConfig()
	cfg.Spec.Policies = &policies
	return cfg
}

// restAPIWithOperationLevelPolicy attaches a single policy on the first (and
// only) operation createValidRestAPIConfig defines.
func restAPIWithOperationLevelPolicy(p api.Policy) *api.RestAPI {
	cfg := createValidRestAPIConfig()
	cfg.Spec.Operations[0].Policies = &[]api.Policy{p}
	return cfg
}

// hasError reports whether errs contains an entry with exactly this field and message.
func hasError(errs []ValidationError, field, message string) bool {
	for _, e := range errs {
		if e.Field == field && e.Message == message {
			return true
		}
	}
	return false
}

// hasWarning reports whether warnings contains an entry with this code and field.
func hasWarning(warnings []clientca.Warning, code, field string) bool {
	for _, w := range warnings {
		if w.Code == code && w.Field == field {
			return true
		}
	}
	return false
}

// ============ ValidateRestAPI: table-driven cases mirroring the accept-list
// rejection scenarios ============

func TestMtlsAuthValidator_ValidateRestAPI_AcceptListRejections(t *testing.T) {
	pool := func() *fakeMtlsCertStore {
		return newFakeMtlsCertStore(
			clientCA("listener-partner-a"),
			relayCA("listener-edge-lb"),
			upstreamCA("listener-backend-trust"),
		)
	}

	tests := []struct {
		name    string
		params  map[string]interface{}
		field   string
		message string
	}{
		{
			name:    "empty accept list",
			params:  map[string]interface{}{"accept": []interface{}{}},
			field:   "spec.policies[0].params.accept",
			message: "omit accept to inherit every pooled authority, or list at least one entry",
		},
		{
			name: "entry without ca",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"match": map[string]interface{}{"uriSANs": []interface{}{"urn:x"}}},
			}},
			field:   "spec.policies[0].params.accept[0].ca",
			message: "ca is required and must name an authority in this gateway's client-CA pool",
		},
		{
			name: "unknown ca",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-b"},
			}},
			field:   "spec.policies[0].params.accept[0].ca",
			message: "no client-CA authority named listener-partner-b exists on this gateway",
		},
		{
			name: "relay ca",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-edge-lb"},
			}},
			field:   "spec.policies[0].params.accept[0].ca",
			message: "listener-edge-lb is a relay (front proxy) entry and cannot be accepted as a client",
		},
		{
			name: "upstream-usage ca",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-backend-trust"},
			}},
			field:   "spec.policies[0].params.accept[0].ca",
			message: "listener-backend-trust is a backend trust certificate (usage: upstream); accept takes usage: client authorities",
		},
		{
			name: "empty uriSANs",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "match": map[string]interface{}{"uriSANs": []interface{}{}}},
			}},
			field:   "spec.policies[0].params.accept[0].match.uriSANs",
			message: "list at least one non-empty SAN, or remove match to accept any certificate from this authority",
		},
		{
			name: "empty-string dnsSANs element at index 1",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "match": map[string]interface{}{"dnsSANs": []interface{}{"a", ""}}},
			}},
			field:   "spec.policies[0].params.accept[0].match.dnsSANs[1]",
			message: "list at least one non-empty SAN, or remove match to accept any certificate from this authority",
		},
		{
			name: "empty thumbprints",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "thumbprints": []interface{}{}},
			}},
			field:   "spec.policies[0].params.accept[0].thumbprints",
			message: "list at least one thumbprint, or remove thumbprints to accept any certificate from this authority",
		},
		{
			name: "malformed thumbprint",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "thumbprints": []interface{}{"zz"}},
			}},
			field:   "spec.policies[0].params.accept[0].thumbprints[0]",
			message: "a thumbprint is the SHA-256 of the certificate as 64 hex characters (colons and a sha256: prefix are accepted)",
		},
		{
			name: "unknown param thumbprint (singular)",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "thumbprint": "9f86d081"},
			}},
			field:   "spec.policies[0].params.accept[0].thumbprint",
			message: "unknown parameter thumbprint; the field is thumbprints",
		},
		{
			name:    "accept given as an object",
			params:  map[string]interface{}{"accept": map[string]interface{}{"ca": "listener-partner-a"}},
			field:   "spec.policies[0].params.accept",
			message: "accept must be a list of entries; omit it to inherit every pooled authority",
		},
		{
			name:    "accept entry given as a bare string",
			params:  map[string]interface{}{"accept": []interface{}{"listener-partner-a"}},
			field:   "spec.policies[0].params.accept[0]",
			message: "each accept entry must be an object naming ca",
		},
		{
			name: "thumbprints given as a scalar",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "thumbprints": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
			}},
			field:   "spec.policies[0].params.accept[0].thumbprints",
			message: "thumbprints must be a list",
		},
		{
			name: "uriSANs given as a scalar",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "match": map[string]interface{}{"uriSANs": "urn:x"}},
			}},
			field:   "spec.policies[0].params.accept[0].match.uriSANs",
			message: "uriSANs must be a list",
		},
		{
			name: "empty match object",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "match": map[string]interface{}{}},
			}},
			field:   "spec.policies[0].params.accept[0].match",
			message: "match must list uriSANs or dnsSANs; remove it to accept any certificate from this authority",
		},
		{
			name: "match given as a scalar",
			params: map[string]interface{}{"accept": []interface{}{
				map[string]interface{}{"ca": "listener-partner-a", "match": "urn:x"},
			}},
			field:   "spec.policies[0].params.accept[0].match",
			message: "match must be an object listing uriSANs or dnsSANs",
		},
		{
			name:    "forwardCertificate given as a string",
			params:  map[string]interface{}{"forwardCertificate": "no"},
			field:   "spec.policies[0].params.forwardCertificate",
			message: "forwardCertificate must be true or false",
		},
		{
			name:    "unknown top-level param mode",
			params:  map[string]interface{}{"mode": "strict"},
			field:   "spec.policies[0].params.mode",
			message: "unknown parameter mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewMtlsAuthValidator(pool(), true, false)
			apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(tt.params))

			errs := v.ValidateRestAPI(apiConfig)

			if !hasError(errs, tt.field, tt.message) {
				t.Fatalf("expected error {field: %q, message: %q}, got %+v", tt.field, tt.message, errs)
			}
		})
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_EmptyPool(t *testing.T) {
	v := NewMtlsAuthValidator(newFakeMtlsCertStore(), true, false)
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))

	errs := v.ValidateRestAPI(apiConfig)

	want := "mtls-auth requires at least one client authority; add one with POST /certificates and usage: client"
	if !hasError(errs, "spec.policies[0]", want) {
		t.Fatalf("expected error {field: spec.policies[0], message: %q}, got %+v", want, errs)
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_HTTPSDisabled(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, false, false)
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))

	errs := v.ValidateRestAPI(apiConfig)

	want := "mtls-auth requires the HTTPS listener, which is disabled on this gateway"
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %+v", len(errs), errs)
	}
	if !hasError(errs, "spec.policies[0]", want) {
		t.Fatalf("expected error {field: spec.policies[0], message: %q}, got %+v", want, errs)
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_DuplicateInOneScope(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-a"},
	}}
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil), mtlsPolicy(acceptParams))

	errs := v.ValidateRestAPI(apiConfig)

	want := "mtls-auth may appear once per scope; use several accept entries instead"
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %+v", len(errs), errs)
	}
	if !hasError(errs, "spec.policies[1]", want) {
		t.Fatalf("expected error {field: spec.policies[1], message: %q}, got %+v", want, errs)
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_APIAndOperationLevel(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	cfg := createValidRestAPIConfig()
	cfg.Spec.Policies = &[]api.Policy{mtlsPolicy(nil)}
	cfg.Spec.Operations[0].Policies = &[]api.Policy{mtlsPolicy(nil)}

	errs := v.ValidateRestAPI(cfg)

	want := "mtls-auth is already attached at API level; attach it at one level only"
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 error, got %d: %+v", len(errs), errs)
	}
	if !hasError(errs, "spec.operations[0].policies[0]", want) {
		t.Fatalf("expected error {field: spec.operations[0].policies[0], message: %q}, got %+v", want, errs)
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_ValidAPI_NoErrors(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-a"},
	}}
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(acceptParams))

	errs := v.ValidateRestAPI(apiConfig)

	if len(errs) != 0 {
		t.Fatalf("expected no errors for a valid API, got %+v", errs)
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_OperationLevelFieldPath(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-b"}, // not in the pool
	}}
	apiConfig := restAPIWithOperationLevelPolicy(mtlsPolicy(acceptParams))

	errs := v.ValidateRestAPI(apiConfig)

	want := "no client-CA authority named listener-partner-b exists on this gateway"
	if !hasError(errs, "spec.operations[0].policies[0].params.accept[0].ca", want) {
		t.Fatalf("expected operation-level field path, got %+v", errs)
	}
}

// ============ ResolveMtlsAuthForResponse ============

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_AcceptOmitted_TwoAuthorities(t *testing.T) {
	store := newFakeMtlsCertStore(
		clientCA("listener-partner-a"),
		clientCA("listener-partner-b"),
		relayCA("listener-edge-lb"),
		upstreamCA("listener-backend-trust"),
	)
	v := NewMtlsAuthValidator(store, true, false)

	original := restAPIWithAPILevelPolicies(mtlsPolicy(nil))
	resolved, warnings := v.ResolveMtlsAuthForResponse(*original)

	// Input untouched: the original policy's Params must remain nil.
	if (*original.Spec.Policies)[0].Params != nil {
		t.Fatalf("expected original policy Params to remain nil, got %v", *(*original.Spec.Policies)[0].Params)
	}

	resolvedPolicies := *resolved.Spec.Policies
	accept, ok := (*resolvedPolicies[0].Params)["accept"].([]interface{})
	if !ok {
		t.Fatalf("expected resolved accept to be []interface{}, got %T", (*resolvedPolicies[0].Params)["accept"])
	}
	if len(accept) != 2 {
		t.Fatalf("expected exactly 2 resolved accept entries, got %d: %+v", len(accept), accept)
	}
	wantNames := []string{"listener-partner-a", "listener-partner-b"}
	for i, entryRaw := range accept {
		entry, ok := entryRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("accept[%d] = %T, want map[string]interface{}", i, entryRaw)
		}
		if entry["ca"] != wantNames[i] {
			t.Errorf("accept[%d].ca = %v, want %v", i, entry["ca"], wantNames[i])
		}
	}

	if !hasWarning(warnings, WarningCodeMTLSAcceptInheritsPool, "spec.policies[0].params.accept") {
		t.Fatalf("expected MTLS_ACCEPT_INHERITS_POOL warning for spec.policies[0].params.accept, got %+v", warnings)
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_SingleAuthority_NoWarning(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))
	resolved, warnings := v.ResolveMtlsAuthForResponse(*apiConfig)

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings with a single pooled authority, got %+v", warnings)
	}

	accept, ok := (*(*resolved.Spec.Policies)[0].Params)["accept"].([]interface{})
	if !ok || len(accept) != 1 {
		t.Fatalf("expected exactly 1 resolved accept entry, got %#v", accept)
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_UnnarrowedEntry_Warning(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"), clientCA("listener-partner-b"))
	v := NewMtlsAuthValidator(store, true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-a"},
	}}
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(acceptParams))
	_, warnings := v.ResolveMtlsAuthForResponse(*apiConfig)

	if !hasWarning(warnings, WarningCodeMTLSAcceptUnnarrowed, "spec.policies[0].params.accept[0]") {
		t.Fatalf("expected MTLS_ACCEPT_UNNARROWED warning for spec.policies[0].params.accept[0], got %+v", warnings)
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_PrecedingAuthPolicy_Warning(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{
			"ca":    "listener-partner-a",
			"match": map[string]interface{}{"uriSANs": []interface{}{"urn:partner-a:payments"}},
		},
	}}
	apiConfig := restAPIWithAPILevelPolicies(namedPolicy("jwt-auth"), mtlsPolicy(acceptParams))
	_, warnings := v.ResolveMtlsAuthForResponse(*apiConfig)

	if !hasWarning(warnings, WarningCodeMTLSAuthNotFirst, "spec.policies[0]") {
		t.Fatalf("expected MTLS_AUTH_NOT_FIRST warning for spec.policies[0], got %+v", warnings)
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_ThumbprintNormalised(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)

	raw := "sha256:9F:86:D0:81:88:4C:7D:65:9A:2F:EA:A0:C5:5A:D0:15:A3:BF:4F:1B:2B:0B:82:2C:D1:5D:6C:15:B0:F0:0A:08"
	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-a", "thumbprints": []interface{}{raw}},
	}}
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(acceptParams))
	resolved, warnings := v.ResolveMtlsAuthForResponse(*apiConfig)

	wantThumbprint := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	accept := (*(*resolved.Spec.Policies)[0].Params)["accept"].([]interface{})
	entry := accept[0].(map[string]interface{})
	tps := entry["thumbprints"].([]interface{})
	if tps[0] != wantThumbprint {
		t.Fatalf("thumbprints[0] = %v, want %v", tps[0], wantThumbprint)
	}

	if !hasWarning(warnings, WarningCodeMTLSThumbprintNormalised, "spec.policies[0].params.accept[0].thumbprints[0]") {
		t.Fatalf("expected MTLS_THUMBPRINT_NORMALISED warning for spec.policies[0].params.accept[0].thumbprints[0], got %+v", warnings)
	}
}

func TestMtlsAuthValidator_ValidateRestAPI_ForwardCertificateBoolean_NoErrors(t *testing.T) {
	for _, forward := range []bool{true, false} {
		v := NewMtlsAuthValidator(newFakeMtlsCertStore(clientCA("listener-partner-a")), true, false)
		params := map[string]interface{}{
			"accept":             []interface{}{map[string]interface{}{"ca": "listener-partner-a"}},
			"forwardCertificate": forward,
		}
		if errs := v.ValidateRestAPI(restAPIWithAPILevelPolicies(mtlsPolicy(params))); len(errs) != 0 {
			t.Fatalf("forwardCertificate: %v: expected no errors, got %+v", forward, errs)
		}
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_UnnarrowedEntry_SingleAuthorityPool_Warning(t *testing.T) {
	v := NewMtlsAuthValidator(newFakeMtlsCertStore(clientCA("listener-partner-a")), true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-a"},
	}}
	_, warnings := v.ResolveMtlsAuthForResponse(*restAPIWithAPILevelPolicies(mtlsPolicy(acceptParams)))

	if !hasWarning(warnings, WarningCodeMTLSAcceptUnnarrowed, "spec.policies[0].params.accept[0]") {
		t.Fatalf("expected MTLS_ACCEPT_UNNARROWED for an explicit unnarrowed entry with one pooled authority, got %+v", warnings)
	}
	if hasWarning(warnings, WarningCodeMTLSAcceptInheritsPool, "spec.policies[0].params.accept") {
		t.Fatalf("MTLS_ACCEPT_INHERITS_POOL must not be raised for an explicit accept list, got %+v", warnings)
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_NarrowedEntry_NoUnnarrowedWarning(t *testing.T) {
	v := NewMtlsAuthValidator(newFakeMtlsCertStore(clientCA("listener-partner-a"), clientCA("listener-partner-b")), true, false)

	acceptParams := map[string]interface{}{"accept": []interface{}{
		map[string]interface{}{"ca": "listener-partner-a", "match": map[string]interface{}{"uriSANs": []interface{}{"urn:x"}}},
	}}
	_, warnings := v.ResolveMtlsAuthForResponse(*restAPIWithAPILevelPolicies(mtlsPolicy(acceptParams)))

	if hasWarning(warnings, WarningCodeMTLSAcceptUnnarrowed, "spec.policies[0].params.accept[0]") {
		t.Fatalf("expected no MTLS_ACCEPT_UNNARROWED for a narrowed entry, got %+v", warnings)
	}
}

// TestMtlsAuthValidator_ResolveMtlsAuthForResponse_AcceptNamesRelayAuthority
// covers the same authority pooled under two names — once as a relay, once
// as a client entry an API names in accept.
func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_AcceptNamesRelayAuthority(t *testing.T) {
	lbPEM, _, _ := generateXDSTestCA(t)
	partnerPEM, _, _ := generateXDSTestCA(t)

	pooled := func(name, role string, pem []byte) *models.StoredCertificate {
		return &models.StoredCertificate{Name: name, Usage: models.CertificateUsageClient, Role: role, Certificate: pem}
	}
	acceptOf := func(ca string) *api.RestAPI {
		return restAPIWithAPILevelPolicies(mtlsPolicy(map[string]interface{}{"accept": []interface{}{
			map[string]interface{}{"ca": ca},
		}}))
	}
	const field = "spec.policies[0].params.accept[0].ca"

	tests := []struct {
		name        string
		pool        []*models.StoredCertificate
		acceptCA    string
		wantWarning bool
	}{
		{
			name: "identical certificate bytes under a client and a relay name",
			pool: []*models.StoredCertificate{
				pooled("edge-lb-relay", models.CertificateRoleRelay, lbPEM),
				pooled("edge-lb-client", models.CertificateRoleClient, lbPEM),
			},
			acceptCA:    "edge-lb-client",
			wantWarning: true,
		},
		{
			name: "same authority stored with different surrounding bytes",
			pool: []*models.StoredCertificate{
				pooled("edge-lb-relay", models.CertificateRoleRelay, lbPEM),
				pooled("edge-lb-client", models.CertificateRoleClient, append([]byte("\n"), lbPEM...)),
			},
			acceptCA:    "edge-lb-client",
			wantWarning: true,
		},
		{
			name: "a different authority than every relay",
			pool: []*models.StoredCertificate{
				pooled("edge-lb-relay", models.CertificateRoleRelay, lbPEM),
				pooled("partner-a", models.CertificateRoleClient, partnerPEM),
			},
			acceptCA:    "partner-a",
			wantWarning: false,
		},
		{
			name:        "no relay entries at all",
			pool:        []*models.StoredCertificate{pooled("edge-lb-client", models.CertificateRoleClient, lbPEM)},
			acceptCA:    "edge-lb-client",
			wantWarning: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewMtlsAuthValidator(newFakeMtlsCertStore(tt.pool...), true, false)
			_, warnings := v.ResolveMtlsAuthForResponse(*acceptOf(tt.acceptCA))
			if got := hasWarning(warnings, WarningCodeMTLSAcceptNamesRelayAuthority, field); got != tt.wantWarning {
				t.Fatalf("MTLS_ACCEPT_NAMES_RELAY_AUTHORITY at %s present = %v, want %v; warnings %+v", field, got, tt.wantWarning, warnings)
			}
		})
	}
}

// ============ ValidateMTLSStartupInvariant ============

func storedConfigWithRestAPI(handle string, restAPI *api.RestAPI) *models.StoredConfig {
	return &models.StoredConfig{
		Handle:        handle,
		Kind:          models.KindRestApi,
		Configuration: *restAPI,
	}
}

func TestValidateMTLSStartupInvariant_HTTPSDisabled_APILevelMTLS_Errors(t *testing.T) {
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))
	configs := []*models.StoredConfig{storedConfigWithRestAPI("mtls-api", apiConfig)}

	err := ValidateMTLSStartupInvariant(configs, false, false)

	if err == nil {
		t.Fatal("expected an error when https is disabled and a stored config attaches mtls-auth at API level")
	}
}

func TestValidateMTLSStartupInvariant_HTTPSDisabled_OperationLevelMTLS_Errors(t *testing.T) {
	apiConfig := restAPIWithOperationLevelPolicy(mtlsPolicy(nil))
	configs := []*models.StoredConfig{storedConfigWithRestAPI("mtls-api", apiConfig)}

	err := ValidateMTLSStartupInvariant(configs, false, false)

	if err == nil {
		t.Fatal("expected an error when https is disabled and a stored config attaches mtls-auth at operation level")
	}
}

func TestValidateMTLSStartupInvariant_HTTPSEnabled_NoError(t *testing.T) {
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))
	configs := []*models.StoredConfig{storedConfigWithRestAPI("mtls-api", apiConfig)}

	if err := ValidateMTLSStartupInvariant(configs, true, false); err != nil {
		t.Fatalf("expected no error when https is enabled, got: %v", err)
	}
}

func TestValidateMTLSStartupInvariant_NoMTLSConfigs_NoError(t *testing.T) {
	plainConfig := createValidRestAPIConfig()
	configs := []*models.StoredConfig{storedConfigWithRestAPI("plain-api", plainConfig)}

	if err := ValidateMTLSStartupInvariant(configs, false, false); err != nil {
		t.Fatalf("expected no error when no stored config attaches mtls-auth, got: %v", err)
	}
}

// ============ headerTrustAny: the header-relay trust_any relaxation ============

// TestMtlsAuthValidator_ValidateRestAPI_HeaderTrustAny_RelaxesHTTPSRequirement
// guards that a relayed header can legitimately arrive over plaintext from a
// trusted front proxy: with trust_any true, HTTPS-listener-disabled no
// longer produces the "requires the HTTPS listener" refusal.
func TestMtlsAuthValidator_ValidateRestAPI_HeaderTrustAny_RelaxesHTTPSRequirement(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, false, true)
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))

	errs := v.ValidateRestAPI(apiConfig)

	want := "mtls-auth requires the HTTPS listener, which is disabled on this gateway"
	if hasError(errs, "spec.policies[0]", want) {
		t.Fatalf("expected the HTTPS-listener refusal to be relaxed when trust_any is true, got %+v", errs)
	}
}

func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_HeaderTrustAny_EmitsBypassWarning(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, true)
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))

	_, warnings := v.ResolveMtlsAuthForResponse(*apiConfig)

	if !hasWarning(warnings, WarningCodeHeaderCertBypassActive, "") {
		t.Fatalf("expected %s warning with an empty field when trust_any is true, got %+v", WarningCodeHeaderCertBypassActive, warnings)
	}
}

// TestMtlsAuthValidator_ResolveMtlsAuthForResponse_HeaderTrustAnyFalse_NoBypassWarning
// guards the off case: headerTrustAny false never emits
// HEADER_CERT_BYPASS_ACTIVE.
func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_HeaderTrustAnyFalse_NoBypassWarning(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, false)
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))

	_, warnings := v.ResolveMtlsAuthForResponse(*apiConfig)

	if hasWarning(warnings, WarningCodeHeaderCertBypassActive, "") {
		t.Fatalf("expected no %s warning when trust_any is false, got %+v", WarningCodeHeaderCertBypassActive, warnings)
	}
}

// TestMtlsAuthValidator_ResolveMtlsAuthForResponse_HeaderTrustAny_NoMTLSAuth_NoBypassWarning
// guards that the warning is attached per mtls-auth deploy response, never
// unconditionally: an API with no mtls-auth attachment at all must not carry
// it even though trust_any is true gateway-wide.
func TestMtlsAuthValidator_ResolveMtlsAuthForResponse_HeaderTrustAny_NoMTLSAuth_NoBypassWarning(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA("listener-partner-a"))
	v := NewMtlsAuthValidator(store, true, true)
	plainConfig := createValidRestAPIConfig()

	_, warnings := v.ResolveMtlsAuthForResponse(*plainConfig)

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings for an API that never attaches mtls-auth, got %+v", warnings)
	}
}

// ============ ValidateMTLSStartupInvariant: the headerTrustAny relaxation ============

func TestValidateMTLSStartupInvariant_HTTPSDisabled_HeaderTrustAny_NoError(t *testing.T) {
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))
	configs := []*models.StoredConfig{storedConfigWithRestAPI("mtls-api", apiConfig)}

	if err := ValidateMTLSStartupInvariant(configs, false, true); err != nil {
		t.Fatalf("expected no error when https is disabled but trust_any is true, got: %v", err)
	}
}

func TestValidateMTLSStartupInvariant_HTTPSDisabled_HeaderTrustAnyFalse_Errors(t *testing.T) {
	apiConfig := restAPIWithAPILevelPolicies(mtlsPolicy(nil))
	configs := []*models.StoredConfig{storedConfigWithRestAPI("mtls-api", apiConfig)}

	if err := ValidateMTLSStartupInvariant(configs, false, false); err == nil {
		t.Fatal("expected an error when https is disabled and trust_any is false")
	}
}

func TestMtlsAuthValidator_ExecutionConditionRefused(t *testing.T) {
	v := NewMtlsAuthValidator(newFakeMtlsCertStore(clientCA("listener-partner-a")), true, false)
	cond := `request.Method == "POST"`
	params := map[string]interface{}{"accept": []interface{}{map[string]interface{}{"ca": "listener-partner-a"}}}
	apiCfg := restAPIWithAPILevelPolicies(api.Policy{Name: MtlsAuthPolicyName, Version: "v1", Params: &params, ExecutionCondition: &cond})

	errs := v.ValidateRestAPI(apiCfg)

	if len(errs) != 1 {
		t.Fatalf("expected exactly one error, got %v", errs)
	}
	if errs[0].Field != "spec.policies[0].executionCondition" {
		t.Errorf("field: got %q", errs[0].Field)
	}
	if errs[0].Message != "mtls-auth runs on every request and cannot carry an executionCondition" {
		t.Errorf("message: got %q", errs[0].Message)
	}
}

func TestMtlsAuthValidator_PoolOfRelaysOnlyCountsAsEmpty(t *testing.T) {
	relayOnly := newFakeMtlsCertStore(relayCA("listener-edge-lb"))
	v := NewMtlsAuthValidator(relayOnly, true, false)
	apiCfg := restAPIWithAPILevelPolicies(api.Policy{Name: MtlsAuthPolicyName, Version: "v1"})

	errs := v.ValidateRestAPI(apiCfg)

	if len(errs) != 1 {
		t.Fatalf("expected exactly one error, got %v", errs)
	}
	if errs[0].Field != "spec.policies[0]" {
		t.Errorf("field: got %q", errs[0].Field)
	}
	if !strings.Contains(errs[0].Message, "requires at least one client authority") {
		t.Errorf("message: got %q", errs[0].Message)
	}
}
