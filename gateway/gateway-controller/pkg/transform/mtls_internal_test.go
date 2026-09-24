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

package transform

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/testutil/pki"
)

// ============ Fake certificate store ============
//
// A minimal, in-memory config.MtlsAuthCertificateStore, mirroring
// pkg/config's own fakeMtlsCertStore (unexported there, so this package needs
// its own copy rather than importing it).

type fakeMtlsCertStore struct {
	byUsage map[string][]*models.StoredCertificate
	byName  map[string]*models.StoredCertificate
	listErr error
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
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.byUsage[usage], nil
}

// clientCA/relayCA build a usage: client pool entry with a real, PEM-encodable
// certificate (from gateway-controller's own testutil/pki helper) so
// splitCertificatePEMs has real PEM blocks to decode.
func clientCA(t *testing.T, name string) *models.StoredCertificate {
	t.Helper()
	entity := pki.NewRootCA(t, name)
	return &models.StoredCertificate{Name: name, Certificate: entity.PEM(), Usage: models.CertificateUsageClient, Role: models.CertificateRoleClient}
}

func relayCA(t *testing.T, name string) *models.StoredCertificate {
	t.Helper()
	entity := pki.NewRootCA(t, name)
	return &models.StoredCertificate{Name: name, Certificate: entity.PEM(), Usage: models.CertificateUsageClient, Role: models.CertificateRoleRelay}
}

// ============ Helpers ============

const mtlsAuthTestRouteKey = "GET|/test/hello|main.local"

func mtlsAuthDefs() map[string]models.PolicyDefinition {
	return map[string]models.PolicyDefinition{"mtls-auth|v1.0.0": {Name: config.MtlsAuthPolicyName, Version: "v1.0.0"}}
}

func mtlsAuthPolicy(params map[string]interface{}) api.Policy {
	p := api.Policy{Name: config.MtlsAuthPolicyName, Version: ""}
	if params != nil {
		p.Params = &params
	}
	return p
}

// findPolicy returns the named policy instance from the chain built for
// routeKey, or nil if absent.
func findPolicy(rdc *models.RuntimeDeployConfig, routeKey, policyName string) *models.Policy {
	chain, ok := rdc.PolicyChains[routeKey]
	if !ok {
		return nil
	}
	for i := range chain.Policies {
		if chain.Policies[i].Name == policyName {
			return &chain.Policies[i]
		}
	}
	return nil
}

func asInterfaceSlice(t *testing.T, v interface{}) []interface{} {
	t.Helper()
	s, ok := v.([]interface{})
	require.Truef(t, ok, "expected []interface{}, got %T (%v)", v, v)
	return s
}

// ============ API-level and operation-level injection ============

func TestBuildPolicyChain_MtlsAuth_InjectsInternalParams_APILevel(t *testing.T) {
	rootA := clientCA(t, "auth-ca-a")
	store := newFakeMtlsCertStore(rootA)

	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig(
		[]api.Policy{mtlsAuthPolicy(map[string]interface{}{
			"accept": []interface{}{map[string]interface{}{"ca": "auth-ca-a"}},
		})},
		nil,
	)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	require.NotNil(t, rdc)

	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p, "expected mtls-auth in the API-level policy chain")

	accept := asInterfaceSlice(t, p.Params[mtlsInternalAcceptParam])
	require.Len(t, accept, 1)
	pool := asInterfaceSlice(t, p.Params[mtlsInternalPoolParam])
	require.Len(t, pool, 1)
}

func TestBuildPolicyChain_MtlsAuth_InjectsInternalParams_OperationLevel(t *testing.T) {
	rootA := clientCA(t, "auth-ca-a")
	store := newFakeMtlsCertStore(rootA)

	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig(
		nil,
		[]api.Policy{mtlsAuthPolicy(map[string]interface{}{
			"accept": []interface{}{map[string]interface{}{"ca": "auth-ca-a"}},
		})},
	)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	require.NotNil(t, rdc)

	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p, "expected mtls-auth in the operation-level policy chain")

	accept := asInterfaceSlice(t, p.Params[mtlsInternalAcceptParam])
	require.Len(t, accept, 1)
	pool := asInterfaceSlice(t, p.Params[mtlsInternalPoolParam])
	require.Len(t, pool, 1)
}

// ============ Omitted accept resolves to every non-relay client row ============

func TestBuildPolicyChain_MtlsAuth_OmittedAccept_ResolvesToNonRelayPool(t *testing.T) {
	clientEntry := clientCA(t, "auth-ca-a")
	relayEntry := relayCA(t, "auth-ca-relay")
	store := newFakeMtlsCertStore(clientEntry, relayEntry)

	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig(
		[]api.Policy{mtlsAuthPolicy(nil)}, // no params at all: accept omitted
		nil,
	)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p)

	accept := asInterfaceSlice(t, p.Params[mtlsInternalAcceptParam])
	require.Len(t, accept, 1, "relay row must be excluded from the inherited accept list")
	entry, ok := accept[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "auth-ca-a", entry["ca"])

	// Pool material — path-building for the policy — includes BOTH the client
	// and relay rows, since it's independent of what this API accepts.
	pool := asInterfaceSlice(t, p.Params[mtlsInternalPoolParam])
	assert.Len(t, pool, 2, "the pool must include the relay row even though accept excludes it")
}

// ============ match copied, thumbprints normalised, author's accept untouched ============

func TestBuildPolicyChain_MtlsAuth_CopiesMatchNormalisesThumbprints_LeavesAuthoredAcceptUntouched(t *testing.T) {
	rootA := clientCA(t, "auth-ca-a")
	store := newFakeMtlsCertStore(rootA)

	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	authoredThumbprint := "SHA256:AA:BB:" + strings.Repeat("0", 60) // mixed-case + colons + prefix, 64 hex chars once normalised
	authoredMatch := map[string]interface{}{"uriSANs": []interface{}{"urn:partner-a:payments"}}
	authoredAccept := []interface{}{
		map[string]interface{}{
			"ca":          "auth-ca-a",
			"match":       authoredMatch,
			"thumbprints": []interface{}{authoredThumbprint},
		},
	}
	params := map[string]interface{}{"accept": authoredAccept}

	cfg := makeRestAPIStoredConfig([]api.Policy{mtlsAuthPolicy(params)}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p)

	// The author's own `accept` key is untouched — same value, not normalised.
	assert.Equal(t, authoredMatch, p.Params["accept"].([]interface{})[0].(map[string]interface{})["match"],
		"author's accept.match must be passed through as the same value, never rewritten")
	gotAuthoredThumbprints := p.Params["accept"].([]interface{})[0].(map[string]interface{})["thumbprints"].([]interface{})
	require.Len(t, gotAuthoredThumbprints, 1)
	assert.Equal(t, authoredThumbprint, gotAuthoredThumbprints[0], "the author-facing accept must keep the as-authored thumbprint form")

	// The internal, engine-facing accept list carries the match through and
	// normalises the thumbprint to 64 lowercase hex.
	internalAccept := asInterfaceSlice(t, p.Params[mtlsInternalAcceptParam])
	require.Len(t, internalAccept, 1)
	internalEntry, ok := internalAccept[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, authoredMatch, internalEntry["match"], "match must be copied through to the internal accept entry")

	wantNormalised := "aabb" + strings.Repeat("0", 60)
	gotThumbprints := asInterfaceSlice(t, internalEntry["thumbprints"])
	require.Len(t, gotThumbprints, 1)
	assert.Equal(t, wantNormalised, gotThumbprints[0])
}

// ============ No injection for other policies, or when the store is nil ============

func TestBuildPolicyChain_MtlsAuth_NoInjectionForOtherPolicies(t *testing.T) {
	rootA := clientCA(t, "auth-ca-a")
	store := newFakeMtlsCertStore(rootA)

	defs := map[string]models.PolicyDefinition{
		"header-mutate|v1.0.0": {Name: "header-mutate", Version: "v1.0.0"},
	}
	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, defs, store)

	cfg := makeRestAPIStoredConfig([]api.Policy{{Name: "header-mutate", Version: ""}}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, "header-mutate")
	require.NotNil(t, p)

	_, hasAccept := p.Params[mtlsInternalAcceptParam]
	_, hasPool := p.Params[mtlsInternalPoolParam]
	assert.False(t, hasAccept, "a non-mtls-auth policy must never get the internal accept param")
	assert.False(t, hasPool, "a non-mtls-auth policy must never get the internal pool param")
}

// ============ __wso2_internal_mtls_relays ============

// TestBuildPolicyChain_MtlsAuth_RelaysParam_ListsRelayRowsWithMatch guards
// __wso2_internal_mtls_relays: it lists every usage: client, role: relay pool
// row (never a plain client row), and a "match" key is present only for a
// relay row that was actually stored with a narrowing Match.
func TestBuildPolicyChain_MtlsAuth_RelaysParam_ListsRelayRowsWithMatch(t *testing.T) {
	clientEntry := clientCA(t, "auth-ca-a")
	relayNoMatch := relayCA(t, "auth-ca-relay-no-match")
	relayWithMatch := relayCA(t, "auth-ca-relay-with-match")
	relayWithMatch.Match = &models.CertificateMatch{DNSSANs: []string{"lb.corp.test"}}
	store := newFakeMtlsCertStore(clientEntry, relayNoMatch, relayWithMatch)

	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig([]api.Policy{mtlsAuthPolicy(nil)}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p)

	relays := asInterfaceSlice(t, p.Params[mtlsInternalRelaysParam])
	require.Len(t, relays, 2, "the client (non-relay) row must be excluded from __wso2_internal_mtls_relays")

	byName := map[string]map[string]interface{}{}
	for _, raw := range relays {
		entry, ok := raw.(map[string]interface{})
		require.True(t, ok)
		byName[entry["name"].(string)] = entry
	}

	noMatchEntry, ok := byName["auth-ca-relay-no-match"]
	require.True(t, ok)
	_, hasMatch := noMatchEntry["match"]
	assert.False(t, hasMatch, "a relay row with no stored Match must carry no match key at all")
	certs := asInterfaceSlice(t, noMatchEntry["certificates"])
	assert.Len(t, certs, 1)

	withMatchEntry, ok := byName["auth-ca-relay-with-match"]
	require.True(t, ok)
	matchRaw, hasMatch := withMatchEntry["match"]
	require.True(t, hasMatch, "a relay row with a stored Match must carry a match key")
	matchMap, ok := matchRaw.(map[string]interface{})
	require.True(t, ok)
	dnsSANs := asInterfaceSlice(t, matchMap["dnsSANs"])
	require.Len(t, dnsSANs, 1)
	assert.Equal(t, "lb.corp.test", dnsSANs[0])
}

// TestBuildPolicyChain_MtlsAuth_RelaysParam_EmptyWhenNoRelays guards the
// "none" case: buildMtlsRelaysMaterial always sets the param (never omits
// it), so a pool with no relay rows resolves to an empty array, not an
// absent key — and the policy (mtlsauth.go's parseRelaysParam) tolerates
// either shape, so this pins down which one the controller actually sends.
func TestBuildPolicyChain_MtlsAuth_RelaysParam_EmptyWhenNoRelays(t *testing.T) {
	clientEntry := clientCA(t, "auth-ca-a")
	store := newFakeMtlsCertStore(clientEntry) // no relay rows at all

	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig([]api.Policy{mtlsAuthPolicy(nil)}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p)

	relaysRaw, present := p.Params[mtlsInternalRelaysParam]
	require.True(t, present, "the relays param must still be present as an empty array, not omitted")
	relays := asInterfaceSlice(t, relaysRaw)
	assert.Len(t, relays, 0)
}

// ============ __wso2_internal_mtls_header ============

// TestBuildPolicyChain_MtlsAuth_HeaderParam_CarriesRouterConfig guards that
// __wso2_internal_mtls_header mirrors
// router.downstream_tls.client_certificate_header exactly — the policy
// engine's only source of that config, since it runs outside the controller
// process.
func TestBuildPolicyChain_MtlsAuth_HeaderParam_CarriesRouterConfig(t *testing.T) {
	clientEntry := clientCA(t, "auth-ca-a")
	store := newFakeMtlsCertStore(clientEntry)

	routerCfg := testRouterCfg()
	routerCfg.DownstreamTLS.ClientCertificateHeader = config.ClientCertificateHeader{
		Name:             "X-Custom-Client-Cert",
		TrustAny:         true,
		ForwardToBackend: true,
	}
	transformer := NewRestAPITransformer(routerCfg, &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig([]api.Policy{mtlsAuthPolicy(nil)}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p)

	header, ok := p.Params[mtlsInternalHeaderParam].(map[string]interface{})
	require.Truef(t, ok, "expected %s to be a map[string]interface{}, got %T", mtlsInternalHeaderParam, p.Params[mtlsInternalHeaderParam])
	assert.Equal(t, "X-Custom-Client-Cert", header["name"])
	assert.Equal(t, true, header["trustAny"])
	assert.Equal(t, true, header["forwardToBackend"])
}

func TestBuildPolicyChain_MtlsAuth_ForwardCertificate_PassesThroughUnchanged(t *testing.T) {
	store := newFakeMtlsCertStore(clientCA(t, "auth-ca-a"))
	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig([]api.Policy{mtlsAuthPolicy(map[string]interface{}{
		"accept":             []interface{}{map[string]interface{}{"ca": "auth-ca-a"}},
		"forwardCertificate": false,
	})}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p)
	assert.Equal(t, false, p.Params["forwardCertificate"])
}

func TestBuildPolicyChain_MtlsAuth_NilStore_NoInjection(t *testing.T) {
	// mtlsCertStore deliberately passed as nil: injection is skipped entirely.
	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), nil)

	cfg := makeRestAPIStoredConfig(
		[]api.Policy{mtlsAuthPolicy(map[string]interface{}{
			"accept": []interface{}{map[string]interface{}{"ca": "auth-ca-a"}},
		})},
		nil,
	)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p, "the mtls-auth instance itself must still be in the chain")

	_, hasAccept := p.Params[mtlsInternalAcceptParam]
	_, hasPool := p.Params[mtlsInternalPoolParam]
	assert.False(t, hasAccept, "no store means no internal accept param is injected")
	assert.False(t, hasPool, "no store means no internal pool param is injected")
}

func TestBuildPolicyChain_MtlsAuth_StoreFailureFailsTheBuild(t *testing.T) {
	rootA := clientCA(t, "ca-a")
	store := newFakeMtlsCertStore(rootA)
	store.listErr = errors.New("database unavailable")
	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, mtlsAuthDefs(), store)

	cfg := makeRestAPIStoredConfig(
		[]api.Policy{mtlsAuthPolicy(map[string]interface{}{
			"accept": []interface{}{map[string]interface{}{"ca": "ca-a"}},
		})},
		nil,
	)

	rdc, err := transformer.Transform(cfg)

	require.Error(t, err, "a chain with an empty pool would deny every caller; the build must fail instead")
	assert.Nil(t, rdc)
}
