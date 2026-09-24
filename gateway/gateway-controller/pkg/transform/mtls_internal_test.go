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
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

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

// transformMtlsAuth builds the chain for a RestAPI whose only policy is
// mtls-auth with params, attached at API level or operation level, and
// returns that mtls-auth instance.
func transformMtlsAuth(t *testing.T, routerCfg *config.RouterConfig, params map[string]interface{}, operationLevel bool) *models.Policy {
	t.Helper()
	transformer := NewRestAPITransformer(routerCfg, &config.Config{}, mtlsAuthDefs())
	policies := []api.Policy{mtlsAuthPolicy(params)}
	cfg := makeRestAPIStoredConfig(policies, nil)
	if operationLevel {
		cfg = makeRestAPIStoredConfig(nil, policies)
	}

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	require.NotNil(t, rdc)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, config.MtlsAuthPolicyName)
	require.NotNil(t, p, "expected mtls-auth in the policy chain")
	return p
}

// internalParamKeys lists the __wso2_internal_mtls_* keys set on p.
func internalParamKeys(p *models.Policy) []string {
	var keys []string
	for k := range p.Params {
		if strings.HasPrefix(k, "__wso2_internal_mtls_") {
			keys = append(keys, k)
		}
	}
	return keys
}

// ============ API-level and operation-level injection ============

func TestBuildPolicyChain_MtlsAuth_InjectsAcceptNamesAndHeader(t *testing.T) {
	for _, operationLevel := range []bool{false, true} {
		name := "API level"
		if operationLevel {
			name = "operation level"
		}
		t.Run(name, func(t *testing.T) {
			p := transformMtlsAuth(t, testRouterCfg(), map[string]interface{}{
				"accept": []interface{}{map[string]interface{}{"ca": " auth-ca-a "}},
			}, operationLevel)

			assert.ElementsMatch(t, []string{mtlsInternalAcceptParam, mtlsInternalHeaderParam}, internalParamKeys(p))
			accept := asInterfaceSlice(t, p.Params[mtlsInternalAcceptParam])
			require.Len(t, accept, 1)
			assert.Equal(t, map[string]interface{}{"ca": "auth-ca-a"}, accept[0],
				"an entry carries only the trimmed authority name when the author wrote no narrowing")
		})
	}
}

// ============ Omitted accept injects nothing for accept ============

func TestBuildPolicyChain_MtlsAuth_OmittedAccept_InjectsNoAccept(t *testing.T) {
	p := transformMtlsAuth(t, testRouterCfg(), nil, false)

	_, hasAccept := p.Params[mtlsInternalAcceptParam]
	assert.False(t, hasAccept, "an omitted accept must reach the engine as omitted, so the policy resolves the pool itself")
	assert.ElementsMatch(t, []string{mtlsInternalHeaderParam}, internalParamKeys(p))
}

// ============ The chain carries no certificate material ============

func TestBuildPolicyChain_MtlsAuth_ChainCarriesNoCertificateMaterial(t *testing.T) {
	for _, params := range []map[string]interface{}{
		nil,
		{"accept": []interface{}{
			map[string]interface{}{"ca": "auth-ca-a", "match": map[string]interface{}{"dnsSANs": []interface{}{"client.example.com"}}},
			map[string]interface{}{"ca": "auth-ca-b"},
		}},
	} {
		p := transformMtlsAuth(t, testRouterCfg(), params, false)
		encoded, err := json.Marshal(p.Params)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), "CERTIFICATE", "a policy chain must never carry PEM")
		assert.NotContains(t, string(encoded), "certificates")
		for _, removed := range []string{"__wso2_internal_mtls_pool", "__wso2_internal_mtls_relays"} {
			_, present := p.Params[removed]
			assert.Falsef(t, present, "%s must not be injected", removed)
		}
	}
}

// ============ match copied, thumbprints normalised, author's accept untouched ============

func TestBuildPolicyChain_MtlsAuth_CopiesMatchNormalisesThumbprints_LeavesAuthoredAcceptUntouched(t *testing.T) {
	authoredThumbprint := "SHA256:AA:BB:" + strings.Repeat("0", 60) // mixed-case + colons + prefix, 64 hex chars once normalised
	authoredMatch := map[string]interface{}{"uriSANs": []interface{}{"urn:partner-a:payments"}}
	authoredAccept := []interface{}{
		map[string]interface{}{
			"ca":          "auth-ca-a",
			"match":       authoredMatch,
			"thumbprints": []interface{}{authoredThumbprint},
		},
	}
	p := transformMtlsAuth(t, testRouterCfg(), map[string]interface{}{"accept": authoredAccept}, false)

	// The author's accept is not normalised.
	assert.Equal(t, authoredMatch, p.Params["accept"].([]interface{})[0].(map[string]interface{})["match"],
		"author's accept.match must be passed through as the same value, never rewritten")
	gotAuthoredThumbprints := p.Params["accept"].([]interface{})[0].(map[string]interface{})["thumbprints"].([]interface{})
	require.Len(t, gotAuthoredThumbprints, 1)
	assert.Equal(t, authoredThumbprint, gotAuthoredThumbprints[0], "the author-facing accept must keep the as-authored thumbprint form")

	// The engine-facing list carries the match and a normalised thumbprint.
	internalAccept := asInterfaceSlice(t, p.Params[mtlsInternalAcceptParam])
	require.Len(t, internalAccept, 1)
	internalEntry, ok := internalAccept[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "auth-ca-a", internalEntry["ca"])
	assert.Equal(t, authoredMatch, internalEntry["match"], "match must be copied through to the internal accept entry")

	wantNormalised := "aabb" + strings.Repeat("0", 60)
	gotThumbprints := asInterfaceSlice(t, internalEntry["thumbprints"])
	require.Len(t, gotThumbprints, 1)
	assert.Equal(t, wantNormalised, gotThumbprints[0])
}

// ============ No injection for other policies ============

func TestBuildPolicyChain_MtlsAuth_NoInjectionForOtherPolicies(t *testing.T) {
	defs := map[string]models.PolicyDefinition{
		"header-mutate|v1.0.0": {Name: "header-mutate", Version: "v1.0.0"},
	}
	transformer := NewRestAPITransformer(testRouterCfg(), &config.Config{}, defs)

	cfg := makeRestAPIStoredConfig([]api.Policy{{Name: "header-mutate", Version: ""}}, nil)

	rdc, err := transformer.Transform(cfg)
	require.NoError(t, err)
	p := findPolicy(rdc, mtlsAuthTestRouteKey, "header-mutate")
	require.NotNil(t, p)
	assert.Empty(t, internalParamKeys(p), "a non-mtls-auth policy must never get an internal mtls-auth param")
}

// ============ __wso2_internal_mtls_header ============

// __wso2_internal_mtls_header mirrors client_certificate_header exactly.
func TestBuildPolicyChain_MtlsAuth_HeaderParam_CarriesRouterConfig(t *testing.T) {
	routerCfg := testRouterCfg()
	routerCfg.DownstreamTLS.ClientCertificateHeader = config.ClientCertificateHeader{
		Name:             "X-Custom-Client-Cert",
		TrustAny:         true,
		ForwardToBackend: true,
	}
	p := transformMtlsAuth(t, routerCfg, nil, false)

	header, ok := p.Params[mtlsInternalHeaderParam].(map[string]interface{})
	require.Truef(t, ok, "expected %s to be a map[string]interface{}, got %T", mtlsInternalHeaderParam, p.Params[mtlsInternalHeaderParam])
	assert.Equal(t, "X-Custom-Client-Cert", header["name"])
	assert.Equal(t, true, header["trustAny"])
	assert.Equal(t, true, header["forwardToBackend"])
}

func TestBuildPolicyChain_MtlsAuth_ForwardCertificate_PassesThrough(t *testing.T) {
	p := transformMtlsAuth(t, testRouterCfg(), map[string]interface{}{
		"accept":             []interface{}{map[string]interface{}{"ca": "auth-ca-a"}},
		"forwardCertificate": false,
	}, false)
	assert.Equal(t, false, p.Params["forwardCertificate"])
}
