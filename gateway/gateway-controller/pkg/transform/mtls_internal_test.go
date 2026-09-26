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

// ============ API-level and operation-level injection ============

// ============ The chain carries no certificate material ============

// ============ The author's accept is passed through unchanged ============

func TestBuildPolicyChain_MtlsAuth_LeavesAuthoredAcceptUntouched(t *testing.T) {
	authoredThumbprint := "SHA256:AA:BB:" + strings.Repeat("0", 60)
	authoredMatch := map[string]interface{}{"uriSANs": []interface{}{"urn:partner-a:payments"}}
	authoredAccept := []interface{}{
		map[string]interface{}{
			"ca":          "auth-ca-a",
			"match":       authoredMatch,
			"thumbprints": []interface{}{authoredThumbprint},
		},
	}
	p := transformMtlsAuth(t, testRouterCfg(), map[string]interface{}{"accept": authoredAccept}, false)

	entry := asInterfaceSlice(t, p.Params["accept"])[0].(map[string]interface{})
	assert.Equal(t, authoredMatch, entry["match"], "accept.match must be passed through as the same value, never rewritten")
	gotThumbprints := asInterfaceSlice(t, entry["thumbprints"])
	require.Len(t, gotThumbprints, 1)
	assert.Equal(t, authoredThumbprint, gotThumbprints[0], "accept keeps the as-authored thumbprint form; the policy normalises it")
}

// ============ No injection for other policies ============

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
