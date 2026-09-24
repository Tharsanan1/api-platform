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

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

// The mtls-auth policy runs inside the policy engine, which reads the
// gateway's client certificate authority pool from shared lazy resources
// (see utils.ClientAuthorityPublisher). A policy chain therefore carries no
// certificate material: only what this API's author wrote, in the form the
// engine evaluates, plus the router's client-certificate header settings.
// These keys are injected into every mtls-auth instance's params at
// chain-build time (see injectMtlsInternalParams) and must never be accepted
// from an author — the deploy validator (pkg/config/mtls_auth_validator.go)
// already rejects unknown params, and __wso2_internal_* is the existing
// convention for engine-internal parameters (see
// sdk/core/policy/v1alpha2/system_parameters.go).
const (
	// mtlsInternalAcceptParam is the policy's own `accept` param as an
	// ordered array of {"ca", "match"?, "thumbprints"?} objects, with each
	// thumbprint normalised to 64 lowercase hex. Absent when the author
	// omitted `accept`: the policy then accepts every client authority in the
	// pool, resolved against the pool it currently holds.
	mtlsInternalAcceptParam = "__wso2_internal_mtls_accept"

	// mtlsInternalHeaderParam is {"name", "trustAny", "forwardToBackend"},
	// mirroring router.downstream_tls.client_certificate_header — the
	// policy's only source of that config, since it runs outside the
	// controller process.
	mtlsInternalHeaderParam = "__wso2_internal_mtls_header"
)

// injectMtlsInternalParams mutates every mtls-auth PolicyInstance in chain in
// place, adding the __wso2_internal_mtls_* parameters above. A chain with no
// mtls-auth instance is left untouched.
func injectMtlsInternalParams(chain []policyenginev1.PolicyInstance, headerConfig config.ClientCertificateHeader) {
	header := map[string]interface{}{
		"name":             headerConfig.Name,
		"trustAny":         headerConfig.TrustAny,
		"forwardToBackend": headerConfig.ForwardToBackend,
	}

	for i := range chain {
		if chain[i].Name != config.MtlsAuthPolicyName {
			continue
		}
		if chain[i].Parameters == nil {
			chain[i].Parameters = map[string]interface{}{}
		}
		if accept, ok := engineAcceptEntries(chain[i].Parameters); ok {
			chain[i].Parameters[mtlsInternalAcceptParam] = accept
		}
		chain[i].Parameters[mtlsInternalHeaderParam] = header
	}
}

// engineAcceptEntries converts one mtls-auth instance's own `accept` param
// (params["accept"], as authored — untouched by this function) into the
// entries the policy engine evaluates: the authority name, the author's
// match copied through, and thumbprints normalised. ok is false when the
// author omitted `accept`, or supplied something that is not an array (the
// deploy validator already refuses that; the policy then treats the list as
// omitted, exactly as it would for a missing key).
func engineAcceptEntries(params map[string]interface{}) ([]interface{}, bool) {
	acceptSlice, ok := params["accept"].([]interface{})
	if !ok {
		return nil, false
	}

	result := make([]interface{}, 0, len(acceptSlice))
	for _, entryRaw := range acceptSlice {
		entryMap, ok := entryRaw.(map[string]interface{})
		if !ok {
			continue
		}
		caName, _ := entryMap["ca"].(string)
		entry := map[string]interface{}{"ca": strings.TrimSpace(caName)}
		if matchRaw, hasMatch := entryMap["match"]; hasMatch {
			entry["match"] = matchRaw
		}
		if tpRaw, hasThumbprints := entryMap["thumbprints"]; hasThumbprints {
			entry["thumbprints"] = normalizeThumbprintsForEngine(tpRaw)
		}
		result = append(result, entry)
	}
	return result, true
}

// normalizeThumbprintsForEngine canonicalises an author-supplied thumbprints
// array to 64 lowercase hex, reusing the same normaliser the deploy-response
// echo uses (config.NormalizeThumbprint) so the policy engine and the
// deploy-response view of an accept entry never disagree on the canonical
// form. An entry that fails to normalise (unreachable past deploy-time
// validation) is passed through unchanged rather than dropped.
func normalizeThumbprintsForEngine(raw interface{}) interface{} {
	tpSlice, ok := raw.([]interface{})
	if !ok {
		return raw
	}
	out := make([]interface{}, len(tpSlice))
	for i, tv := range tpSlice {
		s, _ := tv.(string)
		canonical, _, valid := config.NormalizeThumbprint(s)
		if !valid {
			out[i] = tv
			continue
		}
		out[i] = canonical
	}
	return out
}
