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

// Parameters injected into every mtls-auth instance at chain-build time. The
// policy engine reads the client authority pool from shared lazy resources,
// so a chain carries only the author's accept list and the router's
// client-certificate header settings. Authors can never supply these keys.
const (
	// mtlsInternalAcceptParam is the policy's accept list with thumbprints
	// normalised. Absent when accept was omitted, so the whole pool applies.
	mtlsInternalAcceptParam = "__wso2_internal_mtls_accept"

	// mtlsInternalHeaderParam mirrors client_certificate_header, which the
	// policy cannot read from the controller's config.
	mtlsInternalHeaderParam = "__wso2_internal_mtls_header"
)

// injectMtlsInternalParams adds the __wso2_internal_mtls_* parameters to every
// mtls-auth instance in chain, in place.
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

// engineAcceptEntries converts an instance's accept param into the entries
// the policy engine evaluates, normalising thumbprints. ok is false when
// accept is absent or not an array.
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

// normalizeThumbprintsForEngine canonicalises a thumbprints array with the
// same normaliser as the deploy response. An entry that fails to normalise
// passes through unchanged rather than being dropped.
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
