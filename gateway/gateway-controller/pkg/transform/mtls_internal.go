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
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

// mtlsInternalHeaderParam is injected into every mtls-auth instance at
// chain-build time. It mirrors client_certificate_header, which the policy
// cannot read from the controller's config. The policy engine reads the
// client authority pool from shared lazy resources and the author's own
// accept list from the instance, so this is the only injected key.
const mtlsInternalHeaderParam = "__wso2_internal_mtls_header"

// injectMtlsInternalParams adds the __wso2_internal_mtls_header parameter to
// every mtls-auth instance in chain, in place.
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
		chain[i].Parameters[mtlsInternalHeaderParam] = header
	}
}
