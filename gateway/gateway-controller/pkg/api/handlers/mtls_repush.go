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

package handlers

import (
	"log/slog"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// repushMtlsAuthDeployments re-pushes the policy chain of every deployed
// RestAPI that attaches mtls-auth (API level or operation level), so an API
// that inherits the client-CA pool — an omitted `accept`, or an accept entry
// naming a pool authority — sees the change on its very next request. Called
// from UploadCertificate/DeleteCertificate after a usage: client certificate
// change commits; an upstream-trust (usage: upstream) certificate change
// never calls this, since only the client-CA pool feeds mtls-auth's resolved
// certificate material (pkg/transform's chain-build-time injection).
//
// UpsertAPIConfig re-runs the transformer, which re-resolves
// __wso2_internal_mtls_accept/__wso2_internal_mtls_pool from the store's
// current state — this function only needs to decide which deployed APIs to
// re-run it for.
//
// Best-effort: a failure re-pushing one API is logged and does not stop the
// others, and never surfaces back to the certificate request itself — the
// certificate change already committed successfully by the time this runs.
func (s *APIServer) repushMtlsAuthDeployments(log *slog.Logger) {
	if s.store == nil || s.policyManager == nil {
		return
	}
	for _, cfg := range s.store.GetAllByKind(string(models.KindRestApi)) {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		if !config.HasMtlsAuthAttached(&restCfg) {
			continue
		}
		if err := s.policyManager.UpsertAPIConfig(cfg); err != nil {
			log.Error("Failed to re-push policy chain after client-CA pool change",
				slog.String("handle", cfg.Handle),
				slog.Any("error", err))
		}
	}
}
