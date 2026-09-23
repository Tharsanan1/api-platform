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

// Best-effort scenario teardown shared by every mtls feature.
//
// API cleanup itself lives in steps_api.go's cleanupDeployedAPIs, driven by
// generic per-scenario tracking rather than a fixed name list — see
// RegisterMTLSSteps' After hook (steps_mtls.go) for the full ordering: APIs,
// then identities, then other certificates.
package it

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// cleanupDeleteRetryBudget/Interval bound deleteRetryingConflict: the
// certificate/identity referential-integrity check consults the
// controller's in-memory config store, which can still show a
// just-deleted API for a moment after cleanupDeployedAPIs' own delete call
// has already returned — it converges asynchronously. Retrying a 409 for a
// few seconds absorbs that window; anything else (including 404, already
// removed) is treated as done.
const (
	cleanupDeleteRetryBudget   = 5 * time.Second
	cleanupDeleteRetryInterval = 250 * time.Millisecond
)

// deleteRetryingConflict deletes the /certificates/{id} row (a plain
// certificate or a gateway identity — same endpoint either way), retrying
// while the delete returns 409 up to cleanupDeleteRetryBudget, then giving
// up. Best-effort throughout, like the cleanup functions that call it: this
// is scenario teardown, not an assertion, so the final outcome is never
// checked.
func (m *mtlsSteps) deleteRetryingConflict(id string) {
	deadline := time.Now().Add(cleanupDeleteRetryBudget)
	for {
		_ = m.httpSteps.SendDELETEToService("gateway-controller", "/certificates/"+id)
		resp := m.httpSteps.LastResponse()
		if resp == nil || resp.StatusCode != http.StatusConflict {
			return
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(cleanupDeleteRetryInterval)
	}
}

// cleanupTrackedCertificates deletes every gateway identity and plain
// certificate name this scenario attempted to upload, authenticating as
// admin regardless of which role the scenario last used (or cleared).
// Best-effort throughout: a name that was never actually pooled/stored
// (e.g. a rejected upload), or already removed by the scenario itself, is
// silently skipped, and no prior auth header state is restored afterwards.
// Identities are deleted before other certificates — a deployed API's tls
// block may reference an identity, while a plain certificate is independent
// of identities — by deleting from uploadedIdentityNames first.
func (m *mtlsSteps) cleanupTrackedCertificates() {
	if len(m.uploadedIdentityNames) == 0 && len(m.uploadedNames) == 0 {
		return
	}

	admin, ok := m.state.Config.Users["admin"]
	if !ok {
		return
	}
	creds := base64.StdEncoding.EncodeToString([]byte(admin.Username + ":" + admin.Password))
	m.httpSteps.SetHeader("Authorization", "Basic "+creds)

	if err := m.httpSteps.SendGETToService("gateway-controller", "/certificates"); err != nil {
		return
	}
	var parsed struct {
		Certificates []map[string]any `json:"certificates"`
	}
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return
	}

	idByName := make(map[string]string, len(parsed.Certificates))
	for _, item := range parsed.Certificates {
		idByName[fmt.Sprint(item["name"])] = fmt.Sprint(item["id"])
	}

	deleteTracked := func(names []string) {
		for _, name := range names {
			id, ok := idByName[name]
			if !ok {
				continue
			}
			// Best-effort: ignore the outcome, including 404s for a
			// certificate already removed by the scenario itself; a
			// transient 409 (the referential-integrity check racing
			// config-store convergence) is retried by
			// deleteRetryingConflict rather than given up on immediately.
			m.deleteRetryingConflict(id)
		}
	}
	deleteTracked(m.uploadedIdentityNames)
	deleteTracked(m.uploadedNames)
}
