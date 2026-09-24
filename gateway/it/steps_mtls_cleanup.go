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

package it

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// cleanupDeleteRetryBudget and cleanupDeleteRetryInterval bound the 409
// retries in deleteRetryingConflict. The controller's reference check can
// still see a just-deleted API briefly, because its config store converges
// asynchronously.
const (
	cleanupDeleteRetryBudget   = 5 * time.Second
	cleanupDeleteRetryInterval = 25 * time.Millisecond
)

// deleteRetryingConflict deletes a certificate or gateway identity, retrying
// on 409 until cleanupDeleteRetryBudget runs out. The outcome is not checked.
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

// cleanupTrackedCertificates deletes, as admin, every gateway identity and
// certificate this scenario attempted to upload. Names that were never
// stored are skipped, and the previous auth header is not restored.
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
			m.deleteRetryingConflict(id)
		}
	}
	deleteTracked(m.uploadedIdentityNames)
	deleteTracked(m.uploadedNames)
}
