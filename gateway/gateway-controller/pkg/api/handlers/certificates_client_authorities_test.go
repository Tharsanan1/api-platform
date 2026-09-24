/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/lazyresourcexds"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/testutil/pki"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/utils"
)

// withClientAuthorityPublisher wires a real publisher over server's database
// into server and returns the lazy-resource manager it publishes through.
func withClientAuthorityPublisher(server *APIServer) *lazyresourcexds.LazyResourceStateManager {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store := storage.NewLazyResourceStore(logger)
	manager := lazyresourcexds.NewLazyResourceStateManager(store, lazyresourcexds.NewLazyResourceSnapshotManager(store, logger), logger)
	server.clientAuthorities = utils.NewClientAuthorityPublisher(server.db, manager)
	return manager
}

func publishedClientAuthorities(manager *lazyresourcexds.LazyResourceStateManager) []string {
	var names []string
	for name := range manager.GetResourcesByType(utils.LazyResourceTypeClientCertificateAuthority) {
		names = append(names, name)
	}
	return names
}

func postCertificate(t *testing.T, server *APIServer, name, usage string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(UploadCertificateRequest{
		Name:        name,
		Usage:       usage,
		Certificate: string(pki.NewRootCA(t, name).PEM()),
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	newUploadCertHandler(server).ServeHTTP(w, req)
	return w
}

func TestUploadCertificate_UsageClient_PublishesClientAuthorities(t *testing.T) {
	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{seedUpstreamCert(t)}
	server := createTestAPIServerWithCertStore(t, mockDB)
	manager := withClientAuthorityPublisher(server)

	w := postCertificate(t, server, "partner-root", models.CertificateUsageClient)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	assert.ElementsMatch(t, []string{"partner-root"}, publishedClientAuthorities(manager))
}

func TestUploadCertificate_UsageUpstream_PublishesNothing(t *testing.T) {
	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{seedUpstreamCert(t)}
	server := createTestAPIServerWithCertStore(t, mockDB)
	manager := withClientAuthorityPublisher(server)

	w := postCertificate(t, server, "another-upstream-ca", models.CertificateUsageUpstream)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	assert.Empty(t, publishedClientAuthorities(manager))
}

func TestDeleteCertificate_UsageClient_UnpublishesTheAuthority(t *testing.T) {
	mockDB := NewMockStorage()
	root := pki.NewRootCA(t, "Removed Partner Root")
	mockDB.certs = []*models.StoredCertificate{
		seedUpstreamCert(t),
		{UUID: "kept-id", Name: "kept", Certificate: pki.NewRootCA(t, "Kept Root").PEM(), Usage: models.CertificateUsageClient, NotAfter: time.Now().Add(time.Hour)},
		{UUID: "removed-id", Name: "removed", Certificate: root.PEM(), Usage: models.CertificateUsageClient, NotAfter: time.Now().Add(time.Hour)},
	}
	server := createTestAPIServerWithCertStore(t, mockDB)
	manager := withClientAuthorityPublisher(server)
	require.NoError(t, server.clientAuthorities.Publish(""))
	require.ElementsMatch(t, []string{"kept", "removed"}, publishedClientAuthorities(manager))

	w := httptest.NewRecorder()
	newDeleteCertHandler(server, "removed-id").ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/certificates/removed-id", nil))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	assert.ElementsMatch(t, []string{"kept"}, publishedClientAuthorities(manager))
}

func TestReloadCertificates_PublishesClientAuthorities(t *testing.T) {
	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{seedUpstreamCert(t)}
	server := createTestAPIServerWithCertStore(t, mockDB)
	manager := withClientAuthorityPublisher(server)

	// A row that reached the database without passing through this server's
	// upload handler becomes visible to the policy engine on reload.
	mockDB.certs = append(mockDB.certs, &models.StoredCertificate{
		UUID: "late-id", Name: "late", Certificate: pki.NewRootCA(t, "Late Root").PEM(),
		Usage: models.CertificateUsageClient, NotAfter: time.Now().Add(time.Hour),
	})

	handler := middleware.CorrelationIDMiddleware(server.logger)(http.HandlerFunc(server.ReloadCertificates))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/certificates/reload", nil))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	assert.ElementsMatch(t, []string{"late"}, publishedClientAuthorities(manager))
}

func TestUploadCertificate_UsageClient_PublishFailureIsReported(t *testing.T) {
	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{seedUpstreamCert(t)}
	server := createTestAPIServerWithCertStore(t, mockDB)
	server.clientAuthorities = utils.NewClientAuthorityPublisher(&failingCertificateList{MockStorage: mockDB}, nil)

	w := postCertificate(t, server, "partner-root", models.CertificateUsageClient)
	assert.Equal(t, http.StatusInternalServerError, w.Code, "body: %s", w.Body.String())
}

// failingCertificateList fails the pool listing the publisher performs, while
// every other storage call behaves as the embedded mock.
type failingCertificateList struct {
	*MockStorage
}

func (f *failingCertificateList) ListCertificatesByUsage(string) ([]*models.StoredCertificate, error) {
	return nil, storage.ErrDatabaseUnavailable
}
