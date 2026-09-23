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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/policyxds"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/testutil/pki"
)

// spyConfigTransformer is a minimal models.ConfigTransformer that records
// every cfg.Handle it was asked to transform, and returns an otherwise-empty
// (but resolution-valid) RuntimeDeployConfig — this test only needs to know
// *which* APIs repushMtlsAuthDeployments re-transformed, not what a real
// transform produces.
type spyConfigTransformer struct {
	mu        sync.Mutex
	handles   []string
	transform func(cfg *models.StoredConfig) (*models.RuntimeDeployConfig, error)
}

func (s *spyConfigTransformer) Transform(cfg *models.StoredConfig) (*models.RuntimeDeployConfig, error) {
	s.mu.Lock()
	s.handles = append(s.handles, cfg.Handle)
	s.mu.Unlock()
	if s.transform != nil {
		return s.transform(cfg)
	}
	return &models.RuntimeDeployConfig{Metadata: models.Metadata{UUID: cfg.UUID, Kind: cfg.Kind}}, nil
}

func (s *spyConfigTransformer) calledFor(handle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.handles {
		if h == handle {
			return true
		}
	}
	return false
}

// wireMtlsRepushPolicyManager attaches a working, in-memory *policyxds.PolicyManager
// to server (runtime store + policy-chain snapshot cache, exactly like
// TestGetXDSSyncStatusWithPolicyVersion wires it) with transformer swapped
// for the spy above, so repushMtlsAuthDeployments's calls to
// policyManager.UpsertAPIConfig are both real (exercise AddRuntimeConfig,
// ValidateResolution, and the snapshot cache) and observable.
func wireMtlsRepushPolicyManager(server *APIServer) *spyConfigTransformer {
	runtimeStore := storage.NewRuntimeConfigStore()
	snapshotMgr := policyxds.NewSnapshotManager(server.logger)
	snapshotMgr.SetRuntimeStore(runtimeStore)
	server.policyManager = policyxds.NewPolicyManager(snapshotMgr, server.logger)
	server.policyManager.SetRuntimeStore(runtimeStore)

	spy := &spyConfigTransformer{}
	server.policyManager.SetTransformers(spy)
	return spy
}

// restAPIConfig builds a minimal RestApi StoredConfig, optionally attaching
// mtls-auth at operation level, matching what repushMtlsAuthDeployments reads:
// cfg.Configuration must be an api.RestAPI value (not a pointer), and
// config.HasMtlsAuthAttached inspects its spec.policies / operation policies.
func restAPIConfig(handle string, attachMtlsAuth bool) *models.StoredConfig {
	var opPolicies *[]api.Policy
	if attachMtlsAuth {
		opPolicies = &[]api.Policy{{Name: "mtls-auth", Version: "v1"}}
	}
	cfg := api.RestAPI{
		Kind:     api.RestAPIKindRestApi,
		Metadata: api.Metadata{Name: handle},
		Spec: api.APIConfigData{
			DisplayName: handle,
			Version:     "v1.0",
			Context:     "/" + handle,
			Operations: []api.Operation{
				{Method: api.Ptr(api.OperationMethodGET), Path: api.Ptr("/resource"), Policies: opPolicies},
			},
			Upstream: struct {
				Main    api.Upstream  `json:"main" yaml:"main"`
				Sandbox *api.Upstream `json:"sandbox,omitempty" yaml:"sandbox,omitempty"`
			}{
				Main: api.Upstream{Url: api.Ptr("http://backend:8080")},
			},
		},
	}
	return &models.StoredConfig{
		UUID:          handle,
		Kind:          models.KindRestApi,
		Handle:        handle,
		DisplayName:   handle,
		Version:       "v1.0",
		DesiredState:  models.StateDeployed,
		Configuration: cfg,
	}
}

// uploadClientCert POSTs a usage: client (or usage: upstream, per usage)
// certificate to /certificates and returns the response recorder.
func uploadClientCertOrUpstream(t *testing.T, server *APIServer, name, usage string) *httptest.ResponseRecorder {
	t.Helper()
	handler := newUploadCertHandler(server)
	root := pki.NewRootCA(t, name)
	reqBody := UploadCertificateRequest{
		Name:        name,
		Usage:       usage,
		Certificate: string(root.PEM()),
	}
	bodyBytes, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/certificates", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// TestUploadCertificate_UsageClient_RepushesOnlyMTLSAuthDeployments guards
// repushMtlsAuthDeployments' actual selection logic end-to-end, through the
// real UploadCertificate handler: uploading a usage: client certificate must
// re-push (transform + restore into the runtime store) every deployed RestApi
// that attaches mtls-auth, and must never touch one that doesn't.
func TestUploadCertificate_UsageClient_RepushesOnlyMTLSAuthDeployments(t *testing.T) {
	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{seedUpstreamCert(t)}

	server := createTestAPIServerWithCertStore(t, mockDB)
	spy := wireMtlsRepushPolicyManager(server)

	require.NoError(t, server.store.Add(restAPIConfig("mtls-api", true)))
	require.NoError(t, server.store.Add(restAPIConfig("plain-api", false)))

	w := uploadClientCertOrUpstream(t, server, "pool-partner-client", models.CertificateUsageClient)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	if !spy.calledFor("mtls-api") {
		t.Error("expected repushMtlsAuthDeployments to re-transform the mtls-auth-attached API, but it did not")
	}
	if spy.calledFor("plain-api") {
		t.Error("expected repushMtlsAuthDeployments to leave the non-mtls-auth API alone, but it re-transformed it")
	}
}

// TestUploadCertificate_UsageUpstream_DoesNotRepush guards the other half of
// the same contract: an upstream-trust certificate change never feeds
// mtls-auth's resolved material (only the client-CA pool does), so it must
// never trigger a re-push at all, even when a deployed API attaches
// mtls-auth.
func TestUploadCertificate_UsageUpstream_DoesNotRepush(t *testing.T) {
	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{seedUpstreamCert(t)}

	server := createTestAPIServerWithCertStore(t, mockDB)
	spy := wireMtlsRepushPolicyManager(server)

	require.NoError(t, server.store.Add(restAPIConfig("mtls-api", true)))

	w := uploadClientCertOrUpstream(t, server, "another-upstream-ca", models.CertificateUsageUpstream)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	if spy.calledFor("mtls-api") {
		t.Error("expected an upstream-usage certificate upload to never trigger a re-push, but it did")
	}
}
