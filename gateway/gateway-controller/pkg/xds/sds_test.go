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

package xds

import (
	"os"
	"path/filepath"
	"testing"

	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/certstore"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/testutil/pki"
)

// fakeSDSStorage is a minimal storage.Storage stand-in for GetSecrets tests:
// it only overrides the two certificate-listing methods GetSecrets' call
// chain actually reaches (ListCertificates via LoadCertificates for the
// upstream bundle, ListCertificatesByUsage via GetClientCABundle for the
// client-CA pool) — any other method would nil-pointer-panic if called,
// which is fine since neither path reaches them. Mirrors
// pkg/certstore's own fakeCertificateStorage.
type fakeSDSStorage struct {
	storage.Storage
	certs []*models.StoredCertificate
}

func (f *fakeSDSStorage) ListCertificates() ([]*models.StoredCertificate, error) {
	return f.certs, nil
}

func (f *fakeSDSStorage) ListCertificatesByUsage(usage string) ([]*models.StoredCertificate, error) {
	var filtered []*models.StoredCertificate
	for _, cert := range f.certs {
		effective := cert.Usage
		if effective == "" {
			effective = models.CertificateUsageUpstream
		}
		if effective == usage {
			filtered = append(filtered, cert)
		}
	}
	return filtered, nil
}

// secretsByName indexes a GetSecrets result by name for convenient lookup in
// assertions below.
func secretsByName(t *testing.T, secrets []types.Resource) map[string]*tlsv3.Secret {
	t.Helper()
	out := make(map[string]*tlsv3.Secret, len(secrets))
	for _, res := range secrets {
		s, ok := res.(*tlsv3.Secret)
		require.True(t, ok, "GetSecrets returned a non-Secret resource: %T", res)
		out[s.GetName()] = s
	}
	return out
}

// writeListenerCertFiles writes a freshly generated cert/key pair to temp
// files and returns their paths, for SetDownstreamListenerCert.
func writeListenerCertFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	entity := pki.NewSelfSignedLeaf(t, "listener")
	dir := t.TempDir()
	certPath = filepath.Join(dir, "listener.crt")
	keyPath = filepath.Join(dir, "listener.key")
	require.NoError(t, os.WriteFile(certPath, entity.PEM(), 0o600))
	require.NoError(t, os.WriteFile(keyPath, entity.KeyPEM(), 0o600))
	return certPath, keyPath
}

func TestSDSSecretManager_GetSecrets_UpstreamAndClientRows_HTTPSEnabled(t *testing.T) {
	logger := createTestLogger()
	upstreamCert := pki.NewRootCA(t, "SDS Upstream CA")
	clientCert := pki.NewRootCA(t, "SDS Client CA")

	db := &fakeSDSStorage{certs: []*models.StoredCertificate{
		{UUID: "upstream-1", Name: "upstream-ca", Certificate: upstreamCert.PEM(), Usage: models.CertificateUsageUpstream},
		{UUID: "client-1", Name: "client-ca", Certificate: clientCert.PEM(), Usage: models.CertificateUsageClient},
	}}
	cs := certstore.NewCertStore(logger, db, "", "")
	_, err := cs.LoadCertificates()
	require.NoError(t, err)

	certPath, keyPath := writeListenerCertFiles(t)
	sm := NewSDSSecretManager(cs, nil, "test-node", logger)
	sm.SetDownstreamListenerCert(certPath, keyPath, true)

	secrets, err := sm.GetSecrets()
	require.NoError(t, err)
	require.Len(t, secrets, 3, "expected upstream_ca_bundle, downstream_client_ca and downstream_listener_cert")

	byName := secretsByName(t, secrets)
	assert.Contains(t, byName, SecretNameUpstreamCA)
	assert.Contains(t, byName, SecretNameDownstreamClientCA)
	assert.Contains(t, byName, SecretNameDownstreamListenerCert)

	// downstream_client_ca: a ValidationContext whose TrustedCa carries only
	// the client PEM (never the upstream one), with ACCEPT_UNTRUSTED so a
	// failed chain-verification degrades to mtls-auth's own evaluation
	// instead of aborting the TLS handshake.
	clientSecret := byName[SecretNameDownstreamClientCA]
	validationCtx, ok := clientSecret.GetType().(*tlsv3.Secret_ValidationContext)
	require.True(t, ok, "downstream_client_ca must be a Secret_ValidationContext, got %T", clientSecret.GetType())
	trustedCA := string(validationCtx.ValidationContext.GetTrustedCa().GetInlineBytes())
	assert.Contains(t, trustedCA, string(clientCert.PEM()))
	assert.NotContains(t, trustedCA, string(upstreamCert.PEM()))
	assert.Equal(t, tlsv3.CertificateValidationContext_ACCEPT_UNTRUSTED, validationCtx.ValidationContext.GetTrustChainVerification())

	// upstream_ca_bundle must never carry the client-CA pool's certificate.
	upstreamSecret := byName[SecretNameUpstreamCA]
	upstreamValidationCtx, ok := upstreamSecret.GetType().(*tlsv3.Secret_ValidationContext)
	require.True(t, ok, "upstream_ca_bundle must be a Secret_ValidationContext, got %T", upstreamSecret.GetType())
	upstreamTrustedCA := string(upstreamValidationCtx.ValidationContext.GetTrustedCa().GetInlineBytes())
	assert.Contains(t, upstreamTrustedCA, string(upstreamCert.PEM()))
	assert.NotContains(t, upstreamTrustedCA, string(clientCert.PEM()))
}

func TestSDSSecretManager_GetSecrets_NoClientRows_ClientCASecretAbsent(t *testing.T) {
	logger := createTestLogger()
	upstreamCert := pki.NewRootCA(t, "SDS Upstream Only CA")

	db := &fakeSDSStorage{certs: []*models.StoredCertificate{
		{UUID: "upstream-1", Name: "upstream-ca", Certificate: upstreamCert.PEM(), Usage: models.CertificateUsageUpstream},
	}}
	cs := certstore.NewCertStore(logger, db, "", "")
	_, err := cs.LoadCertificates()
	require.NoError(t, err)

	certPath, keyPath := writeListenerCertFiles(t)
	sm := NewSDSSecretManager(cs, nil, "test-node", logger)
	sm.SetDownstreamListenerCert(certPath, keyPath, true)

	secrets, err := sm.GetSecrets()
	require.NoError(t, err)

	byName := secretsByName(t, secrets)
	assert.Contains(t, byName, SecretNameUpstreamCA)
	assert.Contains(t, byName, SecretNameDownstreamListenerCert)
	assert.NotContains(t, byName, SecretNameDownstreamClientCA, "an empty client-CA pool must omit the secret, not error")
}

func TestSDSSecretManager_GetSecrets_HTTPSEnabled_UnreadableListenerCert_Errors(t *testing.T) {
	logger := createTestLogger()
	db := &fakeSDSStorage{}
	cs := certstore.NewCertStore(logger, db, "", "")

	sm := NewSDSSecretManager(cs, nil, "test-node", logger)
	sm.SetDownstreamListenerCert("/nonexistent/does-not-exist.crt", "/nonexistent/does-not-exist.key", true)

	_, err := sm.GetSecrets()
	assert.Error(t, err, "a failed listener-cert read must fail the whole snapshot, not be silently omitted")
}

func TestSDSSecretManager_GetSecrets_HTTPSDisabled_NoListenerSecretNoError(t *testing.T) {
	logger := createTestLogger()
	db := &fakeSDSStorage{}
	cs := certstore.NewCertStore(logger, db, "", "")

	sm := NewSDSSecretManager(cs, nil, "test-node", logger)
	// Deliberately invalid paths: httpsEnabled false must mean these are never read.
	sm.SetDownstreamListenerCert("/nonexistent/does-not-exist.crt", "/nonexistent/does-not-exist.key", false)

	secrets, err := sm.GetSecrets()
	require.NoError(t, err)

	byName := secretsByName(t, secrets)
	assert.NotContains(t, byName, SecretNameDownstreamListenerCert)
}

// TestCertStore_GetClientCABundle_OnlyClientRows guards that the client-CA
// pool bundle never includes an upstream-usage row, mirroring
// TestCertStore_ExcludesClientUsageFromCombinedBundle's guarantee in the
// other direction.
func TestCertStore_GetClientCABundle_OnlyClientRows(t *testing.T) {
	logger := createTestLogger()
	upstreamCert := pki.NewRootCA(t, "Bundle Split Upstream CA")
	clientCert := pki.NewRootCA(t, "Bundle Split Client CA")

	db := &fakeSDSStorage{certs: []*models.StoredCertificate{
		{UUID: "upstream-1", Name: "upstream-ca", Certificate: upstreamCert.PEM(), Usage: models.CertificateUsageUpstream},
		{UUID: "client-1", Name: "client-ca", Certificate: clientCert.PEM(), Usage: models.CertificateUsageClient},
	}}
	cs := certstore.NewCertStore(logger, db, "", "")

	bundle, err := cs.GetClientCABundle()
	require.NoError(t, err)

	bundleStr := string(bundle)
	assert.Contains(t, bundleStr, string(clientCert.PEM()))
	assert.NotContains(t, bundleStr, string(upstreamCert.PEM()))
}
