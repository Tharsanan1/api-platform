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
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"testing"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/constants"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/metrics"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/testutil/pki"
	"google.golang.org/protobuf/proto"
)

const (
	testDefaultIdentityName = "gateway-default"
	testNamedIdentityName   = "partner-identity"
	testBackendCAName       = "backend-ca"
)

// fixedTransformer returns a prepared RuntimeDeployConfig per config UUID.
type fixedTransformer map[string]*models.RuntimeDeployConfig

func (f fixedTransformer) Transform(cfg *models.StoredConfig) (*models.RuntimeDeployConfig, error) {
	rdc, ok := f[cfg.UUID]
	if !ok {
		return nil, fmt.Errorf("no runtime config for %s", cfg.UUID)
	}
	return rdc, nil
}

// upstreamShapesRDC covers every upstream shape an API kind produces: inline
// main and sandbox upstreams and definitions with no tls block, a
// multi-endpoint definition, a tls block with only trustedCAs, a tls block
// naming an identity, and a plain HTTP upstream.
func upstreamShapesRDC(handle string) *models.RuntimeDeployConfig {
	https := func() *models.UpstreamTLS { return &models.UpstreamTLS{Enabled: true} }
	clusters := map[string]*models.UpstreamCluster{
		handle + "_main": {Endpoints: []models.Endpoint{{Host: "main.backend", Port: 443}}, TLS: https()},
		handle + "_sandbox": {Endpoints: []models.Endpoint{{Host: "sandbox.backend", Port: 443}},
			TLS: https()},
		handle + "_def_plain": {Name: "plain", Endpoints: []models.Endpoint{{Host: "plain.backend", Port: 443}},
			TLS: https()},
		handle + "_def_weighted": {Name: "weighted",
			Endpoints: []models.Endpoint{{Host: "w1.backend", Port: 443}, {Host: "w2.backend", Port: 443}},
			TLS:       https()},
		handle + "_def_trusted": {Name: "trusted", Endpoints: []models.Endpoint{{Host: "trusted.backend", Port: 443}},
			TLS: &models.UpstreamTLS{Enabled: true, HasTLSBlock: true, TrustedCANames: []string{testBackendCAName}, VerifyHostName: true}},
		handle + "_def_identity": {Name: "identity", Endpoints: []models.Endpoint{{Host: "identity.backend", Port: 443}},
			TLS: &models.UpstreamTLS{Enabled: true, HasTLSBlock: true, IdentityName: testNamedIdentityName, VerifyHostName: true}},
		handle + "_http": {Endpoints: []models.Endpoint{{Host: "http.backend", Port: 80}},
			TLS: &models.UpstreamTLS{}},
	}
	return &models.RuntimeDeployConfig{
		Metadata:         models.Metadata{Handle: handle},
		UpstreamClusters: clusters,
		Routes: map[string]*models.Route{
			"GET|/" + handle + "|localhost": {
				Method: "GET", Path: "/" + handle, OperationPath: "/",
				Upstream: models.RouteUpstream{ClusterKey: handle + "_main"},
			},
		},
	}
}

// apiKinds are the kinds whose upstreams carry API traffic.
var apiKinds = []string{models.KindRestApi, models.KindAgent, models.KindLlmProvider, models.KindLlmProxy, models.KindMcp}

// defaultIdentityTestCase builds a translator over every API kind.
type defaultIdentityTestCase struct {
	presentDefault bool
	httpsEnabled   bool
	defaultExists  bool
	logs           *bytes.Buffer
}

func (tc defaultIdentityTestCase) storage(t *testing.T) *fakeSDSStorage {
	t.Helper()
	certs := []*models.StoredCertificate{
		{UUID: "ca-1", Name: testBackendCAName, Certificate: pki.NewRootCA(t, "Backend CA").PEM(), Usage: models.CertificateUsageUpstream},
		{UUID: "named-1", Name: testNamedIdentityName, Certificate: pki.NewSelfSignedLeaf(t, "partner").PEM(),
			Usage: models.CertificateUsageIdentity, Role: models.CertificateRoleClient},
	}
	if tc.defaultExists {
		certs = append(certs, &models.StoredCertificate{
			UUID: "default-1", Name: testDefaultIdentityName, Certificate: pki.NewSelfSignedLeaf(t, "gateway").PEM(),
			Usage: models.CertificateUsageIdentity, Role: models.CertificateRoleDefault,
		})
	}
	return &fakeSDSStorage{certs: certs}
}

func (tc defaultIdentityTestCase) translator(t *testing.T, db storage.Storage) *Translator {
	t.Helper()
	routerCfg := testRouterConfig()
	routerCfg.Upstream.TLS.DisableSslVerification = false
	routerCfg.Upstream.TLS.PresentDefaultIdentity = tc.presentDefault
	routerCfg.HTTPSEnabled = tc.httpsEnabled
	routerCfg.HTTPSPort = 8443
	routerCfg.DownstreamTLS.CertPath, routerCfg.DownstreamTLS.KeyPath = writeListenerCertFiles(t)
	// Internal clusters: a TLS policy engine, the access log collector and
	// the tracing collector.
	routerCfg.PolicyEngine = config.PolicyEngineConfig{Mode: "tcp", Host: "policy-engine", Port: 9001,
		TLS: config.PolicyEngineTLS{Enabled: true, CertPath: "/certs/pe.crt", KeyPath: "/certs/pe.key", CAPath: "/certs/ca.crt"}}
	cfg := testConfig()
	cfg.Router = *routerCfg
	cfg.Analytics.Enabled = true
	cfg.Collector.Server = config.GRPCEventServerConfig{
		Mode:                "uds",
		BufferFlushInterval: 1000000000,
		BufferSizeBytes:     16384,
		GRPCRequestTimeout:  20000000000,
	}
	cfg.TracingConfig.Enabled = true

	logger := createTestLogger()
	if tc.logs != nil {
		logger = slog.New(slog.NewTextHandler(tc.logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	translator, err := NewTranslator(logger, routerCfg, db, cfg)
	require.NoError(t, err)

	transformers := map[string]models.ConfigTransformer{}
	fixed := fixedTransformer{}
	for _, kind := range apiKinds {
		fixed[strings.ToLower(kind)] = upstreamShapesRDC(strings.ToLower(kind))
		transformers[kind] = fixed
	}
	translator.SetTransformers(transformers)
	return translator
}

func apiConfigsOfEveryKind() []*models.StoredConfig {
	configs := make([]*models.StoredConfig, 0, len(apiKinds))
	for _, kind := range apiKinds {
		configs = append(configs, &models.StoredConfig{UUID: strings.ToLower(kind), Kind: kind, DesiredState: models.StateDeployed})
	}
	return configs
}

// clientCertSecrets maps each cluster to the SDS secrets it presents as a
// client certificate, sorted and deduplicated across its endpoints.
func clientCertSecrets(t *testing.T, clusters []types.Resource) map[string][]string {
	t.Helper()
	out := make(map[string][]string, len(clusters))
	for _, res := range clusters {
		c := res.(*cluster.Cluster)
		seen := map[string]bool{}
		var sockets []*core.TransportSocket
		for _, tsm := range c.GetTransportSocketMatches() {
			sockets = append(sockets, tsm.GetTransportSocket())
		}
		if c.GetTransportSocket() != nil {
			sockets = append(sockets, c.GetTransportSocket())
		}
		for _, socket := range sockets {
			var tlsCtx tlsv3.UpstreamTlsContext
			require.NoError(t, socket.GetTypedConfig().UnmarshalTo(&tlsCtx))
			for _, sds := range tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs() {
				seen[sds.GetName()] = true
			}
		}
		names := make([]string, 0, len(seen))
		for name := range seen {
			names = append(names, name)
		}
		sort.Strings(names)
		out[c.GetName()] = names
	}
	return out
}

// expectedClientCertSecrets is what every API kind's clusters present when
// clusters without a tls identity present defaultSecret ("" for none).
func expectedClientCertSecrets(defaultSecret string) map[string][]string {
	var withDefault []string
	if defaultSecret != "" {
		withDefault = []string{defaultSecret}
	}
	want := map[string][]string{
		constants.PolicyEngineClusterName:  {},
		constants.GRPCAccessLogClusterName: {},
		OTELCollectorClusterName:           {},
	}
	for _, kind := range apiKinds {
		handle := strings.ToLower(kind)
		for _, suffix := range []string{"_main", "_sandbox", "_def_plain", "_def_weighted", "_def_trusted"} {
			want[handle+suffix] = append([]string{}, withDefault...)
		}
		want[handle+"_def_identity"] = []string{GatewayIdentitySecretName(testNamedIdentityName)}
		want[handle+"_http"] = []string{}
	}
	return normalizeSecrets(want)
}

func normalizeSecrets(in map[string][]string) map[string][]string {
	for name, secrets := range in {
		if secrets == nil {
			in[name] = []string{}
		}
	}
	return in
}

func translateEveryKind(t *testing.T, translator *Translator) map[resource.Type][]types.Resource {
	t.Helper()
	resources, err := translator.TranslateConfigs(apiConfigsOfEveryKind(), "")
	require.NoError(t, err)
	return resources
}

func TestDefaultClientCertificate_Selection(t *testing.T) {
	tests := []struct {
		name          string
		tc            defaultIdentityTestCase
		defaultSecret string
	}{
		{name: "switch off", tc: defaultIdentityTestCase{httpsEnabled: true, defaultExists: true}, defaultSecret: ""},
		{name: "default identity", tc: defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true},
			defaultSecret: GatewayIdentitySecretName(testDefaultIdentityName)},
		{name: "default identity with HTTPS disabled", tc: defaultIdentityTestCase{presentDefault: true, defaultExists: true},
			defaultSecret: GatewayIdentitySecretName(testDefaultIdentityName)},
		{name: "no default identity", tc: defaultIdentityTestCase{presentDefault: true, httpsEnabled: true},
			defaultSecret: SecretNameDownstreamListenerCert},
		{name: "no default identity and HTTPS disabled", tc: defaultIdentityTestCase{presentDefault: true},
			defaultSecret: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			translator := tt.tc.translator(t, tt.tc.storage(t))
			resources := translateEveryKind(t, translator)

			got := normalizeSecrets(clientCertSecrets(t, resources[resource.ClusterType]))
			assert.Equal(t, expectedClientCertSecrets(tt.defaultSecret), got)
		})
	}
}

// With the switch off, neither a default identity nor the HTTPS listener
// changes a single cluster.
func TestDefaultClientCertificate_SwitchOff_ClustersUnchanged(t *testing.T) {
	baselineCase := defaultIdentityTestCase{}
	baseline := translateEveryKind(t, baselineCase.translator(t, baselineCase.storage(t)))[resource.ClusterType]

	for _, tc := range []defaultIdentityTestCase{
		{defaultExists: true},
		{httpsEnabled: true},
		{httpsEnabled: true, defaultExists: true},
	} {
		got := translateEveryKind(t, tc.translator(t, tc.storage(t)))[resource.ClusterType]
		require.Len(t, got, len(baseline))
		byName := map[string]types.Resource{}
		for _, res := range got {
			byName[res.(*cluster.Cluster).GetName()] = res
		}
		for _, want := range baseline {
			name := want.(*cluster.Cluster).GetName()
			assert.True(t, proto.Equal(want, byName[name]), "cluster %s changed with the switch off (%+v)", name, tc)
		}
	}
}

// Only a cluster built for API traffic can present the default client
// certificate: a nil tlsOpts marks one that is not.
func TestDefaultClientCertificate_NotPresentedWithoutAPIWiring(t *testing.T) {
	tc := defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true}
	translator := tc.translator(t, tc.storage(t))
	translateEveryKind(t, translator)
	require.NotEmpty(t, translator.defaultClientCert.SecretName)

	tlsCtx, err := translator.createUpstreamTLSContext(nil, "hub.internal", nil, "")
	require.NoError(t, err)
	assert.Empty(t, tlsCtx.GetCommonTlsContext().GetTlsCertificateSdsSecretConfigs())
}

// The fallback translation path does not honour tls blocks, so its clusters
// never present the default client certificate.
func TestDefaultClientCertificate_NotPresentedOnFallbackPath(t *testing.T) {
	tc := defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true}
	translator := tc.translator(t, tc.storage(t))
	translator.SetTransformers(nil)

	restAPI := makeRestAPI("fallback-1", "fallback-api", "/fallback")
	restCfg := restAPI.Configuration.(api.RestAPI)
	restCfg.Spec.Upstream.Main.Url = api.Ptr("https://fallback.backend:8443")
	restAPI.Configuration = restCfg

	resources, err := translator.TranslateConfigs([]*models.StoredConfig{restAPI}, "")
	require.NoError(t, err)
	secrets := clientCertSecrets(t, resources[resource.ClusterType])
	var sawHTTPSCluster bool
	for name, presented := range secrets {
		if strings.Contains(name, "fallback") {
			sawHTTPSCluster = true
			assert.Empty(t, presented, "cluster %s", name)
		}
	}
	require.True(t, sawHTTPSCluster, "expected a cluster for the fallback API, got %v", secrets)
}

// Every secret a cluster presents is in the SDS secrets the snapshot keeps.
func TestDefaultClientCertificate_SecretsServedWhenReferenced(t *testing.T) {
	for _, tc := range []defaultIdentityTestCase{
		{presentDefault: true, httpsEnabled: true, defaultExists: true},
		{presentDefault: true, httpsEnabled: true},
		{presentDefault: true, defaultExists: true},
	} {
		db := tc.storage(t)
		mgr := testXDSEncryptionManager(t)
		for _, cert := range db.certs {
			if cert.Usage == models.CertificateUsageIdentity {
				cert.PrivateKeyCiphertext = encryptForStorage(t, mgr, []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"))
			}
		}
		translator := tc.translator(t, db)
		translator.certStore.SetEncryptionManager(mgr)
		resources := translateEveryKind(t, translator)

		sds := NewSDSSecretManager(translator.certStore, nil, "router-node", createTestLogger(),
			translator.routerConfig.DownstreamTLS.CertPath, translator.routerConfig.DownstreamTLS.KeyPath, tc.httpsEnabled)
		secrets, err := sds.GetSecrets(translator.GetUpstreamTLSSecretRefs())
		require.NoError(t, err)
		served := secretsByName(t, secrets)

		for clusterName, names := range clientCertSecrets(t, resources[resource.ClusterType]) {
			for _, name := range names {
				_, ok := served[name]
				assert.True(t, ok, "cluster %s presents %s, which SDS does not serve (%+v)", clusterName, name, tc)
				assert.True(t, SnapshotReferencesSDSSecret(resources[resource.ClusterType], resources[resource.ListenerType], name))
			}
		}
	}
}

// The default identity secret is kept in the snapshot only while a cluster
// presents it, and deleting the identity falls back to the listener
// certificate.
func TestDefaultClientCertificate_SnapshotFollowsDefaultIdentity(t *testing.T) {
	tc := defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true}
	db := tc.storage(t)
	mgr := testXDSEncryptionManager(t)
	for _, cert := range db.certs {
		if cert.Usage == models.CertificateUsageIdentity {
			cert.PrivateKeyCiphertext = encryptForStorage(t, mgr, []byte("-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n"))
		}
	}
	translator := tc.translator(t, db)
	translator.certStore.SetEncryptionManager(mgr)

	store := storage.NewConfigStore()
	for _, cfg := range apiConfigsOfEveryKind() {
		require.NoError(t, store.Add(cfg))
	}
	metrics.Init()
	sm, err := NewSnapshotManager(store, createTestLogger(), translator.routerConfig, db, translator.config)
	require.NoError(t, err)
	sm.translator = translator
	sm.SetSDSSecretManager(NewSDSSecretManager(translator.certStore, sm.cache, "router-node", createTestLogger(),
		translator.routerConfig.DownstreamTLS.CertPath, translator.routerConfig.DownstreamTLS.KeyPath, true))

	secretNames := func() []string {
		require.NoError(t, sm.UpdateSnapshot(context.Background(), ""))
		snap, err := sm.cache.GetSnapshot("router-node")
		require.NoError(t, err)
		var names []string
		for name := range snap.GetResources(resource.SecretType) {
			names = append(names, name)
		}
		sort.Strings(names)
		return names
	}

	assert.Contains(t, secretNames(), GatewayIdentitySecretName(testDefaultIdentityName))
	assert.Equal(t, GatewayIdentitySecretName(testDefaultIdentityName), translator.defaultClientCert.SecretName)

	var remaining []*models.StoredCertificate
	for _, cert := range db.certs {
		if !cert.IsDefaultIdentity() {
			remaining = append(remaining, cert)
		}
	}
	db.certs = remaining

	names := secretNames()
	assert.NotContains(t, names, GatewayIdentitySecretName(testDefaultIdentityName))
	assert.Contains(t, names, SecretNameDownstreamListenerCert)
	assert.Equal(t, SecretNameDownstreamListenerCert, translator.defaultClientCert.SecretName)
}

func TestDefaultClientCertificate_StartupLog(t *testing.T) {
	serverOnly := func(t *testing.T) []byte {
		return pki.NewSelfSignedLeaf(t, "server-only", pki.WithEKU(x509.ExtKeyUsageServerAuth)).PEM()
	}
	tests := []struct {
		name      string
		tc        defaultIdentityTestCase
		leafPEM   func(t *testing.T) []byte // replaces the presented certificate when set
		want      []string
		notWanted []string
	}{
		{
			name:      "default identity",
			tc:        defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true},
			want:      []string{"level=INFO", "Presenting the default gateway identity", "identity=" + testDefaultIdentityName},
			notWanted: []string{"clientAuth"},
		},
		{
			name:      "listener certificate",
			tc:        defaultIdentityTestCase{presentDefault: true, httpsEnabled: true},
			want:      []string{"level=INFO", "Presenting the HTTPS listener certificate"},
			notWanted: []string{"clientAuth"},
		},
		{
			name: "none",
			tc:   defaultIdentityTestCase{presentDefault: true},
			want: []string{"level=WARN", "no client certificate is presented to backends"},
		},
		{
			name:    "default identity without clientAuth",
			tc:      defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true},
			leafPEM: serverOnly,
			want: []string{"level=WARN", "does not assert the clientAuth extended key usage",
				"identity=" + testDefaultIdentityName, `subject="CN=server-only"`},
		},
		{
			name:      "switch off",
			tc:        defaultIdentityTestCase{httpsEnabled: true, defaultExists: true},
			notWanted: []string{"Presenting", "no client certificate is presented", "clientAuth"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.tc.logs = &bytes.Buffer{}
			db := tt.tc.storage(t)
			if tt.leafPEM != nil {
				for _, cert := range db.certs {
					if cert.IsDefaultIdentity() {
						cert.Certificate = tt.leafPEM(t)
					}
				}
			}
			translateEveryKind(t, tt.tc.translator(t, db))

			logs := tt.tc.logs.String()
			for _, want := range tt.want {
				assert.Contains(t, logs, want)
			}
			for _, notWanted := range tt.notWanted {
				assert.NotContains(t, logs, notWanted)
			}
			assert.NotContains(t, logs, "PRIVATE KEY")
		})
	}
}

// The choice is logged once, and again when the presented certificate
// changes.
func TestDefaultClientCertificate_LoggedOnChange(t *testing.T) {
	tc := defaultIdentityTestCase{presentDefault: true, httpsEnabled: true, defaultExists: true, logs: &bytes.Buffer{}}
	db := tc.storage(t)
	translator := tc.translator(t, db)
	const line = "Presenting the default gateway identity"

	translateEveryKind(t, translator)
	translateEveryKind(t, translator)
	assert.Equal(t, 1, strings.Count(tc.logs.String(), line), "an unchanged choice is logged once")

	for _, cert := range db.certs {
		if cert.IsDefaultIdentity() {
			cert.Certificate = pki.NewSelfSignedLeaf(t, "rotated", pki.WithEKU(x509.ExtKeyUsageServerAuth)).PEM()
		}
	}
	translateEveryKind(t, translator)
	logs := tc.logs.String()
	assert.Equal(t, 2, strings.Count(logs, line), "a rotation is logged again")
	assert.Contains(t, logs, "does not assert the clientAuth extended key usage")
}

// A failure to read the default identity fails the translation rather than
// present a different certificate.
func TestDefaultClientCertificate_LookupFailureFailsTranslation(t *testing.T) {
	tc := defaultIdentityTestCase{presentDefault: true, httpsEnabled: true}
	db := &failingIdentityListStorage{fakeSDSStorage: tc.storage(t)}
	translator := tc.translator(t, db)
	db.fail = true

	_, err := translator.TranslateConfigs(apiConfigsOfEveryKind(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "default gateway identity")
}

type failingIdentityListStorage struct {
	*fakeSDSStorage
	fail bool
}

func (f *failingIdentityListStorage) ListCertificatesByUsage(usage string) ([]*models.StoredCertificate, error) {
	if f.fail && usage == models.CertificateUsageIdentity {
		return nil, fmt.Errorf("database unavailable")
	}
	return f.fakeSDSStorage.ListCertificatesByUsage(usage)
}
