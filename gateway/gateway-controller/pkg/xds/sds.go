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

package xds

import (
	"fmt"
	"log/slog"
	"os"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/certstore"
)

const (
	// SecretNameUpstreamCA is the name of the SDS secret for upstream CA certificates
	SecretNameUpstreamCA = "upstream_ca_bundle"

	// SecretNameDownstreamClientCA is the name of the SDS secret carrying the
	// client certificate authority pool (usage: client rows) that the
	// derived HTTPS listener validates a presented client certificate
	// against, once at least one deployed API attaches mtls-auth.
	SecretNameDownstreamClientCA = "downstream_client_ca"

	// SecretNameDownstreamListenerCert is the name of the SDS secret
	// carrying the HTTPS listener's own certificate/key
	// (router.downstream_tls.cert_path/key_path). Delivering it via SDS
	// instead of inlining it into the LDS resource keeps the listener's
	// private key out of the xDS config dump (see
	// go-control-plane-xds-security.md directive 3).
	SecretNameDownstreamListenerCert = "downstream_listener_cert"
)

// SDSSecretManager manages SDS secrets for TLS certificates
type SDSSecretManager struct {
	cache     cache.SnapshotCache
	certStore *certstore.CertStore
	logger    *slog.Logger
	nodeID    string

	// listenerCertPath/listenerKeyPath and httpsEnabled configure the
	// downstream_listener_cert secret. Set via SetDownstreamListenerCert —
	// kept out of the constructor so existing callers/tests that only need
	// the upstream_ca_bundle secret (via GetSecret) are unaffected.
	listenerCertPath string
	listenerKeyPath  string
	httpsEnabled     bool
}

// NewSDSSecretManager creates a new SDS secret manager
// It shares the same cache and node ID as the main xDS to ensure Envoy can fetch secrets
func NewSDSSecretManager(certStore *certstore.CertStore, cache cache.SnapshotCache, nodeID string, logger *slog.Logger) *SDSSecretManager {
	return &SDSSecretManager{
		cache:     cache,
		certStore: certStore,
		logger:    logger,
		nodeID:    nodeID,
	}
}

// SetDownstreamListenerCert configures the source files for the
// downstream_listener_cert secret. Must be called (from the same router
// config that already gates the HTTPS listener itself) before GetSecrets is
// relied on for a snapshot that includes an HTTPS listener; httpsEnabled
// false makes GetSecrets skip this secret entirely rather than attempt to
// read files that may not exist when HTTPS is disabled.
func (sm *SDSSecretManager) SetDownstreamListenerCert(certPath, keyPath string, httpsEnabled bool) {
	sm.listenerCertPath = certPath
	sm.listenerKeyPath = keyPath
	sm.httpsEnabled = httpsEnabled
}

// GetCache returns the SDS snapshot cache
func (sm *SDSSecretManager) GetCache() cache.SnapshotCache {
	return sm.cache
}

// UpdateSecrets creates and updates the SDS snapshot with certificate secrets
// This now updates the main xDS snapshot instead of a separate SDS snapshot
func (sm *SDSSecretManager) UpdateSecrets() error {
	if sm.certStore == nil {
		sm.logger.Warn("No cert store available, skipping SDS secret update")
		return nil
	}

	// Secrets are now managed as part of the main xDS snapshot
	// This method just validates that cert store is ready
	combinedCerts := sm.certStore.GetCombinedCertificates()
	if len(combinedCerts) == 0 {
		sm.logger.Warn("No certificates available in cert store")
		return nil
	}

	sm.logger.Info("Certificate store ready for SDS",
		slog.Int("cert_bytes", len(combinedCerts)),
	)

	return nil
}

// GetSecret creates the SDS secret resource for inclusion in xDS snapshot
func (sm *SDSSecretManager) GetSecret() (types.Resource, error) {
	if sm.certStore == nil {
		return nil, fmt.Errorf("no cert store available")
	}

	// Get combined certificates from cert store
	combinedCerts := sm.certStore.GetCombinedCertificates()
	if len(combinedCerts) == 0 {
		return nil, fmt.Errorf("no certificates available in cert store")
	}

	// Create SDS secret for upstream CA certificates
	secret := &tlsv3.Secret{
		Name: SecretNameUpstreamCA,
		Type: &tlsv3.Secret_ValidationContext{
			ValidationContext: &tlsv3.CertificateValidationContext{
				TrustedCa: &core.DataSource{
					Specifier: &core.DataSource_InlineBytes{
						InlineBytes: combinedCerts,
					},
				},
			},
		},
	}

	return secret, nil
}

// GetSecrets builds every SDS secret this manager can currently serve:
// upstream_ca_bundle (unchanged from GetSecret), downstream_client_ca (the
// client-CA pool, for mTLS validation) and downstream_listener_cert (the
// HTTPS listener's own certificate/key). The snapshot manager includes only
// the subset actually referenced by this snapshot's clusters/listeners (see
// SnapshotReferencesSDSSecret).
//
// Only a genuinely EMPTY result is soft — an empty upstream_ca_bundle or an
// empty client-CA pool is simply omitted, not an error (deploy-time
// validation already refuses to attach mtls-auth against an empty pool, so a
// snapshot that references downstream_client_ca is never expected to find
// one empty). A lookup FAILURE is always fatal — for the client-CA pool
// exactly as for downstream_listener_cert's cert/key files — because
// whenever a deployed API attaches mtls-auth, the listener already
// references that secret name; silently omitting it on error would leave
// the listener waiting on a secret that will never arrive, with nothing
// surfacing the failure. This matches how the old inline-bytes path failed
// snapshot generation outright when it read the listener cert/key files
// directly (see go-network-service-hardening.md).
func (sm *SDSSecretManager) GetSecrets() ([]types.Resource, error) {
	var secrets []types.Resource

	if upstreamSecret, err := sm.GetSecret(); err != nil {
		sm.logger.Debug("upstream_ca_bundle secret not currently available", slog.Any("error", err))
	} else {
		secrets = append(secrets, upstreamSecret)
	}

	if sm.certStore != nil {
		clientCABundle, err := sm.certStore.GetClientCABundle()
		if err != nil {
			// Fatal, not warn-and-continue: whenever a deployed API attaches
			// mtls-auth, the listener references this secret name, so a
			// failed lookup (as opposed to a genuinely empty pool, which
			// returns no error — see GetClientCABundle) must not be
			// swallowed. Silently omitting the secret here would leave the
			// listener waiting on a secret that will never arrive, with
			// nothing surfacing the failure.
			sm.logger.Error("Failed to load client-CA pool for downstream_client_ca secret", slog.Any("error", err))
			return nil, fmt.Errorf("failed to load client-CA pool: %w", err)
		}
		if len(clientCABundle) > 0 {
			secrets = append(secrets, &tlsv3.Secret{
				Name: SecretNameDownstreamClientCA,
				Type: &tlsv3.Secret_ValidationContext{
					ValidationContext: &tlsv3.CertificateValidationContext{
						TrustedCa: &core.DataSource{
							Specifier: &core.DataSource_InlineBytes{
								InlineBytes: clientCABundle,
							},
						},
						// Envoy still performs full X.509 chain verification
						// against this pool and reports the outcome on the
						// connection (connection.peer_certificate_valid) —
						// ACCEPT_UNTRUSTED only stops Envoy from CLOSING the
						// connection when that verification fails. Without
						// it, an untrusted/expired/self-signed certificate
						// would abort the TLS handshake before mtls-auth ever
						// runs, turning every such caller into a bare
						// connection reset instead of a 401 with telemetry —
						// this is what lets a plain API on the same listener
						// stay reachable and lets mtls-auth's own policy
						// evaluation, not the TLS stack, decide the HTTP
						// outcome. mtls-auth MUST still treat a false
						// peer_certificate_valid as a deny; ACCEPT_UNTRUSTED
						// never means "verification doesn't matter".
						TrustChainVerification: tlsv3.CertificateValidationContext_ACCEPT_UNTRUSTED,
					},
				},
			})
		}
	}

	if sm.httpsEnabled {
		certBytes, err := os.ReadFile(sm.listenerCertPath)
		if err != nil {
			sm.logger.Error("Failed to read HTTPS listener certificate for downstream_listener_cert secret",
				slog.String("path", sm.listenerCertPath), slog.Any("error", err))
			return nil, fmt.Errorf("failed to read HTTPS listener certificate: %w", err)
		}
		keyBytes, err := os.ReadFile(sm.listenerKeyPath)
		if err != nil {
			sm.logger.Error("Failed to read HTTPS listener private key for downstream_listener_cert secret",
				slog.String("path", sm.listenerKeyPath), slog.Any("error", err))
			return nil, fmt.Errorf("failed to read HTTPS listener private key: %w", err)
		}
		secrets = append(secrets, &tlsv3.Secret{
			Name: SecretNameDownstreamListenerCert,
			Type: &tlsv3.Secret_TlsCertificate{
				TlsCertificate: &tlsv3.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: certBytes},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{InlineBytes: keyBytes},
					},
				},
			},
		})
	}

	return secrets, nil
}

// GetNodeID returns the node ID for SDS clients
func (sm *SDSSecretManager) GetNodeID() string {
	return sm.nodeID
}
