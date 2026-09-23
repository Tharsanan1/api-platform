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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/encryption"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/testutil/pki"
)

// ============================================================================
// TestUpstreamTLS / probeUpstreamTLS (slice 5)
// ============================================================================
//
// probeUpstreamTLS dials via config.UpstreamSSRFDialContext, which refuses
// loopback addresses outright (see ssrf-prevention.md / upstream_ssrf.go) —
// a 127.0.0.1/::1 listener would make every probe in this file report
// CONNECT_FAILED for the wrong reason. These tests instead bind the in-test
// TLS server to the host's own non-loopback (typically RFC 1918) address,
// which the SSRF policy permits, exactly like a real private backend would
// be reached.

// nonLoopbackIPv4 returns a non-loopback IPv4 address configured on this
// host, or skips the test if none is found (e.g. a fully isolated network
// namespace with only lo) — a skip here is an environment limitation, not a
// test failure.
func nonLoopbackIPv4(t *testing.T) net.IP {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	require.NoError(t, err)
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil || ip4.IsLoopback() {
			continue
		}
		return ip4
	}
	t.Skip("no non-loopback IPv4 address available on this host; skipping probeUpstreamTLS dial tests")
	return nil
}

func mustProbeSerial(t *testing.T) *big.Int {
	t.Helper()
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	require.NoError(t, err)
	return n
}

// issueServerCertForIP issues a serverAuth leaf, signed by ca, carrying ip as
// its sole IP SAN — pki.go only supports DNS/URI SANs, and these tests dial
// a literal IP rather than a hostname, so leaf.VerifyHostname(host) needs an
// IP SAN to ever match.
func issueServerCertForIP(t *testing.T, ca *pki.Entity, ip net.IP, cn string) *pki.Entity {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          mustProbeSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{ip},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &pki.Entity{Cert: cert, Key: key, DER: der}
}

// probeTestBackend is an in-test TLS server plus everything needed to tear
// it down and dial it.
type probeTestBackend struct {
	listener net.Listener
	target   string // https://<host>:<port>
}

func (b *probeTestBackend) Close() { _ = b.listener.Close() }

// startProbeTLSBackend starts a TLS server on a non-loopback address serving
// serverCert, optionally requiring (and validating) a client certificate
// against clientCAPool. Each accepted connection is handshaken and then left
// open briefly (so a canary read on the client side times out rather than
// observing EOF) unless the server itself rejects the client certificate, in
// which case tls.Conn's own handshake failure delivers the rejection.
func startProbeTLSBackend(t *testing.T, ip net.IP, serverCert *pki.Entity, clientCAPool *x509.CertPool) *probeTestBackend {
	t.Helper()

	cert, err := tls.X509KeyPair(serverCert.PEM(), serverCert.KeyPEM())
	require.NoError(t, err)

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if clientCAPool != nil {
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		tlsCfg.ClientCAs = clientCAPool
	}

	ln, err := tls.Listen("tcp", net.JoinHostPort(ip.String(), "0"), tlsCfg)
	require.NoError(t, err)

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				tlsConn, ok := c.(*tls.Conn)
				if !ok {
					return
				}
				// A client-cert-rejecting handshake surfaces the alert here
				// (or, for TLS 1.3, only once the client attempts its canary
				// read below) — either way this goroutine just needs to keep
				// the connection open briefly so the client's short read
				// times out rather than seeing an immediate EOF on success.
				_ = tlsConn.Handshake()
				time.Sleep(tlsTestCanaryReadTimeout * 3)
			}(conn)
		}
	}()

	return &probeTestBackend{listener: ln, target: "https://" + ln.Addr().String()}
}

func TestProbeUpstreamTLS_OK(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	backendCA := pki.NewRootCA(t, "Probe OK Backend CA")
	serverCert := issueServerCertForIP(t, backendCA, ip, "probe-ok-backend")
	identityCA := pki.NewRootCA(t, "Probe OK Identity CA")
	identity := pki.NewLeaf(t, identityCA, "probe-ok-identity")

	clientPool := x509.NewCertPool()
	clientPool.AddCert(identityCA.Cert)
	backend := startProbeTLSBackend(t, ip, serverCert, clientPool)
	defer backend.Close()

	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{
		seedUpstreamCert(t),
		{
			UUID: "ok-trust", Name: "probe-backend-ca", Certificate: backendCA.PEM(),
			Usage: models.CertificateUsageUpstream, NotAfter: time.Now().Add(365 * 24 * time.Hour),
		},
	}
	// createTestAPIServerWithIdentitySupport generates its own encryption
	// manager; the identity ciphertext below must be produced with that SAME
	// instance (accessible directly — this test file is in package handlers)
	// so GetGatewayIdentityMaterial's decrypt actually succeeds.
	server := createTestAPIServerWithIdentitySupport(t, mockDB)
	mockDB.certs = append(mockDB.certs, &models.StoredCertificate{
		UUID: "ok-identity", Name: "probe-identity", Certificate: identity.PEM(),
		Usage: models.CertificateUsageIdentity, PrivateKeyCiphertext: mustEncrypt(t, server.encryptionManager, identity.KeyPEM()),
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

	identityCert, err := server.loadIdentityCertificateForProbe("probe-identity")
	require.NoError(t, err)
	result, detail, backendResult := server.probeUpstreamTLS(context.Background(),
		backend.target, identityCert, []string{"probe-backend-ca"})

	require.Equal(t, tlsTestResultOK, result, "detail: %v", detail)
	assert.Nil(t, detail, "detail must be null on a successful probe")
	require.NotNil(t, backendResult)
	assert.Equal(t, "probe-backend-ca", backendResult.TrustedBy)
	assert.True(t, backendResult.HostnameMatches)
}

func TestProbeUpstreamTLS_UntrustedBackend(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	backendCA := pki.NewRootCA(t, "Probe Untrusted Backend CA")
	serverCert := issueServerCertForIP(t, backendCA, ip, "probe-untrusted-backend")
	identityCA := pki.NewRootCA(t, "Probe Untrusted Identity CA")
	identity := pki.NewLeaf(t, identityCA, "probe-untrusted-identity")
	unrelatedCA := pki.NewRootCA(t, "Probe Unrelated CA")

	clientPool := x509.NewCertPool()
	clientPool.AddCert(identityCA.Cert)
	backend := startProbeTLSBackend(t, ip, serverCert, clientPool)
	defer backend.Close()

	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{
		seedUpstreamCert(t),
		{
			// Named as the "trust", but signed by a different CA than the
			// one that actually issued the server's certificate.
			UUID: "untrusted-trust", Name: "probe-unrelated-ca", Certificate: unrelatedCA.PEM(),
			Usage: models.CertificateUsageUpstream, NotAfter: time.Now().Add(365 * 24 * time.Hour),
		},
	}
	server := createTestAPIServerWithIdentitySupport(t, mockDB)
	mockDB.certs = append(mockDB.certs, &models.StoredCertificate{
		UUID: "untrusted-identity", Name: "probe-identity", Certificate: identity.PEM(),
		Usage: models.CertificateUsageIdentity, PrivateKeyCiphertext: mustEncrypt(t, server.encryptionManager, identity.KeyPEM()),
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

	identityCert, err := server.loadIdentityCertificateForProbe("probe-identity")
	require.NoError(t, err)
	result, _, backendResult := server.probeUpstreamTLS(context.Background(),
		backend.target, identityCert, []string{"probe-unrelated-ca"})

	require.Equal(t, tlsTestResultUntrustedBackend, result)
	require.NotNil(t, backendResult)
	assert.Empty(t, backendResult.TrustedBy)
}

func TestProbeUpstreamTLS_HostnameMismatch(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	backendCA := pki.NewRootCA(t, "Probe Hostname Mismatch CA")
	// Issued for a different IP than the one actually listened on.
	wrongIP := net.IPv4(203, 0, 113, 1)
	serverCert := issueServerCertForIP(t, backendCA, wrongIP, "probe-wronghost-backend")
	identityCA := pki.NewRootCA(t, "Probe Hostname Mismatch Identity CA")
	identity := pki.NewLeaf(t, identityCA, "probe-wronghost-identity")

	clientPool := x509.NewCertPool()
	clientPool.AddCert(identityCA.Cert)
	backend := startProbeTLSBackend(t, ip, serverCert, clientPool)
	defer backend.Close()

	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{
		seedUpstreamCert(t),
		{
			UUID: "wronghost-trust", Name: "probe-backend-ca", Certificate: backendCA.PEM(),
			Usage: models.CertificateUsageUpstream, NotAfter: time.Now().Add(365 * 24 * time.Hour),
		},
	}
	server := createTestAPIServerWithIdentitySupport(t, mockDB)
	mockDB.certs = append(mockDB.certs, &models.StoredCertificate{
		UUID: "wronghost-identity", Name: "probe-identity", Certificate: identity.PEM(),
		Usage: models.CertificateUsageIdentity, PrivateKeyCiphertext: mustEncrypt(t, server.encryptionManager, identity.KeyPEM()),
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

	identityCert, err := server.loadIdentityCertificateForProbe("probe-identity")
	require.NoError(t, err)
	result, _, backendResult := server.probeUpstreamTLS(context.Background(),
		backend.target, identityCert, []string{"probe-backend-ca"})

	require.Equal(t, tlsTestResultHostnameMismatch, result)
	require.NotNil(t, backendResult)
	assert.Equal(t, "probe-backend-ca", backendResult.TrustedBy, "trust chain itself is valid; only the hostname check fails")
	assert.False(t, backendResult.HostnameMatches)
}

func TestProbeUpstreamTLS_BackendRejectedIdentity(t *testing.T) {
	ip := nonLoopbackIPv4(t)
	backendCA := pki.NewRootCA(t, "Probe Rejected Backend CA")
	serverCert := issueServerCertForIP(t, backendCA, ip, "probe-rejected-backend")
	// The identity is signed by its own CA, deliberately absent from the
	// server's ClientCAs pool below — the server must refuse it.
	identityCA := pki.NewRootCA(t, "Probe Rejected Identity CA")
	identity := pki.NewLeaf(t, identityCA, "probe-rejected-identity")
	someOtherCA := pki.NewRootCA(t, "Probe Some Other Trusted Identity CA")

	clientPool := x509.NewCertPool()
	clientPool.AddCert(someOtherCA.Cert) // does NOT include identityCA
	backend := startProbeTLSBackend(t, ip, serverCert, clientPool)
	defer backend.Close()

	mockDB := NewMockStorage()
	mockDB.certs = []*models.StoredCertificate{
		seedUpstreamCert(t),
		{
			UUID: "rejected-trust", Name: "probe-backend-ca", Certificate: backendCA.PEM(),
			Usage: models.CertificateUsageUpstream, NotAfter: time.Now().Add(365 * 24 * time.Hour),
		},
	}
	server := createTestAPIServerWithIdentitySupport(t, mockDB)
	mockDB.certs = append(mockDB.certs, &models.StoredCertificate{
		UUID: "rejected-identity", Name: "probe-identity", Certificate: identity.PEM(),
		Usage: models.CertificateUsageIdentity, PrivateKeyCiphertext: mustEncrypt(t, server.encryptionManager, identity.KeyPEM()),
		NotAfter: time.Now().Add(365 * 24 * time.Hour),
	})

	identityCert, err := server.loadIdentityCertificateForProbe("probe-identity")
	require.NoError(t, err)
	result, detail, _ := server.probeUpstreamTLS(context.Background(),
		backend.target, identityCert, []string{"probe-backend-ca"})

	require.Equal(t, tlsTestResultBackendRejectedIdent, result, "detail: %v", detail)
}

func TestProbeUpstreamTLS_ConnectFailed(t *testing.T) {
	ip := nonLoopbackIPv4(t)

	// Open then immediately close a listener on this address, so its port is
	// (almost certainly) refusing new connections at probe time.
	ln, err := net.Listen("tcp", net.JoinHostPort(ip.String(), "0"))
	require.NoError(t, err)
	target := "https://" + ln.Addr().String()
	require.NoError(t, ln.Close())

	mockDB := NewMockStorage()
	server := createTestAPIServerWithDB(mockDB)

	result, detail, backendResult := server.probeUpstreamTLS(context.Background(), target, nil, nil)

	require.Equal(t, tlsTestResultConnectFailed, result)
	assert.NotNil(t, detail)
	assert.Nil(t, backendResult)
}

// mustEncrypt mirrors handlers.APIServer.encryptPrivateKey for building a
// StoredCertificate fixture's PrivateKeyCiphertext directly, bypassing the
// upload handler.
func mustEncrypt(t *testing.T, mgr *encryption.ProviderManager, plaintext []byte) string {
	t.Helper()
	payload, err := mgr.Encrypt(plaintext)
	require.NoError(t, err)
	return encryption.MarshalPayload(payload)
}
