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

// The HTTPS listener probe and requests carrying (or omitting) a client
// certificate, alone or paired with a JWT (features/mtls-auth.feature,
// features/mtls-listener.feature).
package it

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"
)

// httpsListenerAddr is the derived HTTPS listener's dial address, probed
// directly at the TCP/TLS level (rather than through httpSteps) to observe
// whether the server asked for a client certificate.
const httpsListenerAddr = "localhost:8443"

// mtlsListenerProbeRetries/Interval bound the retry loop used only for the
// positive case (listener should now be requesting a certificate), to absorb
// xDS propagation lag after a deploy. The negative case probes once
// immediately — the feature file waits explicitly wherever propagation lag
// matters there.
const (
	mtlsListenerProbeRetries  = 10
	mtlsListenerProbeInterval = 500 * time.Millisecond
)

// ============ HTTPS listener probing ============

// probeClientCertRequested opens a direct TLS connection to the derived
// HTTPS listener with a GetClientCertificate callback that records whether
// it was invoked, then completes the handshake with no certificate (an
// empty tls.Certificate). The listener validates optionally rather than
// requiring a certificate (see the "never drops a connection" scenario), so
// the handshake is expected to succeed either way — the callback having run
// is itself the signal that a CertificateRequest was sent.
func (m *mtlsSteps) probeClientCertRequested() (bool, error) {
	invoked := false
	conf := &tls.Config{
		InsecureSkipVerify: true, // the listener uses a self-signed default cert
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			invoked = true
			return &tls.Certificate{}, nil
		},
	}
	conn, err := tls.Dial("tcp", httpsListenerAddr, conf)
	if err != nil {
		return false, fmt.Errorf("failed to complete a TLS handshake against %s: %w", httpsListenerAddr, err)
	}
	defer conn.Close()
	return invoked, nil
}

func (m *mtlsSteps) httpsListenerShouldRequestClientCertificate() error {
	var lastErr error
	for attempt := 0; attempt < mtlsListenerProbeRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(mtlsListenerProbeInterval)
		}
		invoked, err := m.probeClientCertRequested()
		if err != nil {
			lastErr = err
			continue
		}
		if invoked {
			return nil
		}
		lastErr = fmt.Errorf("HTTPS listener at %s did not request a client certificate", httpsListenerAddr)
	}
	return lastErr
}

func (m *mtlsSteps) httpsListenerShouldNotRequestClientCertificate() error {
	invoked, err := m.probeClientCertRequested()
	if err != nil {
		return err
	}
	if invoked {
		return fmt.Errorf("HTTPS listener at %s requested a client certificate, expected none", httpsListenerAddr)
	}
	return nil
}

// ============ Requests carrying (or omitting) a client certificate ============

// tlsClientWithCertificate builds a one-off *http.Client whose transport
// presents the named certificate fixture (and, when includeChain is true,
// its intermediate chain) for the TLS handshake. Keep-alives are disabled so
// each step is a fresh connection — the certificate is negotiated per
// connection, not per request.
//
// The certificate is presented unconditionally. Go's default selection
// withholds a certificate whose issuer is not among the authorities the
// server names in its CertificateRequest, which would turn every
// "certificate from an authority outside the pool" scenario into a
// no-certificate handshake; presenting it regardless is what curl and
// OpenSSL-based clients do, and it is the only way to exercise the listener
// accepting an untrusted certificate and the policy rejecting it.
func (m *mtlsSteps) tlsClientWithCertificate(name string, includeChain bool) (*http.Client, error) {
	certPEM, err := m.readFixtureCert(name)
	if err != nil {
		return nil, err
	}
	if includeChain {
		chainPEM, err := m.readFixtureFile(name, ".chain.crt")
		if err != nil {
			return nil, err
		}
		combined := make([]byte, 0, len(certPEM)+len(chainPEM))
		combined = append(combined, certPEM...)
		combined = append(combined, chainPEM...)
		certPEM = combined
	}
	keyPEM, err := m.readFixtureFile(name, ".key")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate fixture %q: %w", name, err)
	}
	return &http.Client{
		Timeout: m.state.Config.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // the listener uses a self-signed default cert
				MinVersion:         tls.VersionTLS12,
				GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &cert, nil
				},
			},
			DisableKeepAlives: true,
		},
	}, nil
}

// tlsClientNoCertificate builds a one-off *http.Client whose transport
// presents no client certificate at all.
func (m *mtlsSteps) tlsClientNoCertificate() *http.Client {
	return &http.Client{
		Timeout: m.state.Config.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		},
	}
}

func (m *mtlsSteps) getWithClientCertificate(url, name string) error {
	client, err := m.tlsClientWithCertificate(name, false)
	if err != nil {
		return err
	}
	return m.httpSteps.SendRequestWithClient(client, http.MethodGet, url)
}

func (m *mtlsSteps) getWithClientCertificateAndChain(url, name string) error {
	client, err := m.tlsClientWithCertificate(name, true)
	if err != nil {
		return err
	}
	return m.httpSteps.SendRequestWithClient(client, http.MethodGet, url)
}

func (m *mtlsSteps) getWithNoClientCertificate(url string) error {
	return m.httpSteps.SendRequestWithClient(m.tlsClientNoCertificate(), http.MethodGet, url)
}

// requireJWTToken guards the two steps below exactly like steps_jwt.go's own
// "with the JWT token" steps do, so the failure mode (call the token-fetch
// step first) is identical whether or not a client certificate is involved.
func (m *mtlsSteps) requireJWTToken() error {
	if m.jwtSteps == nil || m.jwtSteps.currentToken == "" {
		return fmt.Errorf("no JWT token available - call 'I get a JWT token from the mock JWKS server' first")
	}
	return nil
}

// getWithJWTTokenAndClientCertificate combines the existing JWT-bearer
// Authorization header (steps_jwt.go) with a per-request client-certificate
// TLS client (above): the header is a persistent header applied by
// HTTPSteps.SendRequestWithClient, so setting it here (via
// useHeaderForOneRequest, steps_mtls_header.go) and delegating to
// getWithClientCertificate carries both credentials on the same request.
func (m *mtlsSteps) getWithJWTTokenAndClientCertificate(url, name string) error {
	if err := m.requireJWTToken(); err != nil {
		return err
	}
	restore := m.useHeaderForOneRequest("Authorization", "Bearer "+m.jwtSteps.currentToken)
	defer restore()
	return m.getWithClientCertificate(url, name)
}

// getWithJWTTokenAndNoClientCertificate is the same pairing as above without
// a client certificate — used to assert that the JWT alone isn't sufficient
// where an mtls-auth policy is also attached.
func (m *mtlsSteps) getWithJWTTokenAndNoClientCertificate(url string) error {
	if err := m.requireJWTToken(); err != nil {
		return err
	}
	restore := m.useHeaderForOneRequest("Authorization", "Bearer "+m.jwtSteps.currentToken)
	defer restore()
	return m.getWithNoClientCertificate(url)
}

// httpsListenerShouldPresentCertificateFile completes a TLS handshake with
// the HTTPS listener and checks that the leaf certificate it presented is
// byte-for-byte the certificate in the given PEM file — the file the
// controller is configured with and serves to Envoy as the listener secret.
func (m *mtlsSteps) httpsListenerShouldPresentCertificateFile(path string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read expected listener certificate %q: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("%q does not start with a PEM certificate", path)
	}
	expected := sha256.Sum256(block.Bytes)

	conn, err := tls.Dial("tcp", httpsListenerAddr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		return fmt.Errorf("failed to complete a TLS handshake against %s: %w", httpsListenerAddr, err)
	}
	defer conn.Close()
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return fmt.Errorf("the HTTPS listener presented no certificate")
	}
	got := sha256.Sum256(peers[0].Raw)
	if got != expected {
		return fmt.Errorf("the HTTPS listener presented %q (sha256 %x), expected the certificate in %q (sha256 %x)",
			peers[0].Subject.String(), got, path, expected)
	}
	return nil
}
