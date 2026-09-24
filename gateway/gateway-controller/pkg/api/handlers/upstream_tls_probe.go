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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/httpkit/httputil"
)

// tlsTestDialTimeout bounds the whole probe so a slow backend cannot hold the
// handler open.
const tlsTestDialTimeout = 10 * time.Second

// tlsTestCanaryReadTimeout is the post-handshake read that detects a TLS 1.3
// server rejecting the client certificate after the handshake completes.
const tlsTestCanaryReadTimeout = 500 * time.Millisecond

// Result values for UpstreamTLSTestResponse.result.
const (
	tlsTestResultOK                   = "OK"
	tlsTestResultUntrustedBackend     = "UNTRUSTED_BACKEND"
	tlsTestResultHostnameMismatch     = "HOSTNAME_MISMATCH"
	tlsTestResultBackendRejectedIdent = "BACKEND_REJECTED_IDENTITY"
	tlsTestResultConnectFailed        = "CONNECT_FAILED"
)

// upstreamTLSTestBackend mirrors api.UpstreamTLSTestBackend so that false and
// zero values are always present in the response.
type upstreamTLSTestBackend struct {
	Subject         string `json:"subject"`
	Issuer          string `json:"issuer"`
	NotAfter        string `json:"notAfter,omitempty"`
	TrustedBy       string `json:"trustedBy,omitempty"`
	HostnameMatches bool   `json:"hostnameMatches"`
}

type upstreamTLSTestResponse struct {
	Upstream          string                  `json:"upstream"`
	Target            string                  `json:"target"`
	IdentityPresented *string                 `json:"identityPresented"`
	Backend           *upstreamTLSTestBackend `json:"backend,omitempty"`
	Result            string                  `json:"result"`
	Detail            *string                 `json:"detail"`
}

// TestUpstreamTLS handshakes once with an upstream definition's first target
// using its configured TLS settings and reports the outcome in the result
// field of a 200. No HTTP request is made.
func (s *APIServer) TestUpstreamTLS(w http.ResponseWriter, r *http.Request, id string, name string) {
	log := middleware.GetLogger(r, s.logger)

	cfg, err := s.db.GetConfigByKindAndHandle(string(models.KindRestApi), id)
	if err != nil || cfg == nil {
		httputil.WriteJSON(w, http.StatusNotFound, api.ErrorResponse{
			Status: "error", Message: "RestAPI not found",
		})
		return
	}
	restCfg, ok := cfg.Configuration.(api.RestAPI)
	if !ok {
		httputil.WriteJSON(w, http.StatusNotFound, api.ErrorResponse{
			Status: "error", Message: "RestAPI not found",
		})
		return
	}

	var def *api.UpstreamDefinition
	if restCfg.Spec.UpstreamDefinitions != nil {
		for i := range *restCfg.Spec.UpstreamDefinitions {
			if (*restCfg.Spec.UpstreamDefinitions)[i].Name == name {
				def = &(*restCfg.Spec.UpstreamDefinitions)[i]
				break
			}
		}
	}
	if def == nil || len(def.Upstreams) == 0 {
		httputil.WriteJSON(w, http.StatusNotFound, api.ErrorResponse{
			Status: "error", Message: "upstream definition not found",
		})
		return
	}

	target := def.Upstreams[0].Url

	var identityName string
	var trustedCANames []string
	if def.Tls != nil {
		identityName, trustedCANames, _ = config.ResolveUpstreamTLSFromParams(*def.Tls)
	}

	// An identity that fails to load refuses the probe, so a broken identity
	// here is never misreported as the backend's rejection.
	var identityCert *tls.Certificate
	if identityName != "" {
		cert, err := s.loadIdentityCertificateForProbe(identityName)
		if err != nil {
			log.Error("tls-test: failed to load gateway identity material",
				slog.String("identity", identityName), slog.Any("error", err))
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"status":  "error",
				"message": "Failed to load the gateway identity for this upstream",
			})
			return
		}
		identityCert = cert
	}

	result, detail, backend := s.probeUpstreamTLS(r.Context(), target, identityCert, trustedCANames)

	resp := upstreamTLSTestResponse{
		Upstream: name,
		Target:   target,
		Result:   result,
		Detail:   detail,
		Backend:  backend,
	}
	if identityName != "" {
		resp.IdentityPresented = &identityName
	}

	httputil.WriteJSON(w, http.StatusOK, resp)
}

// loadIdentityCertificateForProbe resolves a gateway identity by name to a
// tls.Certificate for the probe.
func (s *APIServer) loadIdentityCertificateForProbe(identityName string) (*tls.Certificate, error) {
	translator := s.snapshotManager.GetTranslator()
	if translator == nil {
		return nil, fmt.Errorf("certificate store not configured")
	}
	certPEM, keyPEM, err := translator.GetCertStore().GetGatewayIdentityMaterial(identityName)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// probeUpstreamTLS dials, handshakes and classifies the outcome as a
// (result, detail) pair. identityCert is the client certificate to present,
// or nil for none.
func (s *APIServer) probeUpstreamTLS(
	ctx context.Context,
	target string,
	identityCert *tls.Certificate,
	trustedCANames []string,
) (result string, detail *string, backend *upstreamTLSTestBackend) {
	parsedURL, err := url.Parse(target)
	if err != nil || parsedURL.Hostname() == "" {
		return tlsTestResultConnectFailed, stringPtr("invalid target URL"), nil
	}
	host := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}

	ctx, cancel := context.WithTimeout(ctx, tlsTestDialTimeout)
	defer cancel()

	// This process, not Envoy, makes the connection, so it goes through the
	// shared SSRF dialer.
	dial := config.UpstreamSSRFDialContext(tlsTestDialTimeout)
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return tlsTestResultConnectFailed, stringPtr(err.Error()), nil
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName: host,
		// Trust and hostname are checked separately below so the probe can
		// tell UNTRUSTED_BACKEND from HOSTNAME_MISMATCH.
		InsecureSkipVerify: true, //nolint:gosec
	}
	if identityCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*identityCert}
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		if strings.Contains(err.Error(), "remote error") {
			return tlsTestResultBackendRejectedIdent, stringPtr(err.Error()), nil
		}
		return tlsTestResultConnectFailed, stringPtr(err.Error()), nil
	}

	peerCerts := tlsConn.ConnectionState().PeerCertificates
	if len(peerCerts) == 0 {
		return tlsTestResultConnectFailed, stringPtr("backend presented no certificate"), nil
	}
	leaf := peerCerts[0]

	backend = &upstreamTLSTestBackend{
		Subject:  leaf.Subject.String(),
		Issuer:   leaf.Issuer.String(),
		NotAfter: leaf.NotAfter.Format(time.RFC3339),
	}

	// TLS 1.3 reports a rejected client certificate as a post-handshake
	// alert, seen only on the next read. An alert or EOF within the deadline
	// means rejection; a timeout means the identity was accepted.
	_ = tlsConn.SetReadDeadline(time.Now().Add(tlsTestCanaryReadTimeout))
	buf := make([]byte, 1)
	_, readErr := tlsConn.Read(buf)
	_ = tlsConn.SetReadDeadline(time.Time{})
	if readErr != nil && !isTimeoutError(readErr) {
		return tlsTestResultBackendRejectedIdent, stringPtr(readErr.Error()), backend
	}

	trustedBy, chainTrusted := s.classifyUpstreamTrust(peerCerts, trustedCANames)
	backend.TrustedBy = trustedBy
	backend.HostnameMatches = leaf.VerifyHostname(host) == nil

	if !chainTrusted {
		return tlsTestResultUntrustedBackend, nil, backend
	}
	if !backend.HostnameMatches {
		return tlsTestResultHostnameMismatch, nil, backend
	}
	return tlsTestResultOK, nil, backend
}

// classifyUpstreamTrust reports which trust anchor verifies peerCerts: a
// named trustedCAs row, or the gateway bundle when trustedCANames is empty.
// It returns ("", false) when none verify.
func (s *APIServer) classifyUpstreamTrust(peerCerts []*x509.Certificate, trustedCANames []string) (string, bool) {
	leaf := peerCerts[0]
	intermediates := x509.NewCertPool()
	for _, c := range peerCerts[1:] {
		intermediates.AddCert(c)
	}
	verifyOpts := x509.VerifyOptions{Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	if len(trustedCANames) > 0 {
		for _, name := range trustedCANames {
			cert, err := s.db.GetCertificateByName(name)
			if err != nil || cert == nil {
				continue
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cert.Certificate) {
				continue
			}
			opts := verifyOpts
			opts.Roots = pool
			if _, err := leaf.Verify(opts); err == nil {
				return name, true
			}
		}
		return "", false
	}

	translator := s.snapshotManager.GetTranslator()
	if translator == nil {
		return "", false
	}
	bundle := translator.GetCertStore().GetCombinedCertificates()
	if len(bundle) == 0 {
		return "", false
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(bundle) {
		return "", false
	}
	opts := verifyOpts
	opts.Roots = pool
	if _, err := leaf.Verify(opts); err == nil {
		return "gateway bundle", true
	}
	return "", false
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
