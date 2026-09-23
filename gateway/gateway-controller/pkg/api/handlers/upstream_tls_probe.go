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

// tlsTestDialTimeout bounds the whole probe (dial + handshake + canary
// read) so a slow/unreachable backend cannot hold this handler open
// indefinitely.
const tlsTestDialTimeout = 10 * time.Second

// tlsTestCanaryReadTimeout is the short post-handshake read used to detect
// a TLS 1.3 server rejecting the client certificate after the handshake
// completes on the client's side (see TestUpstreamTLS's doc comment).
const tlsTestCanaryReadTimeout = 500 * time.Millisecond

// Result values for UpstreamTLSTestResponse.result.
const (
	tlsTestResultOK                   = "OK"
	tlsTestResultUntrustedBackend     = "UNTRUSTED_BACKEND"
	tlsTestResultHostnameMismatch     = "HOSTNAME_MISMATCH"
	tlsTestResultBackendRejectedIdent = "BACKEND_REJECTED_IDENTITY"
	tlsTestResultConnectFailed        = "CONNECT_FAILED"
)

// upstreamTLSTestBackend mirrors api.UpstreamTLSTestBackend, built directly
// (rather than via the generated type) so every field is always present
// even when the generated type's pointer/omitempty fields would otherwise
// hide a false/zero value.
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

// TestUpstreamTLS implements POST /rest-apis/{id}/upstreams/{name}/tls-test:
// dial the deployed upstream definition's first target once with the
// identity/trust/hostname-verification it is configured with, complete (or
// fail) the TLS handshake, and report the outcome. No HTTP request is made.
// Always responds 200 — the outcome is carried in the body's `result` field.
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

	// Resolve the identity to a ready-to-present certificate before dialing
	// anything: a load failure (missing row, undecryptable ciphertext,
	// malformed cert/key) must refuse the probe outright rather than dial
	// without presenting any client certificate, which would misreport a
	// BACKEND_REJECTED_IDENTITY/CONNECT_FAILED result that actually
	// reflects a broken identity on this side, not the backend's behavior.
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

// loadIdentityCertificateForProbe resolves a gateway identity by name (a
// certificates row with usage: identity) to a ready-to-present
// tls.Certificate for the tls-test probe. Returns an error when the row
// cannot be found, its private key cannot be decrypted, or the resulting
// certificate/key pair fails to parse — the caller (TestUpstreamTLS) must
// refuse the whole probe (HTTP 500) rather than silently proceed without a
// client certificate.
func (s *APIServer) loadIdentityCertificateForProbe(identityName string) (*tls.Certificate, error) {
	translator := s.snapshotManager.GetTranslator()
	if translator == nil || translator.GetCertStore() == nil {
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

// probeUpstreamTLS performs the actual dial/handshake/classification. It
// never returns an error itself — every failure mode is expressed as a
// (result, detail) pair, per the sterile-503/generic-rejection posture used
// elsewhere in this handler package: the caller learns the classification,
// never gateway-internal detail beyond the raw TLS error string. identityCert
// is the already-resolved client certificate to present, or nil when the
// definition names none — resolution (and its failure mode) happens in the
// caller (TestUpstreamTLS), never here.
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

	// The target is an operator-configured backend, normally meant to be
	// private (a service-mesh hostname, an RFC 1918 address) — the same
	// SSRF posture as any other upstream dial, applied here since this
	// process (not Envoy) is the one making the connection. Resolution and
	// connection happen in one step (config.UpstreamSSRFDialContext, the
	// one shared SSRF dialer for this codebase — see ssrf-prevention.md
	// directive 6), closing the DNS-rebinding window between a check and
	// the actual dial.
	dial := config.UpstreamSSRFDialContext(tlsTestDialTimeout)
	conn, err := dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return tlsTestResultConnectFailed, stringPtr(err.Error()), nil
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName: host,
		// Trust/hostname are evaluated manually below (against the
		// definition's own trust set / a per-check hostname match) rather
		// than by the stdlib's own verifier, so the probe can distinguish
		// UNTRUSTED_BACKEND from HOSTNAME_MISMATCH instead of a single
		// generic handshake failure.
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

	// TLS 1.3 delivers a server's rejection of the client certificate as a
	// post-handshake alert, which the client only observes on its next
	// read — a successful HandshakeContext above does not by itself mean
	// the identity was accepted. A short read distinguishes the two: an
	// alert or EOF within the deadline means rejection, a timeout means
	// the connection is otherwise idle (accepted).
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

// classifyUpstreamTrust reports which trust anchor (a named trustedCAs row,
// or "gateway bundle") verifies peerCerts, trying each named certificate as
// its own standalone root before falling back to the gateway-wide upstream
// bundle when trustedCANames is empty. Returns ("", false) when none
// verify.
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
	if translator == nil || translator.GetCertStore() == nil {
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
