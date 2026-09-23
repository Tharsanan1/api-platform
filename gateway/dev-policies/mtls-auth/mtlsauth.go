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

// Package mtlsauth implements the mtls-auth policy: it authenticates API
// callers by matching the client certificate presented on the gateway's
// mutual-TLS-capable HTTPS listener against the policy instance's own
// `accept` list (a subset of the gateway's client-CA pool, optionally
// narrowed by SAN match or certificate thumbprint).
//
// The HTTPS listener itself is derived, not configured: it requests a
// client certificate from every connection while at least one deployed API
// attaches this policy (see pkg/xds's createDownstreamTLSContext in the
// gateway-controller), and never closes a connection over the certificate it
// receives — this policy is what turns "a certificate was presented" into
// "this API's caller is authenticated".
//
// The controller resolves this policy instance's `accept` list against the
// gateway's client-CA pool and injects the result as two internal params that
// never appear in the author-facing schema (policy-definition.yaml's
// additionalProperties: false is enforced by the controller's own validator,
// not here):
//
//   - __wso2_internal_mtls_accept: an ordered array of
//     {"ca": "<pool entry name>", "certificates": ["<PEM>", ...],
//     "match": {"uriSANs": [...], "dnsSANs": [...]} (optional),
//     "thumbprints": ["<64 lowercase hex>", ...] (optional)}. Entries are
//     tried in order; the first that verifies AND satisfies every narrowing
//     it carries wins (see evaluate).
//   - __wso2_internal_mtls_pool: every certificate in the gateway's
//     client-CA pool, PEM-encoded. This is path-building material ONLY —
//     every use of it below goes into an x509.VerifyOptions.Intermediates
//     pool, never Roots. A certificate belongs in Roots for a given request
//     only via the specific accept entry that named it.
package mtlsauth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType identifies this authentication mechanism in policy.AuthContext,
	// mirroring the "jwt"/"basic"/"apikey" convention used by the other auth
	// policies.
	AuthType = "mtls"

	defaultOnFailureStatusCode = 401
	defaultErrorMessageFormat  = "json"
	defaultErrorMessage        = "Authentication failed"

	// internalAcceptParam and internalPoolParam are the controller-injected
	// params described in the package doc comment. Never present in the
	// author-facing policy-definition.yaml schema.
	internalAcceptParam = "__wso2_internal_mtls_accept"
	internalPoolParam   = "__wso2_internal_mtls_pool"

	// xfccHeaderName mirrors the gateway-controller's pkg/xds/translator.go
	// constant of the same name — the header Envoy writes with SANITIZE_SET
	// whenever a certificate was presented on this connection.
	xfccHeaderName = "x-forwarded-client-cert"

	// Deny reasons. These are for telemetry/Debug logging only (see
	// evaluationResult) — every deny produces the identical configured
	// failure response regardless of reason, per error-handling.md's
	// unified-auth-failure directive.
	reasonAttributeAbsent = "attribute_absent"
	reasonNoCertificate   = "no_certificate"
	reasonExpired         = "expired"
	reasonNotYetValid     = "not_yet_valid"
	reasonUntrustedChain  = "untrusted_chain"
	reasonInvalidCert     = "invalid_certificate"
	reasonNoMatchingEntry = "no_matching_entry"
)

// acceptEntry is one parsed, ready-to-verify entry of the controller-resolved
// accept list (see __wso2_internal_mtls_accept above).
type acceptEntry struct {
	ca    string
	roots []*x509.Certificate

	// uriSANs/dnsSANs narrow this entry to certificates whose SANs overlap
	// these values; nil (not empty) means "this entry carries no such
	// narrowing" — evaluate treats the two cases differently (see directive 6
	// in the package doc comment).
	uriSANs []string
	dnsSANs []string

	// thumbprints narrows this entry to certificates whose canonical SHA-256
	// fingerprint is one of these values. Normalized to lowercase hex with no
	// separators at parse time. Nil means no thumbprint narrowing.
	thumbprints []string
}

// evaluationResult is evaluate's outcome. Deliberately small and exposed
// (unexported, but visible to same-package tests) so tests can assert the
// derived deny reason and matched entry index without inspecting the
// resulting HTTP response.
type evaluationResult struct {
	authenticated bool
	reason        string
	entryIndex    int // index into accept of the matched entry; -1 when authenticated is false

	// Populated only when authenticated is true — everything OnRequestHeaders
	// needs to build policy.AuthContext.
	subject      string
	issuerCA     string
	credentialID string
	subjectDN    string
	issuerDN     string
	serialNumber string
	notAfter     time.Time
}

// MtlsAuthPolicy authenticates API callers via mutual TLS. Unlike the
// stateless dev/sample policies elsewhere in this repo, this policy IS its
// per-binding instance state: GetPolicy parses the controller-resolved accept
// list and client-CA pool once, at policy-bind time, into x509.Certificate
// values — so a malformed pool entry surfaces as a bind-time error instead of
// being re-parsed (and possibly failing) on every request. This mirrors the
// gateway-controller's cors policy's GetPolicy, not this package's own
// previous singleton-with-no-state convention.
type MtlsAuthPolicy struct {
	accept []acceptEntry
	pool   []*x509.Certificate
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
//
// Deploy-time validation of `accept` (the gateway-controller's mtls-auth
// validator) is what guarantees every instance of this policy can name at
// least one reachable client authority — see go-network-service-hardening.md
// and authentication_authorization.md for the invariants that validation, and
// this policy's own fail-closed behavior below, jointly uphold. A parse
// failure here (a pool or accept-list certificate that isn't valid PEM/DER) is
// itself a GetPolicy error, refusing to bind this policy instance rather than
// deferring the failure to request time.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	pool, err := parsePoolParam(params[internalPoolParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: parsing client-CA pool: %w", err)
	}
	accept, err := parseAcceptParam(params[internalAcceptParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: parsing accept list: %w", err)
	}
	return &MtlsAuthPolicy{accept: accept, pool: pool}, nil
}

// Mode declares that mtls-auth only needs the request-header phase: the
// certificate it authenticates against is a connection-level fact (available
// as soon as headers are), never something carried in the request body.
func (p *MtlsAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// evaluate authenticates the request against this policy instance's accept
// list, fail-closed at every step per authentication_authorization.md
// GO-AUTH-001: any step that cannot decide denies, it never passes through.
func (p *MtlsAuthPolicy) evaluate(reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) evaluationResult {
	deny := evaluationResult{authenticated: false, entryIndex: -1}

	// Step 1: no gateway assertion about this connection's certificate at
	// all. Nil MUST be treated as authentication failure, never as "no
	// certificate required" — see policy.DownstreamTLS's doc comment.
	tls := reqCtx.PeerCertificate()
	if tls == nil {
		deny.reason = reasonAttributeAbsent
		return deny
	}

	// Step 2: the gateway populated TLS but no certificate was presented on
	// this connection at all.
	if !tls.MTLS {
		deny.reason = reasonNoCertificate
		return deny
	}

	// Step 3: consult Envoy's own verification verdict against the
	// client-CA pool before doing any of our own cryptographic work.
	if tls.PeerCertValid == nil {
		deny.reason = reasonAttributeAbsent
		return deny
	}
	now := time.Now()
	if !*tls.PeerCertValid {
		deny.reason = p.deriveRejectReason(tls, now)
		return deny
	}

	// Step 4: parse the leaf and re-check validity dates ourselves on every
	// request — Envoy's verdict above is not a substitute for this policy's
	// own accept-list evaluation.
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		deny.reason = reasonInvalidCert
		return deny
	}
	if now.After(leaf.NotAfter) {
		deny.reason = reasonExpired
		return deny
	}
	if now.Before(leaf.NotBefore) {
		deny.reason = reasonNotYetValid
		return deny
	}

	// Step 5: intermediates pool — every client-pool certificate, plus (only
	// because tls.MTLS is true, per directive 5) any certificates in the
	// X-Forwarded-Client-Cert Chain element, read from the pristine
	// downstream snapshot. Chain certificates are path-building material
	// only, never Roots.
	intermediates := x509.NewCertPool()
	for _, c := range p.pool {
		intermediates.AddCert(c)
	}
	if tls.MTLS {
		for _, c := range p.chainCertificatesFromXFCC(reqCtx) {
			intermediates.AddCert(c)
		}
	}

	canonicalThumbprint := sha256Hex(leaf.Raw)

	// Step 6: first accept entry that verifies AND satisfies every narrowing
	// it carries wins.
	for i, entry := range p.accept {
		roots := x509.NewCertPool()
		for _, c := range entry.roots {
			roots.AddCert(c)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			CurrentTime:   now,
		}); err != nil {
			continue
		}

		var subject string
		switch {
		case len(entry.uriSANs) > 0:
			matched := firstMatchingSAN(uriSANStrings(leaf), entry.uriSANs)
			if matched == "" {
				continue
			}
			if len(entry.dnsSANs) > 0 && firstMatchingSAN(leaf.DNSNames, entry.dnsSANs) == "" {
				continue
			}
			subject = matched
		case len(entry.dnsSANs) > 0:
			matched := firstMatchingSAN(leaf.DNSNames, entry.dnsSANs)
			if matched == "" {
				continue
			}
			subject = matched
		default:
			subject = firstOf(uriSANStrings(leaf))
			if subject == "" {
				subject = firstOf(leaf.DNSNames)
			}
			if subject == "" {
				subject = leaf.Subject.String()
			}
		}

		if len(entry.thumbprints) > 0 {
			if !slices.Contains(entry.thumbprints, canonicalThumbprint) {
				continue
			}
			// Defense in depth: our own PEM-derived digest must agree with
			// what Envoy reported for this same connection.
			if normalizeThumbprint(tls.SHA256Thumbprint) != canonicalThumbprint {
				continue
			}
		}

		return evaluationResult{
			authenticated: true,
			entryIndex:    i,
			subject:       subject,
			issuerCA:      entry.ca,
			credentialID:  canonicalThumbprint,
			subjectDN:     leaf.Subject.String(),
			issuerDN:      leaf.Issuer.String(),
			serialNumber:  leaf.SerialNumber.String(),
			notAfter:      leaf.NotAfter,
		}
	}

	// Step 7: no entry matched.
	deny.reason = reasonNoMatchingEntry
	return deny
}

// deriveRejectReason is called only when Envoy has already rejected the
// certificate (tls.PeerCertValid is a non-nil false); its result is for
// telemetry/Debug logging only and never changes the deny decision itself.
func (p *MtlsAuthPolicy) deriveRejectReason(tls *policy.DownstreamTLS, now time.Time) string {
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		return reasonInvalidCert
	}
	if now.After(leaf.NotAfter) {
		return reasonExpired
	}
	if now.Before(leaf.NotBefore) {
		return reasonNotYetValid
	}

	// Not a date problem — check whether a path exists to ANY certificate in
	// the gateway's whole client-CA pool (not just this API's narrower accept
	// list), to distinguish "the chain genuinely doesn't reach a trusted
	// authority" from some other reason Envoy rejected it.
	pool := x509.NewCertPool()
	for _, c := range p.pool {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: pool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	}); err != nil {
		return reasonUntrustedChain
	}
	return reasonInvalidCert
}

// chainCertificatesFromXFCC extracts every certificate in the Chain= element
// of the X-Forwarded-Client-Cert header, read from the pristine downstream
// snapshot (DownstreamRequest(), never live/mutated headers) — a client can
// never inject a value here because Envoy writes this header with
// SANITIZE_SET, overwriting anything the caller sent.
func (p *MtlsAuthPolicy) chainCertificatesFromXFCC(reqCtx *policy.RequestHeaderContext) []*x509.Certificate {
	values := reqCtx.DownstreamRequest().Headers.Get(xfccHeaderName)
	if len(values) == 0 {
		return nil
	}
	return parseXFCCChainCertificates(values[0])
}

// OnRequestHeaders performs mTLS authentication in the request-header phase.
func (p *MtlsAuthPolicy) OnRequestHeaders(_ context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", defaultOnFailureStatusCode)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", defaultErrorMessageFormat)
	errorMessage := getStringParam(params, "errorMessage", defaultErrorMessage)

	result := p.evaluate(reqCtx, params)
	if !result.authenticated {
		slog.Debug("mtls-auth: rejecting request",
			slog.String("reason", result.reason),
			slog.String("path", reqCtx.Path),
		)
		return p.handleAuthFailure(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage)
	}

	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       result.subject,
		Issuer:        result.issuerCA,
		CredentialID:  result.credentialID,
		Properties: map[string]string{
			"subjectDN":    result.subjectDN,
			"issuerDN":     result.issuerDN,
			"serialNumber": result.serialNumber,
			"notAfter":     result.notAfter.UTC().Format(time.RFC3339),
			"matchedEntry": strconv.Itoa(result.entryIndex),
			"source":       "connection",
		},
		Previous: reqCtx.SharedContext.AuthContext,
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// handleAuthFailure builds the uniform rejection response and records the
// failed attempt on SharedContext.AuthContext for any downstream multi-layer
// auth chain. It mirrors jwt-auth's handleAuthFailureHeaders byte-for-byte
// for the default case, per error-handling.md's unified-auth-failure
// directive: identical status/body regardless of *why* authentication
// failed, and no WWW-Authenticate header — mutual TLS has no challenge
// header equivalent to offer.
func (p *MtlsAuthPolicy) handleAuthFailure(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage string) policy.RequestHeaderAction {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}

	headers := map[string]string{
		"content-type": "application/json",
	}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	case "minimal":
		body = "Unauthorized"
	default:
		// json.Marshal of a map[string]interface{} sorts keys alphabetically,
		// so this always renders as {"error":...,"message":...} — matching
		// the exact byte-for-byte contract in mtls-listener.feature.
		bodyBytes, _ := json.Marshal(map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		})
		body = string(bodyBytes)
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// ─── Instance-param parsing (GetPolicy time) ─────────────────────────────────

// parsePoolParam parses __wso2_internal_mtls_pool: an array of PEM strings.
// A parse failure here is a GetPolicy error (see GetPolicy's doc comment).
func parsePoolParam(raw interface{}) ([]*x509.Certificate, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", internalPoolParam)
	}
	certs := make([]*x509.Certificate, 0, len(items))
	for i, item := range items {
		pemStr, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a string", internalPoolParam, i)
		}
		cert, err := parseCertificatePEM(pemStr)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", internalPoolParam, i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseAcceptParam parses __wso2_internal_mtls_accept: an ordered array of
// accept-list entries. A certificate parse failure here is a GetPolicy error;
// a malformed (non-string) narrowing value is dropped rather than failing the
// whole entry, since narrowing is optional and best-effort by nature.
func parseAcceptParam(raw interface{}) ([]acceptEntry, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", internalAcceptParam)
	}

	entries := make([]acceptEntry, 0, len(items))
	for i, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", internalAcceptParam, i)
		}

		ca, _ := obj["ca"].(string)

		certsRaw, ok := obj["certificates"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d].certificates must be an array", internalAcceptParam, i)
		}
		roots := make([]*x509.Certificate, 0, len(certsRaw))
		for j, c := range certsRaw {
			pemStr, ok := c.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d].certificates[%d] must be a string", internalAcceptParam, i, j)
			}
			cert, err := parseCertificatePEM(pemStr)
			if err != nil {
				return nil, fmt.Errorf("%s[%d].certificates[%d]: %w", internalAcceptParam, i, j, err)
			}
			roots = append(roots, cert)
		}

		entry := acceptEntry{ca: ca, roots: roots}

		if matchRaw, ok := obj["match"]; ok && matchRaw != nil {
			matchObj, ok := matchRaw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s[%d].match must be an object", internalAcceptParam, i)
			}
			entry.uriSANs = toStringSliceOrNil(matchObj["uriSANs"])
			entry.dnsSANs = toStringSliceOrNil(matchObj["dnsSANs"])
		}

		if thumbsRaw, ok := obj["thumbprints"]; ok && thumbsRaw != nil {
			for _, t := range toStringSliceOrNil(thumbsRaw) {
				entry.thumbprints = append(entry.thumbprints, normalizeThumbprint(t))
			}
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

func toStringSliceOrNil(raw interface{}) []string {
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeThumbprint mirrors policy-definition.yaml's documented
// normalization for `thumbprints`: strips a "sha256:" prefix and any colon
// separators, lowercases the rest.
func normalizeThumbprint(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.TrimPrefix(t, "sha256:")
	t = strings.ReplaceAll(t, ":", "")
	return t
}

// parseCertificatePEM decodes a single PEM-encoded certificate. Tolerates a
// URL-encoded PEM string too: Envoy documents connection.peer_certificate as
// plain PEM, but some Envoy builds emit it percent-encoded the same way
// XFCC's Cert/Chain elements are (see parseXFCCChainCertificates) — if the
// input doesn't look like PEM outright, try one RFC 3986 percent-decode
// before giving up.
func parseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil && !strings.Contains(pemStr, "-----BEGIN") {
		if decoded, err := url.PathUnescape(pemStr); err == nil {
			block, _ = pem.Decode([]byte(decoded))
		}
	}
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

// parsePEMCertificates decodes every CERTIFICATE PEM block in data,
// concatenated back-to-back as Envoy's XFCC Chain= element carries them.
// Unlike parseCertificatePEM, a block that fails to parse is silently
// skipped rather than erroring: this is supplementary path-building
// material read from a request-scoped header, not policy configuration, so
// a malformed entry degrades verification rather than aborting the request.
func parsePEMCertificates(data string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
}

// ─── X-Forwarded-Client-Cert parsing ─────────────────────────────────────────

// parseXFCCChainCertificates extracts and parses every certificate from the
// Chain= element of an X-Forwarded-Client-Cert header value, as Envoy writes
// it under SANITIZE_SET (see xfccHeaderName's doc comment). This gateway is
// the sole proxy terminating the client's TLS connection, so SANITIZE_SET
// guarantees the value is exactly one hop's semicolon-separated field list —
// there is no comma-separated multi-hop chain to split first.
func parseXFCCChainCertificates(xfcc string) []*x509.Certificate {
	value, ok := xfccFieldValue(xfcc, "Chain")
	if !ok || value == "" {
		return nil
	}
	// RFC 3986 percent-decoding, NOT form/query decoding: Cert/Chain values
	// are URL-encoded PEM, and PEM's base64 alphabet includes '+' as a
	// meaningful character. url.QueryUnescape would corrupt a literal '+'
	// into a space; url.PathUnescape decodes %XX sequences only and leaves
	// '+' alone.
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return nil
	}
	return parsePEMCertificates(decoded)
}

// xfccFieldValue returns the value of the named field (case-insensitive) in
// a single XFCC hop entry — a semicolon-separated Key=Value list where a
// value may be double-quoted (required whenever it contains a ';', ',', or
// '"') with '\\'-escaped '"' and '\\' inside the quotes.
func xfccFieldValue(entry, wantKey string) (string, bool) {
	i, n := 0, len(entry)
	for i < n {
		for i < n && entry[i] == ';' {
			i++
		}
		if i >= n {
			break
		}
		eq := strings.IndexByte(entry[i:], '=')
		if eq < 0 {
			break
		}
		key := entry[i : i+eq]
		i += eq + 1

		var value strings.Builder
		if i < n && entry[i] == '"' {
			i++
			for i < n {
				c := entry[i]
				if c == '\\' && i+1 < n {
					value.WriteByte(entry[i+1])
					i += 2
					continue
				}
				if c == '"' {
					i++
					break
				}
				value.WriteByte(c)
				i++
			}
		} else {
			start := i
			for i < n && entry[i] != ';' {
				i++
			}
			value.WriteString(entry[start:i])
		}

		if strings.EqualFold(key, wantKey) {
			return value.String(), true
		}

		for i < n && entry[i] != ';' {
			i++
		}
	}
	return "", false
}

// ─── SAN helpers ──────────────────────────────────────────────────────────────

func uriSANStrings(leaf *x509.Certificate) []string {
	if len(leaf.URIs) == 0 {
		return nil
	}
	out := make([]string, len(leaf.URIs))
	for i, u := range leaf.URIs {
		out[i] = u.String()
	}
	return out
}

// firstMatchingSAN returns the first value in accepted that is present among
// candidates, exact string comparison only (no wildcard/pattern matching).
func firstMatchingSAN(candidates []string, accepted []string) string {
	if len(candidates) == 0 || len(accepted) == 0 {
		return ""
	}
	present := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		present[c] = struct{}{}
	}
	for _, want := range accepted {
		if _, ok := present[want]; ok {
			return want
		}
	}
	return ""
}

func firstOf(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ─── Simple param helpers ─────────────────────────────────────────────────────

func getIntParam(params map[string]interface{}, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return def
	}
}

func getStringParam(params map[string]interface{}, key, def string) string {
	v, ok := params[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return def
	}
	return s
}
