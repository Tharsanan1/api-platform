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
//
// Two further internal params turn on support for a client certificate
// relayed by a front proxy in a request header, rather than presented on the
// connection itself — see evaluate's doc comment for the full decision
// order:
//
//   - __wso2_internal_mtls_relays: an ordered array of {"name": "<pool entry
//     name>", "certificates": ["<PEM>", ...], "match": {...} (optional, same
//     shape as accept's)}. A relay entry is never itself accepted as a
//     client — it exists only to let this policy recognize "this connection
//     IS the trusted front proxy", never "this connection is a valid API
//     caller".
//   - __wso2_internal_mtls_header: {"name": "<header name>", "trustAny":
//     bool, "forwardToBackend": bool}. Missing entirely means no relays and
//     header mode off, with the header name defaulting to
//     X-WSO2-CLIENT-CERTIFICATE.
package mtlsauth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

	// internalRelaysParam and internalHeaderParam are the two additional
	// controller-injected params that turn on client-certificate-header
	// support: __wso2_internal_mtls_relays (an ordered array of
	// {"name", "certificates", "match"} — pool entries marked as a front-proxy
	// relay) and __wso2_internal_mtls_header ({"name", "trustAny",
	// "forwardToBackend"}). Both are optional; absent means no relays and
	// header mode off. Never present in the author-facing schema.
	internalRelaysParam = "__wso2_internal_mtls_relays"
	internalHeaderParam = "__wso2_internal_mtls_header"

	// defaultHeaderName is used when __wso2_internal_mtls_header is absent or
	// omits "name".
	defaultHeaderName = "X-WSO2-CLIENT-CERTIFICATE"

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

	// evaluationResult.source values. sourceConnection is "handshake" per
	// directive 1: the certificate came from the TLS handshake itself, as
	// opposed to a header a front proxy relayed (sourceHeader) or an
	// unconditionally-believed header (sourceBypass).
	sourceConnection = "handshake"
	sourceHeader     = "header"
	sourceBypass     = "bypass"
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
	// thumbprint is one of these values. Normalized to lowercase hex with no
	// separators at parse time. Nil means no thumbprint narrowing.
	thumbprints []string
}

// relayEntry is one parsed entry of __wso2_internal_mtls_relays: a pool
// certificate authority marked as a front-proxy relay. A relay entry can
// never itself be an accept entry (enforced by the controller's validator,
// see mtls-header-relay.feature's "cannot be accepted as a client" scenario)
// — this policy only ever uses roots/match here to decide whether the
// CONNECTION's own certificate came from a trusted relay, never to
// authenticate the relay as an API caller.
type relayEntry struct {
	name  string
	roots []*x509.Certificate

	// uriSANs/dnsSANs narrow this relay to connections whose SANs overlap
	// these values; nil means no such narrowing. Same semantics as
	// acceptEntry's fields.
	uriSANs []string
	dnsSANs []string
}

// headerConfig is the parsed __wso2_internal_mtls_header param.
type headerConfig struct {
	name             string
	trustAny         bool
	forwardToBackend bool
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

	// source, relayedBy, and relaySubject are exposed for tests and, on
	// success, copied into AuthContext.Properties by OnRequestHeaders.
	// source is one of sourceConnection/sourceHeader/sourceBypass;
	// relayedBy/relaySubject are populated only when source == sourceHeader.
	source       string
	relayedBy    string
	relaySubject string
}

// MtlsAuthPolicy authenticates API callers via mutual TLS. Unlike the
// stateless dev/sample policies elsewhere in this repo, this policy IS its
// per-binding instance state: GetPolicy parses the controller-resolved accept
// list and client-CA pool once, at policy-bind time, into x509.Certificate
// values — so a malformed pool entry surfaces as a bind-time error instead of
// being re-parsed (and possibly failing) on every request. This mirrors the
// gateway-controller's cors policy's GetPolicy: a per-binding instance
// carrying its own parsed state, rather than a stateless singleton shared
// across every binding.
type MtlsAuthPolicy struct {
	accept []acceptEntry
	pool   []*x509.Certificate
	relays []relayEntry
	header headerConfig
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
	relays, err := parseRelaysParam(params[internalRelaysParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: parsing relay list: %w", err)
	}
	header := parseHeaderParam(params[internalHeaderParam])
	return &MtlsAuthPolicy{accept: accept, pool: pool, relays: relays, header: header}, nil
}

// headerModeOn reports whether a client-certificate header can ever be
// believed for this policy instance: at least one relay entry exists, or the
// (explicitly off-by-default) trustAny bypass is configured.
func (p *MtlsAuthPolicy) headerModeOn() bool {
	return len(p.relays) > 0 || p.header.trustAny
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

// evaluate authenticates the request, fail-closed at every step per
// authentication_authorization.md GO-AUTH-001: any step that cannot decide
// denies, it never passes through.
//
// Decision order (see the package doc comment for the header/relay/bypass
// feature this implements):
//
//  1. Header absent → evaluate the connection certificate as itself.
//  2. Header present, header mode off (no relays, trustAny false) → same as 1;
//     the header is inert text.
//  3. Header present, trustAny true → the header is believed unconditionally;
//     the connection is never consulted (works with no certificate at all,
//     including plaintext).
//  4. Header present, relays configured → believed ONLY IF the connection's
//     own certificate authenticates as a relay entry (mTLS, Envoy's own
//     verdict, chain verification, and any SAN narrowing the relay entry
//     carries — the same evaluation accept entries get). Otherwise the header
//     is IGNORED (never rejected): fall back to 1, and log at Debug that a
//     header was present on a non-relay connection.
//  5. A believed header's certificate is decoded, date-checked, and run
//     through the SAME accept-list evaluation as the connection path.
func (p *MtlsAuthPolicy) evaluate(reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) evaluationResult {
	now := time.Now()

	if p.headerModeOn() {
		if headerValue, present := p.headerRawValue(reqCtx); present {
			if p.header.trustAny {
				return p.evaluateHeaderCertificate(headerValue, now, sourceBypass, "", "")
			}

			tls := reqCtx.PeerCertificate()
			if relay, relayLeaf, ok := p.matchRelay(reqCtx, tls, now); ok {
				return p.evaluateHeaderCertificate(headerValue, now, sourceHeader, relay.name, relayLeaf.Subject.String())
			}

			p.logIgnoredHeader(tls)
		}
	}

	return p.evaluateConnectionCertificate(reqCtx, now)
}

// evaluateConnectionCertificate evaluates the connection's own certificate
// against the accept list. This is
// what runs whenever the header is absent, ignored (header mode off, or on
// but no relay vouches for this connection), ignored-but-logged (step 4
// above), or simply never in play at all.
func (p *MtlsAuthPolicy) evaluateConnectionCertificate(reqCtx *policy.RequestHeaderContext, now time.Time) evaluationResult {
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

	result := p.evaluateAcceptList(leaf, p.intermediatesPool(reqCtx, tls), now, tls.SHA256Thumbprint)
	if result.authenticated {
		result.source = sourceConnection
	}
	return result
}

// evaluateHeaderCertificate decodes and evaluates a believed header value
// (step 5): decode → date-check → the same accept-list evaluation as the
// connection path, but with Intermediates limited to pool material only —
// there is no Envoy verdict and no XFCC chain for a header-carried
// certificate — and with no Envoy-thumbprint cross-check (same reason).
func (p *MtlsAuthPolicy) evaluateHeaderCertificate(raw string, now time.Time, source, relayName, relaySubject string) evaluationResult {
	deny := evaluationResult{authenticated: false, entryIndex: -1}

	leaf, err := decodeHeaderCertificate(raw)
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

	result := p.evaluateAcceptList(leaf, p.poolOnlyIntermediates(), now, "")
	if !result.authenticated {
		return result
	}
	result.source = source
	result.relayedBy = relayName
	result.relaySubject = relaySubject
	return result
}

// evaluateAcceptList is the accept-list matching loop shared by both the
// connection path and the believed-header path: the first accept entry that
// verifies leaf against its roots (via intermediates for path-building) AND
// satisfies every narrowing it carries wins.
//
// connectionThumbprint is the Envoy-reported SHA-256 digest for THIS SAME
// connection's certificate, used only as a defense-in-depth cross-check
// against an entry's configured thumbprints; pass "" when evaluating a
// header-carried leaf, which has no corresponding Envoy verdict to check
// against (skipping the cross-check, not disabling the thumbprint narrowing
// itself).
func (p *MtlsAuthPolicy) evaluateAcceptList(leaf *x509.Certificate, intermediates *x509.CertPool, now time.Time, connectionThumbprint string) evaluationResult {
	deny := evaluationResult{authenticated: false, entryIndex: -1}
	canonicalThumbprint := sha256Hex(leaf.Raw)

	for i, entry := range p.accept {
		if !verifyLeafAgainstRoots(leaf, entry.roots, intermediates, now) {
			continue
		}

		subject, ok := sanNarrowedSubject(leaf, entry.uriSANs, entry.dnsSANs)
		if !ok {
			continue
		}

		if len(entry.thumbprints) > 0 {
			if !slices.Contains(entry.thumbprints, canonicalThumbprint) {
				continue
			}
			// Defense in depth: our own PEM-derived digest must agree with
			// what Envoy reported for this same connection (skipped when
			// there is no Envoy verdict to check against — see doc comment).
			if connectionThumbprint != "" && normalizeThumbprint(connectionThumbprint) != canonicalThumbprint {
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

	deny.reason = reasonNoMatchingEntry
	return deny
}

// matchRelay reports whether the CONNECTION's own certificate (never the
// header's) authenticates as one of this policy instance's relay entries:
// mTLS presented, Envoy's own verdict positive, our own date re-check, and
// the leaf verifies against the relay's roots (Intermediates = pool + XFCC
// chain, KeyUsages ExtKeyUsageAny — identical parameters to accept-entry
// verification) and satisfies the relay's SAN narrowing if any.
func (p *MtlsAuthPolicy) matchRelay(reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS, now time.Time) (*relayEntry, *x509.Certificate, bool) {
	if tls == nil || !tls.MTLS || tls.PeerCertValid == nil || !*tls.PeerCertValid {
		return nil, nil, false
	}
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		return nil, nil, false
	}
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return nil, nil, false
	}

	intermediates := p.intermediatesPool(reqCtx, tls)
	for i := range p.relays {
		entry := &p.relays[i]
		if !verifyLeafAgainstRoots(leaf, entry.roots, intermediates, now) {
			continue
		}
		if _, ok := sanNarrowedSubject(leaf, entry.uriSANs, entry.dnsSANs); !ok {
			continue
		}
		return entry, leaf, true
	}
	return nil, nil, false
}

// logIgnoredHeader logs, at Debug, that a client-certificate header was
// present but the connection did not authenticate as a relay — so the header
// was ignored rather than trusted. Only the connection's own subject DN is
// logged (never header contents or PEM), per GO-AUTH-003/authentication_
// authorization.md's masked-logging requirement.
func (p *MtlsAuthPolicy) logIgnoredHeader(tls *policy.DownstreamTLS) {
	subject := "none"
	if tls != nil && tls.MTLS && tls.PeerCertificatePEM != "" {
		if leaf, err := parseCertificatePEM(tls.PeerCertificatePEM); err == nil {
			subject = leaf.Subject.String()
		}
	}
	slog.Debug("mtls-auth: client certificate header present on a non-relay connection",
		slog.String("subject", subject),
	)
}

// headerRawValue reads the configured client-certificate header from the
// DOWNSTREAM SNAPSHOT (never live/mutated headers — see DownstreamRequest's
// doc comment), so an earlier policy rewriting/removing the header can never
// change this decision. An empty value is treated as absent.
func (p *MtlsAuthPolicy) headerRawValue(reqCtx *policy.RequestHeaderContext) (string, bool) {
	values := reqCtx.DownstreamRequest().Headers.Get(p.header.name)
	if len(values) == 0 {
		return "", false
	}
	v := strings.TrimSpace(values[0])
	if v == "" {
		return "", false
	}
	return v, true
}

// intermediatesPool builds the path-building-only certificate pool used for
// CONNECTION-leaf verification (accept-entry and relay-entry alike): every
// client-pool certificate, plus — only because tls.MTLS is true, per
// directive 5 — any certificates in the X-Forwarded-Client-Cert Chain
// element, read from the pristine downstream snapshot.
func (p *MtlsAuthPolicy) intermediatesPool(reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS) *x509.CertPool {
	intermediates := x509.NewCertPool()
	for _, c := range p.pool {
		intermediates.AddCert(c)
	}
	if tls != nil && tls.MTLS {
		for _, c := range p.chainCertificatesFromXFCC(reqCtx) {
			intermediates.AddCert(c)
		}
	}
	return intermediates
}

// poolOnlyIntermediates builds the path-building-only certificate pool used
// for a HEADER-carried leaf: pool material only, since there is no XFCC
// chain for a certificate that never terminated a TLS connection at this
// gateway.
func (p *MtlsAuthPolicy) poolOnlyIntermediates() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range p.pool {
		pool.AddCert(c)
	}
	return pool
}

// verifyLeafAgainstRoots reports whether leaf verifies against roots (via
// intermediates for path-building), using the same VerifyOptions every
// verification in this package uses: ExtKeyUsageAny and the given point in
// time.
func verifyLeafAgainstRoots(leaf *x509.Certificate, rootCerts []*x509.Certificate, intermediates *x509.CertPool, now time.Time) bool {
	roots := x509.NewCertPool()
	for _, c := range rootCerts {
		roots.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime:   now,
	})
	return err == nil
}

// sanNarrowedSubject applies the shared SAN-narrowing/subject-derivation
// logic used by both accept entries and relay entries: returns the derived
// subject and whether leaf satisfies uriSANs/dnsSANs narrowing (both nil
// means "no such narrowing" — any leaf satisfies it).
func sanNarrowedSubject(leaf *x509.Certificate, uriSANs, dnsSANs []string) (string, bool) {
	switch {
	case len(uriSANs) > 0:
		matched := firstMatchingSAN(uriSANStrings(leaf), uriSANs)
		if matched == "" {
			return "", false
		}
		if len(dnsSANs) > 0 && firstMatchingSAN(leaf.DNSNames, dnsSANs) == "" {
			return "", false
		}
		return matched, true
	case len(dnsSANs) > 0:
		matched := firstMatchingSAN(leaf.DNSNames, dnsSANs)
		if matched == "" {
			return "", false
		}
		return matched, true
	default:
		subject := firstOf(uriSANStrings(leaf))
		if subject == "" {
			subject = firstOf(leaf.DNSNames)
		}
		if subject == "" {
			subject = leaf.Subject.String()
		}
		return subject, true
	}
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

	properties := map[string]string{
		"subjectDN":    result.subjectDN,
		"issuerDN":     result.issuerDN,
		"serialNumber": result.serialNumber,
		"notAfter":     result.notAfter.UTC().Format(time.RFC3339),
		"matchedEntry": strconv.Itoa(result.entryIndex),
		"source":       result.source,
	}
	if result.relayedBy != "" {
		properties["relayedBy"] = result.relayedBy
		properties["relaySubject"] = result.relaySubject
	}

	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       result.subject,
		Issuer:        result.issuerCA,
		CredentialID:  result.credentialID,
		Properties:    properties,
		Previous:      reqCtx.SharedContext.AuthContext,
	}

	action := policy.UpstreamRequestHeaderModifications{}
	// A header the gateway BELIEVED (source == header/bypass) is the one
	// case forwardToBackend's opt-in means anything: the router already
	// strips the header on every route when forwardToBackend is false, so
	// there is nothing for this policy to do in that case. On a route where
	// forwardToBackend is true, this policy must still remove the header
	// whenever it did NOT believe it — a header the connection's own
	// certificate simply carried past unexamined, or one from a
	// non-relay/non-bypassed connection, never reaches upstream.
	believed := result.source == sourceHeader || result.source == sourceBypass
	if p.header.forwardToBackend && !believed {
		action.HeadersToRemove = []string{p.header.name}
	}
	return action
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

// parseRelaysParam parses __wso2_internal_mtls_relays: an array of relay
// entries (pool entries marked as a front-proxy relay). Absent/nil means no
// relays — header mode stays off unless trustAny is separately configured. A
// certificate parse failure here is a GetPolicy error, mirroring
// parseAcceptParam; a malformed narrowing value is dropped rather than
// failing the whole entry, for the same reason.
func parseRelaysParam(raw interface{}) ([]relayEntry, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", internalRelaysParam)
	}

	entries := make([]relayEntry, 0, len(items))
	for i, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", internalRelaysParam, i)
		}

		name, _ := obj["name"].(string)

		certsRaw, ok := obj["certificates"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d].certificates must be an array", internalRelaysParam, i)
		}
		roots := make([]*x509.Certificate, 0, len(certsRaw))
		for j, c := range certsRaw {
			pemStr, ok := c.(string)
			if !ok {
				return nil, fmt.Errorf("%s[%d].certificates[%d] must be a string", internalRelaysParam, i, j)
			}
			cert, err := parseCertificatePEM(pemStr)
			if err != nil {
				return nil, fmt.Errorf("%s[%d].certificates[%d]: %w", internalRelaysParam, i, j, err)
			}
			roots = append(roots, cert)
		}

		entry := relayEntry{name: name, roots: roots}

		if matchRaw, ok := obj["match"]; ok && matchRaw != nil {
			matchObj, ok := matchRaw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s[%d].match must be an object", internalRelaysParam, i)
			}
			entry.uriSANs = toStringSliceOrNil(matchObj["uriSANs"])
			entry.dnsSANs = toStringSliceOrNil(matchObj["dnsSANs"])
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

// parseHeaderParam parses __wso2_internal_mtls_header: {"name", "trustAny",
// "forwardToBackend"}. Unlike parseAcceptParam/parseRelaysParam, absence or a
// malformed shape is never a GetPolicy error — this param only ever narrows
// optional, best-effort behaviour (a missing/invalid field falls back to its
// documented default) and never carries certificate material that could fail
// to parse.
func parseHeaderParam(raw interface{}) headerConfig {
	cfg := headerConfig{name: defaultHeaderName}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return cfg
	}
	if name, ok := obj["name"].(string); ok && strings.TrimSpace(name) != "" {
		cfg.name = name
	}
	if trustAny, ok := obj["trustAny"].(bool); ok {
		cfg.trustAny = trustAny
	}
	if forward, ok := obj["forwardToBackend"].(bool); ok {
		cfg.forwardToBackend = forward
	}
	return cfg
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

// decodeHeaderCertificate decodes a client-certificate header value carrying
// a single certificate, accepting three forms (mtls-header-relay.feature's
// "encoded as pem"/"encoded as base64" scenarios): a URL-encoded or plain PEM
// document (delegated to parseCertificatePEM), or a bare base64 body with no
// PEM armor at all — either base64 of raw DER, or base64 of a PEM document
// that itself lacks BEGIN/END armor. Anything else is a decode failure,
// which callers map to the uniform reasonInvalidCert deny.
func decodeHeaderCertificate(raw string) (*x509.Certificate, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty certificate header value")
	}

	if cert, err := parseCertificatePEM(raw); err == nil {
		return cert, nil
	}

	// A value that's still URL-encoded but doesn't parse as PEM until
	// decoded (parseCertificatePEM only attempts that fallback when the raw
	// string contains no "-----BEGIN" marker at all).
	candidate := raw
	if decoded, err := url.PathUnescape(raw); err == nil {
		candidate = decoded
	}
	if cert, err := parseCertificatePEM(candidate); err == nil {
		return cert, nil
	}

	// PEM armor present but with its internal newlines replaced by spaces (or
	// otherwise stripped) — a common proxy encoding, since an HTTP header
	// cannot carry a literal newline. pem.Decode requires the BEGIN line to
	// be newline-terminated, so this doesn't parse as PEM above; falling
	// through to the bare-base64 branch below would be wrong too, since
	// stripping ALL whitespace there glues the armor markers into the
	// base64 body instead of removing them. Reconstitute proper PEM text
	// first and decode that instead. Handles several concatenated
	// certificates in this form; only the first is the identity.
	if cert, ok := decodeSpaceJoinedPEM(candidate); ok {
		return cert, nil
	}

	// Bare base64 body: strip any whitespace/newlines and try every base64
	// variant a caller might reasonably use, decoding first to DER and, if
	// that isn't a certificate, to a PEM document lacking armor.
	stripped := strings.Join(strings.Fields(candidate), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(stripped)
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(decoded); err == nil {
			return cert, nil
		}
		if block, _ := pem.Decode(decoded); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("could not decode certificate header value")
}

// decodeSpaceJoinedPEM reports whether raw contains one or more
// "-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----" spans whose
// internal newlines were replaced by spaces (or otherwise stripped), and if
// so reconstitutes proper PEM text and decodes it. Only the first
// certificate found is returned — when several are concatenated in this
// form, the first is the identity, exactly as parseXFCCChainCertificates
// treats a Chain= element's leaf-then-intermediates ordering.
func decodeSpaceJoinedPEM(raw string) (*x509.Certificate, bool) {
	rebuilt := reconstitutePEMArmor(raw)
	if rebuilt == "" {
		return nil, false
	}
	certs := parsePEMCertificates(rebuilt)
	if len(certs) == 0 {
		return nil, false
	}
	return certs[0], true
}

// reconstitutePEMArmor rebuilds well-formed, newline-delimited PEM text from
// a value whose PEM armor is intact but whose internal line breaks were
// replaced by spaces (or otherwise collapsed) — an HTTP header cannot carry a
// literal newline, so this is what several front proxies emit instead of
// percent-encoding the certificate. It finds every
// "-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----" span in raw,
// strips all whitespace from each span's body, re-wraps it at the
// conventional 64 characters per line, and concatenates the results — so a
// value carrying several certificates back-to-back reconstitutes as several
// proper PEM blocks, ready for parsePEMCertificates. Returns "" if raw
// contains no complete BEGIN/END span at all.
func reconstitutePEMArmor(raw string) string {
	const beginMarker = "-----BEGIN CERTIFICATE-----"
	const endMarker = "-----END CERTIFICATE-----"

	var out strings.Builder
	rest := raw
	for {
		beginIdx := strings.Index(rest, beginMarker)
		if beginIdx < 0 {
			break
		}
		afterBegin := rest[beginIdx+len(beginMarker):]
		endIdx := strings.Index(afterBegin, endMarker)
		if endIdx < 0 {
			break
		}
		body := afterBegin[:endIdx]
		stripped := strings.Join(strings.Fields(body), "")

		out.WriteString(beginMarker)
		out.WriteByte('\n')
		for i := 0; i < len(stripped); i += 64 {
			end := i + 64
			if end > len(stripped) {
				end = len(stripped)
			}
			out.WriteString(stripped[i:end])
			out.WriteByte('\n')
		}
		out.WriteString(endMarker)
		out.WriteByte('\n')

		rest = afterBegin[endIdx+len(endMarker):]
	}
	return out.String()
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
