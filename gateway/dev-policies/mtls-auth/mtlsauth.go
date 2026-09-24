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
// The gateway's client certificate authority pool does not travel in this
// policy's params. The controller publishes each pool entry once per gateway
// as a shared lazy resource (see authorities.go for its shape), and every
// instance of this policy reads the same parsed copy of that pool, rebuilt
// once per store version. A pool change is therefore seen by every API on its
// next request, without any policy chain being pushed. Every certificate of
// every pool entry is path-building material ONLY — it goes into an
// x509.VerifyOptions.Intermediates pool, never Roots. A certificate belongs in
// Roots for a given request only via the accept entry that names its pool
// entry.
//
// The controller injects two internal params that never appear in the
// author-facing schema (policy-definition.yaml's additionalProperties: false
// is enforced by the controller's own validator, not here):
//
//   - __wso2_internal_mtls_accept: the author's accept list as an ordered
//     array of {"ca": "<pool entry name>", "match": {"uriSANs": [...],
//     "dnsSANs": [...]} (optional), "thumbprints": ["<64 lowercase hex>",
//     ...] (optional)}. Entries are tried in order; the first whose pool
//     entry verifies the certificate AND whose narrowing it satisfies wins
//     (see evaluate). An entry naming no client entry currently in the pool
//     matches nothing. Absent when the author omitted accept: every client
//     entry in the pool is accepted, in name order, with no narrowing.
//   - __wso2_internal_mtls_header: {"name": "<header name>", "trustAny":
//     bool, "forwardToBackend": bool}. Missing entirely means header mode is
//     off unless the pool holds a relay entry, with the header name
//     defaulting to X-WSO2-CLIENT-CERTIFICATE.
//
// Relay entries in the pool, and trustAny, turn on support for a client
// certificate relayed by a front proxy in a request header, rather than
// presented on the connection itself. A relay entry is never itself accepted
// as a client — it exists only to let this policy recognize "this connection
// IS the trusted front proxy", never "this connection is a valid API
// caller". The connection's own certificate is always judged first; a header
// is only ever judged when that certificate did not pass `accept` — see
// evaluate's doc comment for the full decision order.
//
// One developer-facing parameter shapes what reaches the backend:
// forwardCertificate (default true). When false, an allowed request reaches
// this API's backend with neither X-Forwarded-Client-Cert nor the relayed
// certificate header.
package mtlsauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

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

	// internalAcceptParam and internalHeaderParam are the controller-injected
	// params described in the package doc comment. Never present in the
	// author-facing policy-definition.yaml schema.
	internalAcceptParam = "__wso2_internal_mtls_accept"
	internalHeaderParam = "__wso2_internal_mtls_header"

	// defaultHeaderName is used when __wso2_internal_mtls_header is absent or
	// omits "name".
	defaultHeaderName = "X-WSO2-CLIENT-CERTIFICATE"

	// forwardCertificateParam is the developer-facing parameter that, when
	// false, removes every certificate header before this API's backend.
	forwardCertificateParam = "forwardCertificate"

	// xfccHeaderName mirrors the gateway-controller's pkg/xds/translator.go
	// constant of the same name — the header Envoy writes with SANITIZE_SET
	// whenever a certificate was presented on this connection.
	xfccHeaderName = "x-forwarded-client-cert"

	// Deny reasons. These are for telemetry/Debug logging and the
	// mtls_auth.reason span attribute only (see evaluationResult) — every
	// deny produces the identical configured failure response regardless of
	// reason, per error-handling.md's unified-auth-failure directive.
	reasonAttributeAbsent = "attribute_absent"
	reasonNoCertificate   = "no_certificate"
	reasonExpired         = "expired"
	reasonNotYetValid     = "not_yet_valid"
	reasonUntrustedChain  = "untrusted_chain"
	reasonInvalidCert     = "invalid_certificate"

	// The three accept-list rejection reasons, in increasing order of
	// specificity: authority_not_accepted (no entry's authority verified the
	// certificate at all) < san_mismatch (an entry's authority matched but
	// its SAN narrowing didn't) < thumbprint_mismatch (authority and SAN both
	// matched but the thumbprint narrowing didn't). evaluateAcceptList
	// reports the most specific of these reached across every entry, not
	// just the first or last.
	reasonAuthorityNotAccepted = "authority_not_accepted"
	reasonSANMismatch          = "san_mismatch"
	reasonThumbprintMismatch   = "thumbprint_mismatch"

	// evaluationResult.source values. sourceHandshake is "handshake" per
	// directive 1: the certificate came from the TLS handshake itself, as
	// opposed to a header a front proxy relayed (sourceHeader) or an
	// unconditionally-believed header (sourceBypass).
	sourceHandshake = "handshake"
	sourceHeader    = "header"
	sourceBypass    = "bypass"
)

// acceptEntry is one parsed entry of the accept list (see
// __wso2_internal_mtls_accept above): the pool entry it names and the
// narrowing it applies. Its trust anchors come from the pool, per request.
type acceptEntry struct {
	ca string

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

	// subject and issuerCA are populated only when authenticated is true —
	// everything else OnRequestHeaders needs to build policy.AuthContext
	// beyond what's below.
	subject  string
	issuerCA string

	// credentialID (the canonical SHA-256 thumbprint), subjectDN, and
	// notAfter are populated whenever a leaf certificate was successfully
	// parsed and date-checked, on both allow and deny — every step past that
	// point evaluated an actual certificate, so OnRequestHeaders' span
	// attributes (tls.client.hash.sha256/tls.client.subject/tls.client.not_after)
	// still have something to report even on a reject.
	credentialID string
	subjectDN    string
	issuerDN     string
	serialNumber string
	notAfter     time.Time

	// source, relayedBy, and relaySubject are exposed for tests and copied
	// into span attributes by OnRequestHeaders on every outcome — never
	// gated on authenticated. source is one of
	// sourceHandshake/sourceHeader/sourceBypass; relayedBy/relaySubject are
	// populated whenever source == sourceHeader, allow or deny alike (the
	// connection already proved itself a trusted relay before the header's
	// own certificate was ever evaluated).
	source       string
	relayedBy    string
	relaySubject string
}

// MtlsAuthPolicy authenticates API callers via mutual TLS. An instance holds
// only what its binding configured — the accept list's names and narrowing,
// the header settings, forwardCertificate — and no certificate material: the
// pool it verifies against is the shared, per-version parsed set read on
// every request (see authorityCache).
type MtlsAuthPolicy struct {
	// accept is the author's accept list; nil with inheritAccept set when the
	// author omitted it, meaning every client entry in the pool.
	accept        []acceptEntry
	inheritAccept bool

	// acceptNames is accept's pool entry names joined in order, identifying
	// this list in the warning logged when none of them is in the pool.
	acceptNames string

	header headerConfig

	// forwardCertificate is the developer-facing parameter of the same name:
	// false removes X-Forwarded-Client-Cert and the relayed certificate
	// header from every request this policy allows.
	forwardCertificate bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
//
// Deploy-time validation of `accept` (the gateway-controller's mtls-auth
// validator) is what guarantees every instance of this policy names only
// client authorities that were in the pool when it was deployed — see
// go-network-service-hardening.md and authentication_authorization.md for
// the invariants that validation, and this policy's own fail-closed behavior
// below, jointly uphold. Binding parses no certificates; a malformed accept
// list or forwardCertificate is a GetPolicy error, refusing to bind this
// policy instance rather than guessing.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	accept, err := parseAcceptParam(params[internalAcceptParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: parsing accept list: %w", err)
	}
	forwardCertificate, err := parseForwardCertificateParam(params[forwardCertificateParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: %w", err)
	}
	names := make([]string, len(accept))
	for i, entry := range accept {
		names[i] = entry.ca
	}
	return &MtlsAuthPolicy{
		accept:             accept,
		inheritAccept:      params[internalAcceptParam] == nil,
		acceptNames:        strings.Join(names, ","),
		header:             parseHeaderParam(params[internalHeaderParam]),
		forwardCertificate: forwardCertificate,
	}, nil
}

// headerModeOn reports whether a client-certificate header can ever be
// believed: the pool holds at least one relay entry, or the (explicitly
// off-by-default) trustAny bypass is configured.
func (p *MtlsAuthPolicy) headerModeOn(set *authoritySet) bool {
	return len(set.relays) > 0 || p.header.trustAny
}

// acceptEntries returns the accept list evaluated against set: the author's
// own list, or — when the author omitted it — every client entry in set.
func (p *MtlsAuthPolicy) acceptEntries(set *authoritySet) []acceptEntry {
	if p.inheritAccept {
		return set.inherited
	}
	return p.accept
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
// The connection's own certificate is judged before any header. "Good"
// below means Envoy reported a certificate on this connection and verified
// it against the client-CA pool; "judged" means a header is decoded,
// date-checked and run through the same accept-list evaluation as a
// connection certificate.
//
//  1. The connection is good.
//     a. Its certificate passes accept → allow as the connection
//     (source handshake). Any header is ignored.
//     b. Otherwise, with a header present and header mode on, the header is
//     judged when trustAny is on (source bypass) or when the connection
//     matches a relay entry (source header, relayedBy set). Either way
//     a header that is not a single decodable certificate, or fails
//     accept, denies with that reason; one that passes allows as the
//     relayed client.
//     c. Otherwise the header, if any, is ignored (logged at Debug) and the
//     request is denied with the connection's own reason.
//  2. The connection is not good.
//     a. No certificate was presented: under trustAny a present header is
//     judged (source bypass); otherwise deny no_certificate.
//     b. A certificate was presented and Envoy rejected it → deny with the
//     reason derived from that certificate. The header is ignored even
//     under trustAny: a caller that identified itself with a bad
//     certificate gets no second chance.
//     c. No TLS attributes or no Envoy verdict at all → deny
//     attribute_absent.
//
// Every step reads the pool from the one set loaded at the start, so a
// single request is judged against a single version of the pool.
func (p *MtlsAuthPolicy) evaluate(reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) evaluationResult {
	now := time.Now()
	set := clientAuthorities.get()
	tls := reqCtx.PeerCertificate()
	headerValues := p.headerValues(reqCtx, set)
	headerPresent := len(headerValues) > 0

	if connectionVerified(tls) {
		connection := p.evaluateVerifiedConnection(set, reqCtx, tls, now)
		if connection.authenticated || !headerPresent {
			return connection
		}
		if p.header.trustAny {
			return p.evaluateHeaderCertificate(set, headerValues, now, sourceBypass, "", "")
		}
		if relay, relayLeaf, ok := set.matchRelay(reqCtx, tls, now); ok {
			return p.evaluateHeaderCertificate(set, headerValues, now, sourceHeader, relay.name, relayLeaf.Subject.String())
		}
		p.logIgnoredHeader(tls)
		return connection
	}

	deny := evaluationResult{authenticated: false, entryIndex: -1, source: sourceHandshake}
	switch {
	case tls == nil:
		// No gateway assertion about this connection at all. Nil MUST be
		// treated as authentication failure, never as "no certificate
		// required" — see policy.DownstreamTLS's doc comment.
		deny.reason = reasonAttributeAbsent
	case !tls.MTLS:
		if headerPresent && p.header.trustAny {
			return p.evaluateHeaderCertificate(set, headerValues, now, sourceBypass, "", "")
		}
		if headerPresent {
			p.logIgnoredHeader(tls)
		}
		deny.reason = reasonNoCertificate
	case tls.PeerCertValid == nil:
		deny.reason = reasonAttributeAbsent
	default:
		reason, rejectedLeaf := set.deriveRejectReason(tls, now)
		deny.reason = reason
		if rejectedLeaf != nil {
			deny = withLeafInfo(deny, rejectedLeaf)
		}
	}
	return deny
}

// connectionVerified reports whether Envoy delivered a positive verdict for a
// certificate presented on this connection: TLS attributes present, a
// certificate presented, and peer_certificate_valid true.
func connectionVerified(tls *policy.DownstreamTLS) bool {
	return tls != nil && tls.MTLS && tls.PeerCertValid != nil && *tls.PeerCertValid
}

// withLeafInfo attaches leaf-derived, non-sensitive attributes (canonical
// SHA-256 thumbprint, subject DN, NotAfter) to a result whose certificate was
// successfully parsed and date-checked — including a deny result, so
// OnRequestHeaders can still report tls.client.subject/tls.client.hash.sha256/
// tls.client.not_after span attributes for a certificate that failed
// authentication, not only one that passed it.
func withLeafInfo(result evaluationResult, leaf *x509.Certificate) evaluationResult {
	result.subjectDN = leaf.Subject.String()
	result.credentialID = sha256Hex(leaf.Raw)
	result.notAfter = leaf.NotAfter
	return result
}

// evaluateVerifiedConnection evaluates the certificate of a connection Envoy
// already verified (see connectionVerified) against the accept list. Envoy's
// verdict is not a substitute for this policy's own work: the leaf is parsed
// and its validity dates re-checked on every request before the accept list
// runs.
func (p *MtlsAuthPolicy) evaluateVerifiedConnection(set *authoritySet, reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS, now time.Time) evaluationResult {
	deny := evaluationResult{authenticated: false, entryIndex: -1, source: sourceHandshake}

	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		deny.reason = reasonInvalidCert
		return deny
	}
	if now.After(leaf.NotAfter) {
		deny.reason = reasonExpired
		return withLeafInfo(deny, leaf)
	}
	if now.Before(leaf.NotBefore) {
		deny.reason = reasonNotYetValid
		return withLeafInfo(deny, leaf)
	}

	result := p.evaluateAcceptList(set, leaf, set.connectionIntermediates(reqCtx, tls), now, tls.SHA256Thumbprint)
	result.source = sourceHandshake
	return result
}

// evaluateHeaderCertificate decodes and evaluates a judged header: exactly
// one value, decode → date-check → the same accept-list evaluation as the
// connection path, but with Intermediates limited to pool material only —
// there is no Envoy verdict and no XFCC chain for a header-carried
// certificate — and with no Envoy-thumbprint cross-check (same reason).
//
// relayName/relaySubject are carried onto every outcome (allow AND deny)
// whenever source == sourceHeader: the connection already proved itself a
// trusted relay before the header's own certificate was evaluated at all, so
// that fact belongs on the result regardless of what this header's
// certificate turns out to do.
func (p *MtlsAuthPolicy) evaluateHeaderCertificate(set *authoritySet, values []string, now time.Time, source, relayName, relaySubject string) evaluationResult {
	deny := evaluationResult{
		authenticated: false, entryIndex: -1,
		source: source, relayedBy: relayName, relaySubject: relaySubject,
	}

	// Several values for the header is never one identity: deny rather than
	// pick one.
	if len(values) != 1 {
		deny.reason = reasonInvalidCert
		return deny
	}
	leaf, err := decodeHeaderCertificate(values[0])
	if err != nil {
		deny.reason = reasonInvalidCert
		return deny
	}
	if now.After(leaf.NotAfter) {
		deny.reason = reasonExpired
		return withLeafInfo(deny, leaf)
	}
	if now.Before(leaf.NotBefore) {
		deny.reason = reasonNotYetValid
		return withLeafInfo(deny, leaf)
	}

	result := p.evaluateAcceptList(set, leaf, set.pool, now, "")
	// No handshake verified this certificate, so the policy distinguishes the
	// two ways it can reach no accept entry: it chains to no pooled authority
	// at all (untrusted_chain), or it does but this API does not accept that
	// authority (authority_not_accepted).
	if result.reason == reasonAuthorityNotAccepted && !set.chainsToPool(leaf, now) {
		result.reason = reasonUntrustedChain
	}
	result.source = source
	result.relayedBy = relayName
	result.relaySubject = relaySubject
	return result
}

// acceptRejectRank orders the three accept-list rejection reasons by
// specificity, least to most, so evaluateAcceptList can track the single
// most specific one reached across every entry rather than the first or
// last. Any other reason (there shouldn't be one, deny starts unset) ranks
// below all three.
func acceptRejectRank(reason string) int {
	switch reason {
	case reasonThumbprintMismatch:
		return 3
	case reasonSANMismatch:
		return 2
	case reasonAuthorityNotAccepted:
		return 1
	default:
		return 0
	}
}

// evaluateAcceptList is the accept-list matching loop shared by both the
// connection path and the believed-header path: the first accept entry whose
// pool entry in set verifies leaf (via intermediates for path-building) AND
// satisfies every narrowing it carries wins. On a deny, the reported reason
// is the MOST SPECIFIC rejection reached across every entry (see
// acceptRejectRank) — an entry whose authority matched but SAN narrowing
// failed makes the deny at least san_mismatch, one whose authority and SAN
// both matched but thumbprint narrowing failed makes it thumbprint_mismatch,
// and authority_not_accepted only stands when no entry's authority verified
// the certificate at all. An entry naming no client entry in set matches
// nothing; when that is true of every entry, the deny is
// authority_not_accepted and the drift is logged once for this set (see
// warnNoAcceptedAuthority).
//
// connectionThumbprint is the Envoy-reported SHA-256 digest for THIS SAME
// connection's certificate, used only as a defense-in-depth cross-check
// against an entry's configured thumbprints; pass "" when evaluating a
// header-carried leaf, which has no corresponding Envoy verdict to check
// against (skipping the cross-check, not disabling the thumbprint narrowing
// itself).
func (p *MtlsAuthPolicy) evaluateAcceptList(set *authoritySet, leaf *x509.Certificate, intermediates *x509.CertPool, now time.Time, connectionThumbprint string) evaluationResult {
	canonicalThumbprint := sha256Hex(leaf.Raw)
	deny := evaluationResult{
		authenticated: false, entryIndex: -1,
		reason:       reasonAuthorityNotAccepted,
		subjectDN:    leaf.Subject.String(),
		credentialID: canonicalThumbprint,
		notAfter:     leaf.NotAfter,
	}

	upgrade := func(reason string) {
		if acceptRejectRank(reason) > acceptRejectRank(deny.reason) {
			deny.reason = reason
		}
	}

	inPool := 0
	for i, entry := range p.acceptEntries(set) {
		roots, ok := set.clients[entry.ca]
		if !ok {
			continue
		}
		inPool++
		if !verifyLeafAgainstRoots(leaf, roots, intermediates, now) {
			continue
		}

		subject, ok := sanNarrowedSubject(leaf, entry.uriSANs, entry.dnsSANs)
		if !ok {
			upgrade(reasonSANMismatch)
			continue
		}

		if len(entry.thumbprints) > 0 {
			if !containsConstantTime(entry.thumbprints, canonicalThumbprint) {
				upgrade(reasonThumbprintMismatch)
				continue
			}
			// Defense in depth: our own PEM-derived digest must agree with
			// what Envoy reported for this same connection (skipped when
			// there is no Envoy verdict to check against — see doc comment).
			if connectionThumbprint != "" && normalizeThumbprint(connectionThumbprint) != canonicalThumbprint {
				upgrade(reasonThumbprintMismatch)
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

	if inPool == 0 {
		p.warnNoAcceptedAuthority(set)
	}
	return deny
}

// warnNoAcceptedAuthority logs a WARN, once per pool version for this accept
// list, that none of the pool entries it names is in the pool — a chain that
// arrived before the pool entries it names, or an entry removed while this
// API still names it. Every request is denied until the pool holds one of
// them again.
func (p *MtlsAuthPolicy) warnNoAcceptedAuthority(set *authoritySet) {
	key := "accept:" + p.acceptNames
	if p.inheritAccept {
		key = "inherit"
	}
	if !set.firstWarning(key) {
		return
	}
	slog.Warn("mtls-auth: none of the client certificate authorities this API accepts is in the gateway's client-CA pool",
		slog.String("accept", p.acceptNames),
		slog.Bool("inherited", p.inheritAccept),
		slog.Uint64("pool_version", set.version),
	)
}

// matchRelay reports whether the CONNECTION's own certificate (never the
// header's) authenticates as one of the pool's relay entries:
// Envoy's verdict positive (see connectionVerified), our own date re-check,
// and
// the leaf verifies against the relay's roots (Intermediates = pool + XFCC
// chain, KeyUsages ExtKeyUsageAny — identical parameters to accept-entry
// verification) and satisfies the relay's SAN narrowing if any.
func (s *authoritySet) matchRelay(reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS, now time.Time) (*relayEntry, *x509.Certificate, bool) {
	if !connectionVerified(tls) {
		return nil, nil, false
	}
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		return nil, nil, false
	}
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return nil, nil, false
	}

	intermediates := s.connectionIntermediates(reqCtx, tls)
	for i := range s.relays {
		entry := &s.relays[i]
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
// present but was never judged — the connection neither passed accept nor
// matched a relay, and trustAny did not apply. Only the connection's own subject DN is
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

// headerValues returns the non-empty values of the configured
// client-certificate header, or nil when header mode is off (the header is
// then inert text). It reads the DOWNSTREAM SNAPSHOT (never live/mutated
// headers — see DownstreamRequest's doc comment), so an earlier policy
// rewriting/removing the header can never change this decision.
func (p *MtlsAuthPolicy) headerValues(reqCtx *policy.RequestHeaderContext, set *authoritySet) []string {
	if !p.headerModeOn(set) {
		return nil
	}
	var values []string
	for _, v := range reqCtx.DownstreamRequest().Headers.Get(p.header.name) {
		if v = strings.TrimSpace(v); v != "" {
			values = append(values, v)
		}
	}
	return values
}

// connectionIntermediates returns the path-building-only certificate pool
// used for CONNECTION-leaf verification (accept-entry and relay-entry
// alike): every certificate in the pool, plus — only because tls.MTLS is
// true, per directive 5 — any certificates in the X-Forwarded-Client-Cert
// Chain element, read from the pristine downstream snapshot. The shared pool
// is never modified; a request carrying chain certificates gets its own copy.
func (s *authoritySet) connectionIntermediates(reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS) *x509.CertPool {
	if tls == nil || !tls.MTLS {
		return s.pool
	}
	chain := chainCertificatesFromXFCC(reqCtx)
	if len(chain) == 0 {
		return s.pool
	}
	intermediates := s.pool.Clone()
	for _, c := range chain {
		intermediates.AddCert(c)
	}
	return intermediates
}

// verifyLeafAgainstRoots reports whether leaf verifies against roots (via
// intermediates for path-building), using the same VerifyOptions every
// verification in this package uses: ExtKeyUsageAny and the given point in
// time.
func verifyLeafAgainstRoots(leaf *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time) bool {
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
// deriveRejectReason returns the deny reason and, when the leaf parsed
// successfully, the parsed certificate itself — so the caller can still
// attach tls.client.* span attributes (via withLeafInfo) to a certificate
// Envoy rejected outright. A nil certificate means parsing itself failed;
// the reason is always reasonInvalidCert in that case.
func (s *authoritySet) deriveRejectReason(tls *policy.DownstreamTLS, now time.Time) (string, *x509.Certificate) {
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		return reasonInvalidCert, nil
	}
	if now.After(leaf.NotAfter) {
		return reasonExpired, leaf
	}
	if now.Before(leaf.NotBefore) {
		return reasonNotYetValid, leaf
	}

	// Not a date problem — distinguish "the chain genuinely doesn't reach a
	// trusted authority" from some other reason Envoy rejected it.
	if !s.chainsToPool(leaf, now) {
		return reasonUntrustedChain, leaf
	}
	return reasonInvalidCert, leaf
}

// chainsToPool reports whether leaf verifies against ANY certificate in the
// gateway's whole client-CA pool (not just this API's narrower accept list),
// with the pool also serving as path-building material. Used only to choose
// a deny reason, never to allow.
func (s *authoritySet) chainsToPool(leaf *x509.Certificate, now time.Time) bool {
	return verifyLeafAgainstRoots(leaf, s.pool, s.pool, now)
}

// chainCertificatesFromXFCC extracts every certificate in the Chain= element
// of the X-Forwarded-Client-Cert header, read from the pristine downstream
// snapshot (DownstreamRequest(), never live/mutated headers) — a client can
// never inject a value here because Envoy writes this header with
// SANITIZE_SET, overwriting anything the caller sent.
func chainCertificatesFromXFCC(reqCtx *policy.RequestHeaderContext) []*x509.Certificate {
	values := reqCtx.DownstreamRequest().Headers.Get(xfccHeaderName)
	if len(values) == 0 {
		return nil
	}
	return parseXFCCChainCertificates(values[0])
}

// OnRequestHeaders performs mTLS authentication in the request-header phase.
func (p *MtlsAuthPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", defaultOnFailureStatusCode)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", defaultErrorMessageFormat)
	errorMessage := getStringParam(params, "errorMessage", defaultErrorMessage)

	result := p.evaluate(reqCtx, params)
	setSpanAttributes(ctx, result, reqCtx.PeerCertificate())

	if !result.authenticated {
		slog.Debug("mtls-auth: rejecting request",
			slog.String("reason", result.reason),
			slog.String("subject", result.subjectDN),
			slog.String("source", result.source),
			slog.String("api", reqCtx.APIName),
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
	// forwardCertificate false keeps every certificate header away from this
	// API's backend. Otherwise only the relayed header needs this policy's
	// attention: the router already strips it on every route when
	// forwardToBackend is off, and when forwardToBackend is on this policy
	// must still remove it whenever it did NOT believe it (a header carried
	// past an accepted connection, or one from a connection that was neither
	// a relay nor covered by trustAny), so only a believed header reaches
	// upstream.
	believed := result.source == sourceHeader || result.source == sourceBypass
	switch {
	case !p.forwardCertificate:
		action.HeadersToRemove = []string{xfccHeaderName, p.header.name}
	case p.header.forwardToBackend && !believed:
		action.HeadersToRemove = []string{p.header.name}
	}
	return action
}

// setSpanAttributes records this request's mTLS authentication outcome on
// the span already open in ctx (the per-policy span the executor started for
// this call — see internal/executor/chain.go), so a trace shows exactly what
// this policy decided and why without needing the access log or the 401
// body. A no-op when nothing is recording, per OTel convention: attribute
// construction below is cheap, but still gated so it's never paid for
// nothing.
//
// tls is the connection's own TLS attributes (nil-safe): it's read
// independently of result because tls.protocol.version is a property of the
// CONNECTION, not of whichever certificate (connection or header-relayed)
// ended up being evaluated.
//
// Never sets an attribute from a PEM, a certificate chain, or a raw header
// value — only derived, already-non-sensitive fields (subject DN, canonical
// thumbprint, NotAfter, entry index, reason code).
func setSpanAttributes(ctx context.Context, result evaluationResult, tls *policy.DownstreamTLS) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	outcome := "deny"
	if result.authenticated {
		outcome = "allow"
	}
	attrs := make([]attribute.KeyValue, 0, 10)
	attrs = append(attrs, attribute.String("mtls_auth.result", outcome))
	if result.source != "" {
		attrs = append(attrs, attribute.String("mtls_auth.source", result.source))
	}

	if result.authenticated {
		attrs = append(attrs,
			attribute.Int("mtls_auth.matched_entry", result.entryIndex),
			attribute.String("enduser.id", result.subject),
		)
	} else {
		attrs = append(attrs, attribute.String("mtls_auth.reason", result.reason))
	}
	if result.relayedBy != "" {
		attrs = append(attrs, attribute.String("mtls_auth.relayed_by", result.relayedBy))
	}

	if result.subjectDN != "" {
		attrs = append(attrs, attribute.String("tls.client.subject", result.subjectDN))
	}
	if result.authenticated && result.issuerCA != "" {
		attrs = append(attrs, attribute.String("tls.client.issuer", result.issuerCA))
	}
	if result.credentialID != "" {
		attrs = append(attrs, attribute.String("tls.client.hash.sha256", result.credentialID))
	}
	if !result.notAfter.IsZero() {
		attrs = append(attrs, attribute.String("tls.client.not_after", result.notAfter.UTC().Format(time.RFC3339)))
	}
	if tls != nil && tls.TLSVersion != "" {
		attrs = append(attrs, attribute.String("tls.protocol.version", tls.TLSVersion))
	}

	span.SetAttributes(attrs...)
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

// parseAcceptParam parses __wso2_internal_mtls_accept: an ordered array of
// accept-list entries naming pool entries and the narrowing each applies.
// Absent yields nil (the author omitted accept). A malformed entry or
// narrowing value is a GetPolicy error, never silently "no narrowing" — a
// malformed narrowing must fail closed at bind time, not widen what the
// entry accepts.
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
		entry := acceptEntry{ca: ca}

		if matchRaw, ok := obj["match"]; ok && matchRaw != nil {
			matchObj, ok := matchRaw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s[%d].match must be an object", internalAcceptParam, i)
			}
			matchPath := fmt.Sprintf("%s[%d].match", internalAcceptParam, i)
			var err error
			if entry.uriSANs, err = stringListParam(matchObj, "uriSANs", matchPath); err != nil {
				return nil, err
			}
			if entry.dnsSANs, err = stringListParam(matchObj, "dnsSANs", matchPath); err != nil {
				return nil, err
			}
		}

		thumbs, err := stringListParam(obj, "thumbprints", fmt.Sprintf("%s[%d]", internalAcceptParam, i))
		if err != nil {
			return nil, err
		}
		for _, t := range thumbs {
			entry.thumbprints = append(entry.thumbprints, normalizeThumbprint(t))
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

// parseHeaderParam parses __wso2_internal_mtls_header: {"name", "trustAny",
// "forwardToBackend"}. Unlike parseAcceptParam, absence or a malformed shape
// is never a GetPolicy error — a missing/invalid field falls back to its
// documented default, and every default is the more restrictive setting
// (trustAny and forwardToBackend off).
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

// parseForwardCertificateParam parses the developer-facing
// forwardCertificate parameter: absent means true; anything other than a
// boolean is a GetPolicy error rather than a guess, so a malformed value
// never silently forwards (or withholds) certificate headers.
func parseForwardCertificateParam(raw interface{}) (bool, error) {
	if raw == nil {
		return true, nil
	}
	forward, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be true or false", forwardCertificateParam)
	}
	return forward, nil
}

// stringListParam reads an optional list-of-strings field. An absent or nil
// key yields nil; a present key that is not a list of strings is an error,
// never silently "no narrowing" — a malformed narrowing must fail closed,
// not widen what the entry accepts.
func stringListParam(obj map[string]interface{}, key, path string) ([]string, error) {
	raw, ok := obj[key]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s.%s must be a list of strings", path, key)
	}
	out := make([]string, 0, len(items))
	for j, item := range items {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s.%s[%d] must be a string", path, key, j)
		}
		out = append(out, str)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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
	for _, want := range accepted {
		if containsConstantTime(candidates, want) {
			return want
		}
	}
	return ""
}

// containsConstantTime reports whether want is in values, comparing every
// element in constant time so a match position or a shared prefix is not
// observable through timing.
func containsConstantTime(values []string, want string) bool {
	found := 0
	for _, v := range values {
		found |= subtle.ConstantTimeCompare([]byte(v), []byte(want))
	}
	return found == 1
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
