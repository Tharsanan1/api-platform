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

package mtlsauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newTestRequestHeaderContext() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
	}
}

func mustGetPolicy(t *testing.T) *MtlsAuthPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned an error: %v", err)
	}
	mp, ok := p.(*MtlsAuthPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *MtlsAuthPolicy", p)
	}
	return mp
}

// TestMtlsAuthPolicy_DefaultParams_ProducesUniformUnauthorizedResponse guards
// the default failure response contract: with no params configured, every
// request is rejected with a 401, an application/json body of exactly
// {"error":"Unauthorized","message":"Authentication failed"}, and no
// WWW-Authenticate header (mutual TLS has no challenge header equivalent to
// offer).
func TestMtlsAuthPolicy_DefaultParams_ProducesUniformUnauthorizedResponse(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}

	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type header = %q, want %q", got, "application/json")
	}
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(resp.Body), wantBody)
	}
	if _, exists := resp.Headers["WWW-Authenticate"]; exists {
		t.Errorf("expected no WWW-Authenticate header, got %q", resp.Headers["WWW-Authenticate"])
	}

	if reqCtx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be recorded on failure")
	}
	if reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated to be false")
	}
	if reqCtx.SharedContext.AuthContext.AuthType != AuthType {
		t.Errorf("AuthContext.AuthType = %q, want %q", reqCtx.SharedContext.AuthContext.AuthType, AuthType)
	}
}

// TestMtlsAuthPolicy_ErrorMessageFormat_Plain honours errorMessageFormat:
// "plain" — the body is the raw error message text and the content-type
// switches to text/plain instead of the default JSON envelope.
func TestMtlsAuthPolicy_ErrorMessageFormat_Plain(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"errorMessageFormat": "plain",
		"errorMessage":       "no certificate presented",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if got := resp.Headers["content-type"]; got != "text/plain" {
		t.Errorf("content-type header = %q, want %q", got, "text/plain")
	}
	if string(resp.Body) != "no certificate presented" {
		t.Errorf("body = %q, want %q", string(resp.Body), "no certificate presented")
	}
}

// TestMtlsAuthPolicy_ErrorMessageFormat_Minimal honours errorMessageFormat:
// "minimal" — the body is the fixed literal "Unauthorized" regardless of any
// configured errorMessage, with the default JSON content-type retained.
func TestMtlsAuthPolicy_ErrorMessageFormat_Minimal(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"errorMessageFormat": "minimal",
		"errorMessage":       "this text must not appear",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type header = %q, want %q", got, "application/json")
	}
	if string(resp.Body) != "Unauthorized" {
		t.Errorf("body = %q, want %q", string(resp.Body), "Unauthorized")
	}
}

// TestMtlsAuthPolicy_OnFailureStatusCode_Honoured guards that a configured
// onFailureStatusCode overrides the default 401.
func TestMtlsAuthPolicy_OnFailureStatusCode_Honoured(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"onFailureStatusCode": 403,
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", resp.StatusCode)
	}
	// The failure body contract is otherwise unaffected by the status code override.
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(resp.Body), wantBody)
	}
}

// TestMtlsAuthPolicy_Mode guards the declared processing mode: only the
// request-header phase is needed, since the certificate this policy
// authenticates against is a connection-level fact available at header time.
func TestMtlsAuthPolicy_Mode(t *testing.T) {
	p := mustGetPolicy(t)
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode = %v, want HeaderModeProcess", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("RequestBodyMode = %v, want BodyModeSkip", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("ResponseHeaderMode = %v, want HeaderModeSkip", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("ResponseBodyMode = %v, want BodyModeSkip", mode.ResponseBodyMode)
	}
}

// ─── In-test certificate authority helpers ───────────────────────────────────
//
// This module doesn't depend on gateway-controller, so it can't reuse that
// module's pkg/testutil/pki helper — this is a small, self-contained
// equivalent built directly on crypto/x509, sized for exactly what this
// file's tests below need.

// testEntity is a generated certificate plus the private key that created it.
type testEntity struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func (e *testEntity) pemCert() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.der}))
}

// thumbprint returns the lowercase-hex SHA-256 digest of the certificate's DER
// encoding — the same "canonical thumbprint" evaluate() computes from a
// parsed leaf, and the format both __wso2_internal_mtls_accept's thumbprints
// entries and DownstreamTLS.SHA256Thumbprint are normalized to.
func (e *testEntity) thumbprint() string {
	sum := sha256.Sum256(e.der)
	return hex.EncodeToString(sum[:])
}

// certOpts configures a single certificate issuance. Despite the name it
// applies equally to roots, intermediates, and leaves — isCA/parent select
// which.
type certOpts struct {
	parent    *testEntity // nil => self-signed
	isCA      bool
	subject   pkix.Name // zero value => pkix.Name{CommonName: cn}
	uriSANs   []string
	dnsSANs   []string
	ekus      []x509.ExtKeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func issueCert(t *testing.T, cn string, opts certOpts) *testEntity {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key for %q: %v", cn, err)
	}

	subject := opts.subject
	if subject.CommonName == "" && len(subject.Organization) == 0 {
		subject = pkix.Name{CommonName: cn}
	}

	notBefore, notAfter := opts.notBefore, opts.notAfter
	if notBefore.IsZero() && notAfter.IsZero() {
		notBefore = time.Now().Add(-1 * time.Hour)
		notAfter = time.Now().Add(10 * 365 * 24 * time.Hour)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number for %q: %v", cn, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
	}
	if opts.isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	switch {
	case len(opts.ekus) > 0:
		tmpl.ExtKeyUsage = opts.ekus
	case !opts.isCA:
		// Every client leaf in this file defaults to clientAuth-only EKU,
		// mirroring resources/mtls-pki/generate.go's fixtures — this is what
		// makes TestMtlsAuthPolicy_Evaluate_AcceptsClientAuthOnlyLeaf_ExtKeyUsageAny
		// below a meaningful regression guard rather than a one-off.
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	for _, u := range opts.uriSANs {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("invalid URI SAN %q for %q: %v", u, cn, err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	tmpl.DNSNames = append(tmpl.DNSNames, opts.dnsSANs...)

	var parentCert *x509.Certificate
	var signer *ecdsa.PrivateKey
	if opts.parent == nil {
		parentCert = tmpl
		signer = key
	} else {
		parentCert = opts.parent.cert
		signer = opts.parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		t.Fatalf("failed to create certificate for %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated certificate for %q: %v", cn, err)
	}
	return &testEntity{cert: cert, key: key, der: der}
}

func newRootCA(t *testing.T, cn string) *testEntity {
	t.Helper()
	return issueCert(t, cn, certOpts{isCA: true})
}

func newIntermediateCA(t *testing.T, parent *testEntity, cn string) *testEntity {
	t.Helper()
	return issueCert(t, cn, certOpts{isCA: true, parent: parent})
}

func newLeaf(t *testing.T, parent *testEntity, cn string, opts certOpts) *testEntity {
	t.Helper()
	opts.parent = parent
	return issueCert(t, cn, opts)
}

// xfccChainField builds the Chain= field of an X-Forwarded-Client-Cert header
// value exactly as parseXFCCChainCertificates expects to decode it: RFC 3986
// percent-encoding (url.PathEscape, matching the production code's
// url.PathUnescape) of the concatenated PEM blocks — never
// url.QueryEscape/Unescape, which would corrupt a literal '+' in the PEM
// base64 alphabet.
func xfccChainField(certs ...*testEntity) string {
	var pemBlob strings.Builder
	for _, c := range certs {
		pemBlob.WriteString(c.pemCert())
	}
	return "Chain=" + url.PathEscape(pemBlob.String())
}

// ─── __wso2_internal_mtls_accept / _pool param construction ──────────────────

// entrySpec is one accept-list entry, expressed with real certificates/SAN
// values rather than the raw JSON-ish shape GetPolicy actually parses —
// buildParams does that translation once, the same way the
// gateway-controller's transform package would when injecting these params.
type entrySpec struct {
	ca          string
	roots       []*testEntity
	uriSANs     []string
	dnsSANs     []string
	thumbprints []string
}

func stringsToInterfaces(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func entitiesToPEMInterfaces(entities []*testEntity) []interface{} {
	out := make([]interface{}, len(entities))
	for i, e := range entities {
		out[i] = e.pemCert()
	}
	return out
}

func buildParams(pool []*testEntity, entries []entrySpec) map[string]interface{} {
	acceptList := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		obj := map[string]interface{}{
			"ca":           e.ca,
			"certificates": entitiesToPEMInterfaces(e.roots),
		}
		if len(e.uriSANs) > 0 || len(e.dnsSANs) > 0 {
			match := map[string]interface{}{}
			if len(e.uriSANs) > 0 {
				match["uriSANs"] = stringsToInterfaces(e.uriSANs)
			}
			if len(e.dnsSANs) > 0 {
				match["dnsSANs"] = stringsToInterfaces(e.dnsSANs)
			}
			obj["match"] = match
		}
		if len(e.thumbprints) > 0 {
			obj["thumbprints"] = stringsToInterfaces(e.thumbprints)
		}
		acceptList = append(acceptList, obj)
	}

	return map[string]interface{}{
		internalAcceptParam: acceptList,
		internalPoolParam:   entitiesToPEMInterfaces(pool),
	}
}

func mustBuildPolicy(t *testing.T, pool []*testEntity, entries []entrySpec) *MtlsAuthPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, buildParams(pool, entries))
	if err != nil {
		t.Fatalf("GetPolicy returned an error: %v", err)
	}
	mp, ok := p.(*MtlsAuthPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *MtlsAuthPolicy", p)
	}
	return mp
}

// ─── __wso2_internal_mtls_relays / _header param construction ────────────────

// relaySpec is one relay-list entry, expressed with real certificates/SAN
// values rather than the raw JSON-ish shape GetPolicy actually parses — the
// same translation entrySpec/buildParams do for __wso2_internal_mtls_accept.
type relaySpec struct {
	name    string
	roots   []*testEntity
	uriSANs []string
	dnsSANs []string
}

// buildParamsWithHeader is buildParams plus the two header-relay params.
// nil relays/header means the corresponding param is omitted entirely
// (absent, not an empty array/object) — matching parseRelaysParam/
// parseHeaderParam's documented "absent means off" contract.
func buildParamsWithHeader(pool []*testEntity, entries []entrySpec, relays []relaySpec, header map[string]interface{}) map[string]interface{} {
	params := buildParams(pool, entries)

	if relays != nil {
		relayList := make([]interface{}, 0, len(relays))
		for _, r := range relays {
			obj := map[string]interface{}{
				"name":         r.name,
				"certificates": entitiesToPEMInterfaces(r.roots),
			}
			if len(r.uriSANs) > 0 || len(r.dnsSANs) > 0 {
				match := map[string]interface{}{}
				if len(r.uriSANs) > 0 {
					match["uriSANs"] = stringsToInterfaces(r.uriSANs)
				}
				if len(r.dnsSANs) > 0 {
					match["dnsSANs"] = stringsToInterfaces(r.dnsSANs)
				}
				obj["match"] = match
			}
			relayList = append(relayList, obj)
		}
		params[internalRelaysParam] = relayList
	}

	if header != nil {
		params[internalHeaderParam] = header
	}
	return params
}

func mustBuildRelayPolicy(t *testing.T, pool []*testEntity, entries []entrySpec, relays []relaySpec, header map[string]interface{}) *MtlsAuthPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, buildParamsWithHeader(pool, entries, relays, header))
	if err != nil {
		t.Fatalf("GetPolicy returned an error: %v", err)
	}
	mp, ok := p.(*MtlsAuthPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *MtlsAuthPolicy", p)
	}
	return mp
}

// ─── Header-value encodings a front proxy might emit ─────────────────────────

// urlEncodedPEMHeaderValue is the default encoding: the PEM text, RFC 3986
// percent-encoded — url.PathEscape, matching decodeHeaderCertificate's
// url.PathUnescape fallback.
func urlEncodedPEMHeaderValue(e *testEntity) string {
	return url.PathEscape(e.pemCert())
}

// pemWithSpacesHeaderValue is the raw PEM text with newlines replaced by
// spaces — an HTTP header cannot carry a literal newline, and this is what
// several proxies emit instead of percent-encoding it.
func pemWithSpacesHeaderValue(e *testEntity) string {
	return strings.ReplaceAll(e.pemCert(), "\n", " ")
}

// bareBase64DERHeaderValue is the bare base64 of the certificate's DER bytes,
// with no PEM armor at all.
func bareBase64DERHeaderValue(e *testEntity) string {
	return base64.StdEncoding.EncodeToString(e.der)
}

// ─── Request-context / DownstreamTLS construction ────────────────────────────

func boolPtr(b bool) *bool { return &b }

func reqCtxWithTLS(tls *policy.DownstreamTLS) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
		Downstream:    &policy.DownstreamContext{TLS: tls},
	}
}

// reqCtxWithTLSAndHeader is reqCtxWithTLS plus a downstream snapshot carrying
// headerName: headerValue, driving evaluate()'s header-relay decision path via
// Downstream.Request.Headers — the snapshot headerRawValue reads (see
// policy.RequestHeaderContext.DownstreamRequest's doc comment on why the
// snapshot, not the top-level Headers fallback, is what a policy should read
// for an authentication decision).
func reqCtxWithTLSAndHeader(tls *policy.DownstreamTLS, headerName, headerValue string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
		Downstream: &policy.DownstreamContext{
			TLS: tls,
			Request: &policy.DownstreamRequest{
				Headers: policy.NewHeaders(map[string][]string{headerName: {headerValue}}),
			},
		},
	}
}

// downstreamTLSFromLeaf builds the DownstreamTLS Envoy would report for a
// connection that presented leaf, with valid pinning Envoy's own
// peer_certificate_valid verdict (Step 3 in evaluate()).
func downstreamTLSFromLeaf(leaf *testEntity, valid bool) *policy.DownstreamTLS {
	return &policy.DownstreamTLS{
		MTLS:               true,
		PeerCertificatePEM: leaf.pemCert(),
		PeerCertValid:      boolPtr(valid),
		SHA256Thumbprint:   leaf.thumbprint(),
	}
}

// ─── Assertion helpers ────────────────────────────────────────────────────────

// evaluateAndRespond exercises both surfaces the task requires: the
// unexported evaluate() result (reason, matched entry) and the actual
// OnRequestHeaders action (401 ImmediateResponse vs pass-through). evaluate()
// is a pure read of reqCtx, so calling it directly and then letting
// OnRequestHeaders call it again internally is safe — neither call mutates
// reqCtx itself, only OnRequestHeaders's own AuthContext side effect below.
func evaluateAndRespond(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext) (evaluationResult, policy.RequestHeaderAction) {
	t.Helper()
	result := p.evaluate(reqCtx, nil)
	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{})
	return result, action
}

// assertDenied asserts evaluate() denied with wantReason AND that
// OnRequestHeaders produced the identical 401 body — every deny path must
// converge on the same response regardless of *why*, per error-handling.md's
// unified-auth-failure directive, so this same byte-for-byte check runs on
// every call site below rather than being asserted once in isolation.
func assertDenied(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext, wantReason string) {
	t.Helper()
	result, action := evaluateAndRespond(t, p, reqCtx)
	if result.authenticated {
		t.Fatalf("evaluate(): authenticated = true, want false (reason would have been %q)", wantReason)
	}
	if result.reason != wantReason {
		t.Errorf("evaluate() reason = %q, want %q", result.reason, wantReason)
	}

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q (deny body must be byte-identical regardless of reason %q)", resp.Body, wantBody, result.reason)
	}
}

// assertAuthenticated asserts evaluate() authenticated at wantEntryIndex AND
// that OnRequestHeaders produced a pass-through action rather than a 401.
func assertAuthenticated(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext, wantEntryIndex int) evaluationResult {
	t.Helper()
	result, action := evaluateAndRespond(t, p, reqCtx)
	if !result.authenticated {
		t.Fatalf("evaluate(): authenticated = false, reason = %q, want true", result.reason)
	}
	if result.entryIndex != wantEntryIndex {
		t.Errorf("evaluate() entryIndex = %d, want %d", result.entryIndex, wantEntryIndex)
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.UpstreamRequestHeaderModifications (pass-through)", action)
	}
	return result
}

// ─── Connection-level gating (Steps 1-3) ─────────────────────────────────────

// TestMtlsAuthPolicy_Evaluate_ConnectionLevelGating guards evaluate()'s
// fail-closed handling of the three ways the gateway can assert "nothing
// certain about this connection's certificate" — nil TLS, TLS populated but
// no certificate presented, and Envoy's own verification verdict missing.
// None of these may ever be treated as "no certificate required".
func TestMtlsAuthPolicy_Evaluate_ConnectionLevelGating(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	p := mustBuildPolicy(t, []*testEntity{rootA}, []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}})

	t.Run("TLS nil", func(t *testing.T) {
		reqCtx := reqCtxWithTLS(nil)
		assertDenied(t, p, reqCtx, reasonAttributeAbsent)
	})
	t.Run("MTLS false", func(t *testing.T) {
		reqCtx := reqCtxWithTLS(&policy.DownstreamTLS{MTLS: false})
		assertDenied(t, p, reqCtx, reasonNoCertificate)
	})
	t.Run("PeerCertValid nil", func(t *testing.T) {
		reqCtx := reqCtxWithTLS(&policy.DownstreamTLS{MTLS: true, PeerCertValid: nil})
		assertDenied(t, p, reqCtx, reasonAttributeAbsent)
	})
}

// ─── Envoy already rejected: deriveRejectReason (Step 3 false branch) ────────

// TestMtlsAuthPolicy_Evaluate_EnvoyRejection_DerivesReason covers the three
// deriveRejectReason outcomes reachable when tls.PeerCertValid is a non-nil
// false: date-based reasons short-circuit before any chain check, and a
// pool-wide chain check distinguishes "genuinely untrusted" from other
// causes.
func TestMtlsAuthPolicy_Evaluate_EnvoyRejection_DerivesReason(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	unrelatedRoot := newRootCA(t, "Unrelated Root CA")
	p := mustBuildPolicy(t, []*testEntity{rootA}, []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}})

	t.Run("expired leaf", func(t *testing.T) {
		expired := newLeaf(t, rootA, "client-expired", certOpts{
			notBefore: time.Now().Add(-2 * 365 * 24 * time.Hour),
			notAfter:  time.Now().Add(-1 * 365 * 24 * time.Hour),
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(expired, false))
		assertDenied(t, p, reqCtx, reasonExpired)
	})

	t.Run("not yet valid leaf", func(t *testing.T) {
		notYetValid := newLeaf(t, rootA, "client-not-yet-valid", certOpts{
			notBefore: time.Now().Add(1 * 365 * 24 * time.Hour),
			notAfter:  time.Now().Add(11 * 365 * 24 * time.Hour),
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(notYetValid, false))
		assertDenied(t, p, reqCtx, reasonNotYetValid)
	})

	t.Run("leaf from an unpooled CA", func(t *testing.T) {
		leaf := newLeaf(t, unrelatedRoot, "client-wrong-ca", certOpts{})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, false))
		assertDenied(t, p, reqCtx, reasonUntrustedChain)
	})
}

// ─── The happy path: full AuthContext population ─────────────────────────────

// TestMtlsAuthPolicy_Evaluate_AuthenticatesAndPopulatesAuthContext is the one
// dedicated test for the full authenticated outcome: every AuthContext field
// OnRequestHeaders derives from evaluate()'s result, plus that an earlier
// auth layer's AuthContext is preserved via Previous rather than discarded.
func TestMtlsAuthPolicy_Evaluate_AuthenticatesAndPopulatesAuthContext(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})

	p := mustBuildPolicy(t, []*testEntity{rootA}, []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}})

	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
	previous := &policy.AuthContext{Authenticated: true, AuthType: "jwt"} // sentinel: an earlier auth layer
	reqCtx.SharedContext.AuthContext = previous

	result := assertAuthenticated(t, p, reqCtx, 0)
	if result.subject != "urn:partner-a:payments" {
		t.Errorf("evaluate() subject = %q, want %q", result.subject, "urn:partner-a:payments")
	}

	auth := reqCtx.SharedContext.AuthContext
	if auth == nil {
		t.Fatal("expected AuthContext to be populated")
	}
	if !auth.Authenticated {
		t.Error("AuthContext.Authenticated = false, want true")
	}
	if auth.AuthType != AuthType {
		t.Errorf("AuthContext.AuthType = %q, want %q", auth.AuthType, AuthType)
	}
	if auth.Issuer != "auth-ca-a" {
		t.Errorf("AuthContext.Issuer = %q, want %q", auth.Issuer, "auth-ca-a")
	}
	if auth.CredentialID != leaf.thumbprint() {
		t.Errorf("AuthContext.CredentialID = %q, want %q", auth.CredentialID, leaf.thumbprint())
	}
	if auth.Subject != "urn:partner-a:payments" {
		t.Errorf("AuthContext.Subject = %q, want %q", auth.Subject, "urn:partner-a:payments")
	}
	if auth.Properties["source"] != "handshake" {
		t.Errorf(`AuthContext.Properties["source"] = %q, want "handshake"`, auth.Properties["source"])
	}
	if auth.Properties["matchedEntry"] != "0" {
		t.Errorf(`AuthContext.Properties["matchedEntry"] = %q, want "0"`, auth.Properties["matchedEntry"])
	}
	if auth.Previous != previous {
		t.Errorf("AuthContext.Previous = %+v, want the pre-existing AuthContext to be preserved", auth.Previous)
	}
}

// ─── Path-building via the intermediate and the XFCC Chain element ──────────

// TestMtlsAuthPolicy_Evaluate_IntermediateViaXFCCChain covers the four
// XFCC-related scenarios: an intermediate missing entirely, the same
// intermediate supplied via X-Forwarded-Client-Cert's Chain= element, that
// same header ignored outright when MTLS is false, and a chain element that
// can never be promoted to a trusted Root no matter how "complete" a path it
// appears to close.
func TestMtlsAuthPolicy_Evaluate_IntermediateViaXFCCChain(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	intermediateA := newIntermediateCA(t, rootA, "Partner A Issuing CA 1")
	leaf := newLeaf(t, intermediateA, "client-via-intermediate", certOpts{})
	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}

	t.Run("no XFCC: pool holds root only", func(t *testing.T) {
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// Realistic: the client presented only the leaf during the handshake
		// (no intermediate), so Envoy's own verification against pool=[rootA]
		// fails the same way deriveRejectReason's pool-wide check would.
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, false))
		assertDenied(t, p, reqCtx, reasonUntrustedChain)
	})

	t.Run("XFCC Chain carries the intermediate: authenticated", func(t *testing.T) {
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// Realistic: the client presented leaf+intermediate during the TLS
		// handshake, so Envoy verified successfully (pool root + client-supplied
		// intermediate completes the path) and forwarded that same intermediate
		// in X-Forwarded-Client-Cert's Chain element.
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		reqCtx.Headers = policy.NewHeaders(map[string][]string{xfccHeaderName: {xfccChainField(intermediateA)}})
		assertAuthenticated(t, p, reqCtx, 0)
	})

	t.Run("same XFCC but MTLS false: still denied, header never read", func(t *testing.T) {
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		tls := downstreamTLSFromLeaf(leaf, true)
		tls.MTLS = false
		reqCtx := reqCtxWithTLS(tls)
		reqCtx.Headers = policy.NewHeaders(map[string][]string{xfccHeaderName: {xfccChainField(intermediateA)}})
		assertDenied(t, p, reqCtx, reasonNoCertificate)
	})

	t.Run("XFCC Chain ending in an unpooled self-consistent root never becomes a trusted root", func(t *testing.T) {
		rogueRoot := newRootCA(t, "Rogue Root CA")
		rogueLeaf := newLeaf(t, rogueRoot, "client-rogue", certOpts{})
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// PeerCertValid=true here isolates Steps 5-6's own chain-building logic
		// from Step 3's Envoy-verdict gate, specifically to demonstrate that a
		// self-signed CA certificate arriving via the XFCC Chain element is
		// path-building material only — it never gets treated as a Root, no
		// matter how "complete" a chain it appears to close.
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(rogueLeaf, true))
		reqCtx.Headers = policy.NewHeaders(map[string][]string{xfccHeaderName: {xfccChainField(rogueRoot)}})
		assertDenied(t, p, reqCtx, reasonAuthorityNotAccepted)
	})
}

// ─── SAN narrowing ────────────────────────────────────────────────────────────

// TestMtlsAuthPolicy_Evaluate_SANNarrowing covers uriSANs matching among
// several leaf URIs, no match at all, and the both-uriSANs-and-dnsSANs case
// where only one of the two narrowings is satisfied.
func TestMtlsAuthPolicy_Evaluate_SANNarrowing(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")

	t.Run("matches one of several leaf URIs", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// The leaf's FIRST URI deliberately does not match, proving the matched
		// Subject comes from resolving against entry.uriSANs, not leaf.URIs[0].
		leaf := newLeaf(t, rootA, "client-multi-uri", certOpts{
			uriSANs: []string{"urn:partner-a:other", "urn:partner-a:payments"},
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.subject != "urn:partner-a:payments" {
			t.Errorf("subject = %q, want %q", result.subject, "urn:partner-a:payments")
		}
	})

	t.Run("no matching URI", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		leaf := newLeaf(t, rootA, "client-no-match", certOpts{uriSANs: []string{"urn:partner-a:other"}})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		assertDenied(t, p, reqCtx, reasonSANMismatch)
	})

	t.Run("both uriSANs and dnsSANs configured, only one satisfied", func(t *testing.T) {
		entries := []entrySpec{{
			ca:      "auth-ca-a",
			roots:   []*testEntity{rootA},
			uriSANs: []string{"urn:partner-a:payments"},
			dnsSANs: []string{"expected.partner-a.test"},
		}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		leaf := newLeaf(t, rootA, "client-partial-match", certOpts{
			uriSANs: []string{"urn:partner-a:payments"}, // satisfies the uriSANs narrowing
			dnsSANs: []string{"other.partner-a.test"},   // does NOT satisfy dnsSANs
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		assertDenied(t, p, reqCtx, reasonSANMismatch)
	})
}

// ─── Thumbprint narrowing ─────────────────────────────────────────────────────

func TestMtlsAuthPolicy_Evaluate_ThumbprintNarrowing(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{})
	other := newLeaf(t, rootA, "client-other", certOpts{})

	t.Run("thumbprints containing the leaf's canonical hex: authenticated", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, thumbprints: []string{leaf.thumbprint()}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		assertAuthenticated(t, p, reqCtx, 0)
	})

	t.Run("thumbprints not containing it: denied", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, thumbprints: []string{other.thumbprint()}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		assertDenied(t, p, reqCtx, reasonThumbprintMismatch)
	})
}

// ─── Multiple entries: first match wins, index recorded ─────────────────────

// TestMtlsAuthPolicy_Evaluate_MultipleEntries_SecondMatches guards that
// matchedEntry reflects the actual index that verified, not always "0".
func TestMtlsAuthPolicy_Evaluate_MultipleEntries_SecondMatches(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootX := newRootCA(t, "Unrelated Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{})

	entries := []entrySpec{
		{ca: "auth-ca-x", roots: []*testEntity{rootX}}, // never matches this leaf
		{ca: "auth-ca-a", roots: []*testEntity{rootA}}, // matches
	}
	p := mustBuildPolicy(t, []*testEntity{rootA, rootX}, entries)

	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
	result := assertAuthenticated(t, p, reqCtx, 1)
	if result.issuerCA != "auth-ca-a" {
		t.Errorf("issuerCA = %q, want %q", result.issuerCA, "auth-ca-a")
	}
	if got := reqCtx.SharedContext.AuthContext.Properties["matchedEntry"]; got != "1" {
		t.Errorf(`Properties["matchedEntry"] = %q, want "1"`, got)
	}
}

// ─── Pool membership alone never grants access ───────────────────────────────

// TestMtlsAuthPolicy_Evaluate_PoolMembershipAloneNeverGrantsAccess guards that
// an authority merely being in the gateway's client-CA pool (and therefore
// trusted at the connection level) is not sufficient — this API's own accept
// list must separately name it.
func TestMtlsAuthPolicy_Evaluate_PoolMembershipAloneNeverGrantsAccess(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootB := newRootCA(t, "Partner B Root CA")
	leaf := newLeaf(t, rootB, "client-wrong-ca", certOpts{})

	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	p := mustBuildPolicy(t, []*testEntity{rootB}, entries) // pool holds CA-B; accept list never names it

	// PeerCertValid=true: realistic, since rootB genuinely is in the gateway's
	// client-CA pool and the connection legitimately verified against it.
	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
	assertDenied(t, p, reqCtx, reasonAuthorityNotAccepted)
}

// ─── Lookalike CA: verified cryptographically, never by comparing names ─────

// TestMtlsAuthPolicy_Evaluate_LookalikeCA_SameDNDifferentKey_Denies is the
// package doc comment's central security property made concrete: a CA
// certificate whose distinguished name is byte-identical to a pooled,
// accepted authority — but signed with a different key — must never verify.
func TestMtlsAuthPolicy_Evaluate_LookalikeCA_SameDNDifferentKey_Denies(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	lookalikeCA := issueCert(t, "", certOpts{isCA: true, subject: rootA.cert.Subject})
	leaf := newLeaf(t, lookalikeCA, "client-lookalike", certOpts{uriSANs: []string{"urn:partner-a:payments"}})

	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	p := mustBuildPolicy(t, []*testEntity{rootA}, entries) // pool holds the REAL rootA only, never the lookalike

	// Realistic: Envoy's own verification against pool=[rootA] fails too,
	// since the lookalike CA's DN matches rootA's byte-for-byte but its key
	// does not.
	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, false))
	assertDenied(t, p, reqCtx, reasonUntrustedChain)
}

// ─── Verify must use ExtKeyUsageAny ──────────────────────────────────────────

// TestMtlsAuthPolicy_Evaluate_AcceptsClientAuthOnlyLeaf_ExtKeyUsageAny guards
// against a regression to Go's x509.Verify default KeyUsages (which requires
// ExtKeyUsageServerAuth) — every client-certificate fixture in this suite,
// like production client certificates, carries clientAuth-only EKU and would
// fail to verify at all under that default.
func TestMtlsAuthPolicy_Evaluate_AcceptsClientAuthOnlyLeaf_ExtKeyUsageAny(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-clientauth-only", certOpts{
		ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // explicit, though also this file's default
	})

	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	p := mustBuildPolicy(t, []*testEntity{rootA}, entries)

	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
	assertAuthenticated(t, p, reqCtx, 0)
}

// ─── GetPolicy bind-time validation ───────────────────────────────────────────

// TestGetPolicy_MalformedPEM_ReturnsError guards GetPolicy's doc-commented
// contract: a pool or accept-list certificate that isn't valid PEM/DER is a
// bind-time error, never deferred to request time.
func TestGetPolicy_MalformedPEM_ReturnsError(t *testing.T) {
	t.Run("malformed pool certificate", func(t *testing.T) {
		params := map[string]interface{}{
			internalPoolParam: []interface{}{"not a valid PEM certificate"},
		}
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Fatal("expected GetPolicy to return an error for a malformed pool certificate")
		}
	})

	t.Run("malformed accept-list certificate", func(t *testing.T) {
		params := map[string]interface{}{
			internalAcceptParam: []interface{}{
				map[string]interface{}{
					"ca":           "auth-ca-a",
					"certificates": []interface{}{"not a valid PEM certificate"},
				},
			},
		}
		if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
			t.Fatal("expected GetPolicy to return an error for a malformed accept-list certificate")
		}
	})
}

// ─── Header-relay decision order ───────────────────────────────────

// TestMtlsAuthPolicy_Evaluate_HeaderRelay covers evaluate()'s full decision
// order for a client certificate relayed in a header by a front proxy: header
// mode off, a relay-authenticated connection vouching for the header in every
// supported encoding, a header ignored because the connection isn't a relay
// (falling back to evaluating the connection as itself either way), a relay
// narrowed by SAN declining to vouch, and the trustAny bypass.
func TestMtlsAuthPolicy_Evaluate_HeaderRelay(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	acceptLeaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})
	otherAcceptLeaf := newLeaf(t, rootA, "client-other", certOpts{uriSANs: []string{"urn:partner-a:other"}})
	expiredLeaf := newLeaf(t, rootA, "client-expired", certOpts{
		notBefore: time.Now().Add(-2 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(-1 * 365 * 24 * time.Hour),
	})

	unrelatedRoot := newRootCA(t, "Unrelated Root CA")
	unacceptedLeaf := newLeaf(t, unrelatedRoot, "client-wrong-ca", certOpts{})

	relayCA := newRootCA(t, "Edge LB CA")
	relayLeaf := newLeaf(t, relayCA, "edge-lb", certOpts{dnsSANs: []string{"edge-lb.internal"}})

	corpCA := newRootCA(t, "Corp CA")
	// corpOtherLeaf verifies fine against corpCA (a relay root below) but
	// carries "other.corp.test", never the "lb.corp.test" a narrowed relay
	// entry requires — used to prove a SAN-mismatched relay declines to vouch.
	corpOtherLeaf := newLeaf(t, corpCA, "corp-other-service", certOpts{dnsSANs: []string{"other.corp.test"}})

	acceptEntries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	pool := []*testEntity{rootA, relayCA, corpCA}
	relays := []relaySpec{{name: "relay-edge-lb", roots: []*testEntity{relayCA}}}

	t.Run("header mode off: header present but inert, connection evaluated as itself", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, nil, nil) // no relays, trustAny defaults false
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(acceptLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(otherAcceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHandshake {
			t.Errorf("source = %q, want %q", result.source, sourceHandshake)
		}
	})

	t.Run("relay connection, header carries an accepted cert URL-encoded: authenticated via the header", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHeader {
			t.Errorf("source = %q, want %q", result.source, sourceHeader)
		}
		if result.relayedBy != "relay-edge-lb" {
			t.Errorf("relayedBy = %q, want %q", result.relayedBy, "relay-edge-lb")
		}
		if result.relaySubject != relayLeaf.cert.Subject.String() {
			t.Errorf("relaySubject = %q, want the relay leaf's own subject %q", result.relaySubject, relayLeaf.cert.Subject.String())
		}
	})

	t.Run("relay connection, header carries an accepted cert as plain PEM with newlines as spaces: authenticated", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, pemWithSpacesHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHeader {
			t.Errorf("source = %q, want %q", result.source, sourceHeader)
		}
	})

	t.Run("relay connection, header carries an accepted cert as bare base64 DER: authenticated", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, bareBase64DERHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHeader {
			t.Errorf("source = %q, want %q", result.source, sourceHeader)
		}
	})

	t.Run("relay connection, header carries a cert from an unaccepted authority: denied", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(unacceptedLeaf))
		assertDenied(t, p, reqCtx, reasonAuthorityNotAccepted)
	})

	t.Run("relay connection, header carries an expired cert: denied", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(expiredLeaf))
		assertDenied(t, p, reqCtx, reasonExpired)
	})

	t.Run("relay connection, header is garbage: denied with the uniform body", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, "this-is-not-a-certificate")
		assertDenied(t, p, reqCtx, reasonInvalidCert)
	})

	t.Run("connection is a valid non-relay client, header carries another client: authenticated as the connection", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(acceptLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(otherAcceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHandshake {
			t.Errorf("source = %q, want %q (the header must be ignored, never believed, from a non-relay connection)", result.source, sourceHandshake)
		}
		if result.subject != "urn:partner-a:payments" {
			t.Errorf("subject = %q, want the CONNECTION leaf's own subject %q, not the header's", result.subject, "urn:partner-a:payments")
		}
	})

	t.Run("connection has no certificate, header present, relays configured: denied no_certificate", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(&policy.DownstreamTLS{MTLS: false}, defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
		assertDenied(t, p, reqCtx, reasonNoCertificate)
	})

	t.Run("relay entry narrowed by a dnsSAN the relay leaf doesn't carry: header ignored, connection evaluated and denied", func(t *testing.T) {
		narrowedRelays := []relaySpec{{name: "relay-corp", roots: []*testEntity{corpCA}, dnsSANs: []string{"lb.corp.test"}}}
		p := mustBuildRelayPolicy(t, pool, acceptEntries, narrowedRelays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(corpOtherLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
		// corpOtherLeaf fails the relay's SAN narrowing, so the header (however
		// well-formed) is ignored, and this connection is evaluated as itself —
		// against an accept list that never names corpCA.
		assertDenied(t, p, reqCtx, reasonAuthorityNotAccepted)
	})

	t.Run("trustAny bypass: no connection certificate, header carries an accepted cert: authenticated, source bypass", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, nil, map[string]interface{}{"trustAny": true})
		reqCtx := reqCtxWithTLSAndHeader(nil, defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceBypass {
			t.Errorf("source = %q, want %q", result.source, sourceBypass)
		}
		if result.relayedBy != "" {
			t.Errorf("relayedBy = %q, want empty — the bypass names no relay", result.relayedBy)
		}
	})
}

// ─── Header forwarding to the backend ──────────────────────────────

// TestMtlsAuthPolicy_OnRequestHeaders_ForwardToBackend covers
// forwardToBackend's contract: remove the header only when it was NOT
// believed and forwardToBackend is on (a believed header, or forwardToBackend
// off entirely, must never see this policy strip it — the router's own
// default route configuration handles the off case).
func TestMtlsAuthPolicy_OnRequestHeaders_ForwardToBackend(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	acceptLeaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})
	relayCA := newRootCA(t, "Edge LB CA")
	relayLeaf := newLeaf(t, relayCA, "edge-lb", certOpts{})

	acceptEntries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	pool := []*testEntity{rootA, relayCA}
	relays := []relaySpec{{name: "relay-edge-lb", roots: []*testEntity{relayCA}}}

	believedReqCtx := func() *policy.RequestHeaderContext {
		return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
	}
	notBelievedReqCtx := func() *policy.RequestHeaderContext {
		// The connection's own certificate is a valid accepted client, not the
		// relay — so this header, however well-formed, is never believed.
		return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(acceptLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
	}

	mustModifications := func(t *testing.T, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
		t.Helper()
		mods, ok := action.(policy.UpstreamRequestHeaderModifications)
		if !ok {
			t.Fatalf("OnRequestHeaders returned %T, want policy.UpstreamRequestHeaderModifications", action)
		}
		return mods
	}

	t.Run("forwardToBackend true, believed header: not removed", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, map[string]interface{}{"forwardToBackend": true})
		action := p.OnRequestHeaders(context.Background(), believedReqCtx(), map[string]interface{}{})
		mods := mustModifications(t, action)
		if len(mods.HeadersToRemove) != 0 {
			t.Errorf("HeadersToRemove = %v, want empty — a believed header must reach the backend", mods.HeadersToRemove)
		}
	})

	t.Run("forwardToBackend true, header not believed (non-relay connection): removed", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, map[string]interface{}{"forwardToBackend": true})
		action := p.OnRequestHeaders(context.Background(), notBelievedReqCtx(), map[string]interface{}{})
		mods := mustModifications(t, action)
		if !slices.Contains(mods.HeadersToRemove, defaultHeaderName) {
			t.Errorf("HeadersToRemove = %v, want it to contain %q — a header this policy never believed must not reach the backend", mods.HeadersToRemove, defaultHeaderName)
		}
	})

	t.Run("forwardToBackend false: no removal action either way", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil) // forwardToBackend defaults false

		believedAction := p.OnRequestHeaders(context.Background(), believedReqCtx(), map[string]interface{}{})
		if mods := mustModifications(t, believedAction); len(mods.HeadersToRemove) != 0 {
			t.Errorf("HeadersToRemove (believed) = %v, want empty when forwardToBackend is false", mods.HeadersToRemove)
		}

		notBelievedAction := p.OnRequestHeaders(context.Background(), notBelievedReqCtx(), map[string]interface{}{})
		if mods := mustModifications(t, notBelievedAction); len(mods.HeadersToRemove) != 0 {
			t.Errorf("HeadersToRemove (not believed) = %v, want empty when forwardToBackend is false — the router's own default route configuration strips it instead", mods.HeadersToRemove)
		}
	})
}
