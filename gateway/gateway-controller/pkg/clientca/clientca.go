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

// Package clientca validates uploads to the client certificate authority
// pool: the /certificates endpoint's usage=client purpose. A client-CA entry
// may be a single certificate (an authority or a leaf trusted directly) or a
// small chain (e.g. an issuing CA together with its root); this package
// determines the "identity" certificate for such an upload, rejects uploads
// that don't form a single coherent authority, and surfaces non-fatal
// warnings (leaf, not-yet-valid, soon-to-expire).
package clientca

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// ExpiryWarningHorizon is how far in advance of a certificate's NotAfter the
// listing endpoint starts surfacing an expiry warning.
const ExpiryWarningHorizon = 30 * 24 * time.Hour

// Warning is a non-fatal finding attached to a bundle or a stored
// certificate. It is always returned alongside a successful result — it
// never blocks an upload.
type Warning struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// FieldError is a validation failure tied to a single request field. Field
// is the request property the caller should correct (e.g. "certificate").
type FieldError struct {
	Field   string
	Message string
}

// Error implements the error interface, returning the human-readable message.
func (e *FieldError) Error() string {
	return e.Message
}

// Bundle is the result of successfully inspecting an uploaded PEM body.
type Bundle struct {
	// Identity is the certificate no other certificate in the body signed —
	// the bottom of the chain. For a single-certificate upload it is that
	// certificate.
	Identity *x509.Certificate

	// Certificates holds every certificate found in the body, in the order
	// they appeared.
	Certificates []*x509.Certificate

	// IsLeaf is true when Identity lacks CA:TRUE (BasicConstraints), i.e. it
	// is not itself a certificate authority. It is still accepted and pooled
	// as a one-member authority that trusts exactly that certificate.
	IsLeaf bool

	// Warnings are non-fatal findings about the identity certificate
	// (leaf, not-yet-valid). Expiry warnings are computed separately by
	// ExpiryWarning, since they depend on when the bundle is being listed,
	// not just when it was uploaded.
	Warnings []Warning
}

// MsgNotPEMCertificate is the sterile validation message for a
// certificate/uploaded-value field that failed to parse as a PEM-encoded
// certificate. Exported so every certificate-content validator in the
// gateway-controller module (clientca, gatewayidentity, the
// /certificates upload handler) reports this exact wording, rather than
// each declaring its own copy of the same string.
const MsgNotPEMCertificate = "the value is not a PEM-encoded certificate"

const (
	// CodeClientCAIsLeaf, CodeClientCANotYetValid and CodeCertExpiresSoon are
	// exported (unlike the field/message constants alongside them) so a
	// cross-check against the OpenAPI CertificateWarning.code enum can
	// reference the same values this package actually emits, rather than a
	// second hardcoded copy of each string.
	CodeClientCAIsLeaf      = "CLIENT_CA_IS_LEAF"
	CodeClientCANotYetValid = "CLIENT_CA_NOT_YET_VALID"
	CodeCertExpiresSoon     = "CERT_EXPIRES_SOON"
	fieldCertificate        = "certificate"
	fieldNotAfter           = "notAfter"
	msgPrivateKeyPresent    = "the upload contains a private key; a client-CA entry accepts certificates only"
	msgUnrelatedAuthorities = "this PEM contains more than one unrelated authority; upload each as its own entry"
	msgLeafNotAuthority     = "the certificate is not a certificate authority; it is pooled as a one-member authority that trusts exactly this certificate"
)

// Inspect parses and validates an uploaded PEM body intended for the client
// certificate authority pool. now is the point in time expiry/validity is
// evaluated against (normally time.Now(), passed explicitly for testability).
//
// On failure the returned error is always a *FieldError with Field set to
// "certificate". The error message never includes any part of the uploaded
// body, and callers must not log the body either.
func Inspect(pemData []byte, now time.Time) (*Bundle, error) {
	// Check for private key material across the WHOLE body before doing any
	// certificate parsing, so a private key anywhere in the upload is always
	// reported first regardless of what else is (or isn't) parseable.
	if containsPrivateKeyBlock(pemData) {
		return nil, &FieldError{Field: fieldCertificate, Message: msgPrivateKeyPresent}
	}

	certs, err := parseCertificateBlocks(pemData)
	if err != nil {
		return nil, err
	}

	identity, err := findIdentity(certs)
	if err != nil {
		return nil, err
	}
	return inspectBundle(certs, identity, now)
}

// IdentityCertificate re-derives the identity certificate (the bottom of the
// chain, per the same rule Inspect uses) for a PEM body that was already
// accepted into the pool. Unlike Inspect, it does not re-check expiry or
// produce warnings — it exists for read paths (e.g. listing) where an
// already-stored certificate must still display even if it has since
// expired.
func IdentityCertificate(pemData []byte) (*x509.Certificate, error) {
	certs, err := parseCertificateBlocks(pemData)
	if err != nil {
		return nil, err
	}
	return findIdentity(certs)
}

func inspectBundle(certs []*x509.Certificate, identity *x509.Certificate, now time.Time) (*Bundle, error) {

	if now.After(identity.NotAfter) {
		return nil, &FieldError{
			Field:   fieldCertificate,
			Message: fmt.Sprintf("the certificate expired on %s", identity.NotAfter.Format(time.RFC3339)),
		}
	}

	bundle := &Bundle{
		Identity:     identity,
		Certificates: certs,
	}

	if !identity.IsCA {
		bundle.IsLeaf = true
		bundle.Warnings = append(bundle.Warnings, Warning{
			Code:    CodeClientCAIsLeaf,
			Field:   fieldCertificate,
			Message: msgLeafNotAuthority,
		})
	}

	if identity.NotBefore.After(now) {
		bundle.Warnings = append(bundle.Warnings, Warning{
			Code:    CodeClientCANotYetValid,
			Field:   fieldCertificate,
			Message: fmt.Sprintf("the certificate is not valid before %s", identity.NotBefore.Format(time.RFC3339)),
		})
	}

	return bundle, nil
}

// ExpiryWarning returns a CERT_EXPIRES_SOON warning when notAfter is within
// ExpiryWarningHorizon of now (including already past), or nil otherwise.
func ExpiryWarning(notAfter, now time.Time) *Warning {
	if notAfter.Sub(now) > ExpiryWarningHorizon {
		return nil
	}
	return &Warning{
		Code:    CodeCertExpiresSoon,
		Field:   fieldNotAfter,
		Message: fmt.Sprintf("the certificate expires on %s", notAfter.Format(time.RFC3339)),
	}
}

// containsPrivateKeyBlock reports whether any PEM block in data has a type
// ending in "PRIVATE KEY" (covers "PRIVATE KEY", "RSA PRIVATE KEY",
// "EC PRIVATE KEY", etc).
func containsPrivateKeyBlock(data []byte) bool {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if strings.HasSuffix(block.Type, "PRIVATE KEY") {
			return true
		}
	}
}

// parseCertificateBlocks decodes every CERTIFICATE PEM block in data, in
// order. Any block that fails to parse, or the absence of any CERTIFICATE
// block at all, is reported as the same sterile error — the caller learns
// only that the value isn't a usable PEM certificate, not why.
func parseCertificateBlocks(data []byte) ([]*x509.Certificate, error) {
	rest := data
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &FieldError{Field: fieldCertificate, Message: MsgNotPEMCertificate}
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, &FieldError{Field: fieldCertificate, Message: MsgNotPEMCertificate}
	}
	return certs, nil
}

// findIdentity determines the identity certificate of a bundle: the one
// certificate that is not the issuer of any other certificate in the body
// (the bottom of the chain). A single certificate trivially passes. For
// more than one certificate, every certificate must sign or be signed by
// another certificate in the body (checked via CheckSignatureFrom, never by
// comparing issuer/subject names) and exactly one certificate may be the
// bottom of the chain — otherwise the body contains more than one
// unrelated authority.
func findIdentity(certs []*x509.Certificate) (*x509.Certificate, error) {
	n := len(certs)
	if n == 1 {
		return certs[0], nil
	}

	isIssuerOfAnother := make([]bool, n)
	isSignedByAnother := make([]bool, n)

	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j {
				continue
			}
			// certs[i].CheckSignatureFrom(certs[j]) == nil means certs[j]
			// (the parent) signed certs[i] (the child).
			if certs[i].CheckSignatureFrom(certs[j]) == nil {
				isSignedByAnother[i] = true
				isIssuerOfAnother[j] = true
			}
		}
	}

	var bottom []*x509.Certificate
	for i := 0; i < n; i++ {
		if !isSignedByAnother[i] && !isIssuerOfAnother[i] {
			// Unrelated to every other certificate in the body.
			return nil, unrelatedAuthoritiesError()
		}
		if !isIssuerOfAnother[i] {
			bottom = append(bottom, certs[i])
		}
	}

	if len(bottom) != 1 {
		return nil, unrelatedAuthoritiesError()
	}

	return bottom[0], nil
}

func unrelatedAuthoritiesError() error {
	return &FieldError{Field: fieldCertificate, Message: msgUnrelatedAuthorities}
}
