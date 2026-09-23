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

// Package gatewayidentity validates uploads to POST/PUT /gateway-identities:
// a certificate chain (leaf first) plus its private key that the gateway
// presents to a backend requiring mutual TLS on outbound connections. It
// mirrors pkg/clientca's shape (FieldError/Warning, sterile error messages
// that never echo uploaded bytes) but validates a private-key-bearing
// identity rather than a bare certificate authority.
package gatewayidentity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

const (
	fieldCertificate = "certificate"
	fieldPrivateKey  = "privateKey"

	msgNotPEMCertificate = "the value is not a PEM-encoded certificate"
	msgKeyMismatch       = "the private key does not match the certificate"
	msgPassphraseKey     = "passphrase-protected private keys are not supported; " +
		"upload an unencrypted key (it is encrypted at rest by the gateway)"
	msgNotPEMKey = "the value is not a PEM-encoded private key"

	// CodeNoClientAuthEKU is attached when the leaf certificate carries an
	// ExtKeyUsage extension that does not include clientAuth (or "any").
	CodeNoClientAuthEKU = "IDENTITY_NO_CLIENTAUTH_EKU"
)

// FieldError is a validation failure tied to one request field. The message
// never includes any part of the uploaded body.
type FieldError struct {
	Field   string
	Message string
}

func (e *FieldError) Error() string { return e.Message }

// Warning is a non-fatal finding attached to a successful upload.
type Warning struct {
	Code    string `json:"code"`
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Bundle is the result of successfully inspecting an uploaded certificate
// chain + private key pair.
type Bundle struct {
	// Leaf is the first certificate in the chain (the identity presented on
	// the wire).
	Leaf *x509.Certificate
	// Chain holds every certificate in the uploaded body, in order (leaf
	// first).
	Chain []*x509.Certificate
	// PrivateKey is the parsed, unencrypted private key.
	PrivateKey crypto.Signer
	// KeyAlgorithm names the leaf key's algorithm: RSA, ECDSA or Ed25519.
	KeyAlgorithm string
	// Warnings are non-fatal findings about the leaf certificate.
	Warnings []Warning
}

// ParseChain decodes every CERTIFICATE PEM block in data, in order (leaf
// first), with no expiry check — used by read paths (listing, referential-
// integrity checks) where an already-stored identity must still display
// even if it has since expired. On failure the returned error is always a
// *FieldError with Field set to "certificate".
func ParseChain(pemData []byte) ([]*x509.Certificate, error) {
	rest := []byte(pemData)
	var chain []*x509.Certificate
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
			return nil, &FieldError{Field: fieldCertificate, Message: msgNotPEMCertificate}
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, &FieldError{Field: fieldCertificate, Message: msgNotPEMCertificate}
	}
	return chain, nil
}

// InspectCertificateChain parses and validates an uploaded PEM certificate
// chain (leaf first, optionally followed by intermediates). now is the point
// in time expiry is evaluated against (normally time.Now(), passed
// explicitly for testability). On failure the returned error is always a
// *FieldError with Field set to "certificate".
func InspectCertificateChain(pemData []byte, now time.Time) ([]*x509.Certificate, error) {
	chain, err := ParseChain(pemData)
	if err != nil {
		return nil, err
	}

	leaf := chain[0]
	if now.After(leaf.NotAfter) {
		return nil, &FieldError{
			Field:   fieldCertificate,
			Message: fmt.Sprintf("the certificate expired on %s", leaf.NotAfter.Format(time.RFC3339)),
		}
	}

	return chain, nil
}

// InspectPrivateKey parses and validates an uploaded PEM private key,
// rejecting passphrase-protected keys outright (this gateway never prompts
// for or stores a passphrase — the key itself is encrypted at rest instead).
// Supports RSA/ECDSA/Ed25519 in PKCS#8, PKCS#1 (RSA) or SEC1 (EC) form. On
// failure the returned error is always a *FieldError with Field set to
// "privateKey".
func InspectPrivateKey(pemData []byte) (crypto.Signer, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgNotPEMKey}
	}

	if block.Type == "ENCRYPTED PRIVATE KEY" {
		return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgPassphraseKey}
	}
	// Legacy OpenSSL-style encrypted PEM (RSA/EC PRIVATE KEY with a
	// "Proc-Type: 4,ENCRYPTED" header) — reject before attempting to parse.
	if procType, ok := block.Headers["Proc-Type"]; ok && strings.Contains(procType, "ENCRYPTED") {
		return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgPassphraseKey}
	}

	var (
		key crypto.Signer
		alg string
	)

	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgNotPEMKey}
		}
		signer, algName, err := signerAndAlgorithm(parsed)
		if err != nil {
			return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgNotPEMKey}
		}
		key, alg = signer, algName
	case "RSA PRIVATE KEY": // PKCS#1
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgNotPEMKey}
		}
		key, alg = parsed, "RSA"
	case "EC PRIVATE KEY": // SEC1
		parsed, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgNotPEMKey}
		}
		key, alg = parsed, "ECDSA"
	default:
		return nil, "", &FieldError{Field: fieldPrivateKey, Message: msgNotPEMKey}
	}

	return key, alg, nil
}

// signerAndAlgorithm classifies a value returned by x509.ParsePKCS8PrivateKey.
func signerAndAlgorithm(parsed interface{}) (crypto.Signer, string, error) {
	switch k := parsed.(type) {
	case *rsa.PrivateKey:
		return k, "RSA", nil
	case *ecdsa.PrivateKey:
		return k, "ECDSA", nil
	case ed25519.PrivateKey:
		return k, "Ed25519", nil
	default:
		return nil, "", fmt.Errorf("unsupported private key type %T", parsed)
	}
}

// keyMatchesLeaf reports whether priv's public key matches leaf's public key.
func keyMatchesLeaf(leaf *x509.Certificate, priv crypto.Signer) bool {
	type equaler interface {
		Equal(x crypto.PublicKey) bool
	}
	pub, ok := priv.Public().(equaler)
	if !ok {
		return false
	}
	return pub.Equal(leaf.PublicKey)
}

// ClientAuthWarning returns an IDENTITY_NO_CLIENTAUTH_EKU warning when leaf
// carries an ExtKeyUsage extension that does not include clientAuth or
// "any". A leaf with no ExtKeyUsage extension at all returns nil — an
// absent EKU imposes no restriction, so there is nothing to warn about.
func ClientAuthWarning(leaf *x509.Certificate) *Warning {
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return nil
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth || eku == x509.ExtKeyUsageAny {
			return nil
		}
	}
	return &Warning{
		Code:    CodeNoClientAuthEKU,
		Field:   fieldCertificate,
		Message: "certificate does not assert the clientAuth extended key usage; some backends will reject it",
	}
}

// Inspect validates an uploaded certificate chain + private key pair as a
// unit: parses both, rejects an expired or passphrase-protected identity,
// and confirms the key matches the leaf's public key. now is the point in
// time expiry is evaluated against.
func Inspect(certPEM, keyPEM []byte, now time.Time) (*Bundle, error) {
	chain, err := InspectCertificateChain(certPEM, now)
	if err != nil {
		return nil, err
	}

	key, alg, err := InspectPrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}

	leaf := chain[0]
	if !keyMatchesLeaf(leaf, key) {
		return nil, &FieldError{Field: fieldPrivateKey, Message: msgKeyMismatch}
	}

	bundle := &Bundle{
		Leaf:         leaf,
		Chain:        chain,
		PrivateKey:   key,
		KeyAlgorithm: alg,
	}
	if w := ClientAuthWarning(leaf); w != nil {
		bundle.Warnings = append(bundle.Warnings, *w)
	}
	return bundle, nil
}
