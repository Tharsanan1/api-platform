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

// Requests relaying a client certificate through a header instead of (or
// alongside) the TLS handshake (features/mtls-header-relay.feature,
// mtls-header-forward.feature, mtls-header-bypass.feature).
//
// A front proxy that terminates TLS relays the client certificate it saw to
// the gateway in a header instead of (or alongside) its own TLS handshake.
// These steps build that header value and set it via useHeaderForOneRequest
// for one request only, so it never leaks into a later request that must be
// sent without it.
package it

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Header encodings a front proxy might use for a relayed client certificate.
const (
	headerCertEncodingURL    = "url"    // default: the PEM text, URL-path-escaped
	headerCertEncodingPEM    = "pem"    // raw PEM text, newlines replaced by spaces
	headerCertEncodingBase64 = "base64" // bare base64 of the DER bytes, no PEM armor
)

// encodeCertificateForHeader renders fixture "name"'s certificate the way a
// front proxy would place it in a header, per the requested encoding. An
// empty encoding means the default: "url".
func (m *mtlsSteps) encodeCertificateForHeader(name, encoding string) (string, error) {
	certPEM, err := m.readFixtureCert(name)
	if err != nil {
		return "", err
	}
	switch encoding {
	case "", headerCertEncodingURL:
		return url.PathEscape(string(certPEM)), nil
	case headerCertEncodingPEM:
		// HTTP headers cannot carry a literal newline; several proxies emit
		// the PEM text with newlines replaced by spaces instead of encoding it.
		return strings.ReplaceAll(string(certPEM), "\n", " "), nil
	case headerCertEncodingBase64:
		cert, err := m.parseFixtureCert(name)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(cert.Raw), nil
	default:
		return "", fmt.Errorf("unknown certificate header encoding %q", encoding)
	}
}

// useHeaderForOneRequest sets header name to value for the next request only
// and returns a function that restores whatever was in place before it, so a
// value never leaks into a later request that must be sent without it —
// used both for a relayed client certificate and for a bearer JWT
// (Authorization) set for a single request (steps_mtls_request.go).
func (m *mtlsSteps) useHeaderForOneRequest(name, value string) func() {
	previous, had := m.httpSteps.Header(name)
	m.httpSteps.SetHeader(name, value)
	return func() {
		if had {
			m.httpSteps.SetHeader(name, previous)
		} else {
			m.httpSteps.RemoveHeader(name)
		}
	}
}

// getWithClientCertificateAndHeaderCertificate sends a request presenting
// certName as the TLS client certificate while relaying certFixture, encoded
// the default way (url), in headerName.
func (m *mtlsSteps) getWithClientCertificateAndHeaderCertificate(reqURL, certName, headerName, certFixture string) error {
	return m.getWithClientCertificateAndHeaderCertificateEncoded(reqURL, certName, headerName, certFixture, "")
}

// getWithClientCertificateAndHeaderCertificateEncoded is the same pairing,
// with an explicit header encoding ("url", "pem", or "base64").
func (m *mtlsSteps) getWithClientCertificateAndHeaderCertificateEncoded(reqURL, certName, headerName, certFixture, encoding string) error {
	encoded, err := m.encodeCertificateForHeader(certFixture, encoding)
	if err != nil {
		return err
	}
	restore := m.useHeaderForOneRequest(headerName, encoded)
	defer restore()
	return m.getWithClientCertificate(reqURL, certName)
}

// getWithNoClientCertificateAndHeaderCertificate presents no TLS client
// certificate at all while relaying certFixture (default encoding) in
// headerName - the case where the connection itself carries no identity and
// only the header claims one.
func (m *mtlsSteps) getWithNoClientCertificateAndHeaderCertificate(reqURL, headerName, certFixture string) error {
	encoded, err := m.encodeCertificateForHeader(certFixture, "")
	if err != nil {
		return err
	}
	restore := m.useHeaderForOneRequest(headerName, encoded)
	defer restore()
	return m.getWithNoClientCertificate(reqURL)
}

// getWithHeaderCertificate sends a request over plaintext HTTP or over HTTPS
// without presenting any client certificate, relaying certFixture (default
// encoding) in headerName. Shares tlsClientNoCertificate's per-request client:
// its TLS settings are simply unused when reqURL is a plain http:// URL.
func (m *mtlsSteps) getWithHeaderCertificate(reqURL, headerName, certFixture string) error {
	return m.getWithNoClientCertificateAndHeaderCertificate(reqURL, headerName, certFixture)
}
