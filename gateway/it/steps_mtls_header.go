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

// encodeCertificateForHeader renders the fixture certificate the way a front
// proxy would place it in a header. An empty encoding means "url".
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

// useHeaderForOneRequest sets a header for the next request and returns a
// function that restores the previous value, so it never leaks into a later
// request.
func (m *mtlsSteps) useHeaderForOneRequest(name, value string) func() {
	previous := m.httpSteps.Header(name)
	m.httpSteps.SetHeader(name, value)
	return func() {
		if previous != "" {
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

// getWithClientCertificateAndHeaderCertificateEncoded is the same request
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
// certificate while relaying certFixture in headerName, so only the header
// claims an identity.
func (m *mtlsSteps) getWithNoClientCertificateAndHeaderCertificate(reqURL, headerName, certFixture string) error {
	encoded, err := m.encodeCertificateForHeader(certFixture, "")
	if err != nil {
		return err
	}
	restore := m.useHeaderForOneRequest(headerName, encoded)
	defer restore()
	return m.getWithNoClientCertificate(reqURL)
}

// getWithHeaderCertificate relays certFixture in headerName over plain HTTP
// or over HTTPS without a client certificate.
func (m *mtlsSteps) getWithHeaderCertificate(reqURL, headerName, certFixture string) error {
	return m.getWithNoClientCertificateAndHeaderCertificate(reqURL, headerName, certFixture)
}
