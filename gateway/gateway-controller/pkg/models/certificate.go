/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package models

import "time"

// Certificate usage values. Usage determines which trust purpose a stored
// certificate serves: verifying upstream/backend HTTPS connections, or
// pooling client certificate authorities for mutual TLS. The two purposes
// never share a trust bundle (see pkg/certstore).
const (
	// CertificateUsageUpstream marks a certificate as backend/upstream trust
	// (the original, pre-mTLS purpose of the /certificates endpoint).
	CertificateUsageUpstream = "upstream"

	// CertificateUsageClient marks a certificate as a pooled client
	// certificate authority, used to authenticate API callers over mTLS.
	CertificateUsageClient = "client"
)

// Certificate role values. Role only applies to usage: client certificates
// and describes how the gateway is expected to use the authority.
const (
	// CertificateRoleClient is the default role for a client-CA entry: the
	// authority is used to validate a client certificate presented directly
	// on the mTLS connection.
	CertificateRoleClient = "client"

	// CertificateRoleRelay marks a client-CA entry as trusted for validating
	// a client certificate relayed via a header (e.g. from a terminating
	// load balancer/proxy) rather than presented on the connection itself.
	CertificateRoleRelay = "relay"
)

// StoredCertificate represents a certificate stored in the database
type StoredCertificate struct {
	UUID        string    `json:"uuid"`        // Unique UUID
	Name        string    `json:"name"`        // Human-readable name
	Certificate []byte    `json:"certificate"` // PEM-encoded certificate(s)
	Subject     string    `json:"subject"`     // Certificate subject DN
	Issuer      string    `json:"issuer"`      // Certificate issuer DN
	NotBefore   time.Time `json:"notBefore"`   // Certificate validity start
	NotAfter    time.Time `json:"notAfter"`    // Certificate validity end
	CertCount   int       `json:"certCount"`   // Number of certs in bundle
	Usage       string    `json:"usage"`       // "upstream" (default) or "client"
	Role        string    `json:"role"`        // "client" (default) or "relay"; meaningful only for usage: client
	CreatedAt   time.Time `json:"createdAt"`   // When uploaded
	UpdatedAt   time.Time `json:"updatedAt"`   // Last modified
}
