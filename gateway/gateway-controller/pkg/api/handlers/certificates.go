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

package handlers

import (
	"regexp"

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// The /certificates REST API is split by concern across several files, all
// sharing the request/response types and constants declared here:
//
//   - certificates.go (this file): request/response types and constants
//     shared by every handler below.
//   - certificates_upload.go: POST /certificates — request validation
//     (certUploadValidation), certificate/key content inspection, and the
//     upload handler itself.
//   - certificates_identity.go: PUT /certificates/{id} — usage: identity
//     rotation in place.
//   - certificates_listing.go: GET /certificates.
//   - certificates_deletion.go: DELETE /certificates/{id}, POST
//     /certificates/reload, and the referential-integrity checks that guard
//     a delete against a still-deployed API depending on the row being
//     removed.

// maxCertificateUploadBytes bounds the /certificates request body. A client-CA
// chain is small (a handful of KB at most), so 1 MiB comfortably covers any
// legitimate upload while stopping an oversized body from being read into
// memory in full (see go-network-service-hardening.md).
const maxCertificateUploadBytes = 1 << 20 // 1 MiB

// certificateUploadInvalidMessage is the single top-level message returned
// for any 400 from certificate upload validation, regardless of how many
// individual field problems were found.
const certificateUploadInvalidMessage = "certificate upload is invalid"

var certificateNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// UploadCertificateRequest represents the request body for certificate upload
type UploadCertificateRequest struct {
	Certificate string                   `json:"certificate" binding:"required"` // PEM-encoded certificate
	Name        string                   `json:"name" binding:"required"`        // Unique certificate name
	Usage       string                   `json:"usage"`                          // "upstream" (default), "client" or "identity"
	Role        string                   `json:"role"`                           // "client" (default) or "relay"; usage: client only
	Match       *models.CertificateMatch `json:"match,omitempty"`                // Only valid for role: relay
	PrivateKey  string                   `json:"privateKey,omitempty"`           // Required (and only valid) for usage: identity
}

// CertificateResponse represents a certificate information response
type CertificateResponse struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Subject          string                   `json:"subject,omitempty"`
	Issuer           string                   `json:"issuer,omitempty"`
	NotAfter         string                   `json:"notAfter,omitempty"`
	Count            int                      `json:"count"` // Number of certs in file
	Usage            string                   `json:"usage"`
	Role             string                   `json:"role,omitempty"`
	Match            *models.CertificateMatch `json:"match,omitempty"`
	IsLeaf           bool                     `json:"isLeaf"`
	KeyAlgorithm     string                   `json:"keyAlgorithm,omitempty"` // Only present for usage: identity
	ChainLength      int                      `json:"chainLength,omitempty"`  // Only present for usage: identity
	Warnings         []clientca.Warning       `json:"warnings,omitempty"`
	ReferencedByApis *int                     `json:"referencedByApis,omitempty"`
	Message          string                   `json:"message,omitempty"`
	Status           string                   `json:"status"` // success, error
}

// ListCertificatesResponse represents the response for listing certificates
type ListCertificatesResponse struct {
	Certificates []CertificateResponse `json:"certificates"`
	TotalCount   int                   `json:"totalCount"`
	TotalBytes   int                   `json:"totalBytes"`
	Status       string                `json:"status"`
}
