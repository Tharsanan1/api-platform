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
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/gatewayidentity"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/utils"
	"github.com/wso2/api-platform/httpkit/httputil"
)

// certUploadValidation accumulates every request-level problem found while
// validating an upload, so all of them can be reported together in one 400.
type certUploadValidation struct {
	fieldErrors []api.ValidationError

	// legacyUpstreamCertErr holds a certificate-content failure for
	// usage: upstream uploads, validated via the pre-existing
	// s.validateCertificate path. When it is the ONLY problem found, the
	// response keeps today's exact flat shape/message (no errors[]
	// envelope) for backward compatibility with callers already depending
	// on it; when combined with other field errors it is folded into the
	// same errors[] list instead.
	legacyUpstreamCertErr error

	// identityBundle holds the inspected certificate chain + private key
	// for a usage: identity upload (nil unless usage is identity and both
	// certificate and privateKey passed inspection).
	identityBundle *gatewayidentity.Bundle
}

func (v *certUploadValidation) addFieldError(field, message string) {
	v.fieldErrors = append(v.fieldErrors, api.ValidationError{
		Field:   stringPtr(field),
		Message: stringPtr(message),
	})
}

func (v *certUploadValidation) hasProblems() bool {
	return len(v.fieldErrors) > 0 || v.legacyUpstreamCertErr != nil
}

// validateMatchLists validates a role: relay entry's optional match narrowing:
// each of dnsSANs/uriSANs, when present at all, must list at least one
// non-empty SAN. A list omitted entirely (nil) is not an error — it simply
// doesn't narrow on that dimension.
func (v *certUploadValidation) validateMatchLists(match *models.CertificateMatch) {
	v.validateMatchList("match.dnsSANs", match.DNSSANs)
	v.validateMatchList("match.uriSANs", match.URISANs)
}

func (v *certUploadValidation) validateMatchList(fieldPath string, list []string) {
	if list == nil {
		return
	}
	const emptyMessage = "list at least one non-empty SAN"
	if len(list) == 0 {
		v.addFieldError(fieldPath, emptyMessage)
		return
	}
	for i, s := range list {
		if strings.TrimSpace(s) == "" {
			v.addFieldError(fmt.Sprintf("%s[%d]", fieldPath, i), emptyMessage)
		}
	}
}

// UploadCertificate handles certificate upload via REST API
// POST /certificates
func (s *APIServer) UploadCertificate(w http.ResponseWriter, r *http.Request) {
	correlationID := middleware.GetCorrelationID(r)
	log := s.logger.With(slog.String("correlation_id", correlationID))

	// Bound the request body before reading it, per go-network-service-hardening.md.
	r.Body = http.MaxBytesReader(w, r.Body, maxCertificateUploadBytes)

	var req UploadCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			// Generic message: never state the configured limit (file-access.md).
			httputil.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"status":  "error",
				"message": "the request body is too large",
			})
			return
		}
		log.Warn("Invalid certificate upload request", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "Invalid request body: " + err.Error(),
		})
		return
	}

	validation, effectiveUsage, effectiveRole, bundle := s.validateCertificateUpload(&req)

	if validation.legacyUpstreamCertErr != nil && len(validation.fieldErrors) == 0 {
		// Exactly today's response for an invalid upstream certificate: no
		// errors[] envelope, same flat shape and message text.
		log.Warn("Invalid certificate provided", slog.Any("error", validation.legacyUpstreamCertErr))
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "Invalid certificate: " + validation.legacyUpstreamCertErr.Error(),
		})
		return
	}
	if validation.legacyUpstreamCertErr != nil {
		validation.addFieldError("certificate", "Invalid certificate: "+validation.legacyUpstreamCertErr.Error())
	}
	if validation.hasProblems() {
		fieldErrors := validation.fieldErrors
		httputil.WriteJSON(w, http.StatusBadRequest, api.ErrorResponse{
			Status:  "error",
			Message: certificateUploadInvalidMessage,
			Errors:  &fieldErrors,
		})
		return
	}

	// Extract certificate metadata and count for the response/storage record.
	var (
		subject, issuer      string
		notBefore            time.Time
		notAfter             time.Time
		count                int
		isLeaf               bool
		warnings             []clientca.Warning
		keyAlgorithm         string
		privateKeyCiphertext string
	)

	certData := []byte(req.Certificate)

	switch effectiveUsage {
	case models.CertificateUsageClient:
		subject = bundle.Identity.Subject.String()
		issuer = bundle.Identity.Issuer.String()
		notBefore = bundle.Identity.NotBefore
		notAfter = bundle.Identity.NotAfter
		count = len(bundle.Certificates)
		isLeaf = bundle.IsLeaf
		warnings = bundle.Warnings
	case models.CertificateUsageIdentity:
		ib := validation.identityBundle
		subject = ib.Leaf.Subject.String()
		issuer = ib.Leaf.Issuer.String()
		notBefore = ib.Leaf.NotBefore
		notAfter = ib.Leaf.NotAfter
		count = len(ib.Chain)
		isLeaf = !ib.Leaf.IsCA
		keyAlgorithm = ib.KeyAlgorithm
		for _, warn := range ib.Warnings {
			warnings = append(warnings, clientca.Warning{Code: warn.Code, Field: warn.Field, Message: warn.Message})
		}

		if s.encryptionManager == nil {
			log.Error("Cannot store gateway identity: no encryption provider configured")
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"status":  "error",
				"message": "gateway identity storage is not available",
			})
			return
		}
		ciphertext, err := s.encryptPrivateKey(req.PrivateKey)
		if err != nil {
			log.Error("Failed to encrypt gateway identity private key", slog.Any("error", err))
			httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
				"status":  "error",
				"message": "failed to store gateway identity",
			})
			return
		}
		privateKeyCiphertext = ciphertext
	default:
		var err error
		subject, issuer, notBefore, notAfter, err = s.extractCertificateMetadata(certData)
		if err != nil {
			// Should not happen: validateCertificate already succeeded above
			// against the same bytes. Preserve the legacy flat error shape.
			log.Warn("Failed to extract certificate metadata", slog.Any("error", err))
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"status":  "error",
				"message": "Failed to parse certificate metadata: " + err.Error(),
			})
			return
		}
		count, err = s.validateCertificate(certData)
		if err != nil {
			// Already validated above; defensive only.
			log.Warn("Invalid certificate provided", slog.Any("error", err))
			httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
				"status":  "error",
				"message": "Invalid certificate: " + err.Error(),
			})
			return
		}
		if firstCert, err := firstX509Certificate(certData); err == nil {
			isLeaf = !firstCert.IsCA
		} else {
			log.Warn("Failed to determine certificate authority status", slog.Any("error", err))
		}
	}

	for _, warning := range warnings {
		fields := []any{slog.String("code", warning.Code), slog.String("name", req.Name)}
		log.Warn("Client certificate authority warning", fields...)
	}

	// Generate unique ID (UUID v7)
	certID, err := utils.GenerateUUID()
	if err != nil {
		log.Error("Failed to generate certificate ID", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Failed to generate certificate ID",
		})
		return
	}

	// Create certificate model
	cert := &models.StoredCertificate{
		UUID:                 certID,
		Name:                 req.Name,
		Certificate:          certData,
		Subject:              subject,
		Issuer:               issuer,
		NotBefore:            notBefore,
		NotAfter:             notAfter,
		CertCount:            count,
		Usage:                effectiveUsage,
		Role:                 effectiveRole,
		Match:                req.Match,
		PrivateKeyCiphertext: privateKeyCiphertext,
		KeyAlgorithm:         keyAlgorithm,
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Save to database
	if err := s.db.SaveCertificate(cert); err != nil {
		if storage.IsConflictError(err) {
			message := fmt.Sprintf("a certificate named %s already exists", req.Name)
			switch effectiveUsage {
			case models.CertificateUsageClient:
				message = fmt.Sprintf("a client-CA authority named %s already exists", req.Name)
			case models.CertificateUsageIdentity:
				message = fmt.Sprintf("a gateway identity named %s already exists", req.Name)
			}
			httputil.WriteJSON(w, http.StatusConflict, map[string]any{
				"status":  "error",
				"message": message,
			})
			return
		}
		log.Error("Failed to save certificate to database",
			slog.String("name", req.Name),
			slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Failed to save certificate",
		})
		return
	}

	log.Info("Certificate saved to database successfully",
		slog.String("id", certID),
		slog.String("name", req.Name),
		slog.Int("cert_count", count))

	// Get cert store from snapshot manager
	translator := s.snapshotManager.GetTranslator()
	if translator == nil || translator.GetCertStore() == nil {
		log.Error("Certificate store not available")
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificate store not configured",
		})
		return
	}

	certStore := translator.GetCertStore()

	// Reload certificates from database
	if err := certStore.Reload(); err != nil {
		log.Error("Failed to reload certificates", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificate saved but failed to reload",
		})
		return
	}

	// Trigger SDS update by regenerating the snapshot
	if err := s.snapshotManager.UpdateSnapshot(context.Background(), correlationID); err != nil {
		log.Error("Failed to update SDS snapshot", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificate reloaded but failed to update SDS",
		})
		return
	}

	log.Info("SDS snapshot updated with new certificate",
		slog.String("id", certID),
		slog.String("name", req.Name))

	// The client-CA pool just changed: keep every deployed mtls-auth API's
	// policy chain current so an API that inherits the pool sees the new
	// authority on its next request (see repushMtlsAuthDeployments).
	if effectiveUsage == models.CertificateUsageClient {
		s.repushMtlsAuthDeployments(log)
	}

	resp := CertificateResponse{
		ID:       certID,
		Name:     req.Name,
		Subject:  subject,
		Issuer:   issuer,
		NotAfter: notAfter.Format("2006-01-02 15:04:05"),
		Count:    count,
		Usage:    effectiveUsage,
		IsLeaf:   isLeaf,
		Warnings: warnings,
		Message:  "Certificate uploaded and SDS updated successfully",
		Status:   "success",
	}
	if effectiveUsage == models.CertificateUsageClient {
		resp.Role = effectiveRole
		if effectiveRole == models.CertificateRoleRelay {
			resp.Match = req.Match
		}
	}
	if effectiveUsage == models.CertificateUsageIdentity {
		resp.KeyAlgorithm = keyAlgorithm
		resp.ChainLength = count
	}

	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// validateCertificateUpload validates every request-level field on a
// certificate upload and, depending on usage, validates the certificate
// content itself (usage: client), the certificate+key pair as a unit
// (usage: identity), or the legacy upstream-certificate path. All problems
// that can be determined independently of one another are collected
// together so the caller can report them in a single 400.
//
// It returns the accumulated validation result, the effective usage/role
// (defaulted when the request omitted them), and — for usage: client — the
// inspected client-CA Bundle (nil otherwise). For usage: identity, the
// inspected certificate+key bundle is on v.identityBundle instead.
func (s *APIServer) validateCertificateUpload(req *UploadCertificateRequest) (*certUploadValidation, string, string, *clientca.Bundle) {
	v := &certUploadValidation{}

	nameProvided := req.Name != ""
	certProvided := req.Certificate != ""
	keyProvided := req.PrivateKey != ""

	if !nameProvided {
		v.addFieldError("name", "both name and certificate are required")
	}

	if nameProvided && !certificateNamePattern.MatchString(req.Name) {
		v.addFieldError("name", "name may contain only letters, digits, ., _ and -")
	}

	usageProvided := req.Usage != ""
	usageValid := true
	effectiveUsage := models.CertificateUsageUpstream
	if usageProvided {
		switch req.Usage {
		case models.CertificateUsageUpstream, models.CertificateUsageClient, models.CertificateUsageIdentity:
			effectiveUsage = req.Usage
		default:
			usageValid = false
			v.addFieldError("usage", "usage must be upstream, client or identity")
		}
	}

	if effectiveUsage == models.CertificateUsageIdentity {
		if !certProvided {
			v.addFieldError("certificate", "both certificate and privateKey are required for usage: identity")
		}
		if !keyProvided {
			v.addFieldError("privateKey", "both certificate and privateKey are required for usage: identity")
		}
	} else {
		if !certProvided {
			v.addFieldError("certificate", "both name and certificate are required")
		}
		if keyProvided {
			v.addFieldError("privateKey", "privateKey applies only to usage: identity certificates")
		}
	}

	roleProvided := req.Role != ""
	effectiveRole := ""
	if effectiveUsage == models.CertificateUsageClient {
		effectiveRole = models.CertificateRoleClient
	}
	if roleProvided {
		if req.Role != models.CertificateRoleClient && req.Role != models.CertificateRoleRelay {
			v.addFieldError("role", "role must be client or relay")
		} else if usageValid && effectiveUsage != models.CertificateUsageClient {
			v.addFieldError("role", "role applies only to usage: client certificates")
		} else if usageValid {
			effectiveRole = req.Role
		}
	}

	if req.Match != nil {
		if effectiveRole != models.CertificateRoleRelay {
			v.addFieldError("match", "match applies only to role: relay entries")
		} else {
			v.validateMatchLists(req.Match)
		}
	}

	var bundle *clientca.Bundle
	if usageValid {
		switch {
		case effectiveUsage == models.CertificateUsageClient && certProvided:
			b, err := clientca.Inspect([]byte(req.Certificate), time.Now())
			if err != nil {
				var fe *clientca.FieldError
				if errors.As(err, &fe) {
					v.addFieldError(fe.Field, fe.Message)
				} else {
					v.addFieldError("certificate", clientca.MsgNotPEMCertificate)
				}
			} else {
				bundle = b
			}
		case effectiveUsage == models.CertificateUsageIdentity && certProvided && keyProvided:
			ib, err := gatewayidentity.Inspect([]byte(req.Certificate), []byte(req.PrivateKey), time.Now())
			if err != nil {
				var fe *gatewayidentity.FieldError
				if errors.As(err, &fe) {
					v.addFieldError(fe.Field, fe.Message)
				} else {
					v.addFieldError("certificate", clientca.MsgNotPEMCertificate)
				}
			} else {
				v.identityBundle = ib
			}
		case effectiveUsage == models.CertificateUsageUpstream && certProvided:
			if _, err := s.validateCertificate([]byte(req.Certificate)); err != nil {
				v.legacyUpstreamCertErr = err
			}
		}
	}

	return v, effectiveUsage, effectiveRole, bundle
}

// extractCertificateMetadata extracts metadata from the first certificate in the chain
func (s *APIServer) extractCertificateMetadata(data []byte) (subject, issuer string, notBefore, notAfter time.Time, err error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			err = parseErr
			return
		}

		// Use first certificate for metadata
		subject = cert.Subject.String()
		issuer = cert.Issuer.String()
		notBefore = cert.NotBefore
		notAfter = cert.NotAfter
		return
	}

	err = fmt.Errorf("no valid certificate found")
	return
}

func (s *APIServer) validateCertificate(data []byte) (int, error) {
	count := 0
	rest := data

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		_, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, fmt.Errorf("invalid certificate: %w", err)
		}

		count++
	}

	if count == 0 {
		return 0, fmt.Errorf("no valid certificates found in PEM data")
	}

	return count, nil
}

// firstX509Certificate parses and returns the first CERTIFICATE PEM block in
// data, matching the same "first cert in bundle" convention used for
// upstream certificate metadata (extractCertificateMetadata).
func firstX509Certificate(data []byte) (*x509.Certificate, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, fmt.Errorf("no certificate found")
}
