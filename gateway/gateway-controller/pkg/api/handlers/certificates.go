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
	"regexp"
	"strings"
	"sync"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/utils"
	"github.com/wso2/api-platform/httpkit/httputil"
)

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

// certExpiryWarnLogInterval bounds how often the CERT_EXPIRES_SOON warning
// is logged (at WARN) for any single certificate, independent of how often
// GET /certificates is called. The warning itself is still returned in the
// response body on every call — only the log line is throttled.
const certExpiryWarnLogInterval = 24 * time.Hour

// certExpiryWarnThrottle is a small in-memory, mutex-guarded rate limiter
// for the CERT_EXPIRES_SOON WARN log line, keyed by certificate UUID. It is
// intentionally not configurable (no config key) — the interval is fixed.
// Zero value is ready to use: no explicit initialization required.
type certExpiryWarnThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time // certificate UUID -> last time this warning was logged
}

// shouldLog reports whether a CERT_EXPIRES_SOON WARN should be logged now
// for the given certificate UUID, and records the attempt either way so the
// next call within the interval is suppressed.
func (t *certExpiryWarnThrottle) shouldLog(certUUID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	if last, ok := t.last[certUUID]; ok && now.Sub(last) < certExpiryWarnLogInterval {
		return false
	}
	if t.last == nil {
		t.last = make(map[string]time.Time)
	}
	t.last[certUUID] = now
	return true
}

// UploadCertificateRequest represents the request body for certificate upload
type UploadCertificateRequest struct {
	Certificate string                   `json:"certificate" binding:"required"` // PEM-encoded certificate
	Name        string                   `json:"name" binding:"required"`        // Unique certificate name
	Usage       string                   `json:"usage"`                          // "upstream" (default) or "client"
	Role        string                   `json:"role"`                           // "client" (default) or "relay"; usage: client only
	Match       *models.CertificateMatch `json:"match,omitempty"`                // Only valid for role: relay
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
		subject, issuer string
		notBefore       time.Time
		notAfter        time.Time
		count           int
		isLeaf          bool
		warnings        []clientca.Warning
	)

	certData := []byte(req.Certificate)

	if effectiveUsage == models.CertificateUsageClient {
		subject = bundle.Identity.Subject.String()
		issuer = bundle.Identity.Issuer.String()
		notBefore = bundle.Identity.NotBefore
		notAfter = bundle.Identity.NotAfter
		count = len(bundle.Certificates)
		isLeaf = bundle.IsLeaf
		warnings = bundle.Warnings
	} else {
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
		UUID:        certID,
		Name:        req.Name,
		Certificate: certData,
		Subject:     subject,
		Issuer:      issuer,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		CertCount:   count,
		Usage:       effectiveUsage,
		Role:        effectiveRole,
		Match:       req.Match,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save to database
	if err := s.db.SaveCertificate(cert); err != nil {
		if storage.IsConflictError(err) {
			message := fmt.Sprintf("a certificate named %s already exists", req.Name)
			if effectiveUsage == models.CertificateUsageClient {
				message = fmt.Sprintf("a client-CA authority named %s already exists", req.Name)
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

	httputil.WriteJSON(w, http.StatusCreated, resp)
}

// validateCertificateUpload validates every request-level field on a
// certificate upload and, when usage is (or defaults to) upstream/client,
// validates the certificate content itself. All problems that can be
// determined independently of one another are collected together so the
// caller can report them in a single 400.
//
// It returns the accumulated validation result, the effective usage/role
// (defaulted when the request omitted them), and — for usage: client — the
// inspected Bundle (nil when validation failed or usage is upstream).
func (s *APIServer) validateCertificateUpload(req *UploadCertificateRequest) (*certUploadValidation, string, string, *clientca.Bundle) {
	v := &certUploadValidation{}

	nameProvided := req.Name != ""
	certProvided := req.Certificate != ""

	if !nameProvided {
		v.addFieldError("name", "both name and certificate are required")
	}
	if !certProvided {
		v.addFieldError("certificate", "both name and certificate are required")
	}

	if nameProvided && !certificateNamePattern.MatchString(req.Name) {
		v.addFieldError("name", "name may contain only letters, digits, ., _ and -")
	}

	usageProvided := req.Usage != ""
	usageValid := true
	effectiveUsage := models.CertificateUsageUpstream
	if usageProvided {
		if req.Usage != models.CertificateUsageUpstream && req.Usage != models.CertificateUsageClient {
			usageValid = false
			v.addFieldError("usage", "usage must be upstream or client")
		} else {
			effectiveUsage = req.Usage
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
		} else if usageValid && effectiveUsage == models.CertificateUsageUpstream {
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
	if certProvided && usageValid {
		if effectiveUsage == models.CertificateUsageClient {
			b, err := clientca.Inspect([]byte(req.Certificate), time.Now())
			if err != nil {
				var fe *clientca.FieldError
				if errors.As(err, &fe) {
					v.addFieldError(fe.Field, fe.Message)
				} else {
					v.addFieldError("certificate", "the value is not a PEM-encoded certificate")
				}
			} else {
				bundle = b
			}
		} else {
			if _, err := s.validateCertificate([]byte(req.Certificate)); err != nil {
				v.legacyUpstreamCertErr = err
			}
		}
	}

	return v, effectiveUsage, effectiveRole, bundle
}

// ListCertificates lists all custom certificates, optionally filtered by usage
// GET /certificates
func (s *APIServer) ListCertificates(w http.ResponseWriter, r *http.Request, params api.ListCertificatesParams) {
	correlationID := middleware.GetCorrelationID(r)
	log := s.logger.With(slog.String("correlation_id", correlationID))

	usageFilter := ""
	if params.Usage != nil {
		usageFilter = string(*params.Usage)
	}
	if usageFilter != "" && usageFilter != models.CertificateUsageUpstream && usageFilter != models.CertificateUsageClient {
		fieldErrors := []api.ValidationError{{
			Field:   stringPtr("usage"),
			Message: stringPtr("usage must be upstream or client"),
		}}
		httputil.WriteJSON(w, http.StatusBadRequest, api.ErrorResponse{
			Status:  "error",
			Message: "invalid usage filter",
			Errors:  &fieldErrors,
		})
		return
	}

	// Get certificates from database
	var certs []*models.StoredCertificate
	var err error
	if usageFilter != "" {
		certs, err = s.db.ListCertificatesByUsage(usageFilter)
	} else {
		certs, err = s.db.ListCertificates()
	}
	if err != nil {
		log.Error("Failed to list certificates from database", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Failed to list certificates",
		})
		return
	}

	var certificates []CertificateResponse
	totalBytes := 0
	now := time.Now()

	for _, cert := range certs {
		totalBytes += len(cert.Certificate)

		usage := cert.Usage
		if usage == "" {
			usage = models.CertificateUsageUpstream
		}

		item := CertificateResponse{
			ID:       cert.UUID,
			Name:     cert.Name,
			Subject:  cert.Subject,
			Issuer:   cert.Issuer,
			NotAfter: cert.NotAfter.Format("2006-01-02 15:04:05"),
			Count:    cert.CertCount,
			Usage:    usage,
			Status:   "success",
		}

		if usage == models.CertificateUsageClient {
			role := cert.Role
			if role == "" {
				role = models.CertificateRoleClient
			}
			item.Role = role
			if role == models.CertificateRoleRelay {
				item.Match = cert.Match
			}

			if referencedByApis, err := s.countClientCertificateReferences(cert.Name); err != nil {
				log.Warn("Failed to compute referencedByApis for client-CA authority",
					slog.String("name", cert.Name), slog.Any("error", err))
				// item.ReferencedByApis stays nil (absent in the response) rather
				// than a possibly-wrong count — see checkClientAuthorityDeletable's
				// doc comment for why a read failure isn't "no references".
			} else {
				item.ReferencedByApis = &referencedByApis
			}

			if identity, err := clientca.IdentityCertificate(cert.Certificate); err == nil {
				item.IsLeaf = !identity.IsCA
			} else {
				log.Warn("Failed to parse stored client certificate authority",
					slog.String("name", cert.Name), slog.Any("error", err))
			}

			if warning := clientca.ExpiryWarning(cert.NotAfter, now); warning != nil {
				item.Warnings = []clientca.Warning{*warning}
				// The warning always goes back in the response body; the log
				// line is throttled to once per certificate per day so that
				// polling this endpoint doesn't flood logs.
				if s.certExpiryWarnThrottle.shouldLog(cert.UUID, now) {
					log.Warn("Client certificate authority expiry warning",
						slog.String("code", warning.Code),
						slog.String("name", cert.Name),
						slog.Time("notAfter", cert.NotAfter))
				}
			}
		} else {
			if firstCert, err := firstX509Certificate(cert.Certificate); err == nil {
				item.IsLeaf = !firstCert.IsCA
			} else {
				log.Warn("Failed to parse stored certificate",
					slog.String("name", cert.Name), slog.Any("error", err))
			}
		}

		certificates = append(certificates, item)
	}

	httputil.WriteJSON(w, http.StatusOK, ListCertificatesResponse{
		Certificates: certificates,
		TotalCount:   len(certificates),
		TotalBytes:   totalBytes,
		Status:       "success",
	})
}

// DeleteCertificate deletes a certificate by ID
// DELETE /certificates/:id
func (s *APIServer) DeleteCertificate(w http.ResponseWriter, r *http.Request, id string) {
	correlationID := middleware.GetCorrelationID(r)
	log := s.logger.With(slog.String("correlation_id", correlationID))

	if id == "" {
		httputil.WriteJSON(w, http.StatusBadRequest, map[string]any{
			"status":  "error",
			"message": "Certificate ID is required",
		})
		return
	}

	translator := s.snapshotManager.GetTranslator()
	if translator == nil || translator.GetCertStore() == nil {
		log.Error("Certificate store not available")
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificate store not configured",
		})
		return
	}

	// Best-effort: read the certificate's usage before it's gone, so we know
	// afterwards whether the client-CA pool changed (and every mtls-auth
	// deployment needs re-pushing) — a lookup failure here doesn't block the
	// delete itself, which re-validates existence and reports 404 on its own.
	preDeleteCert, _ := s.db.GetCertificate(id)

	// A client-CA authority (never a relay entry — header mode simply turns
	// off when its last relay row goes away) cannot be removed while a
	// deployed API still depends on it: either by naming it explicitly in an
	// accept list, or — when it's the pool's last non-relay authority — by
	// inheriting the pool at all. See checkClientAuthorityDeletable.
	if preDeleteCert != nil {
		role := preDeleteCert.Role
		if role == "" {
			role = models.CertificateRoleClient
		}
		if preDeleteCert.Usage == models.CertificateUsageClient && role != models.CertificateRoleRelay {
			if errResp, statusCode, blocked := s.checkClientAuthorityDeletable(preDeleteCert); blocked {
				httputil.WriteJSON(w, statusCode, errResp)
				return
			}
		}
	}

	// Delete from database
	if err := s.db.DeleteCertificate(id); err != nil {
		log.Error("Failed to delete certificate",
			slog.String("id", id),
			slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusNotFound, map[string]any{
			"status":  "error",
			"message": "Certificate not found or failed to delete: " + err.Error(),
		})
		return
	}

	log.Info("Certificate deleted from database", slog.String("id", id))

	certStore := translator.GetCertStore()

	// Reload certificates from database
	if err := certStore.Reload(); err != nil {
		log.Error("Failed to reload certificates", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificate deleted but failed to reload",
		})
		return
	}

	// Trigger SDS update
	if err := s.snapshotManager.UpdateSnapshot(context.Background(), correlationID); err != nil {
		log.Error("Failed to update SDS snapshot", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificate deleted and reloaded but failed to update SDS",
		})
		return
	}

	log.Info("SDS snapshot updated after certificate deletion", slog.String("id", id))

	// The client-CA pool just changed: keep every deployed mtls-auth API's
	// policy chain current (see repushMtlsAuthDeployments).
	if preDeleteCert != nil && preDeleteCert.Usage == models.CertificateUsageClient {
		s.repushMtlsAuthDeployments(log)
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":  "success",
		"message": "Certificate deleted and SDS updated successfully",
		"id":      id,
	})
}

// ReloadCertificates manually triggers certificate reload and SDS update
// POST /certificates/reload
func (s *APIServer) ReloadCertificates(w http.ResponseWriter, r *http.Request) {
	correlationID := middleware.GetCorrelationID(r)
	log := s.logger.With(slog.String("correlation_id", correlationID))

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
			"message": "Failed to reload certificates",
		})
		return
	}

	// Trigger SDS update
	if err := s.snapshotManager.UpdateSnapshot(context.Background(), correlationID); err != nil {
		log.Error("Failed to update SDS snapshot", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "Certificates reloaded but failed to update SDS",
		})
		return
	}

	log.Info("Certificates reloaded and SDS snapshot updated")

	combinedCerts := certStore.GetCombinedCertificates()
	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"message":    "Certificates reloaded and SDS updated successfully",
		"totalBytes": len(combinedCerts),
	})
}

// Helper functions

// deployedRestAPIConfigs returns every currently-deployed RestApi
// configuration, read from the database rather than the in-memory
// ConfigStore. The in-memory store converges from the database
// asynchronously via the event-hub listener, so a certificate-delete
// referential-integrity check racing a just-completed API delete would see a
// stale, already-removed API if it read the in-memory store instead — the
// database reflects the committed state synchronously, which is what this
// check needs.
//
// A non-nil error means the database read itself failed — callers decide
// how to handle that: the DELETE path (checkClientAuthorityDeletable) must
// fail closed (refuse the delete) rather than silently treat a failed read
// as "no references found"; the GET listing (countClientCertificateReferences)
// may instead log and report the count as absent for that one request. A
// nil s.db (not wired, e.g. some unit tests) is not treated as an error —
// it simply yields no configs, consistent with there being nothing to check.
func (s *APIServer) deployedRestAPIConfigs() ([]*models.StoredConfig, error) {
	if s.db == nil {
		return nil, nil
	}
	configs, err := s.db.GetAllConfigsByKind(string(models.KindRestApi))
	if err != nil {
		return nil, err
	}
	deployed := make([]*models.StoredConfig, 0, len(configs))
	for _, cfg := range configs {
		if cfg.DesiredState == models.StateDeployed {
			deployed = append(deployed, cfg)
		}
	}
	return deployed, nil
}

// countClientCertificateReferences counts the deployed RestApi configurations
// whose mtls-auth instances (API- or operation-level) explicitly name
// certName in an accept entry's `ca`. An API that merely inherits the pool
// (accept omitted) is never counted — only an explicit reference. A non-nil
// error means the underlying database read failed; the caller (ListCertificates)
// logs it and reports referencedByApis as absent for that response, rather
// than a possibly-wrong count.
func (s *APIServer) countClientCertificateReferences(certName string) (int, error) {
	restAPIs, err := s.deployedRestAPIConfigs()
	if err != nil {
		return 0, err
	}
	count := 0
	for _, cfg := range restAPIs {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		if len(config.NamedAcceptEntryFieldPaths(&restCfg, certName)) > 0 {
			count++
		}
	}
	return count, nil
}

// clientAuthorityReference is one deployed API's dependency on a client-CA
// pool authority, either by naming it explicitly or by attaching mtls-auth
// (used for the "last non-relay authority" check, where inheriting counts
// too).
type clientAuthorityReference struct {
	apiHandle string
	fieldPath string
}

// pluralDeployedAPIs renders the "N deployed APIs" / "1 deployed API" clause
// used by both certificate-delete referential-integrity messages below.
func pluralDeployedAPIs(n int) string {
	if n == 1 {
		return "1 deployed API"
	}
	return fmt.Sprintf("%d deployed APIs", n)
}

// checkClientAuthorityDeletable reports whether cert (a usage: client,
// non-relay authority — callers must check this before calling) can be
// removed from the pool right now. It never mutates anything; callers still
// perform the actual delete.
//
// Two refusal conditions, checked in order (the first one that applies wins,
// since a named reference is the more specific problem even when the
// authority also happens to be the pool's last one):
//
//  1. The authority is explicitly named in some deployed API's accept list —
//     removing it would silently invalidate that API's own configuration.
//  2. Removing it would leave the pool with zero non-relay client
//     authorities while some deployed API still attaches mtls-auth (whether
//     or not it names an authority explicitly) — that API could never
//     authenticate any caller again.
//
// A third condition, checked first of all: if the deployed-config read
// itself fails, this fails CLOSED — refuse the delete with a 500 rather than
// silently proceeding as though no API referenced the authority. A read
// failure is not evidence of an empty reference set.
//
// Returns the ready-to-write ErrorResponse body, the HTTP status to write it
// with, and true when refused; false (with an empty body/status) when the
// deletion may proceed.
func (s *APIServer) checkClientAuthorityDeletable(cert *models.StoredCertificate) (api.ErrorResponse, int, bool) {
	restAPIs, err := s.deployedRestAPIConfigs()
	if err != nil {
		s.logger.Error("Failed to read deployed RestApi configurations for client-CA referential-integrity check",
			slog.String("certificate", cert.Name), slog.Any("error", err))
		return api.ErrorResponse{Status: "error", Message: "Failed to verify certificate references"},
			http.StatusInternalServerError, true
	}

	var namedRefs []clientAuthorityReference
	for _, cfg := range restAPIs {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		paths := config.NamedAcceptEntryFieldPaths(&restCfg, cert.Name)
		if len(paths) == 0 {
			continue
		}
		namedRefs = append(namedRefs, clientAuthorityReference{apiHandle: cfg.Handle, fieldPath: paths[0]})
	}
	if len(namedRefs) > 0 {
		errs := make([]api.ValidationError, len(namedRefs))
		for i, ref := range namedRefs {
			errs[i] = api.ValidationError{
				Field:   stringPtr(ref.fieldPath),
				Message: stringPtr(fmt.Sprintf("referenced by API '%s'", ref.apiHandle)),
			}
		}
		message := fmt.Sprintf("client-CA authority '%s' is named by %s; remove those references first",
			cert.Name, pluralDeployedAPIs(len(namedRefs)))
		return api.ErrorResponse{Status: "error", Message: message, Errors: &errs}, http.StatusConflict, true
	}

	remainingNonRelay := 0
	if clientCerts, err := s.db.ListCertificatesByUsage(models.CertificateUsageClient); err == nil {
		for _, c := range clientCerts {
			if c.UUID == cert.UUID {
				continue // the one about to be deleted
			}
			role := c.Role
			if role == "" {
				role = models.CertificateRoleClient
			}
			if role != models.CertificateRoleRelay {
				remainingNonRelay++
			}
		}
	}
	if remainingNonRelay > 0 {
		return api.ErrorResponse{}, 0, false
	}

	var attachRefs []clientAuthorityReference
	for _, cfg := range restAPIs {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		paths := config.MtlsAuthAttachmentFieldPaths(&restCfg)
		if len(paths) == 0 {
			continue
		}
		attachRefs = append(attachRefs, clientAuthorityReference{apiHandle: cfg.Handle, fieldPath: paths[0]})
	}
	if len(attachRefs) == 0 {
		return api.ErrorResponse{}, 0, false
	}

	errs := make([]api.ValidationError, len(attachRefs))
	for i, ref := range attachRefs {
		errs[i] = api.ValidationError{
			Field:   stringPtr(ref.fieldPath),
			Message: stringPtr(fmt.Sprintf("referenced by API '%s'", ref.apiHandle)),
		}
	}
	verb := "attach"
	if len(attachRefs) == 1 {
		verb = "attaches"
	}
	message := fmt.Sprintf("cannot remove the last client-CA authority while %s %s mtls-auth; add a replacement first or remove those APIs",
		pluralDeployedAPIs(len(attachRefs)), verb)
	return api.ErrorResponse{Status: "error", Message: message, Errors: &errs}, http.StatusConflict, true
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
