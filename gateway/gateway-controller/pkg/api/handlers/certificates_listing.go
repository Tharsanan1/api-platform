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
	"log/slog"
	"net/http"
	"sync"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/gatewayidentity"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/httpkit/httputil"
)

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

// ListCertificates lists all custom certificates, optionally filtered by usage
// GET /certificates
func (s *APIServer) ListCertificates(w http.ResponseWriter, r *http.Request, params api.ListCertificatesParams) {
	correlationID := middleware.GetCorrelationID(r)
	log := s.logger.With(slog.String("correlation_id", correlationID))

	usageFilter := ""
	if params.Usage != nil {
		usageFilter = string(*params.Usage)
	}
	if usageFilter != "" && usageFilter != models.CertificateUsageUpstream && usageFilter != models.CertificateUsageClient && usageFilter != models.CertificateUsageIdentity {
		fieldErrors := []api.ValidationError{{
			Field:   stringPtr("usage"),
			Message: stringPtr("usage must be upstream, client or identity"),
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
		} else if usage == models.CertificateUsageIdentity {
			item.KeyAlgorithm = cert.KeyAlgorithm

			if chain, err := gatewayidentity.ParseChain(cert.Certificate); err == nil {
				item.ChainLength = len(chain)
				item.IsLeaf = !chain[0].IsCA
			} else {
				log.Warn("Failed to parse stored gateway identity certificate chain",
					slog.String("name", cert.Name), slog.Any("error", err))
			}

			if referencedByApis, err := s.countGatewayIdentityReferences(cert.Name); err != nil {
				log.Warn("Failed to compute referencedByApis for gateway identity",
					slog.String("name", cert.Name), slog.Any("error", err))
			} else {
				item.ReferencedByApis = &referencedByApis
			}

			if warning := clientca.ExpiryWarning(cert.NotAfter, now); warning != nil {
				item.Warnings = []clientca.Warning{*warning}
				if s.certExpiryWarnThrottle.shouldLog(cert.UUID, now) {
					log.Warn("Gateway identity expiry warning",
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
