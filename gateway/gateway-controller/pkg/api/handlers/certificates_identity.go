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
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/certmetrics"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/encryption"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/httpkit/httputil"
)

// encryptPrivateKey encrypts a usage: identity upload's raw PEM private key
// bytes and marshals the result for storage. Reused by upload and update.
func (s *APIServer) encryptPrivateKey(privateKeyPEM string) (string, error) {
	payload, err := s.encryptionManager.Encrypt([]byte(privateKeyPEM))
	if err != nil {
		return "", err
	}
	return encryption.MarshalPayload(payload), nil
}

// UpdateCertificate rotates a usage: identity certificate's chain and
// private key in place, keeping its name intact. Refused for any other
// usage.
// PUT /certificates/{id}
func (s *APIServer) UpdateCertificate(w http.ResponseWriter, r *http.Request, id string) {
	correlationID := middleware.GetCorrelationID(r)
	log := s.logger.With(slog.String("correlation_id", correlationID))

	existing, err := s.db.GetCertificate(id)
	if err != nil {
		httputil.WriteJSON(w, http.StatusNotFound, map[string]any{
			"status":  "error",
			"message": "certificate not found",
		})
		return
	}

	if existing.Usage != models.CertificateUsageIdentity {
		fieldErrors := []api.ValidationError{{
			Field:   stringPtr("usage"),
			Message: stringPtr("only usage: identity certificates can be updated; delete and re-upload other certificates"),
		}}
		httputil.WriteJSON(w, http.StatusBadRequest, api.ErrorResponse{
			Status:  "error",
			Message: certificateUploadInvalidMessage,
			Errors:  &fieldErrors,
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCertificateUploadBytes)

	var req UploadCertificateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			httputil.WriteJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
				"status":  "error",
				"message": "the request body is too large",
			})
			return
		}
		httputil.WriteJSON(w, http.StatusBadRequest, api.ErrorResponse{
			Status:  "error",
			Message: "invalid request body",
		})
		return
	}
	// Name/usage/role/match are immutable on rotation — force them to the
	// existing row's shape so validateCertificateUpload validates only the
	// certificate+key pair, regardless of what the caller sent.
	req.Name = existing.Name
	req.Usage = models.CertificateUsageIdentity
	req.Role = ""
	req.Match = nil

	validation, _, _, _ := s.validateCertificateUpload(&req)
	if validation.hasProblems() {
		fieldErrors := validation.fieldErrors
		httputil.WriteJSON(w, http.StatusBadRequest, api.ErrorResponse{
			Status:  "error",
			Message: certificateUploadInvalidMessage,
			Errors:  &fieldErrors,
		})
		return
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

	ib := validation.identityBundle
	updated := &models.StoredCertificate{
		UUID:                 existing.UUID,
		Name:                 existing.Name,
		Certificate:          []byte(req.Certificate),
		Subject:              ib.Leaf.Subject.String(),
		Issuer:               ib.Leaf.Issuer.String(),
		NotBefore:            ib.Leaf.NotBefore,
		NotAfter:             ib.Leaf.NotAfter,
		CertCount:            len(ib.Chain),
		Usage:                models.CertificateUsageIdentity,
		PrivateKeyCiphertext: ciphertext,
		KeyAlgorithm:         ib.KeyAlgorithm,
		UpdatedAt:            time.Now(),
	}

	if err := s.db.UpdateCertificate(updated); err != nil {
		log.Error("Failed to update certificate", slog.String("id", id), slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "failed to update certificate",
		})
		return
	}

	// Identity rows never enter the upstream trust/system bundle, so
	// certStore.Reload() is a no-op for them — still called for parity with
	// the upload/delete paths. The SDS snapshot update is what actually
	// matters: it rebuilds this identity's gateway_identity:<name> secret
	// from the new certificate/key.
	if translator := s.snapshotManager.GetTranslator(); translator != nil && translator.GetCertStore() != nil {
		if err := translator.GetCertStore().Reload(); err != nil {
			log.Warn("Failed to reload certificate store after identity rotation", slog.Any("error", err))
		}
	}

	if err := s.snapshotManager.UpdateSnapshot(context.Background(), correlationID); err != nil {
		log.Error("Failed to update SDS snapshot after certificate update", slog.Any("error", err))
		httputil.WriteJSON(w, http.StatusInternalServerError, map[string]any{
			"status":  "error",
			"message": "certificate updated but failed to update SDS",
		})
		return
	}

	if _, err := certmetrics.Refresh(s.db); err != nil {
		log.Warn("Failed to refresh certificate metrics after update", slog.Any("error", err))
	}

	zero := 0
	var warnings []clientca.Warning
	for _, warn := range ib.Warnings {
		warnings = append(warnings, clientca.Warning{Code: warn.Code, Field: warn.Field, Message: warn.Message})
	}

	resp := CertificateResponse{
		ID:                             updated.UUID,
		Name:                           updated.Name,
		Subject:                        updated.Subject,
		Issuer:                         updated.Issuer,
		NotAfter:                       updated.NotAfter.Format("2006-01-02 15:04:05"),
		Count:                          updated.CertCount,
		Usage:                          models.CertificateUsageIdentity,
		IsLeaf:                         !ib.Leaf.IsCA,
		KeyAlgorithm:                   updated.KeyAlgorithm,
		ChainLength:                    updated.CertCount,
		PooledConnectionsUsingPrevious: &zero,
		Warnings:                       warnings,
		Message:                        "Certificate updated and SDS updated successfully",
		Status:                         "success",
	}
	httputil.WriteJSON(w, http.StatusOK, resp)
}
