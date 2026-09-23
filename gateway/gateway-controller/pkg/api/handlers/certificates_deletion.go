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
	"fmt"
	"log/slog"
	"net/http"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/middleware"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/httpkit/httputil"
)

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
		usage := preDeleteCert.Usage
		if usage == "" {
			usage = models.CertificateUsageUpstream
		}
		if usage == models.CertificateUsageClient && role != models.CertificateRoleRelay {
			if errResp, statusCode, blocked := s.checkClientAuthorityDeletable(preDeleteCert); blocked {
				httputil.WriteJSON(w, statusCode, errResp)
				return
			}
		}
		if usage == models.CertificateUsageUpstream {
			if errResp, statusCode, blocked := s.checkUpstreamCertificateDeletable(preDeleteCert); blocked {
				httputil.WriteJSON(w, statusCode, errResp)
				return
			}
		}
		if usage == models.CertificateUsageIdentity {
			if errResp, statusCode, blocked := s.checkGatewayIdentityDeletable(preDeleteCert); blocked {
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
	seen := make(map[string]*models.StoredConfig)

	if s.db != nil {
		configs, err := s.db.GetAllConfigsByKind(string(models.KindRestApi))
		if err != nil {
			return nil, err
		}
		for _, cfg := range configs {
			if cfg.DesiredState == models.StateDeployed {
				seen[cfg.UUID] = cfg
			}
		}
	}

	// Also consult the in-memory ConfigStore, deduped by UUID with the
	// database results above. The two sources converge asynchronously (the
	// event-hub listener applies a database-committed change to the
	// in-memory store on its own schedule), so a referential-integrity
	// check that reads only one of them races: a delete already committed
	// to the database can still be reachable through an in-memory-only
	// deployed config for a short window (or vice versa, a deploy visible
	// in memory before its database write lands). Treating a reference
	// found in EITHER source as live is what closes that window — reading
	// only the database is exactly what let a gateway-identity delete
	// through while an API's upstreamDefinitions[].tls.identity still
	// named it in the not-yet-converged in-memory store, which then broke
	// SDS secret generation for that API on the next snapshot.
	if s.store != nil {
		for _, cfg := range s.store.GetAllByKind(string(models.KindRestApi)) {
			if cfg.DesiredState != models.StateDeployed {
				continue
			}
			if _, ok := seen[cfg.UUID]; !ok {
				seen[cfg.UUID] = cfg
			}
		}
	}

	deployed := make([]*models.StoredConfig, 0, len(seen))
	for _, cfg := range seen {
		deployed = append(deployed, cfg)
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

// checkUpstreamCertificateDeletable reports whether a usage: upstream
// certificate (cert) can be removed right now: refused when some deployed
// API's upstreamDefinitions[].tls.trustedCAs still names it explicitly by
// name. A deployed-config read failure fails closed (500) rather than
// silently proceeding as though nothing referenced it.
func (s *APIServer) checkUpstreamCertificateDeletable(cert *models.StoredCertificate) (api.ErrorResponse, int, bool) {
	restAPIs, err := s.deployedRestAPIConfigs()
	if err != nil {
		s.logger.Error("Failed to read deployed RestApi configurations for upstream-certificate referential-integrity check",
			slog.String("certificate", cert.Name), slog.Any("error", err))
		return api.ErrorResponse{Status: "error", Message: "Failed to verify certificate references"},
			http.StatusInternalServerError, true
	}

	var refs []clientAuthorityReference
	for _, cfg := range restAPIs {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		paths := config.NamedTLSTrustedCAFieldPaths(&restCfg, cert.Name)
		if len(paths) == 0 {
			continue
		}
		refs = append(refs, clientAuthorityReference{apiHandle: cfg.Handle, fieldPath: paths[0]})
	}
	if len(refs) == 0 {
		return api.ErrorResponse{}, 0, false
	}

	errs := make([]api.ValidationError, len(refs))
	for i, ref := range refs {
		errs[i] = api.ValidationError{
			Field:   stringPtr(ref.fieldPath),
			Message: stringPtr(fmt.Sprintf("referenced by API '%s'", ref.apiHandle)),
		}
	}
	message := fmt.Sprintf("certificate '%s' is named by %s; remove those references first",
		cert.Name, pluralDeployedAPIs(len(refs)))
	return api.ErrorResponse{Status: "error", Message: message, Errors: &errs}, http.StatusConflict, true
}

// countGatewayIdentityReferences counts the deployed RestApi configurations
// whose upstreamDefinitions[].tls.identity explicitly names identityName.
func (s *APIServer) countGatewayIdentityReferences(identityName string) (int, error) {
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
		if len(config.NamedTLSIdentityFieldPaths(&restCfg, identityName)) > 0 {
			count++
		}
	}
	return count, nil
}

// checkGatewayIdentityDeletable reports whether a usage: identity
// certificate (cert) can be removed right now: refused when some deployed
// API's upstreamDefinitions[].tls.identity still names it. A deployed-config
// read failure fails closed (500) rather than silently proceeding as though
// nothing referenced it.
func (s *APIServer) checkGatewayIdentityDeletable(cert *models.StoredCertificate) (api.ErrorResponse, int, bool) {
	restAPIs, err := s.deployedRestAPIConfigs()
	if err != nil {
		s.logger.Error("Failed to read deployed RestApi configurations for gateway-identity referential-integrity check",
			slog.String("identity", cert.Name), slog.Any("error", err))
		return api.ErrorResponse{Status: "error", Message: "Failed to verify gateway identity references"},
			http.StatusInternalServerError, true
	}

	var refs []clientAuthorityReference
	for _, cfg := range restAPIs {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		paths := config.NamedTLSIdentityFieldPaths(&restCfg, cert.Name)
		if len(paths) == 0 {
			continue
		}
		refs = append(refs, clientAuthorityReference{apiHandle: cfg.Handle, fieldPath: paths[0]})
	}
	if len(refs) == 0 {
		return api.ErrorResponse{}, 0, false
	}

	errs := make([]api.ValidationError, len(refs))
	for i, ref := range refs {
		errs[i] = api.ValidationError{
			Field:   stringPtr(ref.fieldPath),
			Message: stringPtr(fmt.Sprintf("referenced by API '%s'", ref.apiHandle)),
		}
	}
	message := fmt.Sprintf("gateway identity '%s' is named by %s; remove those references first",
		cert.Name, pluralDeployedAPIs(len(refs)))
	return api.ErrorResponse{Status: "error", Message: message, Errors: &errs}, http.StatusConflict, true
}
