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

package config

import (
	"fmt"
	"strings"
	"time"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// Warning-code constants for the tls-block deploy-response warnings. See
// (*UpstreamTLSValidator).ResolveWarnings.
const (
	WarningCodeTLSVerifyHostNameDisabled = "TLS_VERIFY_HOSTNAME_DISABLED"
	WarningCodeTLSIdentityExpired        = "TLS_IDENTITY_EXPIRED"
)

// upstreamTLSAllowedParams is the set of top-level parameter names the tls
// block accepts. Generic gojsonschema validation never runs against this
// field (it is a free-form map like mtls-auth's params — see
// mtls_auth_validator.go), so this validator is the sole source of "unknown
// parameter" errors for it.
var upstreamTLSAllowedParams = map[string]bool{
	"identity":       true,
	"trustedCAs":     true,
	"verifyHostName": true,
}

// UpstreamTLSCertificateStore is the subset of storage.Storage the tls-block
// validator needs: a read-only lookup against the certificates table, which
// also holds gateway identities as usage: identity rows. A narrow interface
// (rather than depending on storage.Storage directly) so tests can supply a
// minimal fake.
type UpstreamTLSCertificateStore interface {
	GetCertificateByName(name string) (*models.StoredCertificate, error)
}

// UpstreamTLSValidator validates deploy-time use of the tls block on
// upstreamDefinitions entries (identity/trustedCAs/verifyHostName), rejects
// it on an inline (main/sandbox) upstream, and resolves the warnings shown
// on a successful deploy response.
type UpstreamTLSValidator struct {
	store UpstreamTLSCertificateStore
	// sslVerificationDisabled mirrors router.upstream.tls.disable_ssl_verification:
	// while it is on, Envoy verifies no backend at all, so a tls block asking
	// for per-upstream trust or hostname verification could never be honoured.
	sslVerificationDisabled bool
}

// NewUpstreamTLSValidator creates a validator bound to the gateway's
// certificate/gateway-identity store and the router's verification posture.
func NewUpstreamTLSValidator(store UpstreamTLSCertificateStore, sslVerificationDisabled bool) *UpstreamTLSValidator {
	return &UpstreamTLSValidator{store: store, sslVerificationDisabled: sslVerificationDisabled}
}

// resolvedUpstreamTLS is the parsed, effective view of one tls block.
type resolvedUpstreamTLS struct {
	identity          string   // "" means none
	trustedCAs        []string // resolved list; nil when the key was omitted
	hasTrustedCAs     bool     // true when the key was present at all, even as an empty list
	verifyHostName    bool     // effective value; defaults to true
	hasVerifyHostName bool     // true when the key was explicitly present
}

// parseUpstreamTLSParams parses one tls block's raw params, reporting an
// "unknown parameter" error for any key outside identity/trustedCAs/
// verifyHostName. fieldPath is the path to the tls block itself (e.g.
// "spec.upstreamDefinitions[0].tls").
func parseUpstreamTLSParams(fieldPath string, params map[string]interface{}) (resolvedUpstreamTLS, []ValidationError) {
	var errs []ValidationError
	r := resolvedUpstreamTLS{verifyHostName: true}

	for key := range params {
		if !upstreamTLSAllowedParams[key] {
			errs = append(errs, unknownParamError(fieldPath, key))
		}
	}

	if idRaw, ok := params["identity"]; ok {
		if idStr, ok := idRaw.(string); ok {
			r.identity = strings.TrimSpace(idStr)
		}
	}

	if caRaw, ok := params["trustedCAs"]; ok {
		r.hasTrustedCAs = true
		if caSlice, ok := caRaw.([]interface{}); ok {
			for _, c := range caSlice {
				if s, ok := c.(string); ok {
					r.trustedCAs = append(r.trustedCAs, s)
				}
			}
		}
	}

	if vhRaw, ok := params["verifyHostName"]; ok {
		r.hasVerifyHostName = true
		if vh, ok := vhRaw.(bool); ok {
			r.verifyHostName = vh
		}
	}

	return r, errs
}

// ValidateRestAPI reports every deploy-blocking problem with the tls block
// on apiConfig: an inline (main/sandbox) upstream carrying tls at all, and,
// for every upstreamDefinitions entry with a tls block, unknown parameters,
// an unresolvable identity/trustedCAs reference, an empty trustedCAs list,
// a trustedCAs entry that names a usage: client authority, and any target
// URL that is not https://.
func (v *UpstreamTLSValidator) ValidateRestAPI(apiConfig *api.RestAPI) []ValidationError {
	var errs []ValidationError

	errs = append(errs, v.validateInlineUpstreamTLS("spec.upstream.main", apiConfig.Spec.Upstream.Main.Tls)...)
	if apiConfig.Spec.Upstream.Sandbox != nil {
		errs = append(errs, v.validateInlineUpstreamTLS("spec.upstream.sandbox", apiConfig.Spec.Upstream.Sandbox.Tls)...)
	}

	if apiConfig.Spec.UpstreamDefinitions == nil {
		return errs
	}

	for d, def := range *apiConfig.Spec.UpstreamDefinitions {
		if def.Tls == nil {
			continue
		}
		fieldPath := fmt.Sprintf("spec.upstreamDefinitions[%d].tls", d)
		resolved, paramErrs := parseUpstreamTLSParams(fieldPath, *def.Tls)
		errs = append(errs, paramErrs...)

		if v.sslVerificationDisabled {
			_, wantsTrust := (*def.Tls)["trustedCAs"]
			_, wantsHostname := (*def.Tls)["verifyHostName"]
			if wantsTrust || wantsHostname {
				errs = append(errs, ValidationError{
					Field:   fieldPath,
					Message: "per-upstream trust cannot be enforced while router.upstream.tls.disable_ssl_verification is on",
				})
			}
		}

		if resolved.identity != "" {
			cert, err := v.store.GetCertificateByName(resolved.identity)
			if err != nil || cert == nil {
				errs = append(errs, ValidationError{
					Field:   fieldPath + ".identity",
					Message: fmt.Sprintf("no gateway identity named %s exists on this gateway", resolved.identity),
				})
			} else {
				usage := cert.Usage
				if usage == "" {
					usage = models.CertificateUsageUpstream
				}
				if usage != models.CertificateUsageIdentity {
					errs = append(errs, ValidationError{
						Field:   fieldPath + ".identity",
						Message: fmt.Sprintf("%s is not a gateway identity (usage: identity)", resolved.identity),
					})
				}
			}
		}

		if resolved.hasTrustedCAs && len(resolved.trustedCAs) == 0 {
			errs = append(errs, ValidationError{
				Field:   fieldPath + ".trustedCAs",
				Message: "omit trustedCAs to use the gateway trust bundle, or list at least one certificate",
			})
		}
		for k, name := range resolved.trustedCAs {
			caPath := fmt.Sprintf("%s.trustedCAs[%d]", fieldPath, k)
			cert, err := v.store.GetCertificateByName(name)
			if err != nil || cert == nil {
				errs = append(errs, ValidationError{
					Field:   caPath,
					Message: fmt.Sprintf("no certificate named %s exists on this gateway", name),
				})
				continue
			}
			usage := cert.Usage
			if usage == "" {
				usage = models.CertificateUsageUpstream
			}
			switch usage {
			case models.CertificateUsageUpstream:
				// OK — trustedCAs takes usage: upstream certificates.
			case models.CertificateUsageClient:
				errs = append(errs, ValidationError{
					Field:   caPath,
					Message: fmt.Sprintf("%s is a client authority (usage: client); trustedCAs takes usage: upstream certificates", name),
				})
			case models.CertificateUsageIdentity:
				errs = append(errs, ValidationError{
					Field:   caPath,
					Message: fmt.Sprintf("%s is a gateway identity (usage: identity); trustedCAs takes usage: upstream certificates", name),
				})
			}
		}

		for u, up := range def.Upstreams {
			if !strings.HasPrefix(up.Url, "https://") {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("spec.upstreamDefinitions[%d].upstreams[%d].url", d, u),
					Message: "tls is configured but this target is http://; every target of a definition with tls must be https://",
				})
			}
		}
	}

	return errs
}

// validateInlineUpstreamTLS rejects a tls block declared directly on a
// main/sandbox upstream (fieldPrefix e.g. "spec.upstream.main") — tls is
// only valid on an upstreamDefinitions entry.
func (v *UpstreamTLSValidator) validateInlineUpstreamTLS(fieldPrefix string, tls *map[string]interface{}) []ValidationError {
	if tls == nil {
		return nil
	}
	return []ValidationError{{
		Field:   fieldPrefix + ".tls",
		Message: "tls is not supported on an inline upstream; move it to upstreamDefinitions and reference it",
	}}
}

// ResolveWarnings computes TLS_VERIFY_HOSTNAME_DISABLED and
// TLS_IDENTITY_EXPIRED for every upstreamDefinitions tls block on apiConfig,
// for a successful deploy response. Callers must only invoke this after
// ValidateRestAPI has reported zero errors.
func (v *UpstreamTLSValidator) ResolveWarnings(apiConfig api.RestAPI) []clientca.Warning {
	var warnings []clientca.Warning
	if apiConfig.Spec.UpstreamDefinitions == nil {
		return warnings
	}

	now := time.Now()
	for d, def := range *apiConfig.Spec.UpstreamDefinitions {
		if def.Tls == nil {
			continue
		}
		fieldPath := fmt.Sprintf("spec.upstreamDefinitions[%d].tls", d)
		resolved, _ := parseUpstreamTLSParams(fieldPath, *def.Tls)

		if resolved.hasVerifyHostName && !resolved.verifyHostName {
			warnings = append(warnings, clientca.Warning{
				Code:    WarningCodeTLSVerifyHostNameDisabled,
				Field:   fieldPath + ".verifyHostName",
				Message: "hostname verification is disabled for this upstream; the backend certificate's name is not checked against the target host",
			})
		}

		if resolved.identity != "" {
			if identity, err := v.store.GetCertificateByName(resolved.identity); err == nil && identity != nil {
				if now.After(identity.NotAfter) {
					warnings = append(warnings, clientca.Warning{
						Code:    WarningCodeTLSIdentityExpired,
						Field:   fieldPath + ".identity",
						Message: fmt.Sprintf("gateway identity %s expired on %s", resolved.identity, identity.NotAfter.Format(time.RFC3339)),
					})
				}
			}
		}
	}

	return warnings
}

// ResolveUpstreamTLSFromParams extracts the effective identity, trustedCAs
// and verifyHostName settings from an already-validated tls block. Callers
// (the RestAPI transformer) must only use this after ValidateRestAPI has
// reported zero errors for the owning configuration — it performs no
// validation itself.
func ResolveUpstreamTLSFromParams(params map[string]interface{}) (identity string, trustedCAs []string, verifyHostName bool) {
	r, _ := parseUpstreamTLSParams("", params)
	return r.identity, r.trustedCAs, r.verifyHostName
}

// NamedTLSIdentityFieldPaths returns, in document order, the field path of
// every upstreamDefinitions[].tls.identity entry on apiConfig that
// explicitly names identityName. Used by the gateway-identity delete
// referential-integrity check.
func NamedTLSIdentityFieldPaths(apiConfig *api.RestAPI, identityName string) []string {
	var paths []string
	if apiConfig.Spec.UpstreamDefinitions == nil {
		return paths
	}
	for d, def := range *apiConfig.Spec.UpstreamDefinitions {
		if def.Tls == nil {
			continue
		}
		idRaw, ok := (*def.Tls)["identity"]
		if !ok {
			continue
		}
		idStr, _ := idRaw.(string)
		if strings.TrimSpace(idStr) == identityName {
			paths = append(paths, fmt.Sprintf("spec.upstreamDefinitions[%d].tls.identity", d))
		}
	}
	return paths
}

// NamedTLSTrustedCAFieldPaths returns, in document order, the field path of
// every upstreamDefinitions[].tls.trustedCAs[k] entry on apiConfig that
// explicitly names certName. Used by the certificate delete
// referential-integrity check (usage: upstream certificates named as
// per-upstream trust).
func NamedTLSTrustedCAFieldPaths(apiConfig *api.RestAPI, certName string) []string {
	var paths []string
	if apiConfig.Spec.UpstreamDefinitions == nil {
		return paths
	}
	for d, def := range *apiConfig.Spec.UpstreamDefinitions {
		if def.Tls == nil {
			continue
		}
		caRaw, ok := (*def.Tls)["trustedCAs"]
		if !ok {
			continue
		}
		caSlice, ok := caRaw.([]interface{})
		if !ok {
			continue
		}
		for k, c := range caSlice {
			s, _ := c.(string)
			if s == certName {
				paths = append(paths, fmt.Sprintf("spec.upstreamDefinitions[%d].tls.trustedCAs[%d]", d, k))
			}
		}
	}
	return paths
}

// HasUpstreamTLSAttached reports whether apiConfig configures a tls block on
// any upstreamDefinitions entry. Exposed for callers that need to know
// whether the tls-block machinery applies at all without duplicating the
// traversal.
func HasUpstreamTLSAttached(apiConfig *api.RestAPI) bool {
	if apiConfig.Spec.UpstreamDefinitions == nil {
		return false
	}
	for _, def := range *apiConfig.Spec.UpstreamDefinitions {
		if def.Tls != nil {
			return true
		}
	}
	return false
}
