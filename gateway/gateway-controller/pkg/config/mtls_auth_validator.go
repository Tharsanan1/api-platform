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
	"regexp"
	"strings"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/clientca"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// MtlsAuthPolicyName is the policy name this validator applies to.
const MtlsAuthPolicyName = "mtls-auth"

// Warning-code constants for the mtls-auth-specific deploy-response warnings.
// See ResolveMtlsAuthForResponse.
const (
	WarningCodeMTLSAcceptInheritsPool   = "MTLS_ACCEPT_INHERITS_POOL"
	WarningCodeMTLSAcceptUnnarrowed     = "MTLS_ACCEPT_UNNARROWED"
	WarningCodeMTLSAuthNotFirst         = "MTLS_AUTH_NOT_FIRST"
	WarningCodeMTLSThumbprintNormalised = "MTLS_THUMBPRINT_NORMALISED"
)

// mtlsAuthAllowedParams is the set of top-level parameter names mtls-auth
// accepts. Generic gojsonschema validation is skipped entirely for mtls-auth
// (see PolicyValidator.validatePolicy) so this validator is the sole source
// of "unknown parameter" errors — never duplicated with a generic
// "Additional property X is not allowed" schema message.
var mtlsAuthAllowedParams = map[string]bool{
	"accept":              true,
	"onFailureStatusCode": true,
	"errorMessageFormat":  true,
	"errorMessage":        true,
}

var mtlsAuthAllowedAcceptEntryParams = map[string]bool{
	"ca":          true,
	"match":       true,
	"thumbprints": true,
}

var mtlsAuthAllowedMatchParams = map[string]bool{
	"uriSANs": true,
	"dnsSANs": true,
}

// mtlsAuthPrecedingAuthPolicies lists other authentication-policy names
// that, when they appear earlier than mtls-auth in the same policy chain,
// trigger the MTLS_AUTH_NOT_FIRST warning.
var mtlsAuthPrecedingAuthPolicies = map[string]bool{
	"jwt-auth":          true,
	"api-key-auth":      true,
	"basic-auth":        true,
	"opaque-token-auth": true,
	"mcp-auth":          true,
	"oauth2-auth":       true,
}

var thumbprintHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// MtlsAuthCertificateStore is the subset of storage.Storage the mtls-auth
// validator needs: read-only lookups against the client certificate
// authority pool. Kept as a narrow interface (rather than depending on
// storage.Storage directly) so tests can supply a minimal fake.
type MtlsAuthCertificateStore interface {
	GetCertificateByName(name string) (*models.StoredCertificate, error)
	ListCertificatesByUsage(usage string) ([]*models.StoredCertificate, error)
}

// MtlsAuthValidator validates deploy-time use of the mtls-auth policy and
// resolves the warnings/echoed-accept-list shown on a successful deploy
// response. See go-network-service-hardening.md and
// authentication_authorization.md for why an mtls-auth deployment that could
// never authenticate anyone (empty pool, an accept list naming nothing
// reachable) must be refused rather than silently deployed inert.
type MtlsAuthValidator struct {
	store        MtlsAuthCertificateStore
	httpsEnabled bool
}

// NewMtlsAuthValidator creates a validator bound to the gateway's
// certificate store and its (static, config-file-sourced) HTTPS-listener
// enablement.
func NewMtlsAuthValidator(store MtlsAuthCertificateStore, httpsEnabled bool) *MtlsAuthValidator {
	return &MtlsAuthValidator{store: store, httpsEnabled: httpsEnabled}
}

// mtlsOccurrence is one place mtls-auth is attached in a RestAPI: either the
// API-level policies list or a single operation's policies list.
type mtlsOccurrence struct {
	fieldPath string
	params    map[string]interface{}
	scopeKey  string // "api" or "op:<index>" — occurrences sharing a scopeKey are in the same chain
	apiLevel  bool
}

func paramsOrEmpty(p *map[string]interface{}) map[string]interface{} {
	if p == nil {
		return map[string]interface{}{}
	}
	return *p
}

// collectMTLSAuthOccurrences finds every mtls-auth attachment, in document
// order, across the API-level policies list and every operation's own
// policies list.
func collectMTLSAuthOccurrences(apiConfig *api.RestAPI) []mtlsOccurrence {
	var occs []mtlsOccurrence

	if apiConfig.Spec.Policies != nil {
		for i, p := range *apiConfig.Spec.Policies {
			if p.Name == MtlsAuthPolicyName {
				occs = append(occs, mtlsOccurrence{
					fieldPath: fmt.Sprintf("spec.policies[%d]", i),
					params:    paramsOrEmpty(p.Params),
					scopeKey:  "api",
					apiLevel:  true,
				})
			}
		}
	}

	for opIdx, op := range apiConfig.Spec.Operations {
		if op.Policies == nil {
			continue
		}
		for pIdx, p := range *op.Policies {
			if p.Name == MtlsAuthPolicyName {
				occs = append(occs, mtlsOccurrence{
					fieldPath: fmt.Sprintf("spec.operations[%d].policies[%d]", opIdx, pIdx),
					params:    paramsOrEmpty(p.Params),
					scopeKey:  fmt.Sprintf("op:%d", opIdx),
					apiLevel:  false,
				})
			}
		}
	}

	return occs
}

// ValidateRestAPI reports every deploy-blocking problem with every mtls-auth
// attachment on apiConfig. Called from PolicyValidator.ValidateRestAPIPolicies
// alongside (not instead of) the generic per-policy validation that runs for
// every other policy name.
func (v *MtlsAuthValidator) ValidateRestAPI(apiConfig *api.RestAPI) []ValidationError {
	occs := collectMTLSAuthOccurrences(apiConfig)
	if len(occs) == 0 {
		return nil
	}

	var errs []ValidationError

	// One occurrence per scope (spec.policies as a whole, or a single
	// operation's own policies list): every occurrence after the first in
	// the same scope is refused.
	seenScope := map[string]bool{}
	for _, occ := range occs {
		if seenScope[occ.scopeKey] {
			errs = append(errs, ValidationError{
				Field:   occ.fieldPath,
				Message: "mtls-auth may appear once per scope; use several accept entries instead",
			})
		}
		seenScope[occ.scopeKey] = true
	}

	// API-level and operation-level attachment together: every
	// operation-level occurrence is refused when an API-level occurrence
	// also exists.
	hasAPILevel := false
	for _, occ := range occs {
		if occ.apiLevel {
			hasAPILevel = true
			break
		}
	}
	if hasAPILevel {
		for _, occ := range occs {
			if !occ.apiLevel {
				errs = append(errs, ValidationError{
					Field:   occ.fieldPath,
					Message: "mtls-auth is already attached at API level; attach it at one level only",
				})
			}
		}
	}

	for _, occ := range occs {
		if !v.httpsEnabled {
			errs = append(errs, ValidationError{
				Field:   occ.fieldPath,
				Message: "mtls-auth requires the HTTPS listener, which is disabled on this gateway",
			})
		}

		clientAuthorities, err := v.store.ListCertificatesByUsage(models.CertificateUsageClient)
		if err != nil || len(clientAuthorities) == 0 {
			errs = append(errs, ValidationError{
				Field:   occ.fieldPath,
				Message: "mtls-auth requires at least one client authority; add one with POST /certificates and usage: client",
			})
			continue
		}

		errs = append(errs, v.validateParams(occ.fieldPath, occ.params)...)
	}

	return errs
}

// validateParams validates one mtls-auth occurrence's own params (unknown
// keys and the accept list's structure), assuming the client-CA pool is
// non-empty and HTTPS is enabled (both checked by the caller first).
func (v *MtlsAuthValidator) validateParams(fieldPath string, params map[string]interface{}) []ValidationError {
	var errs []ValidationError
	paramsPath := fieldPath + ".params"

	for key := range params {
		if !mtlsAuthAllowedParams[key] {
			errs = append(errs, unknownParamError(paramsPath, key))
		}
	}

	acceptRaw, hasAccept := params["accept"]
	if !hasAccept {
		return errs
	}
	acceptSlice, ok := acceptRaw.([]interface{})
	if !ok {
		return errs
	}
	acceptPath := paramsPath + ".accept"
	if len(acceptSlice) == 0 {
		errs = append(errs, ValidationError{
			Field:   acceptPath,
			Message: "omit accept to inherit every pooled authority, or list at least one entry",
		})
		return errs
	}

	for j, entryRaw := range acceptSlice {
		entryMap, ok := entryRaw.(map[string]interface{})
		if !ok {
			continue
		}
		errs = append(errs, v.validateAcceptEntry(fmt.Sprintf("%s[%d]", acceptPath, j), entryMap)...)
	}

	return errs
}

func (v *MtlsAuthValidator) validateAcceptEntry(entryPath string, entry map[string]interface{}) []ValidationError {
	var errs []ValidationError

	for key := range entry {
		if mtlsAuthAllowedAcceptEntryParams[key] {
			continue
		}
		if key == "thumbprint" {
			errs = append(errs, ValidationError{
				Field:   entryPath + ".thumbprint",
				Message: "unknown parameter thumbprint; the field is thumbprints",
			})
			continue
		}
		errs = append(errs, unknownParamError(entryPath, key))
	}

	errs = append(errs, v.validateAcceptEntryCA(entryPath, entry)...)
	errs = append(errs, validateAcceptEntryMatch(entryPath, entry)...)
	errs = append(errs, validateAcceptEntryThumbprints(entryPath, entry)...)

	return errs
}

func (v *MtlsAuthValidator) validateAcceptEntryCA(entryPath string, entry map[string]interface{}) []ValidationError {
	caPath := entryPath + ".ca"
	caRaw, hasCA := entry["ca"]
	caName, caIsString := caRaw.(string)
	if !hasCA || !caIsString || strings.TrimSpace(caName) == "" {
		return []ValidationError{{
			Field:   caPath,
			Message: "ca is required and must name an authority in this gateway's client-CA pool",
		}}
	}

	cert, err := v.store.GetCertificateByName(caName)
	if err != nil || cert == nil {
		return []ValidationError{{
			Field:   caPath,
			Message: fmt.Sprintf("no client-CA authority named %s exists on this gateway", caName),
		}}
	}

	usage := cert.Usage
	if usage == "" {
		usage = models.CertificateUsageUpstream
	}
	if usage != models.CertificateUsageClient {
		return []ValidationError{{
			Field:   caPath,
			Message: fmt.Sprintf("%s is a backend trust certificate (usage: upstream); accept takes usage: client authorities", caName),
		}}
	}

	role := cert.Role
	if role == "" {
		role = models.CertificateRoleClient
	}
	if role == models.CertificateRoleRelay {
		return []ValidationError{{
			Field:   caPath,
			Message: fmt.Sprintf("%s is a relay (front proxy) entry and cannot be accepted as a client", caName),
		}}
	}

	return nil
}

func validateAcceptEntryMatch(entryPath string, entry map[string]interface{}) []ValidationError {
	matchRaw, hasMatch := entry["match"]
	if !hasMatch || matchRaw == nil {
		return nil
	}
	matchMap, ok := matchRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	var errs []ValidationError
	matchPath := entryPath + ".match"

	for key := range matchMap {
		if !mtlsAuthAllowedMatchParams[key] {
			errs = append(errs, unknownParamError(matchPath, key))
		}
	}

	for _, sanField := range []string{"uriSANs", "dnsSANs"} {
		sanRaw, ok := matchMap[sanField]
		if !ok {
			continue
		}
		sanSlice, ok := sanRaw.([]interface{})
		if !ok {
			continue
		}
		sanPath := matchPath + "." + sanField
		const sanEmptyMessage = "list at least one non-empty SAN, or remove match to accept any certificate from this authority"
		if len(sanSlice) == 0 {
			errs = append(errs, ValidationError{Field: sanPath, Message: sanEmptyMessage})
			continue
		}
		for k, sv := range sanSlice {
			s, _ := sv.(string)
			if strings.TrimSpace(s) == "" {
				errs = append(errs, ValidationError{
					Field:   fmt.Sprintf("%s[%d]", sanPath, k),
					Message: sanEmptyMessage,
				})
			}
		}
	}

	return errs
}

func validateAcceptEntryThumbprints(entryPath string, entry map[string]interface{}) []ValidationError {
	tpRaw, hasTP := entry["thumbprints"]
	if !hasTP {
		return nil
	}
	tpSlice, ok := tpRaw.([]interface{})
	if !ok {
		return nil
	}

	var errs []ValidationError
	tpPath := entryPath + ".thumbprints"
	if len(tpSlice) == 0 {
		errs = append(errs, ValidationError{
			Field:   tpPath,
			Message: "list at least one fingerprint, or remove thumbprints to accept any certificate from this authority",
		})
		return errs
	}

	for k, tv := range tpSlice {
		s, _ := tv.(string)
		if _, _, valid := normalizeThumbprint(s); !valid {
			errs = append(errs, ValidationError{
				Field:   fmt.Sprintf("%s[%d]", tpPath, k),
				Message: "a fingerprint is the SHA-256 of the certificate as 64 hex characters (colons and a sha256: prefix are accepted)",
			})
		}
	}

	return errs
}

// normalizeThumbprint canonicalises a caller-supplied fingerprint: lowercase,
// no colon separators, no "sha256:" prefix. valid reports whether the result
// is exactly 64 hex characters; changed reports whether normalisation
// altered the input (used to decide whether MTLS_THUMBPRINT_NORMALISED is
// warranted).
func normalizeThumbprint(raw string) (normalized string, changed bool, valid bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	if !thumbprintHexPattern.MatchString(s) {
		return "", false, false
	}
	return s, s != raw, true
}

func unknownParamError(basePath, key string) ValidationError {
	return ValidationError{
		Field:   basePath + "." + key,
		Message: "unknown parameter " + key,
	}
}

// nonRelayClientAuthorityNames returns the names of every usage: client
// authority in the pool that is not a relay entry, in the order the store
// returns them. This is the resolved-authority set an omitted `accept`
// inherits, and the count used to decide whether the inheritance/unnarrowed
// warnings apply.
func (v *MtlsAuthValidator) nonRelayClientAuthorityNames() ([]string, error) {
	certs, err := v.store.ListCertificatesByUsage(models.CertificateUsageClient)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(certs))
	for _, cert := range certs {
		role := cert.Role
		if role == "" {
			role = models.CertificateRoleClient
		}
		if role == models.CertificateRoleRelay {
			continue
		}
		names = append(names, cert.Name)
	}
	return names, nil
}

// ResolveMtlsAuthForResponse computes the warnings and the echoed/resolved
// view of every mtls-auth policy on apiConfig for a SUCCESSFUL deploy
// response. It never mutates apiConfig — it returns a new value whose
// mtls-auth policies carry the resolved `accept` list, leaving the caller's
// original (which is what gets persisted) untouched, per
// "the stored configuration stays exactly as the caller sent it, so pool
// changes keep applying".
//
// Callers must only invoke this after ValidateRestAPI has reported zero
// errors for apiConfig — it assumes every mtls-auth occurrence is
// well-formed and does not re-validate.
func (v *MtlsAuthValidator) ResolveMtlsAuthForResponse(apiConfig api.RestAPI) (api.RestAPI, []clientca.Warning) {
	if collectMTLSAuthOccurrences(&apiConfig) == nil {
		return apiConfig, nil
	}

	poolNames, err := v.nonRelayClientAuthorityNames()
	if err != nil {
		poolNames = nil
	}

	var warnings []clientca.Warning

	if apiConfig.Spec.Policies != nil {
		resolved, w := v.resolvePolicyList(*apiConfig.Spec.Policies, "spec.policies", poolNames)
		apiConfig.Spec.Policies = &resolved
		warnings = append(warnings, w...)
	}

	newOps := make([]api.Operation, len(apiConfig.Spec.Operations))
	copy(newOps, apiConfig.Spec.Operations)
	for i := range newOps {
		if newOps[i].Policies == nil {
			continue
		}
		resolved, w := v.resolvePolicyList(*newOps[i].Policies, fmt.Sprintf("spec.operations[%d].policies", i), poolNames)
		newOps[i].Policies = &resolved
		warnings = append(warnings, w...)
	}
	apiConfig.Spec.Operations = newOps

	return apiConfig, warnings
}

// resolvePolicyList resolves every mtls-auth entry in one policy chain
// (either spec.policies or a single operation's policies), and reports
// MTLS_AUTH_NOT_FIRST for any of the other auth policies preceding it in
// that same chain.
func (v *MtlsAuthValidator) resolvePolicyList(policies []api.Policy, listPath string, poolNames []string) ([]api.Policy, []clientca.Warning) {
	resolved := make([]api.Policy, len(policies))
	copy(resolved, policies)

	var warnings []clientca.Warning
	mtlsSeen := false
	for i, p := range policies {
		if p.Name == MtlsAuthPolicyName {
			mtlsSeen = true
			continue
		}
		if mtlsAuthPrecedingAuthPolicies[p.Name] && !mtlsSeen {
			// Only warn once mtls-auth actually appears later in this chain.
			for _, later := range policies[i+1:] {
				if later.Name == MtlsAuthPolicyName {
					warnings = append(warnings, clientca.Warning{
						Code:    WarningCodeMTLSAuthNotFirst,
						Field:   fmt.Sprintf("%s[%d]", listPath, i),
						Message: fmt.Sprintf("%s runs before mtls-auth in this chain; an authentication policy ahead of mtls-auth runs first", p.Name),
					})
					break
				}
			}
		}
	}

	for i, p := range policies {
		if p.Name != MtlsAuthPolicyName {
			continue
		}
		fieldPath := fmt.Sprintf("%s[%d]", listPath, i)
		newPolicy, w := v.resolveOnePolicy(p, fieldPath, poolNames)
		resolved[i] = newPolicy
		warnings = append(warnings, w...)
	}

	return resolved, warnings
}

// resolveOnePolicy resolves a single mtls-auth policy's accept list for the
// response echo and reports MTLS_ACCEPT_INHERITS_POOL,
// MTLS_ACCEPT_UNNARROWED and MTLS_THUMBPRINT_NORMALISED as applicable.
func (v *MtlsAuthValidator) resolveOnePolicy(p api.Policy, fieldPath string, poolNames []string) (api.Policy, []clientca.Warning) {
	params := paramsOrEmpty(p.Params)
	newParams := make(map[string]interface{}, len(params))
	for k, val := range params {
		newParams[k] = val
	}

	var warnings []clientca.Warning
	acceptPath := fieldPath + ".params.accept"

	acceptRaw, hasAccept := params["accept"]
	if !hasAccept {
		resolvedAccept := make([]interface{}, 0, len(poolNames))
		for _, name := range poolNames {
			resolvedAccept = append(resolvedAccept, map[string]interface{}{"ca": name})
		}
		newParams["accept"] = resolvedAccept
		if len(poolNames) > 1 {
			warnings = append(warnings, clientca.Warning{
				Code:  WarningCodeMTLSAcceptInheritsPool,
				Field: acceptPath,
				Message: fmt.Sprintf(
					"accept is omitted and the pool holds %d authorities; this API accepts certificates from all of them",
					len(poolNames)),
			})
		}
	} else if acceptSlice, ok := acceptRaw.([]interface{}); ok {
		newAccept := make([]interface{}, len(acceptSlice))
		for j, entryRaw := range acceptSlice {
			entryMap, ok := entryRaw.(map[string]interface{})
			if !ok {
				newAccept[j] = entryRaw
				continue
			}
			newEntry := make(map[string]interface{}, len(entryMap))
			for k, val := range entryMap {
				newEntry[k] = val
			}
			entryPath := fmt.Sprintf("%s[%d]", acceptPath, j)

			_, hasMatch := entryMap["match"]
			tpRaw, hasThumbprints := entryMap["thumbprints"]
			if !hasMatch && !hasThumbprints && len(poolNames) > 1 {
				warnings = append(warnings, clientca.Warning{
					Code:  WarningCodeMTLSAcceptUnnarrowed,
					Field: entryPath,
					Message: "this entry has neither match nor thumbprints, so it accepts any certificate from this authority; " +
						"narrow it with match or thumbprints, since the pool holds other authorities too",
				})
			}

			if hasThumbprints {
				if tpSlice, ok := tpRaw.([]interface{}); ok {
					newTP := make([]interface{}, len(tpSlice))
					for k, tv := range tpSlice {
						s, _ := tv.(string)
						canonical, changed, valid := normalizeThumbprint(s)
						if !valid {
							newTP[k] = tv
							continue
						}
						newTP[k] = canonical
						if changed {
							warnings = append(warnings, clientca.Warning{
								Code:    WarningCodeMTLSThumbprintNormalised,
								Field:   fmt.Sprintf("%s.thumbprints[%d]", entryPath, k),
								Message: fmt.Sprintf("fingerprint normalised to %s", canonical),
							})
						}
					}
					newEntry["thumbprints"] = newTP
				}
			}

			newAccept[j] = newEntry
		}
		newParams["accept"] = newAccept
	}

	p.Params = &newParams
	return p, warnings
}

// ValidateMTLSStartupInvariant enforces, once at startup, that no persisted
// RestAPI attaches mtls-auth while the HTTPS listener is disabled. This
// mirrors the deploy-time check in ValidateRestAPI, applied to whatever is
// already on disk — router.https_enabled is config-file-sourced and static
// per process, so this only ever fires when the operator disabled HTTPS
// after previously deploying an mtls-auth API, per
// authentication_authorization.md GO-AUTH-011: validate the *effective*
// startup state and fail closed (refuse to start) rather than silently
// running with a listener that can never satisfy an already-deployed API's
// authentication requirement.
func ValidateMTLSStartupInvariant(configs []*models.StoredConfig, httpsEnabled bool) error {
	if httpsEnabled {
		return nil
	}
	for _, cfg := range configs {
		restCfg, ok := cfg.Configuration.(api.RestAPI)
		if !ok {
			continue
		}
		if len(collectMTLSAuthOccurrences(&restCfg)) > 0 {
			return fmt.Errorf(
				"RestAPI %q attaches mtls-auth but router.https_enabled is false; "+
					"enable the HTTPS listener or remove mtls-auth before starting", cfg.Handle)
		}
	}
	return nil
}
