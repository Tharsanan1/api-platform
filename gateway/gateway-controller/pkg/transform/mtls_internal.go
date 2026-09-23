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

package transform

import (
	"encoding/pem"
	"strings"

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	policyenginev1 "github.com/wso2/api-platform/sdk/core/policyengine"
)

// The mtls-auth policy runs inside the policy engine, which has no database
// access, so the controller must hand it the client-CA pool material it
// needs to evaluate a presented certificate, inside the policy chain already
// pushed over policy-xDS. These two keys are injected into every mtls-auth
// instance's params at chain-build time (see injectMtlsInternalParams) and
// must never be accepted from an author — the deploy validator
// (pkg/config/mtls_auth_validator.go) already rejects unknown params, and
// __wso2_internal_* is the existing convention for engine-internal
// parameters (see sdk/core/policy/v1alpha2/system_parameters.go).
const (
	// mtlsInternalAcceptParam resolves the policy's own (possibly omitted)
	// `accept` param into an ordered array of
	// {"ca", "certificates", "match"?, "thumbprints"?} objects.
	mtlsInternalAcceptParam = "__wso2_internal_mtls_accept"

	// mtlsInternalPoolParam is an ordered array of every certificate PEM held
	// by every usage: client row on the gateway (relay rows included) —
	// path-building material for the policy, independent of what this
	// particular API accepts.
	mtlsInternalPoolParam = "__wso2_internal_mtls_pool"

	// mtlsInternalRelaysParam is an ordered array of
	// {"name", "certificates", "match"?} objects, one per usage: client,
	// role: relay pool row — the set of connections whose presented
	// certificate can make a relayed header believed. "match" is present
	// only when the relay entry itself was stored with a narrowing match.
	mtlsInternalRelaysParam = "__wso2_internal_mtls_relays"

	// mtlsInternalHeaderParam is {"name", "trustAny", "forwardToBackend"},
	// mirroring router.downstream_tls.client_certificate_header — the
	// policy's only source of that config, since it runs outside the
	// controller process.
	mtlsInternalHeaderParam = "__wso2_internal_mtls_header"
)

// injectMtlsInternalParams mutates every mtls-auth PolicyInstance in chain in
// place, adding the __wso2_internal_mtls_* parameters above. A nil store
// (not yet wired, e.g. in a test transformer) or a chain with no mtls-auth
// instance is a no-op. Certificate PEM material is never logged by any of
// the helpers this function calls.
func injectMtlsInternalParams(chain []policyenginev1.PolicyInstance, store config.MtlsAuthCertificateStore, headerConfig config.ClientCertificateHeader) {
	if store == nil {
		return
	}

	hasMtlsAuth := false
	for i := range chain {
		if chain[i].Name == config.MtlsAuthPolicyName {
			hasMtlsAuth = true
			break
		}
	}
	if !hasMtlsAuth {
		return
	}

	clientCerts, err := store.ListCertificatesByUsage(models.CertificateUsageClient)
	if err != nil {
		clientCerts = nil
	}

	pool := make([]interface{}, 0, len(clientCerts))
	for _, cert := range clientCerts {
		for _, pemStr := range splitCertificatePEMs(cert.Certificate) {
			pool = append(pool, pemStr)
		}
	}

	relays := buildMtlsRelaysMaterial(clientCerts)
	header := map[string]interface{}{
		"name":             headerConfig.Name,
		"trustAny":         headerConfig.TrustAny,
		"forwardToBackend": headerConfig.ForwardToBackend,
	}

	for i := range chain {
		if chain[i].Name != config.MtlsAuthPolicyName {
			continue
		}
		if chain[i].Parameters == nil {
			chain[i].Parameters = map[string]interface{}{}
		}
		chain[i].Parameters[mtlsInternalAcceptParam] = resolveMtlsAcceptMaterial(chain[i].Parameters, store, clientCerts)
		chain[i].Parameters[mtlsInternalPoolParam] = pool
		chain[i].Parameters[mtlsInternalRelaysParam] = relays
		chain[i].Parameters[mtlsInternalHeaderParam] = header
	}
}

// buildMtlsRelaysMaterial builds the __wso2_internal_mtls_relays material:
// one entry per usage: client, role: relay row in clientCerts, in the same
// (pool) order the rows were returned.
func buildMtlsRelaysMaterial(clientCerts []*models.StoredCertificate) []interface{} {
	relays := make([]interface{}, 0)
	for _, cert := range clientCerts {
		role := cert.Role
		if role == "" {
			role = models.CertificateRoleClient
		}
		if role != models.CertificateRoleRelay {
			continue
		}
		entry := map[string]interface{}{
			"name":         cert.Name,
			"certificates": stringsToInterfaces(splitCertificatePEMs(cert.Certificate)),
		}
		if cert.Match != nil {
			matchParam := map[string]interface{}{}
			if len(cert.Match.DNSSANs) > 0 {
				matchParam["dnsSANs"] = stringsToInterfaces(cert.Match.DNSSANs)
			}
			if len(cert.Match.URISANs) > 0 {
				matchParam["uriSANs"] = stringsToInterfaces(cert.Match.URISANs)
			}
			entry["match"] = matchParam
		}
		relays = append(relays, entry)
	}
	return relays
}

// resolveMtlsAcceptMaterial resolves one mtls-auth instance's own `accept`
// param (params["accept"], as authored — untouched by this function) into
// the certificate material the policy engine evaluates against. When the
// author omitted accept (or supplied something that isn't the expected
// array shape — the deploy validator already refuses that at deploy time,
// this is a defensive fallback), every usage: client, non-relay pool entry
// is listed, in pool order, with no match/thumbprints.
func resolveMtlsAcceptMaterial(params map[string]interface{}, store config.MtlsAuthCertificateStore, clientCerts []*models.StoredCertificate) []interface{} {
	acceptRaw, hasAccept := params["accept"]
	if !hasAccept {
		return defaultMtlsAccept(clientCerts)
	}
	acceptSlice, ok := acceptRaw.([]interface{})
	if !ok {
		return defaultMtlsAccept(clientCerts)
	}

	result := make([]interface{}, 0, len(acceptSlice))
	for _, entryRaw := range acceptSlice {
		entryMap, ok := entryRaw.(map[string]interface{})
		if !ok {
			continue
		}
		caName, _ := entryMap["ca"].(string)
		caName = strings.TrimSpace(caName)
		cert, err := store.GetCertificateByName(caName)
		if err != nil || cert == nil {
			// The deploy validator (ValidateRestAPI) already refuses to deploy
			// an accept entry naming an authority absent from the pool, so this
			// should be unreachable in practice; skip defensively rather than
			// hand the policy engine a half-built entry.
			continue
		}

		entry := map[string]interface{}{
			"ca":           caName,
			"certificates": stringsToInterfaces(splitCertificatePEMs(cert.Certificate)),
		}
		if matchRaw, hasMatch := entryMap["match"]; hasMatch {
			entry["match"] = matchRaw
		}
		if tpRaw, hasThumbprints := entryMap["thumbprints"]; hasThumbprints {
			entry["thumbprints"] = normalizeThumbprintsForEngine(tpRaw)
		}
		result = append(result, entry)
	}
	return result
}

// defaultMtlsAccept builds the inherited-pool accept list for an omitted
// `accept`: every usage: client, non-relay pool entry in listing order, with
// no match/thumbprints keys at all.
func defaultMtlsAccept(clientCerts []*models.StoredCertificate) []interface{} {
	result := make([]interface{}, 0, len(clientCerts))
	for _, cert := range clientCerts {
		role := cert.Role
		if role == "" {
			role = models.CertificateRoleClient
		}
		if role == models.CertificateRoleRelay {
			continue
		}
		result = append(result, map[string]interface{}{
			"ca":           cert.Name,
			"certificates": stringsToInterfaces(splitCertificatePEMs(cert.Certificate)),
		})
	}
	return result
}

// normalizeThumbprintsForEngine canonicalises an author-supplied thumbprints
// array to 64 lowercase hex, reusing the same normaliser the deploy-response
// echo uses (config.NormalizeThumbprint) so the policy engine and the
// deploy-response view of an accept entry never disagree on the canonical
// form. An entry that fails to normalise (unreachable past deploy-time
// validation) is passed through unchanged rather than dropped.
func normalizeThumbprintsForEngine(raw interface{}) interface{} {
	tpSlice, ok := raw.([]interface{})
	if !ok {
		return raw
	}
	out := make([]interface{}, len(tpSlice))
	for i, tv := range tpSlice {
		s, _ := tv.(string)
		canonical, _, valid := config.NormalizeThumbprint(s)
		if !valid {
			out[i] = tv
			continue
		}
		out[i] = canonical
	}
	return out
}

// splitCertificatePEMs decodes every CERTIFICATE PEM block in data, in
// order, re-encoding each one individually so callers get a clean
// one-certificate-per-string slice (dropping any other block type and any
// stray bytes between/around blocks). Certificate material only — never
// logged by any caller.
func splitCertificatePEMs(data []byte) []string {
	var out []string
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
		out = append(out, strings.TrimRight(string(pem.EncodeToMemory(block)), "\n"))
	}
	return out
}

// stringsToInterfaces converts a []string to []interface{} for embedding in
// the generic map[string]interface{} params shape the policy engine expects.
func stringsToInterfaces(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
