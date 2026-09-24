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

// Package it's mtls step definitions are split by concern across several
// files, all registering onto the same *mtlsSteps receiver defined here:
//
//   - steps_mtls.go (this file): the mtlsSteps type, step registration, and
//     the fixture-reading/templating helpers every other file shares.
//   - steps_mtls_pool.go: the client-certificate-authority-pool feature
//     (features/mtls-client-ca-pool.feature) — uploading, listing,
//     validation errors, deletion, and deploy-response warnings.
//   - steps_mtls_request.go: the HTTPS listener probe and requests carrying
//     (or omitting) a client certificate, alone or paired with a JWT
//     (features/mtls-auth.feature, features/mtls-listener.feature).
//   - steps_mtls_header.go: requests relaying a client certificate through a
//     header instead of (or alongside) the TLS handshake (features/mtls-
//     header-relay.feature, mtls-header-forward.feature, mtls-header-
//     bypass.feature).
//   - steps_mtls_outbound.go: gateway identities (features/mtls-outbound.feature).
//   - steps_mtls_cleanup.go: best-effort scenario teardown shared by every
//     feature above.
package it

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2/api-platform/gateway/it/steps"
)

// mtlsFixturesDir is where resources/mtls-pki/generate.go writes certificate
// and key fixtures. Tests run with the working directory set to the `it`
// module root, so this relative path resolves correctly.
const mtlsFixturesDir = "resources/mtls-pki"

// mtlsPemPlaceholder, mtlsKeyPlaceholder and mtlsEncryptedKeyPlaceholder match
// {{pem "name"}} / {{key "name"}} / {{encryptedkey "name"}} template markers
// inside a docstring request body.
var (
	mtlsPemPlaceholder          = regexp.MustCompile(`\{\{pem "([^"]+)"\}\}`)
	mtlsKeyPlaceholder          = regexp.MustCompile(`\{\{key "([^"]+)"\}\}`)
	mtlsEncryptedKeyPlaceholder = regexp.MustCompile(`\{\{encryptedkey "([^"]+)"\}\}`)
)

// mtlsNotAfterPlaceholder matches {{notafter "name"}} template markers,
// expanded to fixture "name"'s certificate NotAfter timestamp (RFC3339,
// matching resources/mtls-pki/manifest.json's notAfter format). Used both
// inside docstring request bodies (via resolveTemplates) and inside plain
// step-argument strings such as an Examples table's expected message column
// (via resolveNotAfterTemplates).
var mtlsNotAfterPlaceholder = regexp.MustCompile(`\{\{notafter "([^"]+)"\}\}`)

// mtlsThumbprintPlaceholder matches {{thumbprint "name"}} template markers
// inside a docstring request body, expanded to fixture "name"'s SHA-256
// thumbprint (64 lowercase hex characters of the certificate's DER bytes).
var mtlsThumbprintPlaceholder = regexp.MustCompile(`\{\{thumbprint "([^"]+)"\}\}`)

// mtlsSteps holds scenario-scoped bookkeeping for the client-certificate-
// authority-pool step definitions: every certificate name this scenario
// attempted to upload, for best-effort cleanup. Listing itself has no
// dedicated step — the feature file lists via the existing generic
// "I send a GET request to the ... service at ..." step — so the "list
// certificates" assertion steps below deliberately don't cache anything:
// they re-parse whatever the last HTTP response was, straight off the
// shared HTTPSteps.LastBody(), each time they run.
type mtlsSteps struct {
	state     *TestState
	httpSteps *steps.HTTPSteps
	jwtSteps  *JWTSteps

	uploadedNames []string

	// uploadedIdentityNames tracks every gateway identity name this scenario
	// attempted to upload (features/mtls-outbound.feature), deleted before
	// uploadedNames (certificates) — see cleanupTrackedCertificates.
	uploadedIdentityNames []string
}

// RegisterMTLSSteps registers step definitions for the client certificate
// authority pool feature (features/mtls-client-ca-pool.feature) and the
// client-certificate-authentication feature (features/mtls-auth.feature). It
// returns the mtlsSteps instance so another registration function (e.g.
// RegisterMTLSObservabilitySteps) can reuse its fixture-reading helpers
// (thumbprintOf, parseFixtureCert) rather than re-implementing them.
func RegisterMTLSSteps(ctx *godog.ScenarioContext, state *TestState, httpSteps *steps.HTTPSteps, jwtSteps *JWTSteps) *mtlsSteps {
	m := &mtlsSteps{state: state, httpSteps: httpSteps, jwtSteps: jwtSteps}

	ctx.Before(func(c context.Context, sc *godog.Scenario) (context.Context, error) {
		m.uploadedNames = nil
		m.uploadedIdentityNames = nil
		return c, nil
	})
	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		// Only the mTLS features hand their APIs and certificates to this
		// hook; other features manage their own APIs and may share one
		// across scenarios. A pooled certificate cannot be removed while a
		// deployed API still references it (or while it is the last
		// authority an mtls-auth API depends on), so the APIs this scenario
		// deployed are deleted first, explicitly, rather than relying on the
		// order godog runs After hooks in; a second deletion by the API
		// steps' own hook is a harmless 404. Gateway identities go next —
		// after APIs (which may reference them) but before certificates
		// (which are independent of identities).
		if !scenarioHasTag(sc, "@mtls") {
			return c, nil
		}
		cleanupDeployedAPIs(m.state, m.httpSteps)
		m.cleanupTrackedCertificates()
		return c, nil
	})

	// ---- Uploading ----
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)" and role "([^"]*)" and dns SAN "([^"]*)"$`, m.uploadFixtureWithUsageRoleAndDNSSAN)
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)" and role "([^"]*)"$`, m.uploadFixtureWithUsageAndRole)
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)"$`, m.uploadFixtureWithUsage)
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)"$`, m.uploadFixtureNoUsage)
	ctx.Step(`^I upload the certificate fixtures "([^"]*)" as "([^"]*)" with usage "([^"]*)"$`, m.uploadFixturesWithUsage)
	ctx.Step(`^the certificate fixture "([^"]*)" is pooled as "([^"]*)" with usage "([^"]*)"$`, m.pooledFixtureWithUsage)
	ctx.Step(`^the certificate fixture "([^"]*)" is pooled as "([^"]*)"$`, m.pooledFixtureNoUsage)
	ctx.Step(`^I upload to the certificates endpoint the body:$`, m.uploadRawBody)
	ctx.Step(`^I upload a certificate body of (\d+) megabytes as "([^"]*)" with usage "([^"]*)"$`, m.uploadOversizedBody)

	// ---- Gateway identities (features/mtls-outbound.feature) ----
	// A gateway identity is a certificate pooled via /certificates with
	// usage: "identity"; see steps_mtls_outbound.go.
	ctx.Step(`^I upload the gateway identity fixture "([^"]*)" with its chain as "([^"]*)"$`, m.uploadGatewayIdentityFixtureWithChain)
	ctx.Step(`^I upload the gateway identity fixture "([^"]*)" as "([^"]*)"$`, m.uploadGatewayIdentityFixture)
	ctx.Step(`^the gateway identity fixture "([^"]*)" is stored as "([^"]*)"$`, m.gatewayIdentityFixtureIsStored)
	ctx.Step(`^I upload to the certificates endpoint the identity body:$`, m.uploadGatewayIdentityRawBody)
	ctx.Step(`^I delete the gateway identity named "([^"]*)"$`, m.deleteGatewayIdentityNamed)
	ctx.Step(`^I update the gateway identity "([^"]*)" with the fixture "([^"]*)" and its chain$`, m.updateGatewayIdentityWithFixtureAndChain)
	ctx.Step(`^I update the certificate "([^"]*)" with the identity fixture "([^"]*)"$`, m.updateCertificateWithIdentityFixture)

	// ---- Deploying/updating with fixture-derived values ----
	ctx.Step(`^I deploy this API configuration with fixture values:$`, m.deployWithFixtureValues)
	ctx.Step(`^I update the API "([^"]*)" with this configuration with fixture values:$`, m.updateWithFixtureValues)

	// ---- Listing assertions ----
	// Listing itself is done via the existing generic
	// "I send a GET request to the ... service at ..." step; these steps only
	// inspect whatever the last response was.
	ctx.Step(`^the certificate list should contain "([^"]*)"$`, m.listShouldContain)
	ctx.Step(`^the certificate list should not contain "([^"]*)"$`, m.listShouldNotContain)
	ctx.Step(`^the listed certificate "([^"]*)" should have "([^"]*)" equal to "?([^"]*)"?$`, m.listedCertShouldHaveFieldEqualTo)
	ctx.Step(`^the listed certificate "([^"]*)" should not have field "([^"]*)"$`, m.listedCertShouldNotHaveField)
	ctx.Step(`^the listed certificate "([^"]*)" should have a warning with code "([^"]*)"$`, m.listedCertShouldHaveWarningWithCode)
	ctx.Step(`^the listed certificate "([^"]*)" should have a warning with field "([^"]*)"$`, m.listedCertShouldHaveWarningWithField)
	ctx.Step(`^the listed certificate "([^"]*)" should have no warnings$`, m.listedCertShouldHaveNoWarnings)

	// ---- Validation errors ----
	ctx.Step(`^the response should list a validation error for field "([^"]*)" with message "([^"]*)"$`, m.validationErrorWithMessage)
	ctx.Step(`^the response should list a validation error for field "([^"]*)" containing "([^"]*)"$`, m.validationErrorContaining)
	ctx.Step(`^the response should list a validation error for field "([^"]*)"$`, m.validationErrorAny)

	// ---- Fixture-derived assertions ----
	ctx.Step(`^the JSON response field "([^"]*)" should be the subject of fixture "([^"]*)"$`, m.jsonFieldShouldBeSubjectOfFixture)

	// ---- Deletion ----
	ctx.Step(`^I delete the certificate named "([^"]*)"$`, m.deleteCertificateNamed)

	// ---- HTTPS listener probing ----
	ctx.Step(`^the HTTPS listener should request a client certificate$`, m.httpsListenerShouldRequestClientCertificate)
	ctx.Step(`^the HTTPS listener should not request a client certificate$`, m.httpsListenerShouldNotRequestClientCertificate)

	// ---- Requests carrying (or omitting) a client certificate ----
	ctx.Step(`^I send a GET request to "([^"]*)" with client certificate "([^"]*)" and its chain$`, m.getWithClientCertificateAndChain)
	ctx.Step(`^I send a GET request to "([^"]*)" with client certificate "([^"]*)" and header "([^"]*)" carrying certificate "([^"]*)" encoded as "([^"]*)"$`, m.getWithClientCertificateAndHeaderCertificateEncoded)
	ctx.Step(`^I send a GET request to "([^"]*)" with client certificate "([^"]*)" and header "([^"]*)" carrying certificate "([^"]*)"$`, m.getWithClientCertificateAndHeaderCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with client certificate "([^"]*)"$`, m.getWithClientCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with no client certificate and header "([^"]*)" carrying certificate "([^"]*)"$`, m.getWithNoClientCertificateAndHeaderCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with no client certificate$`, m.getWithNoClientCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with header "([^"]*)" carrying certificate "([^"]*)"$`, m.getWithHeaderCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with the JWT token and client certificate "([^"]*)"$`, m.getWithJWTTokenAndClientCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with the JWT token and no client certificate$`, m.getWithJWTTokenAndNoClientCertificate)

	// ---- Client authority pool state ----
	ctx.Step(`^the client authority pool is empty$`, m.clientAuthorityPoolIsEmpty)

	// ---- Deploy-response warnings ----
	ctx.Step(`^the response should include a warning with code "([^"]*)" for field "([^"]*)"$`, m.responseShouldIncludeWarningWithCodeForField)
	ctx.Step(`^the response should include a warning with code "([^"]*)"$`, m.responseShouldIncludeWarningWithCode)
	ctx.Step(`^the response should include no warnings$`, m.responseShouldIncludeNoWarnings)

	return m
}

// ============ Fixture reading ============

func (m *mtlsSteps) readFixtureFile(fixture, ext string) ([]byte, error) {
	path := filepath.Join(mtlsFixturesDir, fixture+ext)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate fixture %q: %w", path, err)
	}
	return data, nil
}

func (m *mtlsSteps) readFixtureCert(fixture string) ([]byte, error) {
	return m.readFixtureFile(fixture, ".crt")
}

func (m *mtlsSteps) parseFixtureCert(fixture string) (*x509.Certificate, error) {
	data, err := m.readFixtureCert(fixture)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("fixture %q does not contain a PEM certificate", fixture)
	}
	return x509.ParseCertificate(block.Bytes)
}

// resolveTemplates replaces {{pem "name"}} / {{key "name"}} /
// {{encryptedkey "name"}} / {{notafter "name"}} markers with the
// JSON-string-escaped contents (or, for notafter, value) of the named
// fixture.
func (m *mtlsSteps) resolveTemplates(body string) (string, error) {
	var firstErr error

	substitute := func(re *regexp.Regexp, ext string, input string) string {
		return re.ReplaceAllStringFunc(input, func(match string) string {
			sub := re.FindStringSubmatch(match)
			fixture := sub[1]
			data, err := m.readFixtureFile(fixture, ext)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return match
			}
			escaped, err := json.Marshal(string(data))
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to encode fixture %q: %w", fixture, err)
				}
				return match
			}
			// escaped is a JSON string literal including surrounding quotes;
			// strip them since the placeholder already sits inside a quoted
			// JSON string value in the docstring template.
			return string(escaped[1 : len(escaped)-1])
		})
	}

	substituteNotAfter := func(input string) string {
		return mtlsNotAfterPlaceholder.ReplaceAllStringFunc(input, func(match string) string {
			sub := mtlsNotAfterPlaceholder.FindStringSubmatch(match)
			fixture := sub[1]
			value, err := m.notAfterOf(fixture)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return match
			}
			escaped, err := json.Marshal(value)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("failed to encode notAfter for fixture %q: %w", fixture, err)
				}
				return match
			}
			return string(escaped[1 : len(escaped)-1])
		})
	}

	body = substitute(mtlsPemPlaceholder, ".crt", body)
	body = substitute(mtlsKeyPlaceholder, ".key", body)
	body = substitute(mtlsEncryptedKeyPlaceholder, ".encrypted.key", body)
	body = substituteNotAfter(body)
	if firstErr != nil {
		return "", firstErr
	}
	return body, nil
}

// thumbprintOf returns fixture "name"'s SHA-256 thumbprint: 64 lowercase hex
// characters over the certificate's DER bytes, matching both what
// resources/mtls-pki/manifest.json records and what the mtls-auth policy's
// own thumbprint field expects.
func (m *mtlsSteps) thumbprintOf(fixture string) (string, error) {
	cert, err := m.parseFixtureCert(fixture)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// resolveThumbprintTemplates replaces {{thumbprint "name"}} markers with
// fixture "name"'s SHA-256 thumbprint. Unlike resolveTemplates' {{pem}}/
// {{key}} substitution, the replacement is a bare hex string — it needs no
// JSON escaping, since a hex thumbprint contains no characters a YAML or
// JSON string would need to escape.
func (m *mtlsSteps) resolveThumbprintTemplates(body string) (string, error) {
	var firstErr error
	resolved := mtlsThumbprintPlaceholder.ReplaceAllStringFunc(body, func(match string) string {
		sub := mtlsThumbprintPlaceholder.FindStringSubmatch(match)
		fixture := sub[1]
		thumb, err := m.thumbprintOf(fixture)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return match
		}
		return thumb
	})
	if firstErr != nil {
		return "", firstErr
	}
	return resolved, nil
}

// notAfterOf returns fixture "name"'s certificate NotAfter timestamp,
// formatted as RFC3339 in UTC — matching resources/mtls-pki/generate.go's
// manifest.json notAfter field.
func (m *mtlsSteps) notAfterOf(fixture string) (string, error) {
	cert, err := m.parseFixtureCert(fixture)
	if err != nil {
		return "", err
	}
	return cert.NotAfter.UTC().Format(time.RFC3339), nil
}

// resolveNotAfterTemplates replaces {{notafter "name"}} markers in a plain
// (non-JSON) string — such as an Examples table's expected validation-error
// message — with fixture "name"'s NotAfter timestamp. Unlike resolveTemplates'
// use of the same placeholder inside a docstring body, no JSON escaping is
// applied here since the caller is comparing against plain text, not
// embedding into a JSON document.
func (m *mtlsSteps) resolveNotAfterTemplates(s string) (string, error) {
	var firstErr error
	resolved := mtlsNotAfterPlaceholder.ReplaceAllStringFunc(s, func(match string) string {
		sub := mtlsNotAfterPlaceholder.FindStringSubmatch(match)
		fixture := sub[1]
		value, err := m.notAfterOf(fixture)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return match
		}
		return value
	})
	if firstErr != nil {
		return "", firstErr
	}
	return resolved, nil
}
