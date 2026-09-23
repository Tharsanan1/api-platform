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

package it

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2/api-platform/gateway/it/steps"
)

// mtlsFixturesDir is where resources/mtls-pki/generate.go writes certificate
// and key fixtures. Tests run with the working directory set to the `it`
// module root, so this relative path resolves correctly.
const mtlsFixturesDir = "resources/mtls-pki"

// httpsListenerAddr is the derived HTTPS listener's dial address, probed
// directly at the TCP/TLS level (rather than through httpSteps) to observe
// whether the server asked for a client certificate.
const httpsListenerAddr = "localhost:8443"

// mtlsListenerProbeRetries/Interval bound the retry loop used only for the
// positive case (listener should now be requesting a certificate), to absorb
// xDS propagation lag after a deploy. The negative case probes once
// immediately — the feature file waits explicitly wherever propagation lag
// matters there.
const (
	mtlsListenerProbeRetries  = 10
	mtlsListenerProbeInterval = 500 * time.Millisecond
)

// mtlsListenerAPINames lists every API name the mtls-listener feature
// deploys via the existing "I deploy this API configuration:" step. Nothing
// in this codebase tracks deployed API names generically, so the
// after-scenario cleanup below removes these fixed names directly instead —
// deleting a name that was never deployed in a given scenario is a no-op
// (404, ignored).
var mtlsListenerAPINames = []string{
	"mtls-listener-api",
	"plain-neighbour-api",
	"mtls-refused-api",
	"mtls-warned-api",
}

// mtlsPemPlaceholder and mtlsKeyPlaceholder match {{pem "name"}} / {{key "name"}}
// template markers inside a docstring request body.
var (
	mtlsPemPlaceholder = regexp.MustCompile(`\{\{pem "([^"]+)"\}\}`)
	mtlsKeyPlaceholder = regexp.MustCompile(`\{\{key "([^"]+)"\}\}`)
)

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

	uploadedNames []string
}

// RegisterMTLSSteps registers step definitions for the client certificate
// authority pool feature (features/mtls-client-ca-pool.feature).
func RegisterMTLSSteps(ctx *godog.ScenarioContext, state *TestState, httpSteps *steps.HTTPSteps) {
	m := &mtlsSteps{state: state, httpSteps: httpSteps}

	ctx.Before(func(c context.Context, sc *godog.Scenario) (context.Context, error) {
		m.uploadedNames = nil
		return c, nil
	})
	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		// Delete any API deployed by this scenario before cleaning up pooled
		// certificates: an mtls-auth deployment can reference a pooled
		// authority, so removing the API first avoids leaving that ordering
		// to chance if the scenario failed before its own cleanup step ran.
		m.cleanupDeployedAPIs()
		m.cleanup()
		return c, nil
	})

	// ---- Uploading ----
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)" and role "([^"]*)"$`, m.uploadFixtureWithUsageAndRole)
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)"$`, m.uploadFixtureWithUsage)
	ctx.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)"$`, m.uploadFixtureNoUsage)
	ctx.Step(`^I upload the certificate fixtures "([^"]*)" as "([^"]*)" with usage "([^"]*)"$`, m.uploadFixturesWithUsage)
	ctx.Step(`^the certificate fixture "([^"]*)" is pooled as "([^"]*)" with usage "([^"]*)"$`, m.pooledFixtureWithUsage)
	ctx.Step(`^the certificate fixture "([^"]*)" is pooled as "([^"]*)"$`, m.pooledFixtureNoUsage)
	ctx.Step(`^I upload to the certificates endpoint the body:$`, m.uploadRawBody)
	ctx.Step(`^I upload a certificate body of (\d+) megabytes as "([^"]*)" with usage "([^"]*)"$`, m.uploadOversizedBody)

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
	ctx.Step(`^I send a GET request to "([^"]*)" with client certificate "([^"]*)"$`, m.getWithClientCertificate)
	ctx.Step(`^I send a GET request to "([^"]*)" with no client certificate$`, m.getWithNoClientCertificate)

	// ---- Client authority pool state ----
	ctx.Step(`^the client authority pool is empty$`, m.clientAuthorityPoolIsEmpty)

	// ---- Deploy-response warnings ----
	ctx.Step(`^the response should include a warning with code "([^"]*)" for field "([^"]*)"$`, m.responseShouldIncludeWarningWithCodeForField)
	ctx.Step(`^the response should include no warnings$`, m.responseShouldIncludeNoWarnings)
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

// resolveTemplates replaces {{pem "name"}} / {{key "name"}} markers with the
// JSON-string-escaped contents of the named fixture file.
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

	body = substitute(mtlsPemPlaceholder, ".crt", body)
	body = substitute(mtlsKeyPlaceholder, ".key", body)
	if firstErr != nil {
		return "", firstErr
	}
	return body, nil
}

// ============ Uploading ============

func (m *mtlsSteps) recordUploaded(name string) {
	m.uploadedNames = append(m.uploadedNames, name)
}

func (m *mtlsSteps) uploadRaw(name, certPEM, usage, role string) error {
	m.recordUploaded(name)

	body := map[string]any{
		"name":        name,
		"certificate": certPEM,
	}
	if usage != "" {
		body["usage"] = usage
	}
	if role != "" {
		body["role"] = role
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to encode certificate upload body: %w", err)
	}

	m.httpSteps.SetHeader("Content-Type", "application/json")
	return m.httpSteps.SendPOSTToService("gateway-controller", "/certificates", &godog.DocString{Content: string(bodyBytes)})
}

func (m *mtlsSteps) uploadFixtureNoUsage(fixture, name string) error {
	certPEM, err := m.readFixtureCert(fixture)
	if err != nil {
		return err
	}
	return m.uploadRaw(name, string(certPEM), "", "")
}

func (m *mtlsSteps) uploadFixtureWithUsage(fixture, name, usage string) error {
	certPEM, err := m.readFixtureCert(fixture)
	if err != nil {
		return err
	}
	return m.uploadRaw(name, string(certPEM), usage, "")
}

func (m *mtlsSteps) uploadFixtureWithUsageAndRole(fixture, name, usage, role string) error {
	certPEM, err := m.readFixtureCert(fixture)
	if err != nil {
		return err
	}
	return m.uploadRaw(name, string(certPEM), usage, role)
}

func (m *mtlsSteps) uploadFixturesWithUsage(fixtureList, name, usage string) error {
	fixtures := strings.Split(fixtureList, ",")
	var buf bytes.Buffer
	for i, f := range fixtures {
		data, err := m.readFixtureCert(strings.TrimSpace(f))
		if err != nil {
			return err
		}
		if i > 0 {
			buf.WriteString("\n")
		}
		buf.Write(data)
	}
	return m.uploadRaw(name, buf.String(), usage, "")
}

func (m *mtlsSteps) expectPooled() error {
	resp := m.httpSteps.LastResponse()
	if resp == nil {
		return fmt.Errorf("expected certificate to be pooled, but no response was received")
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("expected certificate to be pooled (status 201), got %d: %s", resp.StatusCode, string(m.httpSteps.LastBody()))
	}
	return nil
}

func (m *mtlsSteps) pooledFixtureWithUsage(fixture, name, usage string) error {
	if err := m.uploadFixtureWithUsage(fixture, name, usage); err != nil {
		return err
	}
	return m.expectPooled()
}

func (m *mtlsSteps) pooledFixtureNoUsage(fixture, name string) error {
	if err := m.uploadFixtureNoUsage(fixture, name); err != nil {
		return err
	}
	return m.expectPooled()
}

func (m *mtlsSteps) uploadRawBody(body *godog.DocString) error {
	resolved, err := m.resolveTemplates(body.Content)
	if err != nil {
		return err
	}
	m.recordUploadedNameFromJSON(resolved)

	m.httpSteps.SetHeader("Content-Type", "application/json")
	return m.httpSteps.SendPOSTToService("gateway-controller", "/certificates", &godog.DocString{Content: resolved})
}

func (m *mtlsSteps) recordUploadedNameFromJSON(body string) {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return
	}
	if name, ok := parsed["name"].(string); ok && name != "" {
		m.recordUploaded(name)
	}
}

func (m *mtlsSteps) uploadOversizedBody(megabytes int, name, usage string) error {
	m.recordUploaded(name)

	payload := strings.Repeat("A", megabytes*1024*1024)
	body := map[string]any{
		"name":        name,
		"usage":       usage,
		"certificate": payload,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to encode oversized certificate upload body: %w", err)
	}

	m.httpSteps.SetHeader("Content-Type", "application/json")
	return m.httpSteps.SendPOSTToService("gateway-controller", "/certificates", &godog.DocString{Content: string(bodyBytes)})
}

// ============ Listing assertions ============
//
// Listing has no dedicated step: the feature file lists via the existing
// generic "I send a GET request to the ... service at ..." step. Everything
// below only inspects whatever the last HTTP response was.

// currentList parses the certificates array out of whatever the last HTTP
// response was. It intentionally does not cache: scenarios freely interleave
// list requests with other calls, so every assertion re-reads the live last
// response rather than trusting state left over from an earlier step.
func (m *mtlsSteps) currentList() ([]map[string]any, error) {
	var parsed struct {
		Certificates []map[string]any `json:"certificates"`
	}
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse certificate list response: %w", err)
	}
	return parsed.Certificates, nil
}

func (m *mtlsSteps) findInList(name string) (map[string]any, error) {
	list, err := m.currentList()
	if err != nil {
		return nil, err
	}
	for _, item := range list {
		if fmt.Sprint(item["name"]) == name {
			return item, nil
		}
	}
	return nil, nil
}

func (m *mtlsSteps) listShouldContain(name string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item == nil {
		list, _ := m.currentList()
		return fmt.Errorf("expected certificate list to contain %q, got %d entries", name, len(list))
	}
	return nil
}

func (m *mtlsSteps) listShouldNotContain(name string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item != nil {
		return fmt.Errorf("expected certificate list to not contain %q", name)
	}
	return nil
}

func (m *mtlsSteps) listedCertShouldHaveFieldEqualTo(name, field, value string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("certificate %q not found in last list response", name)
	}
	actual, ok := item[field]
	if !ok {
		return fmt.Errorf("certificate %q has no field %q", name, field)
	}
	actualStr := fmt.Sprint(actual)
	if actualStr != value {
		return fmt.Errorf("expected certificate %q field %q to equal %q, got %q", name, field, value, actualStr)
	}
	return nil
}

func (m *mtlsSteps) listedCertShouldNotHaveField(name, field string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("certificate %q not found in last list response", name)
	}
	if _, ok := item[field]; ok {
		return fmt.Errorf("expected certificate %q to not have field %q, got %v", name, field, item[field])
	}
	return nil
}

func (m *mtlsSteps) warningsOf(item map[string]any) []map[string]any {
	raw, ok := item["warnings"]
	if !ok || raw == nil {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, w := range arr {
		if entry, ok := w.(map[string]any); ok {
			out = append(out, entry)
		}
	}
	return out
}

func (m *mtlsSteps) listedCertShouldHaveWarningWithCode(name, code string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("certificate %q not found in last list response", name)
	}
	for _, w := range m.warningsOf(item) {
		if fmt.Sprint(w["code"]) == code {
			return nil
		}
	}
	return fmt.Errorf("certificate %q has no warning with code %q, got %v", name, code, item["warnings"])
}

func (m *mtlsSteps) listedCertShouldHaveWarningWithField(name, field string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("certificate %q not found in last list response", name)
	}
	for _, w := range m.warningsOf(item) {
		if fmt.Sprint(w["field"]) == field {
			return nil
		}
	}
	return fmt.Errorf("certificate %q has no warning with field %q, got %v", name, field, item["warnings"])
}

func (m *mtlsSteps) listedCertShouldHaveNoWarnings(name string) error {
	item, err := m.findInList(name)
	if err != nil {
		return err
	}
	if item == nil {
		return fmt.Errorf("certificate %q not found in last list response", name)
	}
	if warnings := m.warningsOf(item); len(warnings) != 0 {
		return fmt.Errorf("expected certificate %q to have no warnings, got %v", name, item["warnings"])
	}
	return nil
}

// ============ Validation errors ============

func (m *mtlsSteps) validationErrors() ([]map[string]any, error) {
	var parsed struct {
		Errors []map[string]any `json:"errors"`
	}
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse validation error response: %w", err)
	}
	return parsed.Errors, nil
}

func (m *mtlsSteps) validationErrorWithMessage(field, message string) error {
	errs, err := m.validationErrors()
	if err != nil {
		return err
	}
	for _, e := range errs {
		if fmt.Sprint(e["field"]) == field && fmt.Sprint(e["message"]) == message {
			return nil
		}
	}
	return fmt.Errorf("no validation error for field %q with message %q found in %v", field, message, errs)
}

func (m *mtlsSteps) validationErrorContaining(field, substr string) error {
	errs, err := m.validationErrors()
	if err != nil {
		return err
	}
	for _, e := range errs {
		if fmt.Sprint(e["field"]) == field && strings.Contains(fmt.Sprint(e["message"]), substr) {
			return nil
		}
	}
	return fmt.Errorf("no validation error for field %q containing %q found in %v", field, substr, errs)
}

func (m *mtlsSteps) validationErrorAny(field string) error {
	errs, err := m.validationErrors()
	if err != nil {
		return err
	}
	for _, e := range errs {
		if fmt.Sprint(e["field"]) == field {
			return nil
		}
	}
	return fmt.Errorf("no validation error for field %q found in %v", field, errs)
}

// ============ Fixture-derived assertions ============

func (m *mtlsSteps) jsonFieldShouldBeSubjectOfFixture(field, fixture string) error {
	var parsed map[string]any
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return fmt.Errorf("failed to parse JSON response: %w", err)
	}
	actual, ok := parsed[field]
	if !ok {
		return fmt.Errorf("JSON response has no field %q", field)
	}

	cert, err := m.parseFixtureCert(fixture)
	if err != nil {
		return err
	}
	expected := cert.Subject.String()

	actualStr := fmt.Sprint(actual)
	if actualStr != expected {
		return fmt.Errorf("expected field %q to be the subject of fixture %q (%q), got %q", field, fixture, expected, actualStr)
	}
	return nil
}

// ============ HTTPS listener probing ============

// probeClientCertRequested opens a direct TLS connection to the derived
// HTTPS listener with a GetClientCertificate callback that records whether
// it was invoked, then completes the handshake with no certificate (an
// empty tls.Certificate). The listener validates optionally rather than
// requiring a certificate (see the "never drops a connection" scenario), so
// the handshake is expected to succeed either way — the callback having run
// is itself the signal that a CertificateRequest was sent.
func (m *mtlsSteps) probeClientCertRequested() (bool, error) {
	invoked := false
	conf := &tls.Config{
		InsecureSkipVerify: true, // the listener uses a self-signed default cert
		MinVersion:         tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			invoked = true
			return &tls.Certificate{}, nil
		},
	}
	conn, err := tls.Dial("tcp", httpsListenerAddr, conf)
	if err != nil {
		return false, fmt.Errorf("failed to complete a TLS handshake against %s: %w", httpsListenerAddr, err)
	}
	defer conn.Close()
	return invoked, nil
}

func (m *mtlsSteps) httpsListenerShouldRequestClientCertificate() error {
	var lastErr error
	for attempt := 0; attempt < mtlsListenerProbeRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(mtlsListenerProbeInterval)
		}
		invoked, err := m.probeClientCertRequested()
		if err != nil {
			lastErr = err
			continue
		}
		if invoked {
			return nil
		}
		lastErr = fmt.Errorf("HTTPS listener at %s did not request a client certificate", httpsListenerAddr)
	}
	return lastErr
}

func (m *mtlsSteps) httpsListenerShouldNotRequestClientCertificate() error {
	invoked, err := m.probeClientCertRequested()
	if err != nil {
		return err
	}
	if invoked {
		return fmt.Errorf("HTTPS listener at %s requested a client certificate, expected none", httpsListenerAddr)
	}
	return nil
}

// ============ Requests carrying (or omitting) a client certificate ============

// tlsClientWithCertificate builds a one-off *http.Client whose transport
// presents the named certificate fixture (and, when includeChain is true,
// its intermediate chain) for the TLS handshake. Keep-alives are disabled so
// each step is a fresh connection — the certificate is negotiated per
// connection, not per request.
func (m *mtlsSteps) tlsClientWithCertificate(name string, includeChain bool) (*http.Client, error) {
	certPEM, err := m.readFixtureCert(name)
	if err != nil {
		return nil, err
	}
	if includeChain {
		chainPEM, err := m.readFixtureFile(name, ".chain.crt")
		if err != nil {
			return nil, err
		}
		combined := make([]byte, 0, len(certPEM)+len(chainPEM))
		combined = append(combined, certPEM...)
		combined = append(combined, chainPEM...)
		certPEM = combined
	}
	keyPEM, err := m.readFixtureFile(name, ".key")
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate fixture %q: %w", name, err)
	}
	return &http.Client{
		Timeout: m.state.Config.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // the listener uses a self-signed default cert
				MinVersion:         tls.VersionTLS12,
				Certificates:       []tls.Certificate{cert},
			},
			DisableKeepAlives: true,
		},
	}, nil
}

// tlsClientNoCertificate builds a one-off *http.Client whose transport
// presents no client certificate at all.
func (m *mtlsSteps) tlsClientNoCertificate() *http.Client {
	return &http.Client{
		Timeout: m.state.Config.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS12,
			},
			DisableKeepAlives: true,
		},
	}
}

func (m *mtlsSteps) getWithClientCertificate(url, name string) error {
	client, err := m.tlsClientWithCertificate(name, false)
	if err != nil {
		return err
	}
	return m.httpSteps.SendRequestWithClient(client, http.MethodGet, url)
}

func (m *mtlsSteps) getWithClientCertificateAndChain(url, name string) error {
	client, err := m.tlsClientWithCertificate(name, true)
	if err != nil {
		return err
	}
	return m.httpSteps.SendRequestWithClient(client, http.MethodGet, url)
}

func (m *mtlsSteps) getWithNoClientCertificate(url string) error {
	return m.httpSteps.SendRequestWithClient(m.tlsClientNoCertificate(), http.MethodGet, url)
}

// ============ Client authority pool state ============

// clientAuthorityPoolIsEmpty empties the client-usage certificate pool by
// listing every "client" usage entry and deleting it, as the current
// authenticated user (the feature runs as admin throughout). A delete
// returning anything other than 2xx/404 is treated as a failure; a 404 (the
// entry already gone) is ignored.
func (m *mtlsSteps) clientAuthorityPoolIsEmpty() error {
	if err := m.httpSteps.SendGETToService("gateway-controller", "/certificates?usage=client"); err != nil {
		return err
	}
	var parsed struct {
		Certificates []map[string]any `json:"certificates"`
	}
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return fmt.Errorf("failed to parse certificate list while emptying the client authority pool: %w", err)
	}

	for _, item := range parsed.Certificates {
		id := fmt.Sprint(item["id"])
		if err := m.httpSteps.SendDELETEToService("gateway-controller", "/certificates/"+id); err != nil {
			return err
		}
		resp := m.httpSteps.LastResponse()
		if resp != nil && resp.StatusCode != http.StatusNotFound && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
			return fmt.Errorf("failed to delete certificate %q (id %s) while emptying the client authority pool: status %d", item["name"], id, resp.StatusCode)
		}
	}
	return nil
}

// ============ Deploy-response warnings ============

// responseWarnings reads the warnings array off the last response body,
// wherever the deploy response places it: nested under "status.warnings" (a
// k8s-style management resource) or top-level "warnings".
func (m *mtlsSteps) responseWarnings() ([]map[string]any, error) {
	var parsed map[string]any
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response while inspecting warnings: %w", err)
	}
	if status, ok := parsed["status"].(map[string]any); ok {
		if raw, ok := status["warnings"].([]any); ok {
			return toWarningEntries(raw), nil
		}
	}
	if raw, ok := parsed["warnings"].([]any); ok {
		return toWarningEntries(raw), nil
	}
	return nil, nil
}

func toWarningEntries(raw []any) []map[string]any {
	var out []map[string]any
	for _, w := range raw {
		if entry, ok := w.(map[string]any); ok {
			out = append(out, entry)
		}
	}
	return out
}

func (m *mtlsSteps) responseShouldIncludeWarningWithCodeForField(code, field string) error {
	warnings, err := m.responseWarnings()
	if err != nil {
		return err
	}
	for _, w := range warnings {
		if fmt.Sprint(w["code"]) == code && fmt.Sprint(w["field"]) == field {
			return nil
		}
	}
	return fmt.Errorf("no warning with code %q for field %q found in %v", code, field, warnings)
}

func (m *mtlsSteps) responseShouldIncludeNoWarnings() error {
	warnings, err := m.responseWarnings()
	if err != nil {
		return err
	}
	if len(warnings) != 0 {
		return fmt.Errorf("expected no warnings, got %v", warnings)
	}
	return nil
}

// ============ Deletion ============

func (m *mtlsSteps) findCertificateIDByName(name string) (string, error) {
	if err := m.httpSteps.SendGETToService("gateway-controller", "/certificates"); err != nil {
		return "", err
	}
	var parsed struct {
		Certificates []map[string]any `json:"certificates"`
	}
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return "", fmt.Errorf("failed to parse certificate list while resolving %q: %w", name, err)
	}
	for _, item := range parsed.Certificates {
		if fmt.Sprint(item["name"]) == name {
			return fmt.Sprint(item["id"]), nil
		}
	}
	return "", fmt.Errorf("no certificate named %q found", name)
}

func (m *mtlsSteps) deleteCertificateNamed(name string) error {
	id, err := m.findCertificateIDByName(name)
	if err != nil {
		return fmt.Errorf("failed to delete certificate %q: %w", name, err)
	}
	return m.httpSteps.SendDELETEToService("gateway-controller", "/certificates/"+id)
}

// ============ Cleanup ============

// cleanupDeployedAPIs deletes every fixed API name the mtls-listener feature
// deploys, authenticating as admin, so a scenario that fails before its own
// "I delete the API ..." step still leaves the gateway clean. Deleting a name
// that was never deployed in this run is a no-op (404, ignored) — this
// cleanup runs for every scenario registered through RegisterMTLSSteps, not
// only mtls-listener ones.
func (m *mtlsSteps) cleanupDeployedAPIs() {
	admin, ok := m.state.Config.Users["admin"]
	if !ok {
		return
	}
	creds := base64.StdEncoding.EncodeToString([]byte(admin.Username + ":" + admin.Password))
	m.httpSteps.SetHeader("Authorization", "Basic "+creds)

	for _, name := range mtlsListenerAPINames {
		_ = m.httpSteps.SendDELETEToService("gateway-controller", "/rest-apis/"+name)
	}
}

// cleanup deletes every certificate name this scenario attempted to upload,
// authenticating as admin regardless of which role the scenario last used
// (or cleared). Best-effort: a certificate that was never actually pooled
// (e.g. a rejected upload) or a 404 on delete is silently ignored, and no
// prior auth header state is restored afterwards.
func (m *mtlsSteps) cleanup() {
	if len(m.uploadedNames) == 0 {
		return
	}

	admin, ok := m.state.Config.Users["admin"]
	if !ok {
		return
	}
	creds := base64.StdEncoding.EncodeToString([]byte(admin.Username + ":" + admin.Password))
	m.httpSteps.SetHeader("Authorization", "Basic "+creds)

	if err := m.httpSteps.SendGETToService("gateway-controller", "/certificates"); err != nil {
		return
	}
	var parsed struct {
		Certificates []map[string]any `json:"certificates"`
	}
	if err := json.Unmarshal(m.httpSteps.LastBody(), &parsed); err != nil {
		return
	}

	idByName := make(map[string]string, len(parsed.Certificates))
	for _, item := range parsed.Certificates {
		idByName[fmt.Sprint(item["name"])] = fmt.Sprint(item["id"])
	}

	for _, name := range m.uploadedNames {
		id, ok := idByName[name]
		if !ok {
			continue
		}
		// Best-effort: ignore the outcome, including 404s for a certificate
		// already removed by the scenario itself.
		_ = m.httpSteps.SendDELETEToService("gateway-controller", "/certificates/"+id)
	}
}
