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
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cucumber/godog"
	"github.com/wso2/api-platform/gateway/it/steps"
)

// mtlsFixturesDir is where resources/mtls-pki/generate.go writes certificate
// and key fixtures. Tests run with the working directory set to the `it`
// module root, so this relative path resolves correctly.
const mtlsFixturesDir = "resources/mtls-pki"

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
