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

package platformgateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/testpki"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

// Encodings a front proxy uses for a certificate it relays in a header.
const (
	relayEncodingURL    = "url"    // the PEM text, URL-path-escaped; the default
	relayEncodingPEM    = "pem"    // the PEM text with newlines replaced by spaces
	relayEncodingBase64 = "base64" // base64 of the DER bytes, without PEM armour
)

// relayedCertificate is a fixture certificate carried in a request header.
type relayedCertificate struct {
	header   string
	fixture  string
	encoding string
}

// value renders the fixture the way a front proxy places it in the header.
func (r *relayedCertificate) value() (string, error) {
	fixture, err := mtlsFixtureNamed(r.fixture)
	if err != nil {
		return "", err
	}
	switch r.encoding {
	case "", relayEncodingURL:
		return url.PathEscape(string(fixture.CertPEM)), nil
	case relayEncodingPEM:
		// A header cannot carry a newline; several proxies send the PEM with spaces instead.
		return strings.ReplaceAll(string(fixture.CertPEM), "\n", " "), nil
	case relayEncodingBase64:
		return base64.StdEncoding.EncodeToString(fixture.Certificate.Raw), nil
	default:
		return "", fmt.Errorf("unknown certificate header encoding %q: expected %q, %q or %q",
			r.encoding, relayEncodingURL, relayEncodingPEM, relayEncodingBase64)
	}
}

func mtlsFixtureNamed(name string) (*testpki.Fixture, error) {
	fixtures, err := testpki.Default()
	if err != nil {
		return nil, err
	}
	return fixtures.Get(name)
}

func (g *Gateway) registerMTLSRelaySteps(sc *godog.ScenarioContext) {
	sc.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)" and role "([^"]*)"$`, g.uploadCertificateWithRole)
	sc.Step(`^I upload the certificate fixture "([^"]*)" as "([^"]*)" with usage "([^"]*)" and role "([^"]*)" and dns SAN "([^"]*)"$`, g.uploadCertificateWithRoleAndDNSSAN)
	sc.Step(`^I delete the certificate named "([^"]*)"$`, g.deleteCertificateNamed)
	sc.Step(`^the backend's X-Forwarded-Client-Cert should (name|not name) certificate "([^"]*)"$`, g.forwardedCertificateNames)
	sc.Step(`^the response should include a warning with code "([^"]*)"(?: for field "([^"]*)")?$`, g.responseIncludesWarning)
	sc.Step(`^the response should list a validation error for field "([^"]*)" with message "([^"]*)"$`, g.validationErrorWithMessage)
}

// uploadCertificateWithRole uploads one fixture with an explicit pool role.
func (g *Gateway) uploadCertificateWithRole(ctx context.Context, fixture, name, usage, role string) error {
	_, err := g.uploadFixtures(ctx, fixture, name, certificateUpload{usage: usage, role: role})
	return err
}

// uploadCertificateWithRoleAndDNSSAN uploads one fixture whose relay match lists one DNS SAN.
func (g *Gateway) uploadCertificateWithRoleAndDNSSAN(ctx context.Context, fixture, name, usage, role, dnsSAN string) error {
	san, err := stepscommon.Expand(ctx, dnsSAN)
	if err != nil {
		return err
	}
	_, err = g.uploadFixtures(ctx, fixture, name, certificateUpload{usage: usage, role: role, dnsSANs: []string{san}})
	return err
}

// deleteCertificateNamed deletes a certificate by its generated name. The listing is not
// published. The delete is, and cleanup forgets the certificate only when that delete succeeded.
func (g *Gateway) deleteCertificateNamed(ctx context.Context, nameExpr string) error {
	name, err := g.generatedCertificateName(ctx, nameExpr)
	if err != nil {
		return err
	}
	id, err := g.certificateIDByName(ctx, name)
	if err != nil {
		return err
	}
	url, err := g.serviceURL(ctx, "gateway-controller", "/certificates/"+id)
	if err != nil {
		return err
	}
	resp, err := g.funnel.Delete(ctx, url, g.scenarioHeaders(ctx))
	if err != nil {
		return err
	}
	if !resp.Succeeded() {
		return nil
	}
	registry, err := cleanup.Of(ctx)
	if err != nil {
		return err
	}
	registry.Deregister(cleanup.KindCertificate, id)
	return nil
}

// certificateIDByName lists certificates until the name is present. A missing name fails at
// once; an unready controller is polled through.
func (g *Gateway) certificateIDByName(ctx context.Context, name string) (string, error) {
	var id string
	err := awaitState(ctx, fmt.Sprintf("waiting to list certificate %q", name), func(ctx context.Context) error {
		var listing struct {
			Certificates []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"certificates"`
		}
		if err := g.readJSON(ctx, "gateway-controller", "/certificates", &listing); err != nil {
			return err
		}
		for _, cert := range listing.Certificates {
			if cert.Name != name {
				continue
			}
			if cert.ID == "" {
				return fmt.Errorf("certificate %q is listed without an id", name)
			}
			id = cert.ID
			return nil
		}
		return fmt.Errorf("no certificate named %q", name)
	})
	return id, err
}

// validationErrorWithMessage asserts the published response lists an error with this field
// and this message.
func (g *Gateway) validationErrorWithMessage(ctx context.Context, field, message string) error {
	field, err := stepscommon.Expand(ctx, field)
	if err != nil {
		return err
	}
	message, err = stepscommon.Expand(ctx, message)
	if err != nil {
		return err
	}
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	var parsed struct {
		Errors []struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return fmt.Errorf("reading validation errors: %w (%s)", err, resp.Describe())
	}
	for _, e := range parsed.Errors {
		if e.Field == field && e.Message == message {
			return nil
		}
	}
	return fmt.Errorf("no validation error for field %q with message %q in %+v: %s", field, message, parsed.Errors, resp.Describe())
}

// xfccHash reads each Hash element of an X-Forwarded-Client-Cert value.
var xfccHash = regexp.MustCompile(`(?i)(?:^|[;,])Hash=([0-9a-f]{64})(?:[;,]|$)`)

// forwardedCertificateNames asserts what the backend's X-Forwarded-Client-Cert describes. It
// names a certificate when its first element's Hash is the fixture's thumbprint and its Subject
// carries the fixture's common name; it does not name one when no element's Hash is that
// thumbprint.
func (g *Gateway) forwardedCertificateNames(ctx context.Context, mode, fixtureName string) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	fixture, err := mtlsFixtureNamed(fixtureName)
	if err != nil {
		return err
	}
	xfcc, err := echoedHeaderValues(resp, "x-forwarded-client-cert")
	if err != nil {
		return err
	}
	hashes := xfccHash.FindAllStringSubmatch(xfcc, -1)
	if mode == "not name" {
		for _, h := range hashes {
			if strings.EqualFold(h[1], fixture.Thumbprint) {
				return fmt.Errorf("expected X-Forwarded-Client-Cert not to name %q, got %q", fixtureName, xfcc)
			}
		}
		return nil
	}
	if xfcc == "" {
		return fmt.Errorf("expected the backend to receive X-Forwarded-Client-Cert naming %q, got none: %s", fixtureName, resp.Describe())
	}
	if len(hashes) == 0 || !strings.EqualFold(hashes[0][1], fixture.Thumbprint) {
		return fmt.Errorf("expected X-Forwarded-Client-Cert Hash to be the thumbprint of %q (%s), got %q", fixtureName, fixture.Thumbprint, xfcc)
	}
	if cn := "CN=" + fixture.Certificate.Subject.CommonName; !strings.Contains(xfcc, cn) {
		return fmt.Errorf("expected X-Forwarded-Client-Cert Subject to name %s, got %q", cn, xfcc)
	}
	return nil
}

// echoedHeaderValues returns every value the echo backend received for a header, joined by
// commas, or "" when it received none.
func echoedHeaderValues(resp *httpx.Response, name string) (string, error) {
	var echo struct {
		Headers map[string]any `json:"headers"`
	}
	if err := json.Unmarshal(resp.Body, &echo); err != nil || echo.Headers == nil {
		return "", fmt.Errorf("the response carries no echoed headers: %s", resp.Describe())
	}
	for key, value := range echo.Headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		switch v := value.(type) {
		case string:
			return v, nil
		case []any:
			parts := make([]string, 0, len(v))
			for _, part := range v {
				parts = append(parts, fmt.Sprint(part))
			}
			return strings.Join(parts, ","), nil
		default:
			return "", fmt.Errorf("echoed header %q is %T, not a string or an array", name, value)
		}
	}
	return "", nil
}

// responseIncludesWarning asserts the published management response carries a warning with
// the code and, when given, for the field. Warnings are read from status.warnings or a
// top-level warnings array.
func (g *Gateway) responseIncludesWarning(ctx context.Context, code, field string) error {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return err
	}
	warnings, err := responseWarnings(resp)
	if err != nil {
		return err
	}
	for _, w := range warnings {
		if w.Code == code && (field == "" || w.Field == field) {
			return nil
		}
	}
	if field == "" {
		return fmt.Errorf("no warning with code %q in %+v: %s", code, warnings, resp.Describe())
	}
	return fmt.Errorf("no warning with code %q for field %q in %+v: %s", code, field, warnings, resp.Describe())
}

// managementWarning is one warning a management response carries.
type managementWarning struct {
	Code  string `json:"code"`
	Field string `json:"field"`
}

func responseWarnings(resp *httpx.Response) ([]managementWarning, error) {
	var body struct {
		Status struct {
			Warnings []managementWarning `json:"warnings"`
		} `json:"status"`
		Warnings []managementWarning `json:"warnings"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		return nil, fmt.Errorf("reading warnings: %w (%s)", err, resp.Describe())
	}
	if len(body.Status.Warnings) > 0 {
		return body.Status.Warnings, nil
	}
	return body.Warnings, nil
}
