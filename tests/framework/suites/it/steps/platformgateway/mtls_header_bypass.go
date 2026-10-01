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

	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/testpki"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

// Encodings a front proxy uses for a certificate it relays in a header.
const (
	relayEncodingURL    = "url"    // the PEM text, URL-path-escaped
	relayEncodingPEM    = "pem"    // the PEM text with newlines replaced by spaces
	relayEncodingBase64 = "base64" // base64 of the DER bytes, without PEM armour
)

// relayedCertificate is a fixture a request carries in a header, as a front proxy relays the
// certificate its own caller presented. An empty header relays nothing.
type relayedCertificate struct {
	header   string
	fixture  string
	encoding string
}

// apply sets the relayed certificate header on one request's headers.
func (r relayedCertificate) apply(headers map[string]string) error {
	if r.header == "" {
		return nil
	}
	value, err := encodeRelayedCertificate(r.fixture, r.encoding)
	if err != nil {
		return err
	}
	headers[r.header] = value
	return nil
}

// encodeRelayedCertificate renders a fixture's certificate for a header. Empty means url.
func encodeRelayedCertificate(fixtureName, encoding string) (string, error) {
	fixtures, err := testpki.Default()
	if err != nil {
		return "", err
	}
	fixture, err := fixtures.Get(fixtureName)
	if err != nil {
		return "", err
	}
	switch encoding {
	case "", relayEncodingURL:
		return url.PathEscape(string(fixture.CertPEM)), nil
	case relayEncodingPEM:
		return strings.ReplaceAll(string(fixture.CertPEM), "\n", " "), nil
	case relayEncodingBase64:
		return base64.StdEncoding.EncodeToString(fixture.Certificate.Raw), nil
	default:
		return "", fmt.Errorf("unknown certificate header encoding %q: expected url, pem or base64", encoding)
	}
}

func (g *Gateway) registerMTLSHeaderBypassSteps(sc *godog.ScenarioContext) {
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" with header "([^"]*)" carrying certificate "([^"]*)"(?: encoded as "([^"]*)")?$`,
		g.sendRelayingCertificate)
	sc.Step(`^the backend's X-Forwarded-Client-Cert should name certificate "([^"]*)"$`, g.forwardedCertificateNames)
}

// sendRelayingCertificate sends one plain HTTP request carrying a fixture's certificate in a
// header and publishes the response. In an @mtls scenario it first waits for the gateway to
// apply the client authority pool.
func (g *Gateway) sendRelayingCertificate(ctx context.Context, method, path, header, fixture, encoding string) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	target, err := g.gatewayURL(resolved)
	if err != nil {
		return err
	}
	headers := g.scenarioHeaders(ctx)
	if err := (relayedCertificate{header: header, fixture: fixture, encoding: encoding}).apply(headers); err != nil {
		return err
	}
	if isMTLSScenario(ctx) {
		if err := g.awaitGatewayApplied(ctx); err != nil {
			return err
		}
	}
	method = strings.ToUpper(method)
	if _, err := g.funnel.Send(ctx, httpx.Request{
		Method: method, URL: target, Headers: headers, Host: g.requestHost(ctx),
	}); err != nil {
		return fmt.Errorf("invoking %s %s: %w", method, target, err)
	}
	return nil
}

// xfccHash reads the Hash element of an X-Forwarded-Client-Cert value.
var xfccHash = regexp.MustCompile(`(?i)(?:^|;)Hash=([0-9a-f]{64})(?:;|$)`)

// forwardedCertificateNames asserts the X-Forwarded-Client-Cert the echo backend received
// describes the fixture: its Hash is the fixture's thumbprint and its Subject carries the
// fixture's common name.
func (g *Gateway) forwardedCertificateNames(ctx context.Context, fixtureName string) error {
	xfcc, err := echoedForwardedCertificate(ctx)
	if err != nil {
		return err
	}
	if xfcc == "" {
		return fmt.Errorf("expected the backend to receive X-Forwarded-Client-Cert naming %q, got none", fixtureName)
	}
	fixtures, err := testpki.Default()
	if err != nil {
		return err
	}
	fixture, err := fixtures.Get(fixtureName)
	if err != nil {
		return err
	}
	if m := xfccHash.FindStringSubmatch(xfcc); m == nil || !strings.EqualFold(m[1], fixture.Thumbprint) {
		return fmt.Errorf("expected X-Forwarded-Client-Cert Hash to be the thumbprint of %q (%s), got %q",
			fixtureName, fixture.Thumbprint, xfcc)
	}
	if cn := "CN=" + fixture.Certificate.Subject.CommonName; !strings.Contains(xfcc, cn) {
		return fmt.Errorf("expected X-Forwarded-Client-Cert Subject to name %s, got %q", cn, xfcc)
	}
	return nil
}

// echoedForwardedCertificate returns the X-Forwarded-Client-Cert the echo backend reflected in
// the published response, or "" when it received none.
func echoedForwardedCertificate(ctx context.Context) (string, error) {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return "", err
	}
	var echo struct {
		Headers map[string]any `json:"headers"`
	}
	if err := json.Unmarshal(resp.Body, &echo); err != nil || echo.Headers == nil {
		return "", fmt.Errorf("the response is not an echo of the request headers: %s", resp.Describe())
	}
	for name, value := range echo.Headers {
		if !strings.EqualFold(name, "X-Forwarded-Client-Cert") {
			continue
		}
		switch v := value.(type) {
		case string:
			return v, nil
		case []any:
			parts := make([]string, 0, len(v))
			for _, item := range v {
				parts = append(parts, fmt.Sprint(item))
			}
			return strings.Join(parts, ","), nil
		default:
			return "", fmt.Errorf("the echoed X-Forwarded-Client-Cert is %T, not a string or a list", value)
		}
	}
	return "", nil
}
