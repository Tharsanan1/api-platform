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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cucumber/godog"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
	"github.com/wso2/api-platform/tests/framework/core/util/testpki"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

// encryptedKeyPassphrase protects the encrypted copy of every fixture key published to an
// @mtls scenario.
const encryptedKeyPassphrase = "test"

// tlsConnectFailureMarker opens the body Envoy answers with when it cannot establish the
// upstream connection.
const tlsConnectFailureMarker = "upstream connect error"

func (g *Gateway) registerOutboundMTLSSteps(sc *godog.ScenarioContext) {
	sc.Before(publishFixtureMaterial)
	sc.Step(`^the certificate fixtures? "([^"]*)" (?:is|are) pooled as "([^"]*)"$`, g.poolFixtureWithDefaultUsage)
	sc.Step(`^I upload the gateway identity fixture "([^"]*)" with its chain as "([^"]*)"$`, g.uploadIdentityWithChain)
	sc.Step(`^I upload the gateway identity fixture "([^"]*)" as "([^"]*)"$`, g.uploadIdentity)
	sc.Step(`^the gateway identity fixture "([^"]*)" is stored as "([^"]*)"$`, g.storeIdentity)
	sc.Step(`^I upload to the certificates endpoint the identity body:$`, g.uploadIdentityBody)
	sc.Step(`^I delete the gateway identity named "([^"]*)"$`, g.deleteIdentityNamed)
	sc.Step(`^I delete the certificate named "([^"]*)"$`, g.deleteCertificateNamed)
	sc.Step(`^I update the gateway identity "([^"]*)" with the fixture "([^"]*)" and its chain$`, g.rotateIdentity)
	sc.Step(`^I update the certificate "([^"]*)" with the identity fixture "([^"]*)"$`, g.updateCertificateWithIdentity)
	sc.Step(`^the response should list a validation error for field "([^"]*)" with message "([^"]*)"$`, validationErrorWithMessage)
	sc.Step(`^the response should list a validation error for field "([^"]*)" containing "([^"]*)"$`, validationErrorContaining)
	sc.Step(`^the response should include a warning with code "([^"]*)" for field "([^"]*)"$`, warningForField)
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" until the backend refuses the request with 400$`, g.sendUntilBackendRefuses)
	sc.Step(`^I send a "([^"]*)" request to "([^"]*)" until the upstream TLS connection fails with 503$`, g.sendUntilUpstreamTLSFails)
	sc.Step(`^the gateway has applied its configuration$`, g.awaitGatewayApplied)
}

// ── Fixture material ─────────────────────────────────────────────────────────────

// fixtureMaterialKey names a context value holding one JSON-string-escaped form of a fixture:
// "pem", "key" or "encryptedKey". It lets a feature write a request body with the fixture
// embedded as ${CTX:...}.
func fixtureMaterialKey(fixture, form string) string { return "fixture." + fixture + "." + form }

// publishFixtureMaterial publishes every fixture's certificate, key and passphrase-protected
// key to an @mtls scenario.
func publishFixtureMaterial(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	if sc == nil || !hasTag(scenarioTags(sc), tagMTLS) {
		return ctx, nil
	}
	return ctx, publishMaterial(ctx)
}

func publishMaterial(ctx context.Context) error {
	fixtures, err := testpki.Default()
	if err != nil {
		return err
	}
	for _, name := range fixtures.Names() {
		fixture, err := fixtures.Get(name)
		if err != nil {
			return err
		}
		forms := map[string][]byte{"pem": fixture.CertPEM, "key": fixture.KeyPEM}
		if len(fixture.KeyPEM) > 0 {
			encrypted, err := fixture.EncryptedKeyPEM(encryptedKeyPassphrase)
			if err != nil {
				return err
			}
			forms["encryptedKey"] = encrypted
		}
		for form, material := range forms {
			if err := tcontext.Set(ctx, fixtureMaterialKey(name, form), jsonStringBody(material)); err != nil {
				return err
			}
		}
	}
	return nil
}

// jsonStringBody escapes text for the inside of a JSON string.
func jsonStringBody(text []byte) string {
	quoted, _ := json.Marshal(string(text))
	return string(quoted[1 : len(quoted)-1])
}

func (g *Gateway) poolFixtureWithDefaultUsage(ctx context.Context, fixtureList, name string) error {
	return g.poolCertificateFixtures(ctx, fixtureList, name, "")
}

// ── Gateway identities ───────────────────────────────────────────────────────────

// identityMaterial returns the fixture's certificate, followed by its issuing chain when
// withChain is set, and its key.
func identityMaterial(fixture *testpki.Fixture, withChain bool) (certificate, key string, err error) {
	pem := append([]byte{}, fixture.CertPEM...)
	if withChain {
		if len(fixture.ChainPEM) == 0 {
			return "", "", fmt.Errorf("fixture %q has no issuing chain", fixture.Name)
		}
		pem = append(pem, fixture.ChainPEM...)
	}
	return string(pem), string(fixture.KeyPEM), nil
}

func (g *Gateway) uploadIdentity(ctx context.Context, fixtureName, nameExpr string) error {
	_, err := g.uploadIdentityFixture(ctx, fixtureName, nameExpr, false)
	return err
}

func (g *Gateway) uploadIdentityWithChain(ctx context.Context, fixtureName, nameExpr string) error {
	_, err := g.uploadIdentityFixture(ctx, fixtureName, nameExpr, true)
	return err
}

// storeIdentity uploads an identity and requires the gateway to have created it.
func (g *Gateway) storeIdentity(ctx context.Context, fixtureName, nameExpr string) error {
	resp, err := g.uploadIdentityFixture(ctx, fixtureName, nameExpr, false)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("expected gateway identity %q to be stored with status 201, got %s", fixtureName, resp.Describe())
	}
	return nil
}

func (g *Gateway) uploadIdentityFixture(ctx context.Context, fixtureName, nameExpr string, withChain bool) (*httpx.Response, error) {
	name, err := g.generatedCertificateName(ctx, nameExpr)
	if err != nil {
		return nil, err
	}
	fixtures, err := testpki.Default()
	if err != nil {
		return nil, err
	}
	fixture, err := fixtures.Get(fixtureName)
	if err != nil {
		return nil, err
	}
	certificate, key, err := identityMaterial(fixture, withChain)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(map[string]string{
		"name": name, "usage": "identity", "certificate": certificate, "privateKey": key,
	})
	if err != nil {
		return nil, fmt.Errorf("encoding the identity upload: %w", err)
	}
	return g.postCertificate(ctx, name, payload)
}

// uploadIdentityBody posts a feature-written body, with fixture material embedded as context
// values, to the certificates endpoint.
func (g *Gateway) uploadIdentityBody(ctx context.Context, body *godog.DocString) error {
	expanded, err := stepscommon.Expand(ctx, body.Content)
	if err != nil {
		return err
	}
	var named struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal([]byte(expanded), &named) // an unparseable body is refused by the gateway, which the scenario asserts
	_, err = g.postCertificate(ctx, named.Name, []byte(expanded))
	return err
}

// postCertificate posts a certificate upload, publishes the response, and registers an
// accepted certificate for cleanup at once.
func (g *Gateway) postCertificate(ctx context.Context, name string, payload []byte) (*httpx.Response, error) {
	url, err := g.serviceURL(ctx, "gateway-controller", "/certificates")
	if err != nil {
		return nil, err
	}
	resp, err := g.funnel.Post(ctx, url, g.headerWith(ctx, "Content-Type", "application/json"), payload)
	if err != nil {
		return nil, err
	}
	if !resp.Succeeded() {
		return resp, nil
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(resp.Body, &created); err != nil || created.ID == "" {
		return resp, fmt.Errorf("certificate %q was accepted without an id: %s", name, resp.Describe())
	}
	if err := cleanup.Register(ctx, cleanup.Resource{
		Kind: cleanup.KindCertificate, ID: created.ID, Actor: "admin",
		Description: "certificate " + name + " uploaded by " + scenarioLabel(ctx),
	}); err != nil {
		deleteURL, urlErr := g.serviceURL(ctx, "gateway-controller", "/certificates/"+created.ID)
		if urlErr == nil {
			if deleteErr := g.compensateDelete(ctx, deleteURL, g.scenarioHeaders(ctx)); deleteErr != nil {
				return resp, fmt.Errorf("registering certificate %q for cleanup: %w; compensation failed: %v", name, err, deleteErr)
			}
		}
		return resp, fmt.Errorf("registering certificate %q for cleanup: %w", name, err)
	}
	return resp, nil
}

// certificateIDByName returns the id of the certificate with the given name, looking only at
// the given usage when it is set, so an identity is never mistaken for another certificate.
func (g *Gateway) certificateIDByName(ctx context.Context, name, usage string) (string, error) {
	path := "/certificates"
	if usage != "" {
		path += "?usage=" + usage
	}
	url, err := g.serviceURL(ctx, "gateway-controller", path)
	if err != nil {
		return "", err
	}
	// An intermediate read: the response a step publishes is the one a scenario asserts on.
	resp, err := g.funnel.Client().Do(ctx, httpx.Request{Method: http.MethodGet, URL: url, Headers: g.scenarioHeaders(ctx)}, 0, 0)
	if err != nil {
		return "", err
	}
	if !resp.Succeeded() {
		return "", fmt.Errorf("listing certificates to resolve %q: %s", name, resp.Describe())
	}
	var listing struct {
		Certificates []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal(resp.Body, &listing); err != nil {
		return "", fmt.Errorf("parsing the certificate list while resolving %q: %w", name, err)
	}
	for _, c := range listing.Certificates {
		if c.Name == name {
			return c.ID, nil
		}
	}
	return "", fmt.Errorf("no certificate named %q found (usage filter %q)", name, usage)
}

func (g *Gateway) deleteIdentityNamed(ctx context.Context, nameExpr string) error {
	return g.deleteCertificateByName(ctx, nameExpr, "identity")
}

func (g *Gateway) deleteCertificateNamed(ctx context.Context, nameExpr string) error {
	return g.deleteCertificateByName(ctx, nameExpr, "")
}

// deleteCertificateByName deletes the named certificate and publishes the answer. A deletion
// the gateway accepted is taken off the cleanup list.
func (g *Gateway) deleteCertificateByName(ctx context.Context, nameExpr, usage string) error {
	name, err := stepscommon.Expand(ctx, nameExpr)
	if err != nil {
		return err
	}
	id, err := g.certificateIDByName(ctx, name, usage)
	if err != nil {
		return fmt.Errorf("deleting certificate %q: %w", name, err)
	}
	url, err := g.serviceURL(ctx, "gateway-controller", "/certificates/"+id)
	if err != nil {
		return err
	}
	resp, err := g.funnel.Delete(ctx, url, g.scenarioHeaders(ctx))
	if err != nil {
		return err
	}
	if resp.Succeeded() {
		if reg, regErr := cleanup.Of(ctx); regErr == nil {
			reg.Deregister(cleanup.KindCertificate, id)
		}
	}
	return nil
}

// rotateIdentity replaces the named identity's certificate chain and key in place.
func (g *Gateway) rotateIdentity(ctx context.Context, nameExpr, fixtureName string) error {
	return g.putIdentityShape(ctx, nameExpr, "identity", fixtureName, true)
}

// updateCertificateWithIdentity sends an identity-shaped update to a certificate that is not
// an identity.
func (g *Gateway) updateCertificateWithIdentity(ctx context.Context, nameExpr, fixtureName string) error {
	return g.putIdentityShape(ctx, nameExpr, "", fixtureName, false)
}

func (g *Gateway) putIdentityShape(ctx context.Context, nameExpr, usage, fixtureName string, withChain bool) error {
	name, err := stepscommon.Expand(ctx, nameExpr)
	if err != nil {
		return err
	}
	id, err := g.certificateIDByName(ctx, name, usage)
	if err != nil {
		return fmt.Errorf("updating certificate %q: %w", name, err)
	}
	fixtures, err := testpki.Default()
	if err != nil {
		return err
	}
	fixture, err := fixtures.Get(fixtureName)
	if err != nil {
		return err
	}
	certificate, key, err := identityMaterial(fixture, withChain)
	if err != nil {
		return err
	}
	// An update names neither the certificate nor its usage.
	payload, err := json.Marshal(map[string]string{"certificate": certificate, "privateKey": key})
	if err != nil {
		return fmt.Errorf("encoding the identity update: %w", err)
	}
	url, err := g.serviceURL(ctx, "gateway-controller", "/certificates/"+id)
	if err != nil {
		return err
	}
	_, err = g.funnel.Put(ctx, url, g.headerWith(ctx, "Content-Type", "application/json"), payload)
	return err
}

// ── Reading the management API's findings ────────────────────────────────────────

type validationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func publishedValidationErrors(ctx context.Context) ([]validationError, error) {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Errors []validationError `json:"errors"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("the response is not a validation error list: %w (%s)", err, resp.Describe())
	}
	return parsed.Errors, nil
}

func validationErrorWithMessage(ctx context.Context, field, message string) error {
	return requireValidationError(ctx, field, message, func(got, want string) bool { return got == want }, "with message")
}

func validationErrorContaining(ctx context.Context, field, fragment string) error {
	return requireValidationError(ctx, field, fragment, strings.Contains, "containing")
}

func requireValidationError(ctx context.Context, field, wantExpr string, matches func(got, want string) bool, how string) error {
	want, err := stepscommon.Expand(ctx, wantExpr)
	if err != nil {
		return err
	}
	field, err = stepscommon.Expand(ctx, field)
	if err != nil {
		return err
	}
	found, err := publishedValidationErrors(ctx)
	if err != nil {
		return err
	}
	for _, e := range found {
		if e.Field == field && matches(e.Message, want) {
			return nil
		}
	}
	return fmt.Errorf("no validation error for field %q %s %q among %v", field, how, want, found)
}

type warning struct {
	Code  string `json:"code"`
	Field string `json:"field"`
}

// publishedWarnings reads the warnings of a deployment response, which carries them under
// "status" for a resource document and at the top level for a certificate.
func publishedWarnings(ctx context.Context) ([]warning, error) {
	resp, err := httpx.Published(ctx)
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Warnings []warning `json:"warnings"`
		Status   struct {
			Warnings []warning `json:"warnings"`
		} `json:"status"`
	}
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return nil, fmt.Errorf("the response is not JSON: %w (%s)", err, resp.Describe())
	}
	return append(parsed.Status.Warnings, parsed.Warnings...), nil
}

func warningForField(ctx context.Context, code, field string) error {
	found, err := publishedWarnings(ctx)
	if err != nil {
		return err
	}
	for _, w := range found {
		if w.Code == code && w.Field == field {
			return nil
		}
	}
	return fmt.Errorf("no warning with code %q for field %q among %v", code, field, found)
}

// ── Waiting for a route to a TLS backend ─────────────────────────────────────────

// tlsConnectFailure reports whether Envoy itself answered 503 because it could not establish
// the upstream connection.
func tlsConnectFailure(resp *httpx.Response) bool {
	return resp.StatusCode == http.StatusServiceUnavailable && !fromUpstream(resp) &&
		strings.Contains(resp.Text(), tlsConnectFailureMarker)
}

// judgeBackendRefusal accepts the backend's own 400. The in-between states are the no-route
// 404 and Envoy's 503 while the upstream cluster warms; a failed upstream connection, or any
// other answer, ends the wait.
func judgeBackendRefusal(resp *httpx.Response) error {
	if resp.StatusCode == http.StatusBadRequest && fromUpstream(resp) {
		return nil
	}
	if tlsConnectFailure(resp) {
		return fmt.Errorf("expected the backend's 400 but the upstream TLS connection failed: %s", describe(resp))
	}
	if state, ok := routeInBetween(resp, true); ok {
		return tolerated("%s: %s", state, describe(resp))
	}
	return fmt.Errorf("expected the backend's 400 once the route is live, got %s", describe(resp))
}

// judgeUpstreamTLSFailure accepts Envoy's 503 for a failed upstream connection. The in-between
// states are the no-route 404 and Envoy's 503 while the upstream cluster warms; a reply from
// the backend, which means the connection succeeded, ends the wait.
func judgeUpstreamTLSFailure(resp *httpx.Response) error {
	if tlsConnectFailure(resp) {
		return nil
	}
	if state, ok := routeInBetween(resp, true); ok {
		return tolerated("%s: %s", state, describe(resp))
	}
	return fmt.Errorf("expected Envoy's 503 %q once the route is live, got %s", tlsConnectFailureMarker, describe(resp))
}

func (g *Gateway) sendUntilBackendRefuses(ctx context.Context, method, path string) error {
	return g.sendUntilJudged(ctx, method, path, "be refused by the backend with 400", judgeBackendRefusal)
}

func (g *Gateway) sendUntilUpstreamTLSFails(ctx context.Context, method, path string) error {
	return g.sendUntilJudged(ctx, method, path, "fail its upstream TLS connection with 503", judgeUpstreamTLSFailure)
}

// sendUntilJudged polls a data-plane path until judge accepts the answer, then waits for the
// gateway to hold what the controller holds, so the next request meets a settled gateway.
func (g *Gateway) sendUntilJudged(
	ctx context.Context, method, path, what string, judge func(*httpx.Response) error,
) error {
	resolved, err := stepscommon.Expand(ctx, path)
	if err != nil {
		return err
	}
	url, err := g.gatewayURL(resolved)
	if err != nil {
		return err
	}
	method = strings.ToUpper(method)
	headers := g.scenarioHeaders(ctx)
	if err := awaitState(ctx, fmt.Sprintf("waiting for %s %s to %s", method, url, what),
		func(ctx context.Context) error {
			resp, sendErr := g.funnel.Send(ctx, httpx.Request{Method: method, URL: url, Headers: headers, Host: g.requestHost(ctx)})
			if sendErr != nil {
				return tolerated("the gateway did not answer: %v", sendErr)
			}
			return judge(resp)
		}); err != nil {
		return err
	}
	return g.awaitGatewayApplied(ctx)
}
