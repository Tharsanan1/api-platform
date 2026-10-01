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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

// fakeCertificates is the controller's certificates endpoint: it keeps what is uploaded and
// records every request.
type fakeCertificates struct {
	mu        sync.Mutex
	status    int // answer to an upload; 0 means 201
	listed    []map[string]string
	requests  []string
	bodies    [][]byte
	deleteAns int // answer to a delete; 0 means 204
}

func (f *fakeCertificates) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.bodies = append(f.bodies, body)
	switch {
	case r.Method == http.MethodPost:
		status := f.status
		if status == 0 {
			status = http.StatusCreated
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"id":"cert-1","status":"success"}`))
	case r.Method == http.MethodGet:
		out := []map[string]string{}
		for _, c := range f.listed {
			if usage := r.URL.Query().Get("usage"); usage == "" || usage == c["usage"] {
				out = append(out, c)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": out})
	case r.Method == http.MethodDelete:
		status := f.deleteAns
		if status == 0 {
			status = http.StatusNoContent
		}
		w.WriteHeader(status)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func certificatesUnderTest(t *testing.T) (*fakeCertificates, *Gateway, context.Context) {
	t.Helper()
	fake := &fakeCertificates{listed: []map[string]string{
		{"id": "id-identity", "name": "identity-1", "usage": "identity"},
		{"id": "id-trust", "name": "trust-1", "usage": "upstream"},
	}}
	g, ctx := mtlsGatewayUnderTest(t, fake, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "identity", "identity"))
	return fake, g, ctx
}

func (f *fakeCertificates) last() (string, map[string]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]string
	_ = json.Unmarshal(f.bodies[len(f.bodies)-1], &body)
	return f.requests[len(f.requests)-1], body
}

func TestIdentityMaterial(t *testing.T) {
	leaf := mtlsFixture(t, "gw-identity-a")
	certificate, key, err := identityMaterial(leaf, false)
	require.NoError(t, err)
	require.Equal(t, string(leaf.CertPEM), certificate)
	require.Equal(t, string(leaf.KeyPEM), key)

	chained := mtlsFixture(t, "gw-identity-via-intermediate")
	certificate, _, err = identityMaterial(chained, true)
	require.NoError(t, err)
	require.Equal(t, string(chained.CertPEM)+string(chained.ChainPEM), certificate)
	require.Equal(t, 2, strings.Count(certificate, "BEGIN CERTIFICATE"))

	_, _, err = identityMaterial(leaf, true)
	require.ErrorContains(t, err, "has no issuing chain")
}

func TestPublishedFixtureMaterialIsJSONReady(t *testing.T) {
	_, _, ctx := certificatesUnderTest(t)
	require.NoError(t, publishMaterial(ctx))

	for _, form := range []string{"pem", "key", "encryptedKey"} {
		value, err := tcontext.ResolveString(ctx, fixtureMaterialKey("gw-identity-a", form))
		require.NoError(t, err, form)
		var decoded string
		require.NoError(t, json.Unmarshal([]byte(`"`+value+`"`), &decoded), form)
		require.Contains(t, decoded, "-----BEGIN", form)
		require.NotContains(t, value, "\n", form)
	}
	pem, err := tcontext.ResolveString(ctx, fixtureMaterialKey("gw-identity-a", "pem"))
	require.NoError(t, err)
	require.Equal(t, jsonStringBody(mtlsFixture(t, "gw-identity-a").CertPEM), pem)
	encrypted, err := tcontext.ResolveString(ctx, fixtureMaterialKey("gw-identity-a", "encryptedKey"))
	require.NoError(t, err)
	require.Contains(t, encrypted, "ENCRYPTED PRIVATE KEY")

	expanded, err := stepscommon.Expand(ctx, `{"privateKey":"${CTX:fixture.key-mismatch.key}"}`)
	require.NoError(t, err)
	require.Contains(t, expanded, "PRIVATE KEY")
}

func TestFixtureMaterialIsPublishedOnlyToMTLSScenarios(t *testing.T) {
	_, _, ctx := certificatesUnderTest(t)
	out, err := publishFixtureMaterial(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, ctx, out)
	_, err = publishFixtureMaterial(ctx, &godog.Scenario{})
	require.NoError(t, err)
	require.False(t, tcontext.Contains(ctx, fixtureMaterialKey("gw-identity-a", "pem")))
}

func TestUploadIdentityPostsTheIdentityAndRegistersIt(t *testing.T) {
	fake, g, ctx := certificatesUnderTest(t)
	name, err := stepscommon.StoredValue(ctx, "identity")
	require.NoError(t, err)

	require.ErrorContains(t, g.uploadIdentity(ctx, "gw-identity-a", "literal"), "is not generated")
	require.ErrorContains(t, g.uploadIdentity(ctx, "no-such-fixture", "${CTX:identity}"), "unknown fixture")

	require.NoError(t, g.uploadIdentity(ctx, "gw-identity-a", "${CTX:identity}"))
	request, body := fake.last()
	require.Equal(t, "POST /api/management/v1/certificates", request)
	require.Equal(t, map[string]string{
		"name": name, "usage": "identity",
		"certificate": string(mtlsFixture(t, "gw-identity-a").CertPEM),
		"privateKey":  string(mtlsFixture(t, "gw-identity-a").KeyPEM),
	}, body)
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.Len(t, registry.Pending(), 1)
	require.Equal(t, "cert-1", registry.Pending()[0].ID)

	require.NoError(t, g.uploadIdentityWithChain(ctx, "gw-identity-via-intermediate", "${CTX:identity}"))
	_, body = fake.last()
	require.Equal(t, 2, strings.Count(body["certificate"], "BEGIN CERTIFICATE"))
	require.ErrorContains(t, g.uploadIdentityWithChain(ctx, "gw-identity-a", "${CTX:identity}"), "has no issuing chain")
}

func TestStoreIdentityRequiresACreatedIdentity(t *testing.T) {
	fake, g, ctx := certificatesUnderTest(t)
	require.NoError(t, g.storeIdentity(ctx, "gw-identity-a", "${CTX:identity}"))

	fake.status = http.StatusConflict
	require.ErrorContains(t, g.storeIdentity(ctx, "gw-identity-a", "${CTX:identity}"), "status 201")
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.Len(t, registry.Pending(), 1, "a refused upload registers nothing")
}

func TestUploadIdentityBodyExpandsFixtureMaterialAndRegistersACreatedCertificate(t *testing.T) {
	fake, g, ctx := certificatesUnderTest(t)
	require.NoError(t, publishMaterial(ctx))
	body := &godog.DocString{Content: `{"name":"${CTX:identity}","usage":"identity","certificate":"${CTX:fixture.gw-identity-a.pem}","privateKey":"${CTX:fixture.gw-identity-a.key}"}`}

	require.NoError(t, g.uploadIdentityBody(ctx, body))
	_, sent := fake.last()
	require.Equal(t, string(mtlsFixture(t, "gw-identity-a").CertPEM), sent["certificate"])
	require.Equal(t, string(mtlsFixture(t, "gw-identity-a").KeyPEM), sent["privateKey"])
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.Len(t, registry.Pending(), 1)

	fake.status = http.StatusBadRequest
	require.NoError(t, g.uploadIdentityBody(ctx, body))
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, published.StatusCode)
	require.Len(t, registry.Pending(), 1)

	require.NoError(t, g.uploadIdentityBody(ctx, &godog.DocString{Content: "not json"}))
	require.ErrorContains(t, g.uploadIdentityBody(ctx, &godog.DocString{Content: "${CTX:missing}"}), "no value in context")
}

func TestDeleteResolvesTheNameAmongTheRightUsage(t *testing.T) {
	fake, g, ctx := certificatesUnderTest(t)
	fake.listed[0]["name"] = mustStored(t, ctx, "identity")
	require.NoError(t, cleanup.Register(ctx, cleanup.Resource{Kind: cleanup.KindCertificate, ID: "id-identity", Actor: "admin"}))

	require.NoError(t, g.deleteIdentityNamed(ctx, "${CTX:identity}"))
	request, _ := fake.last()
	require.Equal(t, "DELETE /api/management/v1/certificates/id-identity", request)
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.Empty(t, registry.Pending(), "a deleted identity leaves the cleanup list")

	require.ErrorContains(t, g.deleteIdentityNamed(ctx, "trust-1"), "no certificate named")
	require.NoError(t, g.deleteCertificateNamed(ctx, "trust-1"))
	request, _ = fake.last()
	require.Equal(t, "DELETE /api/management/v1/certificates/id-trust", request)

	fake.deleteAns = http.StatusConflict
	require.NoError(t, cleanup.Register(ctx, cleanup.Resource{Kind: cleanup.KindCertificate, ID: "id-trust", Actor: "admin"}))
	require.NoError(t, g.deleteCertificateNamed(ctx, "trust-1"))
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, published.StatusCode)
	require.Len(t, registry.Pending(), 1, "a refused deletion leaves the certificate registered")
}

func mustStored(t *testing.T, ctx context.Context, key string) string {
	t.Helper()
	value, err := stepscommon.StoredValue(ctx, key)
	require.NoError(t, err)
	return value
}

func TestIdentityUpdates(t *testing.T) {
	fake, g, ctx := certificatesUnderTest(t)
	fake.listed[0]["name"] = mustStored(t, ctx, "identity")

	require.NoError(t, g.rotateIdentity(ctx, "${CTX:identity}", "gw-identity-via-intermediate"))
	request, body := fake.last()
	require.Equal(t, "PUT /api/management/v1/certificates/id-identity", request)
	require.Equal(t, 2, strings.Count(body["certificate"], "BEGIN CERTIFICATE"))
	require.Equal(t, string(mtlsFixture(t, "gw-identity-via-intermediate").KeyPEM), body["privateKey"])
	require.Len(t, body, 2, "an update names neither the certificate nor its usage")

	require.NoError(t, g.updateCertificateWithIdentity(ctx, "trust-1", "gw-identity-a"))
	request, body = fake.last()
	require.Equal(t, "PUT /api/management/v1/certificates/id-trust", request)
	require.Equal(t, string(mtlsFixture(t, "gw-identity-a").CertPEM), body["certificate"])

	require.ErrorContains(t, g.rotateIdentity(ctx, "trust-1", "gw-identity-a"), "no certificate named")
	require.ErrorContains(t, g.rotateIdentity(ctx, "${CTX:identity}", "gw-identity-a"), "has no issuing chain")
	require.ErrorContains(t, g.updateCertificateWithIdentity(ctx, "trust-1", "no-such-fixture"), "unknown fixture")
}

func publish(t *testing.T, ctx context.Context, status int, body string) {
	t.Helper()
	funnel := httpx.NewFunnel(httpx.NewClient(httpx.Options{}), 0, time.Millisecond)
	require.NoError(t, funnel.Publish(ctx, &httpx.Response{StatusCode: status, Body: []byte(body)}))
}

func TestValidationErrorAssertions(t *testing.T) {
	_, _, ctx := certificatesUnderTest(t)
	name := mustStored(t, ctx, "identity")
	publish(t, ctx, 400, `{"status":"error","errors":[{"field":"privateKey","message":"the private key does not match the certificate"},{"field":"spec.tls.identity","message":"no gateway identity named `+name+` exists"}]}`)

	require.NoError(t, validationErrorWithMessage(ctx, "privateKey", "the private key does not match the certificate"))
	require.NoError(t, validationErrorWithMessage(ctx, "spec.tls.identity", "no gateway identity named ${CTX:identity} exists"))
	require.NoError(t, validationErrorContaining(ctx, "privateKey", "does not match"))

	require.ErrorContains(t, validationErrorWithMessage(ctx, "privateKey", "the private key"), "with message")
	require.ErrorContains(t, validationErrorWithMessage(ctx, "certificate", "the private key does not match the certificate"), "no validation error for field")
	require.ErrorContains(t, validationErrorContaining(ctx, "privateKey", "expired"), "containing")
	require.ErrorContains(t, validationErrorWithMessage(ctx, "privateKey", "${CTX:missing}"), "no value in context")

	publish(t, ctx, 400, "not json")
	require.ErrorContains(t, validationErrorWithMessage(ctx, "privateKey", "x"), "not a validation error list")
	publish(t, ctx, 400, `{"status":"error"}`)
	require.ErrorContains(t, validationErrorContaining(ctx, "privateKey", "x"), "no validation error for field")
}

func TestWarningAssertion(t *testing.T) {
	_, _, ctx := certificatesUnderTest(t)
	publish(t, ctx, 201, `{"status":{"warnings":[{"code":"TLS_VERIFY_HOSTNAME_DISABLED","field":"spec.upstreamDefinitions[0].tls.verifyHostName"}]}}`)
	require.NoError(t, warningForField(ctx, "TLS_VERIFY_HOSTNAME_DISABLED", "spec.upstreamDefinitions[0].tls.verifyHostName"))
	require.ErrorContains(t, warningForField(ctx, "TLS_VERIFY_HOSTNAME_DISABLED", "spec.other"), "no warning with code")
	require.ErrorContains(t, warningForField(ctx, "OTHER", "spec.upstreamDefinitions[0].tls.verifyHostName"), "no warning with code")

	publish(t, ctx, 201, `{"warnings":[{"code":"IDENTITY_NO_CLIENTAUTH_EKU","field":"certificate"}]}`)
	require.NoError(t, warningForField(ctx, "IDENTITY_NO_CLIENTAUTH_EKU", "certificate"))

	publish(t, ctx, 201, `{"id":"x"}`)
	require.ErrorContains(t, warningForField(ctx, "IDENTITY_NO_CLIENTAUTH_EKU", "certificate"), "among []")
	publish(t, ctx, 201, "not json")
	require.ErrorContains(t, warningForField(ctx, "X", "y"), "not JSON")
}

func upstreamReply(status int, body string) *httpx.Response {
	headers := http.Header{}
	headers.Set(headerUpstreamServiceTime, "3")
	return &httpx.Response{StatusCode: status, Headers: headers, Body: []byte(body)}
}

func envoyReply(status int, body string) *httpx.Response {
	return &httpx.Response{StatusCode: status, Headers: http.Header{}, Body: []byte(body)}
}

const connectFailureBody = "upstream connect error or disconnect/reset before headers. reset reason: remote connection failure, transport failure reason: TLS_error"

func TestJudgeBackendRefusal(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp *httpx.Response
		want string
	}{
		{"the backend's 400", upstreamReply(400, `{"backend":"a"}`), ""},
		{"no route yet", envoyReply(404, noRouteBody), "tolerated"},
		{"cluster warming", envoyReply(503, "no healthy upstream"), "tolerated"},
		{"an upstream connect failure is not a warming cluster", envoyReply(503, connectFailureBody), "fail"},
		{"the backend accepted the request", upstreamReply(200, "{}"), "fail"},
		{"a 400 Envoy produced itself", envoyReply(400, ""), "fail"},
		{"a backend 404", upstreamReply(404, "{}"), "fail"},
		{"a backend 503", upstreamReply(503, "down"), "fail"},
	} {
		require.Equal(t, tc.want, outcome(judgeBackendRefusal(tc.resp)), tc.name)
	}
	require.ErrorContains(t, judgeBackendRefusal(envoyReply(503, connectFailureBody)), "upstream TLS connection failed")
}

func TestJudgeUpstreamTLSFailure(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp *httpx.Response
		want string
	}{
		{"the connect failure", envoyReply(503, connectFailureBody), ""},
		{"no route yet", envoyReply(404, noRouteBody), "tolerated"},
		{"cluster warming", envoyReply(503, ""), "tolerated"},
		{"the backend answered, so the connection succeeded", upstreamReply(200, "{}"), "fail"},
		{"the backend refused", upstreamReply(400, "{}"), "fail"},
		{"a backend 503 carrying the marker", upstreamReply(503, connectFailureBody), "fail"},
		{"another Envoy status", envoyReply(502, ""), "fail"},
	} {
		require.Equal(t, tc.want, outcome(judgeUpstreamTLSFailure(tc.resp)), tc.name)
	}
}

func TestSendUntilJudgedPollsThroughInBetweenStatesAndSettles(t *testing.T) {
	var mu sync.Mutex
	answers := []func(http.ResponseWriter){
		func(w http.ResponseWriter) { w.WriteHeader(404); _, _ = w.Write([]byte(noRouteBody)) },
		func(w http.ResponseWriter) { w.WriteHeader(503) },
		func(w http.ResponseWriter) { w.Header().Set(headerUpstreamServiceTime, "1"); w.WriteHeader(400) },
	}
	calls := 0
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		answers[min(calls, len(answers)-1)](w)
		calls++
	}))
	t.Cleanup(dataPlane.Close)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	g.base = stubBase{dataPlane: dataPlane.URL}

	require.NoError(t, g.sendUntilBackendRefuses(ctx, "get", "/out/anything"))
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, 400, published.StatusCode)
	require.Equal(t, 3, calls)
}

func TestSendUntilJudgedFailsAtOnceOnAContradiction(t *testing.T) {
	calls := 0
	dataPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set(headerUpstreamServiceTime, "1")
		_, _ = w.Write([]byte("accepted"))
	}))
	t.Cleanup(dataPlane.Close)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	g.base = stubBase{dataPlane: dataPlane.URL}

	err := g.sendUntilUpstreamTLSFails(ctx, "GET", "/out/anything")
	require.ErrorContains(t, err, "expected Envoy's 503")
	require.ErrorContains(t, err, "200")
	require.Equal(t, 1, calls)
	require.ErrorContains(t, g.sendUntilUpstreamTLSFails(ctx, "GET", "${CTX:missing}"), "no value in context")
}

func TestPoolFixtureWithDefaultUsageOmitsTheUsage(t *testing.T) {
	fake, g, ctx := certificatesUnderTest(t)
	require.NoError(t, g.poolFixtureWithDefaultUsage(ctx, "backend-ca", "${CTX:identity}"))
	_, body := fake.last()
	_, hasUsage := body["usage"]
	require.False(t, hasUsage)
	require.Equal(t, string(mtlsFixture(t, "backend-ca").CertPEM), body["certificate"])
}
