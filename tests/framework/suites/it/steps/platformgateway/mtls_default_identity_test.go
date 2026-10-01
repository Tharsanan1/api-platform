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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

func noListener() (string, error) { return "", errors.New("no listener") }

func TestParseBackendView(t *testing.T) {
	gatewayA := mtlsFixture(t, "gw-identity-a").Certificate.Subject.String()
	require.Equal(t, "CN=gateway-a", gatewayA)
	listener := func() (string, error) { return "CN=localhost", nil }

	for phrase, want := range map[string]backendView{
		`no client certificate`: {kind: viewNone},
		`a refusal`:             {kind: viewRefused},
		`the client certificate of "gw-identity-a"`:     {kind: viewSubject, subject: gatewayA},
		`the gateway listener certificate`:              {kind: viewSubject, subject: "CN=localhost"},
		`  the client certificate of "gw-identity-a"  `: {kind: viewSubject, subject: gatewayA},
	} {
		got, err := parseBackendView(phrase, listener)
		require.NoError(t, err, phrase)
		require.Equal(t, want, got, phrase)
	}

	_, err := parseBackendView("a certificate", listener)
	require.ErrorContains(t, err, `unknown backend view "a certificate"`)
	_, err = parseBackendView(`the client certificate of "no-such-fixture"`, listener)
	require.ErrorContains(t, err, "unknown fixture")
	_, err = parseBackendView("the gateway listener certificate", noListener)
	require.ErrorContains(t, err, "no listener")
}

func TestBackendViewString(t *testing.T) {
	require.Equal(t, "no client certificate", backendView{kind: viewNone}.String())
	require.Equal(t, "a refusal", backendView{kind: viewRefused}.String())
	require.Equal(t, `the client certificate "CN=a"`, backendView{kind: viewSubject, subject: "CN=a"}.String())
}

func echoResponse(status int, upstream bool, subject string) *httpx.Response {
	headers := http.Header{}
	if upstream {
		headers.Set(headerUpstreamServiceTime, "2")
	}
	if subject != "" {
		headers.Set(echoHeaderClientSubject, subject)
	}
	return &httpx.Response{StatusCode: status, Headers: headers, Method: http.MethodGet, URL: "http://gw/anything"}
}

func TestJudgeBackendResponse(t *testing.T) {
	listener := backendView{kind: viewSubject, subject: "CN=localhost"}
	gatewayA := backendView{kind: viewSubject, subject: "CN=gateway-a"}
	none := backendView{kind: viewNone}
	refused := backendView{kind: viewRefused}

	noRoute := &httpx.Response{StatusCode: http.StatusNotFound, Body: []byte(noRouteBody), Headers: http.Header{}}
	warming := &httpx.Response{StatusCode: http.StatusServiceUnavailable, Body: []byte("no healthy upstream"), Headers: http.Header{}}

	for _, tc := range []struct {
		name      string
		resp      *httpx.Response
		want      backendView
		inBetween []backendView
		outcome   string
		message   string
	}{
		{name: "the expected subject", resp: echoResponse(200, true, "CN=gateway-a"), want: gatewayA},
		{name: "an empty subject is no certificate", resp: echoResponse(200, true, ""), want: none},
		{name: "a refusal", resp: echoResponse(400, true, ""), want: refused},
		{name: "no route yet", resp: noRoute, want: gatewayA, outcome: "tolerated", message: "Envoy has no route yet"},
		{name: "a warming upstream", resp: warming, want: gatewayA, outcome: "tolerated", message: "still warming"},
		{name: "the previous subject while it propagates", resp: echoResponse(200, true, "CN=localhost"),
			want: gatewayA, inBetween: []backendView{listener}, outcome: "tolerated", message: "expected the client certificate"},
		{name: "a subject nobody listed", resp: echoResponse(200, true, "CN=intruder"),
			want: gatewayA, inBetween: []backendView{listener}, outcome: "fail", message: `sees the client certificate "CN=intruder"`},
		{name: "the previous subject without a tolerance", resp: echoResponse(200, true, "CN=localhost"),
			want: gatewayA, outcome: "fail", message: "expected the client certificate"},
		{name: "no certificate where one is expected", resp: echoResponse(200, true, ""),
			want: gatewayA, inBetween: []backendView{listener}, outcome: "fail", message: "sees no client certificate"},
		{name: "a refusal where a subject is expected", resp: echoResponse(400, true, ""),
			want: gatewayA, outcome: "fail", message: "sees a refusal"},
		{name: "a subject where a refusal is expected", resp: echoResponse(200, true, "CN=gateway-a"),
			want: refused, outcome: "fail", message: `sees the client certificate "CN=gateway-a"`},
		{name: "a backend error", resp: echoResponse(500, true, ""), want: gatewayA, outcome: "fail", message: "answered 500"},
		{name: "a reply of the gateway that is no in-between state", resp: echoResponse(502, false, ""),
			want: gatewayA, outcome: "fail", message: "expected the request to reach the backend"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := judgeBackendResponse(tc.resp, tc.want, tc.inBetween)
			require.Equal(t, tc.outcome, outcome(err))
			if tc.message != "" {
				require.ErrorContains(t, err, tc.message)
			}
		})
	}
}

// subjectDataPlane answers each request with the next scripted reply, repeating the last one.
type subjectDataPlane struct {
	mu      sync.Mutex
	replies []subjectReply
	served  int
}

type subjectReply struct {
	status   int
	upstream bool
	subject  string
	body     string
}

func (d *subjectDataPlane) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	d.mu.Lock()
	reply := d.replies[min(d.served, len(d.replies)-1)]
	d.served++
	d.mu.Unlock()
	if reply.upstream {
		w.Header().Set(headerUpstreamServiceTime, "3")
	}
	if reply.subject != "" {
		w.Header().Set(echoHeaderClientSubject, reply.subject)
	}
	w.WriteHeader(reply.status)
	_, _ = w.Write([]byte(reply.body))
}

func TestSendUntilBackendSees(t *testing.T) {
	const gatewayA = "CN=gateway-a"
	noRoute := subjectReply{status: 404, body: noRouteBody}
	warming := subjectReply{status: 503, body: "no healthy upstream"}
	for _, tc := range []struct {
		name    string
		phrase  string
		replies []subjectReply
		status  int
		err     string
		served  int
	}{
		{name: "polls through the route coming up and the old view", phrase: `the client certificate of "gw-identity-a" while tolerating no client certificate`,
			replies: []subjectReply{noRoute, warming, {status: 200, upstream: true}, {status: 200, upstream: true, subject: gatewayA}},
			status:  200, served: 4},
		{name: "two tolerated views", phrase: `the client certificate of "gw-identity-a" while tolerating no client certificate or a refusal`,
			replies: []subjectReply{{status: 400, upstream: true}, {status: 200, upstream: true}, {status: 200, upstream: true, subject: gatewayA}},
			status:  200, served: 3},
		{name: "a subject that was not listed ends the wait", phrase: `the client certificate of "gw-identity-a" while tolerating a refusal`,
			replies: []subjectReply{{status: 200, upstream: true, subject: "CN=intruder"}}, err: `sees the client certificate "CN=intruder"`, served: 1},
		{name: "the old view is fatal without a tolerance", phrase: `the client certificate of "gw-identity-a"`,
			replies: []subjectReply{{status: 200, upstream: true}}, err: "sees no client certificate", served: 1},
		{name: "a refusal is awaited", phrase: `a refusal`,
			replies: []subjectReply{noRoute, {status: 400, upstream: true}}, status: 400, served: 2},
		{name: "an unknown view", phrase: `somebody`, err: "unknown backend view"},
		{name: "an unknown tolerated view", phrase: `a refusal while tolerating somebody`, err: "unknown backend view"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataPlane := &subjectDataPlane{replies: tc.replies}
			if len(tc.replies) == 0 {
				dataPlane.replies = []subjectReply{{status: 500}}
			}
			server := httptest.NewServer(dataPlane)
			t.Cleanup(server.Close)
			g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
			g.base = stubBase{dataPlane: server.URL}

			err := g.sendUntilBackendSees(ctx, "get", "/anything", tc.phrase)
			if tc.err == "" {
				require.NoError(t, err)
				published, pubErr := httpx.Published(ctx)
				require.NoError(t, pubErr)
				require.Equal(t, tc.status, published.StatusCode)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
			require.Equal(t, tc.served, dataPlane.served)
		})
	}
}

func TestListenerSubjectIsReadFromTheHTTPSListener(t *testing.T) {
	https := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(https.Close)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), https)

	subject, err := g.listenerSubject(ctx)
	require.NoError(t, err)
	require.Equal(t, https.Certificate().Subject.String(), subject)

	dataPlane := &subjectDataPlane{replies: []subjectReply{{status: 200, upstream: true, subject: subject}}}
	server := httptest.NewServer(dataPlane)
	t.Cleanup(server.Close)
	g.base = stubBase{dataPlane: server.URL}
	require.NoError(t, g.sendUntilBackendSees(ctx, "GET", "/anything", "the gateway listener certificate"))

	stopped := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closed, closedCtx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), stopped)
	stopped.Close()
	_, err = closed.listenerSubject(closedCtx)
	require.ErrorContains(t, err, "reading the HTTPS listener certificate")
}

func TestStoreEchoBackendURL(t *testing.T) {
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	require.NoError(t, g.storeEchoBackendURL(ctx, "optional", "optionalBackend"))
	require.NoError(t, g.storeEchoBackendURL(ctx, "required", "requiredBackend"))
	optional, err := stepscommon.StoredValue(ctx, "optionalBackend")
	require.NoError(t, err)
	require.Equal(t, "https://tls-backend:8446", optional)
	required, err := stepscommon.StoredValue(ctx, "requiredBackend")
	require.NoError(t, err)
	require.Equal(t, "https://tls-backend:8443", required)
	require.ErrorContains(t, g.storeEchoBackendURL(ctx, "other", "x"), `unknown TLS backend kind "other"`)
	require.ErrorContains(t, g.storeEchoBackendURL(context.Background(), "optional", "x"), "without runner context")
}

// fakeIdentityController serves the certificate endpoints the identity steps use.
type fakeIdentityController struct {
	mu       sync.Mutex
	identity []identityEntry
	status   int
	posted   []map[string]string
	put      map[string]map[string]string
	deleted  []string
	message  string
}

func (f *fakeIdentityController) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(status int, v any) {
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.URL.Path == "/api/management/v1/certificates" && r.Method == http.MethodPost:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.posted = append(f.posted, body)
		if f.status != http.StatusCreated {
			write(f.status, map[string]string{"message": f.message})
			return
		}
		write(http.StatusCreated, map[string]string{"id": "cert-" + body["name"]})
	case r.URL.Path == "/api/management/v1/certificates" && r.URL.Query().Get("usage") == "identity":
		write(http.StatusOK, map[string]any{"certificates": f.identity})
	case strings.HasPrefix(r.URL.Path, "/api/management/v1/certificates/") && r.Method == http.MethodPut:
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if f.put == nil {
			f.put = map[string]map[string]string{}
		}
		f.put[strings.TrimPrefix(r.URL.Path, "/api/management/v1/certificates/")] = body
		write(http.StatusOK, map[string]string{"status": "success"})
	case strings.HasPrefix(r.URL.Path, "/api/management/v1/certificates/") && r.Method == http.MethodDelete:
		f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/api/management/v1/certificates/"))
		write(http.StatusOK, map[string]string{"status": "success"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestUploadingAGatewayIdentityCarriesKeyAndRole(t *testing.T) {
	fake := &fakeIdentityController{status: http.StatusCreated}
	g, ctx := mtlsGatewayUnderTest(t, fake, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "default-identity", "defaultIdentity"))
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "other-identity", "otherIdentity"))
	gatewayA := mtlsFixture(t, "gw-identity-a")

	require.NoError(t, g.storeGatewayIdentity(ctx, "${CTX:defaultIdentity}", "gw-identity-a", " with role default"))
	require.NoError(t, g.uploadGatewayIdentity(ctx, "${CTX:otherIdentity}", "gw-identity-a", ""))
	require.Len(t, fake.posted, 2)

	name, err := stepscommon.StoredValue(ctx, "defaultIdentity")
	require.NoError(t, err)
	require.Equal(t, map[string]string{
		"name": name, "usage": "identity", "role": "default",
		"certificate": string(gatewayA.CertPEM), "privateKey": string(gatewayA.KeyPEM),
	}, fake.posted[0])
	require.NotContains(t, fake.posted[1], "role")
	require.Equal(t, string(gatewayA.KeyPEM), fake.posted[1]["privateKey"])

	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.Len(t, registry.Pending(), 2)

	require.ErrorContains(t, g.uploadGatewayIdentity(ctx, "literal-name", "gw-identity-a", ""), "is not generated")
	require.ErrorContains(t, g.uploadGatewayIdentity(ctx, "${CTX:otherIdentity}", "no-such-fixture", ""), "unknown fixture")
}

func TestUploadingAnotherUsageCarriesTheRoleWithoutAKey(t *testing.T) {
	fake := &fakeIdentityController{status: http.StatusBadRequest, message: "invalid"}
	g, ctx := mtlsGatewayUnderTest(t, fake, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "pool", "pool"))

	require.NoError(t, g.uploadCertificateWithRole(ctx, "ca-b", "${CTX:pool}", "upstream", "default"))
	require.Len(t, fake.posted, 1)
	require.Equal(t, "upstream", fake.posted[0]["usage"])
	require.Equal(t, "default", fake.posted[0]["role"])
	require.NotContains(t, fake.posted[0], "privateKey")

	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, published.StatusCode)
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.Empty(t, registry.Pending(), "a refused upload leaves nothing to clean up")
}

func TestARefusedGatewayIdentityIsReportedWithItsAnswer(t *testing.T) {
	fake := &fakeIdentityController{status: http.StatusConflict, message: "already has role: default"}
	g, ctx := mtlsGatewayUnderTest(t, fake, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "default-identity", "defaultIdentity"))

	err := g.storeGatewayIdentity(ctx, "${CTX:defaultIdentity}", "gw-identity-a", " with role default")
	require.ErrorContains(t, err, "status 201")
	require.ErrorContains(t, err, "already has role: default")
	require.NoError(t, g.uploadGatewayIdentity(ctx, "${CTX:defaultIdentity}", "gw-identity-a", " with role default"))
	published, pubErr := httpx.Published(ctx)
	require.NoError(t, pubErr)
	require.Equal(t, http.StatusConflict, published.StatusCode)
}

func TestRotatingAndRemovingAGatewayIdentityAddressItByName(t *testing.T) {
	fake := &fakeIdentityController{identity: []identityEntry{
		{ID: "id-1", Name: "first", Role: "default"}, {ID: "id-2", Name: "second"},
	}}
	g, ctx := mtlsGatewayUnderTest(t, fake, nil)
	gatewayB := mtlsFixture(t, "gw-identity-b")

	require.NoError(t, g.rotateGatewayIdentity(ctx, "first", "gw-identity-b"))
	require.Equal(t, map[string]string{
		"certificate": string(gatewayB.CertPEM), "privateKey": string(gatewayB.KeyPEM),
	}, fake.put["id-1"])
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, published.StatusCode)

	require.NoError(t, g.deleteGatewayIdentity(ctx, "second"))
	require.Equal(t, []string{"id-2"}, fake.deleted)

	require.ErrorContains(t, g.rotateGatewayIdentity(ctx, "missing", "gw-identity-b"), `no identity named "missing"`)
	require.ErrorContains(t, g.deleteGatewayIdentity(ctx, "missing"), `no identity named "missing"`)
	require.ErrorContains(t, g.rotateGatewayIdentity(ctx, "first", "no-such-fixture"), "unknown fixture")
}

func TestListingShowsDefaultOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity []identityEntry
		err      string
	}{
		{name: "the default alone", identity: []identityEntry{{Name: "first", Role: "default"}, {Name: "second"}}},
		{name: "the named identity has no role", identity: []identityEntry{{Name: "first"}, {Name: "second"}}, err: `"first" has role ""`},
		{name: "another identity is the default too", identity: []identityEntry{{Name: "first", Role: "default"}, {Name: "second", Role: "default"}},
			err: `"second" has role "default", only "first" should have one`},
		{name: "the identity is missing", identity: []identityEntry{{Name: "second"}}, err: `no identity named "first"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, ctx := mtlsGatewayUnderTest(t, &fakeIdentityController{identity: tc.identity}, nil)
			err := g.listingShowsDefaultOnly(ctx, "first")
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestRoleFromPhrase(t *testing.T) {
	require.Equal(t, "", roleFromPhrase(""))
	require.Equal(t, "default", roleFromPhrase(" with role default"))
}
