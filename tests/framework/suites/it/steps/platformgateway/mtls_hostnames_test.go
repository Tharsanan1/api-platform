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
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

const askedServerName = "asked.example"

// listenerAskingOn serves HTTPS and asks for a client certificate only on connections that send
// askedServerName, as the gateway's listener does for the hostname of an mtls-auth API. It
// records the server name of the last handshake.
func listenerAskingOn(t *testing.T) (*httptest.Server, *atomic.Value) {
	t.Helper()
	var sni atomic.Value
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello " + r.Host))
	}))
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			sni.Store(hello.ServerName)
			if strings.EqualFold(hello.ServerName, askedServerName) {
				return &tls.Config{Certificates: server.TLS.Certificates, ClientAuth: tls.RequestClientCert}, nil
			}
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, &sni
}

func TestServerNameChoiceAppliesToTheClientHandshake(t *testing.T) {
	opts := &httpx.ClientTLS{ServerName: gatewaySNI}
	serverNameChoice{}.apply(opts)
	require.Equal(t, gatewaySNI, opts.ServerName)
	require.False(t, opts.OmitServerName)

	serverNameChoice{name: "api.example"}.apply(opts)
	require.Equal(t, "api.example", opts.ServerName)

	serverNameChoice{none: true}.apply(opts)
	require.Empty(t, opts.ServerName)
	require.True(t, opts.OmitServerName)
}

func TestServerNameChoiceOfExpandsAndRejectsNothing(t *testing.T) {
	_, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "orders", "label"))
	label, err := stepscommon.StoredValue(ctx, "label")
	require.NoError(t, err)

	choice, err := serverNameChoiceOf(ctx, "${CTX:label}.example", "")
	require.NoError(t, err)
	require.Equal(t, label+".example", choice.name)

	choice, err = serverNameChoiceOf(ctx, "${CTX:label}.example", " in upper case")
	require.NoError(t, err)
	require.Equal(t, strings.ToUpper(label)+".EXAMPLE", choice.name)

	_, err = serverNameChoiceOf(ctx, " ", "")
	require.ErrorContains(t, err, "expands to nothing")
	_, err = serverNameChoiceOf(ctx, "${CTX:missing}.example", "")
	require.ErrorContains(t, err, `no value in context for key "missing"`)
}

func TestHTTPSRequestsSendTheChosenServerNameUntilTheScenarioEnds(t *testing.T) {
	server, sni := listenerAskingOn(t)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), server)
	send := func() *httpx.TLSState {
		require.NoError(t, g.sendHTTPS(ctx, "GET", "/anything", "with no client certificate"))
		published, err := httpx.Published(ctx)
		require.NoError(t, err)
		return published.TLS
	}

	require.Equal(t, gatewaySNI, send().ServerName)
	require.Equal(t, gatewaySNI, sni.Load())

	require.NoError(t, sendServerName(ctx, askedServerName, " in upper case"))
	state := send()
	require.Equal(t, strings.ToUpper(askedServerName), state.ServerName)
	require.True(t, state.ClientCertificateRequested)

	require.NoError(t, sendNoServerName(ctx))
	state = send()
	require.Empty(t, state.ServerName)
	require.Empty(t, sni.Load())
	require.False(t, state.ClientCertificateRequested)

	_, err := resetHostnameState(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, gatewaySNI, send().ServerName)
}

func TestObserveAskedReportsTheListenersCertificateRequest(t *testing.T) {
	server, _ := listenerAskingOn(t)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), server)

	asked, err := g.observeAsked(ctx, serverNameChoice{name: askedServerName})
	require.NoError(t, err)
	require.True(t, asked)
	asked, err = g.observeAsked(ctx, serverNameChoice{name: strings.ToUpper(askedServerName)})
	require.NoError(t, err)
	require.True(t, asked)
	asked, err = g.observeAsked(ctx, serverNameChoice{name: "public.example"})
	require.NoError(t, err)
	require.False(t, asked)
	asked, err = g.observeAsked(ctx, serverNameChoice{none: true})
	require.NoError(t, err)
	require.False(t, asked)

	server.Close()
	_, err = g.observeAsked(ctx, serverNameChoice{name: askedServerName})
	require.Equal(t, "tolerated", outcome(err), "%v", err)
	require.ErrorContains(t, err, "did not complete a handshake")
}

func TestHandshakeAskedWaitsForTheStateTheStepNames(t *testing.T) {
	server, _ := listenerAskingOn(t)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), server)

	require.NoError(t, g.handshakeAsked(ctx, `with server name "asked.example"`, askedServerName, "", ""))
	require.NoError(t, g.handshakeAsked(ctx, `with server name "asked.example" in upper case`, askedServerName, " in upper case", ""))
	require.NoError(t, g.awaitNotAsked(ctx, serverNameChoice{name: "public.example"}, 300*time.Millisecond))
	require.NoError(t, g.awaitNotAsked(ctx, serverNameChoice{none: true}, 300*time.Millisecond))
	require.ErrorContains(t, g.handshakeAsked(ctx, `with server name "${CTX:missing}"`, "${CTX:missing}", "", "not "),
		`no value in context for key "missing"`)
}

func TestNotAskedHoldFailsTheMomentTheListenerAsks(t *testing.T) {
	var asking atomic.Bool
	flipped := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	flipped.TLS = &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			if asking.Load() {
				return &tls.Config{Certificates: flipped.TLS.Certificates, ClientAuth: tls.RequestClientCert}, nil
			}
			return nil, nil
		},
	}
	flipped.StartTLS()
	t.Cleanup(flipped.Close)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), flipped)
	time.AfterFunc(700*time.Millisecond, func() { asking.Store(true) })
	err := g.awaitNotAsked(ctx, serverNameChoice{name: "x.example"}, 5*time.Second)
	require.ErrorContains(t, err, "the invariant was violated")
}

func TestConnectionAskedAndSessionResumedReadThePublishedHandshake(t *testing.T) {
	_, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	funnel := httpx.NewFunnel(httpx.NewClient(httpx.Options{}), 0, time.Millisecond)

	require.NoError(t, funnel.Publish(ctx, &httpx.Response{StatusCode: 200}))
	require.ErrorContains(t, connectionAsked(ctx, ""), "did not arrive over an HTTPS request step")
	require.ErrorContains(t, sessionResumed(ctx), "did not arrive over an HTTPS request step")

	require.NoError(t, funnel.Publish(ctx, &httpx.Response{StatusCode: 200, TLS: &httpx.TLSState{ServerName: "a.example", ClientCertificateRequested: true}}))
	require.NoError(t, connectionAsked(ctx, ""))
	require.ErrorContains(t, connectionAsked(ctx, "not "), `asked the connection for a client certificate (server name "a.example")`)
	require.ErrorContains(t, sessionResumed(ctx), "full TLS handshake")

	require.NoError(t, funnel.Publish(ctx, &httpx.Response{StatusCode: 200, TLS: &httpx.TLSState{DidResume: true}}))
	require.NoError(t, connectionAsked(ctx, "not "))
	require.ErrorContains(t, connectionAsked(ctx, ""), "did not ask the connection")
	require.NoError(t, sessionResumed(ctx))
}

func TestPoolRelayFixtureUploadsTheRelayRoleAndRegistersItForCleanup(t *testing.T) {
	fake := consistentMTLSGateway(t)
	g, ctx := mtlsGatewayUnderTest(t, fake, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "relay", "relayName"))

	require.ErrorContains(t, g.poolRelayFixture(ctx, "edge-lb-ca", "literal-name"), "is not generated")
	require.ErrorContains(t, g.poolRelayFixture(ctx, "no-such-fixture", "${CTX:relayName}"), "unknown fixture")
	require.NoError(t, g.poolRelayFixture(ctx, "edge-lb-ca", "${CTX:relayName}"))

	name, err := stepscommon.StoredValue(ctx, "relayName")
	require.NoError(t, err)
	require.Len(t, fake.uploads, 1)
	require.Equal(t, name, fake.uploads[0]["name"])
	require.Equal(t, "downstream", fake.uploads[0]["usage"])
	require.Equal(t, "relay", fake.uploads[0]["role"])
	require.Equal(t, string(mtlsFixture(t, "edge-lb-ca").CertPEM), fake.uploads[0]["certificate"])
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Contains(t, published.Text(), "cert-1")
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	pending := registry.Pending()
	require.Len(t, pending, 1)
	require.Equal(t, cleanup.KindCertificate.Name, pending[0].Kind.Name)
	require.Equal(t, "cert-1", pending[0].ID)

	fake.uploadStatus = http.StatusConflict
	require.ErrorContains(t, g.poolRelayFixture(ctx, "edge-lb-ca", "${CTX:relayName}"), "status 201")
	require.Len(t, registry.Pending(), 1)
}

func TestKeptAliveConnectionCarriesSeveralRequestsAndNamesAClosure(t *testing.T) {
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("host=" + r.Host + " path=" + r.URL.Path))
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), server)

	require.ErrorContains(t, g.sendOnKeptAliveConnection(ctx, "/second"), "open one first")

	require.NoError(t, g.openKeptAliveConnection(ctx, "public.example", "anything"))
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, published.StatusCode)
	require.Equal(t, "host=public.example path=/anything", published.Text())

	require.NoError(t, g.sendOnKeptAliveConnection(ctx, "/second"))
	published, err = httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, "host=public.example path=/second", published.Text())
	require.EqualValues(t, 1, connections.Load())

	server.CloseClientConnections()
	err = g.sendOnKeptAliveConnection(ctx, "/third")
	require.Error(t, err)
	require.Contains(t, err.Error(), "kept-alive HTTPS connection")
	_, published2 := httpx.Published(ctx)
	require.Error(t, published2, "a failed request leaves no stale response behind")

	_, err = closeKeptAliveConnection(ctx, nil, nil)
	require.NoError(t, err)
	require.False(t, tcontext.Contains(ctx, keyKeptAliveConnection))
	require.ErrorContains(t, g.sendOnKeptAliveConnection(ctx, "/fourth"), "open one first")
}
