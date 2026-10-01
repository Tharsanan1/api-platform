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
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/components"
	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
)

// twoControllerGatewayUnderTest serves management on one fake and the xDS controller's admin
// API on another, so a test sees which controller each read reaches.
func twoControllerGatewayUnderTest(t *testing.T, management, xds *fakeMTLSGateway) (*Gateway, context.Context) {
	t.Helper()
	managementServer := httptest.NewServer(management)
	t.Cleanup(managementServer.Close)
	xdsServer := httptest.NewServer(xds)
	t.Cleanup(xdsServer.Close)
	port := func(raw string) int {
		parsed, err := url.Parse(raw)
		require.NoError(t, err)
		p, err := strconv.Atoi(parsed.Port())
		require.NoError(t, err)
		return p
	}
	mapped := map[int]int{
		9090: port(managementServer.URL), 9092: port(managementServer.URL),
		9002: port(managementServer.URL), 9901: port(managementServer.URL),
		9094: port(xdsServer.URL),
	}
	definition := &components.Definition{
		Name: "platform-gateway", Alias: "platform-gateway",
		Endpoints: []components.Endpoint{
			{Name: "rest", Port: 9090, Scheme: "http"},
			{Name: "admin", Port: 9092, Scheme: "http"},
			{Name: "policy-admin", Port: 9002, Scheme: "http"},
			{Name: "envoy-admin", Port: 9901, Scheme: "http"},
			{Name: xdsControllerAdminEndpoint, Port: 9094, Scheme: "http"},
		},
	}
	instance, err := components.NewInstance(definition, 0, 1, "127.0.0.1", mapped)
	require.NoError(t, err)
	instances := components.NewSet()
	require.NoError(t, instances.Add(instance))

	shared := tcontext.NewShared("block")
	shared.Set(frameworkruntime.KeyAdminUser, "admin")
	shared.Set(frameworkruntime.KeyAdminPass, "secret")
	ctx := tcontext.WithLocal(tcontext.WithShared(context.Background(), shared), tcontext.NewLocal("runner"))
	require.NoError(t, cleanup.Install(ctx, cleanup.NewRegistry(nil)))
	client := httpx.NewClient(httpx.Options{Timeout: 5 * time.Second})
	return &Gateway{topo: &frameworkruntime.Topology{Instances: instances}, funnel: httpx.NewFunnel(client, 0, time.Millisecond), base: stubBase{}}, ctx
}

func TestRuntimeControllerAdminIsTheManagementControllerOnOneController(t *testing.T) {
	g, _ := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	service, separate, err := g.runtimeControllerAdmin()
	require.NoError(t, err)
	require.False(t, separate)
	require.Equal(t, managementControllerAdmin, service)
}

func TestRuntimeControllerAdminIsTheXDSControllerOnTwoControllers(t *testing.T) {
	g, _ := twoControllerGatewayUnderTest(t, consistentMTLSGateway(t), consistentMTLSGateway(t))
	service, separate, err := g.runtimeControllerAdmin()
	require.NoError(t, err)
	require.True(t, separate)
	require.Equal(t, xdsControllerAdmin, service)
}

func TestPolicySnapshotVersionsReadTheControllerThatFeedsTheRuntime(t *testing.T) {
	management, xds := consistentMTLSGateway(t), consistentMTLSGateway(t)
	management.controllerVersion, management.engineVersion = "9", "4"
	xds.controllerVersion = "4"
	g, ctx := twoControllerGatewayUnderTest(t, management, xds)
	got, err := g.policySnapshotVersions(ctx)
	require.NoError(t, err)
	require.Equal(t, policySync{controller: "4", engine: "4"}, got)
}

func TestRuntimeControllerAgreementWaitsForTheEventPath(t *testing.T) {
	management, xds := consistentMTLSGateway(t), consistentMTLSGateway(t)
	xds.attachesMTLSAuth = false
	g, ctx := twoControllerGatewayUnderTest(t, management, xds)

	require.Equal(t, "tolerated", outcome(g.requireRuntimeControllerAgrees(ctx, true)))
	require.NoError(t, g.requireRuntimeControllerAgrees(ctx, false))

	xds.mu.Lock()
	xds.attachesMTLSAuth = true
	xds.mu.Unlock()
	require.NoError(t, g.requireRuntimeControllerAgrees(ctx, true))
	require.Equal(t, "tolerated", outcome(g.requireRuntimeControllerAgrees(ctx, false)))
}

func TestRuntimeControllerAgreementIsNothingToWaitForOnOneController(t *testing.T) {
	g, ctx := mtlsGatewayUnderTest(t, consistentMTLSGateway(t), nil)
	require.NoError(t, g.requireRuntimeControllerAgrees(ctx, true))
	require.NoError(t, g.requireRuntimeControllerAgrees(ctx, false))
}
