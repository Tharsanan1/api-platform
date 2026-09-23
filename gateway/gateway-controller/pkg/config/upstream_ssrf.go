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

package config

import (
	"context"
	"net"
	"time"

	"github.com/wso2/api-platform/httpkit/netguard"
)

// UpstreamSSRFPolicy is the single, shared address policy for every place
// this controller process itself dials (or otherwise resolves) an
// operator-configured upstream/backend host — see ssrf-prevention.md
// directive 6: exactly one shared validation helper across every
// upstream/backend feature, never a per-feature reimplementation.
//
// Private/RFC 1918 addresses are permitted: an upstream backend is normally
// meant to be private (a Kubernetes ClusterIP, a docker-compose service
// name, a VPC-internal host), so blocking them would break ordinary
// deployments. What stays refused is the set of addresses that is never a
// legitimate backend but is a standard SSRF target or a hazard: loopback,
// link-local (which is where the cloud instance metadata endpoint
// 169.254.169.254 lives), the unspecified address, and multicast/broadcast.
//
// As of this writing, this helper's only caller is
// (*APIServer).probeUpstreamTLS (the POST .../tls-test handshake probe,
// pkg/api/handlers/upstream_tls_probe.go) — the only place in
// gateway-controller that dials an operator-configured upstream host
// directly from this process. pkg/config's deploy-time upstream URL
// validators (api_validator.go's validateUpstreamUrl/
// validateUpstreamDefinitionsList, and the MCP/LLM equivalents) currently
// perform only syntactic checks (scheme, host presence) and do not resolve
// or dial the target at all; extending them to call this same helper is a
// separate, broader change (deploy-time validation would then perform a
// live DNS lookup on every RestApi/MCP/LLM deploy) that should be its own
// reviewed change rather than folded into this one, so any future feature
// that does need to dial such a host, or any effort to retrofit those
// validators, must call this function rather than re-implementing the
// policy inline.
func UpstreamSSRFPolicy() netguard.Policy {
	return netguard.PermitPrivateBlockMetadata()
}

// UpstreamSSRFDialContext returns a dial function (compatible with
// net.Dialer.DialContext / http.Transport.DialContext) that resolves the
// target host and validates every candidate address against
// UpstreamSSRFPolicy before connecting — never the original hostname again
// once validated, so a DNS answer that changes between the check and the
// connection (DNS rebinding) cannot smuggle a disallowed address through.
func UpstreamSSRFDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return netguard.DialContext(UpstreamSSRFPolicy(), timeout)
}
