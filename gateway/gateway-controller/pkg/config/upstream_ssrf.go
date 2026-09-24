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

// UpstreamSSRFPolicy is the one address policy for every place this process
// dials an operator-configured upstream host; callers must use it rather
// than reimplement it. Private addresses are allowed because backends are
// normally private. Loopback, link-local (including cloud metadata),
// unspecified and multicast/broadcast addresses are refused.
func UpstreamSSRFPolicy() netguard.Policy {
	return netguard.PermitPrivateBlockMetadata()
}

// UpstreamSSRFDialContext returns a DialContext function that validates every
// resolved address against UpstreamSSRFPolicy and dials the validated address,
// never the hostname, so DNS rebinding cannot bypass the check.
func UpstreamSSRFDialContext(timeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return netguard.DialContext(UpstreamSSRFPolicy(), timeout)
}
