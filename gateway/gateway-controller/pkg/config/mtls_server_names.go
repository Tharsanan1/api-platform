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
	"net"
	"strings"

	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/management"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/constants"
)

// SplitVhosts parses a vhosts.main value into its individual production
// hostnames. Multiple hostnames may be provided separated by ";" (each serves
// the main upstream); surrounding whitespace is trimmed, empty entries are
// dropped, and duplicates are removed while preserving order. A single
// hostname (the common case) returns a one-element slice.
func SplitVhosts(raw string) []string {
	parts := strings.Split(raw, ";")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// RestAPIHasSandbox reports whether a REST API has a sandbox upstream, set
// through either url or ref.
func RestAPIHasSandbox(spec api.APIConfigData) bool {
	sb := spec.Upstream.Sandbox
	return sb != nil &&
		((sb.Url != nil && strings.TrimSpace(*sb.Url) != "") ||
			(sb.Ref != nil && strings.TrimSpace(*sb.Ref) != ""))
}

// RestAPIVhosts resolves the vhosts a REST API's routes are served on. main
// holds every vhosts.main entry, or the main default when none is set; the
// first is the primary vhost. sandbox is vhosts.sandbox or the sandbox
// default, and applies only when hasSandbox is true. The gateway-default
// sentinel resolves to the matching default.
func RestAPIVhosts(spec api.APIConfigData, vhosts VHostsConfig) (main []string, sandbox string, hasSandbox bool) {
	main = []string{vhosts.Main.Default}
	sandbox = vhosts.Sandbox.Default
	if spec.Vhosts != nil {
		if parsed := SplitVhosts(spec.Vhosts.Main); len(parsed) > 0 && !(len(parsed) == 1 && parsed[0] == constants.VHostGatewayDefault) {
			main = parsed
		}
		if s := spec.Vhosts.Sandbox; s != nil && strings.TrimSpace(*s) != "" && *s != constants.VHostGatewayDefault {
			sandbox = *s
		}
	}
	return main, sandbox, RestAPIHasSandbox(spec)
}

// Domains returns the routing domains of a resolved vhost: the configured
// domains when vhost is the main or sandbox default and that default lists
// any, otherwise vhost itself.
func (v VHostsConfig) Domains(vhost string) []string {
	for _, entry := range []VHostEntry{v.Main, v.Sandbox} {
		if vhost != entry.Default {
			continue
		}
		var out []string
		for _, d := range entry.Domains {
			if d = strings.TrimSpace(d); d != "" {
				out = append(out, d)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{vhost}
}

// ServerName returns the TLS server name (SNI) a client reaching a
// dedicated vhost sends, lower-cased and without a port. ok is false when the
// vhost cannot be told apart on SNI: a main or sandbox default, which every
// API without its own hostname shares; an IP address, which clients never
// send as SNI; and anything but an exact DNS name or a single leading "*."
// wildcard.
func (v VHostsConfig) ServerName(vhost string) (name string, ok bool) {
	vhost = strings.TrimSpace(vhost)
	if vhost == strings.TrimSpace(v.Main.Default) || vhost == strings.TrimSpace(v.Sandbox.Default) {
		return "", false
	}
	return sniName(vhost)
}

// sniName converts a hostname, optionally with a port, to the server name a
// client sends.
func sniName(domain string) (string, bool) {
	host := strings.ToLower(strings.TrimSpace(domain))
	if strings.Contains(host, ":") {
		h, _, err := net.SplitHostPort(host)
		if err != nil {
			return "", false
		}
		host = h
	}
	if host == "" || net.ParseIP(host) != nil {
		return "", false
	}
	rest := strings.TrimPrefix(host, "*.")
	if rest == "" || strings.Contains(rest, "*") {
		return "", false
	}
	return host, true
}
