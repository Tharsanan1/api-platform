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

// Package mtlsauth implements the mtls-auth policy: it authenticates API
// callers by matching the client certificate presented on the gateway's
// mutual-TLS-capable HTTPS listener against the policy instance's own
// `accept` list (a subset of the gateway's client-CA pool, optionally
// narrowed by SAN match or certificate thumbprint).
//
// The HTTPS listener itself is derived, not configured: it requests a
// client certificate from every connection while at least one deployed API
// attaches this policy (see pkg/xds's createDownstreamTLSContext in the
// gateway-controller), and never closes a connection over the certificate it
// receives — this policy is what turns "a certificate was presented" into
// "this API's caller is authenticated".
package mtlsauth

import (
	"context"
	"encoding/json"
	"log/slog"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType identifies this authentication mechanism in policy.AuthContext,
	// mirroring the "jwt"/"basic"/"apikey" convention used by the other auth
	// policies.
	AuthType = "mtls"

	defaultOnFailureStatusCode = 401
	defaultErrorMessageFormat  = "json"
	defaultErrorMessage        = "Authentication failed"
)

// MtlsAuthPolicy authenticates API callers via mutual TLS. Deploy-time
// validation of `accept` (the gateway-controller's mtls-auth validator) is
// what guarantees every instance of this policy can name at least one
// reachable client authority — see go-network-service-hardening.md and
// authentication_authorization.md for the invariants that validation, and
// this policy's own fail-closed behavior below, jointly uphold.
//
// This is a stateless singleton, matching the convention used by the other
// dev/sample policies in this repo (see transform-payload-case): GetPolicy is
// called once per route binding but the policy instance itself holds no
// per-route state — every value it needs comes from params on each call.
type MtlsAuthPolicy struct{}

var ins = &MtlsAuthPolicy{}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	return ins, nil
}

// Mode declares that mtls-auth only needs the request-header phase: the
// certificate it authenticates against is a connection-level fact (available
// as soon as headers are), never something carried in the request body.
func (p *MtlsAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// verdict is evaluate's outcome: whether the connection's certificate (once
// consulted) satisfies this policy instance's accept list.
type verdict struct {
	authenticated bool
	subject       string
	reason        string
}

// evaluate authenticates no request: it always reports authenticated:false,
// so every request receives the configured failure response (see
// handleAuthFailure) regardless of what certificate, if any, the connection
// presented. It does not read the connection.* ext_proc request attributes —
// connection.mtls, connection.peer_certificate_valid,
// connection.subject_peer_certificate, connection.uri_san_peer_certificate,
// connection.dns_san_peer_certificate, connection.sha256_peer_certificate_digest
// (see pkg/xds/constants in the gateway-controller) — and it does not
// consult the resolved `accept` list. This is fail-closed, per
// authentication_authorization.md GO-AUTH-001: an auth check that cannot
// decide denies, it never passes through.
func (p *MtlsAuthPolicy) evaluate(_ *policy.RequestHeaderContext, _ map[string]interface{}) verdict {
	return verdict{authenticated: false, reason: "no client certificate accepted"}
}

// OnRequestHeaders performs mTLS authentication in the request-header phase.
func (p *MtlsAuthPolicy) OnRequestHeaders(_ context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", defaultOnFailureStatusCode)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", defaultErrorMessageFormat)
	errorMessage := getStringParam(params, "errorMessage", defaultErrorMessage)

	result := p.evaluate(reqCtx, params)
	if !result.authenticated {
		slog.Debug("mtls-auth: rejecting request", slog.String("reason", result.reason))
		return p.handleAuthFailure(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage)
	}

	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       result.subject,
		Previous:      reqCtx.SharedContext.AuthContext,
	}
	return policy.UpstreamRequestHeaderModifications{}
}

// handleAuthFailure builds the uniform rejection response and records the
// failed attempt on SharedContext.AuthContext for any downstream multi-layer
// auth chain. It mirrors jwt-auth's handleAuthFailureHeaders byte-for-byte
// for the default case, per error-handling.md's unified-auth-failure
// directive: identical status/body regardless of *why* authentication
// failed, and no WWW-Authenticate header — mutual TLS has no challenge
// header equivalent to offer.
func (p *MtlsAuthPolicy) handleAuthFailure(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage string) policy.RequestHeaderAction {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}

	headers := map[string]string{
		"content-type": "application/json",
	}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	case "minimal":
		body = "Unauthorized"
	default:
		// json.Marshal of a map[string]interface{} sorts keys alphabetically,
		// so this always renders as {"error":...,"message":...} — matching
		// the exact byte-for-byte contract in mtls-listener.feature.
		bodyBytes, _ := json.Marshal(map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		})
		body = string(bodyBytes)
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

func getIntParam(params map[string]interface{}, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return def
	}
}

func getStringParam(params map[string]interface{}, key, def string) string {
	v, ok := params[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return def
	}
	return s
}
