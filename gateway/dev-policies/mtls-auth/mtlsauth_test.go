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

package mtlsauth

import (
	"context"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newTestRequestHeaderContext() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
	}
}

func mustGetPolicy(t *testing.T) *MtlsAuthPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned an error: %v", err)
	}
	mp, ok := p.(*MtlsAuthPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *MtlsAuthPolicy", p)
	}
	return mp
}

// TestMtlsAuthPolicy_DefaultParams_ProducesUniformUnauthorizedResponse guards
// the default failure response contract: with no params configured, every
// request is rejected with a 401, an application/json body of exactly
// {"error":"Unauthorized","message":"Authentication failed"}, and no
// WWW-Authenticate header (mutual TLS has no challenge header equivalent to
// offer).
func TestMtlsAuthPolicy_DefaultParams_ProducesUniformUnauthorizedResponse(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}

	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type header = %q, want %q", got, "application/json")
	}
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(resp.Body), wantBody)
	}
	if _, exists := resp.Headers["WWW-Authenticate"]; exists {
		t.Errorf("expected no WWW-Authenticate header, got %q", resp.Headers["WWW-Authenticate"])
	}

	if reqCtx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be recorded on failure")
	}
	if reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated to be false")
	}
	if reqCtx.SharedContext.AuthContext.AuthType != AuthType {
		t.Errorf("AuthContext.AuthType = %q, want %q", reqCtx.SharedContext.AuthContext.AuthType, AuthType)
	}
}

// TestMtlsAuthPolicy_ErrorMessageFormat_Plain honours errorMessageFormat:
// "plain" — the body is the raw error message text and the content-type
// switches to text/plain instead of the default JSON envelope.
func TestMtlsAuthPolicy_ErrorMessageFormat_Plain(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"errorMessageFormat": "plain",
		"errorMessage":       "no certificate presented",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if got := resp.Headers["content-type"]; got != "text/plain" {
		t.Errorf("content-type header = %q, want %q", got, "text/plain")
	}
	if string(resp.Body) != "no certificate presented" {
		t.Errorf("body = %q, want %q", string(resp.Body), "no certificate presented")
	}
}

// TestMtlsAuthPolicy_ErrorMessageFormat_Minimal honours errorMessageFormat:
// "minimal" — the body is the fixed literal "Unauthorized" regardless of any
// configured errorMessage, with the default JSON content-type retained.
func TestMtlsAuthPolicy_ErrorMessageFormat_Minimal(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"errorMessageFormat": "minimal",
		"errorMessage":       "this text must not appear",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type header = %q, want %q", got, "application/json")
	}
	if string(resp.Body) != "Unauthorized" {
		t.Errorf("body = %q, want %q", string(resp.Body), "Unauthorized")
	}
}

// TestMtlsAuthPolicy_OnFailureStatusCode_Honoured guards that a configured
// onFailureStatusCode overrides the default 401.
func TestMtlsAuthPolicy_OnFailureStatusCode_Honoured(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"onFailureStatusCode": 403,
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", resp.StatusCode)
	}
	// The failure body contract is otherwise unaffected by the status code override.
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(resp.Body), wantBody)
	}
}

// TestMtlsAuthPolicy_Mode guards the declared processing mode: only the
// request-header phase is needed, since the certificate this policy
// authenticates against is a connection-level fact available at header time.
func TestMtlsAuthPolicy_Mode(t *testing.T) {
	p := mustGetPolicy(t)
	mode := p.Mode()

	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode = %v, want HeaderModeProcess", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("RequestBodyMode = %v, want BodyModeSkip", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("ResponseHeaderMode = %v, want HeaderModeSkip", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("ResponseBodyMode = %v, want BodyModeSkip", mode.ResponseBodyMode)
	}
}
