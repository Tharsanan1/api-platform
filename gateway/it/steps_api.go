/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package it

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/cucumber/godog"
	"github.com/wso2/api-platform/gateway/it/steps"
	"gopkg.in/yaml.v3"
)

// policyPropagationDelay is the time to wait after mutating operations
// to allow the Policy Engine to receive and apply configuration changes.
// Reduced from 2s to 500ms as xDS sync typically completes in <500ms.
const policyPropagationDelay = 1 * time.Second

// deployedAPINamesContextKey is the TestState.Context key under which every
// API name this scenario has deployed is recorded (see recordDeployedAPIName
// and the After-scenario cleanup hook below). Keeping this in TestState.Context
// rather than a package-level slice means it's automatically scoped and reset
// per scenario by TestState.Reset(), with no separate Before hook needed here.
const deployedAPINamesContextKey = "deployedAPINames"

// apiConfigMetadata captures just enough of a RestApi configuration's YAML to
// recover its name for cleanup tracking; every other field is ignored.
type apiConfigMetadata struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
}

// recordDeployedAPIName best-effort parses the deployed configuration's
// metadata.name and appends it to this scenario's tracked list, so the
// After-scenario cleanup hook can delete it regardless of which step pattern
// or feature deployed it. A body that doesn't parse, or carries no name, is
// silently skipped: if the configuration didn't parse, nothing was created
// for this cleanup to worry about either.
func recordDeployedAPIName(state *TestState, body string) {
	var cfg apiConfigMetadata
	if err := yaml.Unmarshal([]byte(body), &cfg); err != nil || cfg.Metadata.Name == "" {
		return
	}
	existing, _ := state.GetContextValue(deployedAPINamesContextKey)
	names, _ := existing.([]string)
	names = append(names, cfg.Metadata.Name)
	state.SetContextValue(deployedAPINamesContextKey, names)
}

// deployAPIConfiguration POSTs a RestApi configuration to the gateway
// controller, records its name for end-of-scenario cleanup, and waits out
// policy propagation. Shared by every "deploy" step pattern registered below
// and by the fixture-values deploy step in steps_mtls.go, so a single
// implementation is what actually talks to the controller.
func deployAPIConfiguration(state *TestState, httpSteps *steps.HTTPSteps, body string) error {
	recordDeployedAPIName(state, body)
	httpSteps.SetHeader("Content-Type", "application/yaml")
	if err := httpSteps.SendPOSTToService("gateway-controller", "/rest-apis", &godog.DocString{Content: body}); err != nil {
		return err
	}
	time.Sleep(policyPropagationDelay)
	return nil
}

// updateAPIConfiguration PUTs a RestApi configuration to the gateway
// controller under the given API name and waits out policy propagation.
// Shared by the plain "I update the API ... with this configuration:" step
// below and the fixture-values update step in steps_mtls.go, so both go
// through a single implementation.
func updateAPIConfiguration(httpSteps *steps.HTTPSteps, apiName, body string) error {
	httpSteps.SetHeader("Content-Type", "application/yaml")
	if err := httpSteps.SendPUTToService("gateway-controller", "/rest-apis/"+apiName, &godog.DocString{Content: body}); err != nil {
		return err
	}
	time.Sleep(policyPropagationDelay)
	return nil
}

// cleanupDeployedAPIs deletes every API name this scenario recorded via
// deployAPIConfiguration, authenticating as admin. Best-effort: a scenario
// that already deleted its own API explicitly gets a silent 404 here, and a
// name that never actually got created (e.g. a rejected deploy) is a no-op
// too — sendRequest only errors on network-layer failures, never on the
// resulting HTTP status.
func cleanupDeployedAPIs(state *TestState, httpSteps *steps.HTTPSteps) {
	raw, ok := state.GetContextValue(deployedAPINamesContextKey)
	if !ok {
		return
	}
	names, ok := raw.([]string)
	if !ok || len(names) == 0 {
		return
	}

	admin, ok := state.Config.Users["admin"]
	if !ok {
		return
	}
	creds := base64.StdEncoding.EncodeToString([]byte(admin.Username + ":" + admin.Password))
	httpSteps.SetHeader("Authorization", "Basic "+creds)

	for _, name := range names {
		_ = httpSteps.SendDELETEToService("gateway-controller", "/rest-apis/"+name)
	}
}

// RegisterAPISteps registers all API deployment step definitions
func RegisterAPISteps(ctx *godog.ScenarioContext, state *TestState, httpSteps *steps.HTTPSteps) {
	// Single deploy function used by multiple step patterns
	deployAPI := func(body *godog.DocString) error {
		return deployAPIConfiguration(state, httpSteps, body.Content)
	}

	// Single delete function used by multiple step patterns
	deleteAPI := func(name string) error {
		err := httpSteps.SendDELETEToService("gateway-controller", "/rest-apis/"+name)
		if err != nil {
			return err
		}
		time.Sleep(policyPropagationDelay)
		return nil
	}

	// Register multiple step patterns for deploy
	ctx.Step(`^I deploy this API configuration:$`, deployAPI)
	ctx.Step(`^I deploy an API with the following configuration:$`, deployAPI)
	ctx.Step(`^I deploy a test API with the following configuration:$`, deployAPI)

	// Register multiple step patterns for delete
	ctx.Step(`^I delete the API "([^"]*)"$`, deleteAPI)
	// Note: Version parameter is semantically meaningful in tests but not used by the API endpoint.
	// The API deletes by name only - version is embedded in the API YAML, not in the DELETE path.
	ctx.Step(`^I delete the API "([^"]*)" version "([^"]*)"$`, func(name, version string) error {
		return deleteAPI(name)
	})

	ctx.Step(`^I update the API "([^"]*)" with this configuration:$`, func(apiName string, body *godog.DocString) error {
		return updateAPIConfiguration(httpSteps, apiName, body.Content)
	})

	ctx.Step(`^I get the API "([^"]*)"$`, func(name string) error {
		return httpSteps.SendGETToService("gateway-controller", "/rest-apis/"+name)
	})

	// After-scenario cleanup: delete every API this scenario deployed (via
	// deployAPIConfiguration, above), as admin, before any feature-specific
	// After hook (e.g. mtlsSteps' certificate-pool cleanup) runs — this
	// function is registered ahead of RegisterMTLSSteps in suite_test.go, and
	// godog runs After hooks in registration order. Applies to every feature,
	// not only mtls ones; existing scenarios that already delete their own
	// API explicitly just see a silent no-op (404) here.
	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		cleanupDeployedAPIs(state, httpSteps)
		return c, nil
	})
}
