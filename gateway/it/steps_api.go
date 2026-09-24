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

// deployedAPINamesContextKey holds the API names this scenario deployed. It
// lives in TestState.Context so TestState.Reset clears it per scenario.
const deployedAPINamesContextKey = "deployedAPINames"

// apiConfigMetadata captures just enough of a RestApi configuration's YAML to
// recover its name for cleanup tracking; every other field is ignored.
type apiConfigMetadata struct {
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
}

// recordDeployedAPIName records the configuration's metadata.name for
// end-of-scenario cleanup. A body without a parseable name created nothing,
// so it is skipped.
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
// controller, records its name for cleanup, and waits out policy propagation
// if the controller accepted it.
func deployAPIConfiguration(state *TestState, httpSteps *steps.HTTPSteps, body string) error {
	recordDeployedAPIName(state, body)
	httpSteps.SetHeader("Content-Type", "application/yaml")
	if err := httpSteps.SendPOSTToService("gateway-controller", "/rest-apis", &godog.DocString{Content: body}); err != nil {
		return err
	}
	waitForPropagationIfAccepted(httpSteps)
	return nil
}

// waitForPropagationIfAccepted sleeps out policy propagation only after a
// mutation the controller accepted (2xx). A refused mutation leaves the
// gateway untouched, so waiting would only slow the suite down.
func waitForPropagationIfAccepted(httpSteps *steps.HTTPSteps) {
	if resp := httpSteps.LastResponse(); resp != nil && (resp.StatusCode < 200 || resp.StatusCode >= 300) {
		return
	}
	time.Sleep(policyPropagationDelay)
}

// updateAPIConfiguration PUTs a RestApi configuration to the gateway
// controller under the given API name and waits out policy propagation.
func updateAPIConfiguration(httpSteps *steps.HTTPSteps, apiName, body string) error {
	httpSteps.SetHeader("Content-Type", "application/yaml")
	if err := httpSteps.SendPUTToService("gateway-controller", "/rest-apis/"+apiName, &godog.DocString{Content: body}); err != nil {
		return err
	}
	waitForPropagationIfAccepted(httpSteps)
	return nil
}

// cleanupDeployedAPIs deletes, as admin, every API this scenario recorded.
// It is best-effort: an API already deleted or never created just gets a 404.
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
		waitForPropagationIfAccepted(httpSteps)
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

	// @mtls scenarios delete their APIs here. This hook is registered before
	// the certificate cleanup hook and godog runs After hooks in registration
	// order, so no API still references a pool entry being removed. Other
	// features may share an API across scenarios, so they are left alone.
	ctx.After(func(c context.Context, sc *godog.Scenario, err error) (context.Context, error) {
		if scenarioHasTag(sc, "@mtls") {
			cleanupDeployedAPIs(state, httpSteps)
		}
		return c, nil
	})
}

// scenarioHasTag reports whether the scenario, or the feature it belongs to,
// carries the given tag (godog copies feature-level tags onto each scenario).
func scenarioHasTag(sc *godog.Scenario, tag string) bool {
	for _, t := range sc.Tags {
		if t.Name == tag {
			return true
		}
	}
	return false
}
