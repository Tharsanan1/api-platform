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

package steps

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cucumber/godog"
	"github.com/stretchr/testify/require"

	frameworkruntime "github.com/wso2/api-platform/tests/framework/core/runtime"
)

// TestDefaultIdentityFeatureStepsAreDefined matches every step of the default identity
// feature against the registered steps without running one: a hook that fails every scenario
// first makes godog skip the steps, and it still reports an undefined or ambiguous one.
func TestDefaultIdentityFeatureStepsAreDefined(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	require.True(t, ok)
	featureRoot := filepath.Join(filepath.Dir(source), "..")
	suite, err := New(&frameworkruntime.Topology{}, featureRoot)
	require.NoError(t, err)

	var output bytes.Buffer
	godog.TestSuite{
		ScenarioInitializer: func(sc *godog.ScenarioContext) {
			suite.Register(sc)
			sc.Before(func(ctx context.Context, _ *godog.Scenario) (context.Context, error) {
				return ctx, errors.New("steps are matched, not run")
			})
		},
		Options: &godog.Options{
			Format: "progress", Output: &output, NoColors: true,
			Paths: []string{filepath.Join(featureRoot, "features", "mtls_default_identity.feature")},
			// The Agent scenario needs the Agent resource steps.
			Tags: "~@agent",
		},
	}.Run()

	report := output.String()
	require.NotContains(t, report, "undefined", report)
	require.NotContains(t, strings.ToLower(report), "ambiguous", report)
	require.Contains(t, report, "scenarios", report)
}
