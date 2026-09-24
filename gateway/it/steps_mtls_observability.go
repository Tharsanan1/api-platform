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

package it

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
)

// mtlsObservabilitySteps holds the mTLS container-log and analytics
// attribution steps, reusing the mTLS and analytics step instances.
type mtlsObservabilitySteps struct {
	composeManager *ComposeManager
	mtls           *mtlsSteps
	analytics      *AnalyticsSteps

	// scenarioStart bounds log polling so a line from an earlier scenario
	// cannot satisfy this scenario's assertion.
	scenarioStart time.Time
}

// RegisterMTLSObservabilitySteps registers the mTLS observability steps.
func RegisterMTLSObservabilitySteps(ctx *godog.ScenarioContext, composeManager *ComposeManager, mtls *mtlsSteps, analytics *AnalyticsSteps) {
	o := &mtlsObservabilitySteps{composeManager: composeManager, mtls: mtls, analytics: analytics}

	ctx.Before(func(c context.Context, sc *godog.Scenario) (context.Context, error) {
		o.scenarioStart = time.Now()
		return c, nil
	})

	ctx.Step(`^the "([^"]*)" container log should contain the thumbprint of fixture "([^"]*)" within (\d+) seconds$`,
		o.containerLogShouldContainThumbprintOfFixtureWithin)
	// (.*) because the expected substring can carry escaped quotes (e.g.
	// `\"peerSubj\":\"CN=client-valid\"`), which [^"]* would stop at.
	ctx.Step(`^the "([^"]*)" container log should contain "(.*)" within (\d+) seconds$`,
		o.containerLogShouldContainWithin)

	ctx.Step(`^the latest analytics event should have the user id of fixture "([^"]*)"$`,
		o.latestAnalyticsEventShouldHaveUserIDOfFixture)
	ctx.Step(`^the latest analytics event should have no metadata field "([^"]*)"$`,
		o.latestAnalyticsEventShouldHaveNoMetadataField)
}

// containerLogShouldContainWithin polls the service's log since the scenario
// started until it contains substr, matched exactly and case-sensitively.
func (o *mtlsObservabilitySteps) containerLogShouldContainWithin(service, substr string, seconds int) error {
	substr = unescapeGherkinQuotes(substr)
	return o.pollLogs(service, seconds, func(logs string) bool {
		return strings.Contains(logs, substr)
	}, fmt.Sprintf("%q", substr))
}

// containerLogShouldContainThumbprintOfFixtureWithin polls the service's log
// for the fixture's thumbprint, case-insensitively because Envoy's
// fingerprint rendering case is not guaranteed.
func (o *mtlsObservabilitySteps) containerLogShouldContainThumbprintOfFixtureWithin(service, fixture string, seconds int) error {
	thumbprint, err := o.mtls.thumbprintOf(fixture)
	if err != nil {
		return err
	}
	lowerThumbprint := strings.ToLower(thumbprint)
	return o.pollLogs(service, seconds, func(logs string) bool {
		return strings.Contains(strings.ToLower(logs), lowerThumbprint)
	}, fmt.Sprintf("the thumbprint of fixture %q (%s)", fixture, thumbprint))
}

// pollLogs polls the service's log every 500ms until match returns true or
// the timeout elapses.
func (o *mtlsObservabilitySteps) pollLogs(service string, seconds int, match func(logs string) bool, describeWant string) error {
	if o.composeManager == nil {
		return fmt.Errorf("compose manager is not initialized")
	}

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	var lastErr error
	for {
		logs, err := o.composeManager.ServiceLogs(service, o.scenarioStart)
		if err != nil {
			lastErr = err
		} else if match(logs) {
			return nil
		}

		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("%q container log did not contain %s within %ds (last log-collection error: %v)",
					service, describeWant, seconds, lastErr)
			}
			return fmt.Errorf("%q container log did not contain %s within %ds", service, describeWant, seconds)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// mtlsAuthSubjectIdentity mirrors the mtls-auth policy's subject: the first
// URI SAN, else the first DNS SAN, else the Subject DN. It becomes the
// analytics event's user_id.
func mtlsAuthSubjectIdentity(cert *x509.Certificate) string {
	if len(cert.URIs) > 0 {
		return cert.URIs[0].String()
	}
	if len(cert.DNSNames) > 0 {
		return cert.DNSNames[0]
	}
	return cert.Subject.String()
}

// latestAnalyticsEventShouldHaveUserIDOfFixture verifies the latest
// analytics event's user_id is the fixture certificate's subject identity.
func (o *mtlsObservabilitySteps) latestAnalyticsEventShouldHaveUserIDOfFixture(fixture string) error {
	event, err := o.analytics.latestEventOrFetch()
	if err != nil {
		return err
	}

	cert, err := o.mtls.parseFixtureCert(fixture)
	if err != nil {
		return err
	}
	expected := mtlsAuthSubjectIdentity(cert)

	if event.UserID != expected {
		return fmt.Errorf("expected latest analytics event user_id to be the subject of fixture %q (%q), got %q",
			fixture, expected, event.UserID)
	}
	return nil
}

// latestAnalyticsEventShouldHaveNoMetadataField verifies fieldName is absent
// from the latest analytics event's metadata.
func (o *mtlsObservabilitySteps) latestAnalyticsEventShouldHaveNoMetadataField(fieldName string) error {
	event, err := o.analytics.latestEventOrFetch()
	if err != nil {
		return err
	}

	if _, present := event.Metadata[fieldName]; present {
		return fmt.Errorf("expected latest analytics event to have no metadata field %q, but it was present", fieldName)
	}
	return nil
}
