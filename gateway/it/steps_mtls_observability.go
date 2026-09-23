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

// mtlsObservabilitySteps holds the step definitions for
// features/mtls-observability.feature: container-log polling, analytics
// attribution, and the metric-absence assertion these scenarios need beyond
// what steps_mtls.go, steps_analytics.go and steps_metrics.go already
// provide. It reuses those existing steps' instances rather than
// duplicating fixture-reading or analytics-lookup logic.
type mtlsObservabilitySteps struct {
	composeManager *ComposeManager
	mtls           *mtlsSteps
	analytics      *AnalyticsSteps

	// scenarioStart is the wall-clock time this scenario began, used as
	// --since for polling a container's logs so a line left over from an
	// earlier scenario can never satisfy this scenario's assertion.
	scenarioStart time.Time
}

// RegisterMTLSObservabilitySteps registers step definitions for
// features/mtls-observability.feature.
func RegisterMTLSObservabilitySteps(ctx *godog.ScenarioContext, composeManager *ComposeManager, mtls *mtlsSteps, analytics *AnalyticsSteps) {
	o := &mtlsObservabilitySteps{composeManager: composeManager, mtls: mtls, analytics: analytics}

	ctx.Before(func(c context.Context, sc *godog.Scenario) (context.Context, error) {
		o.scenarioStart = time.Now()
		return c, nil
	})

	ctx.Step(`^the "([^"]*)" container log should contain the thumbprint of fixture "([^"]*)" within (\d+) seconds$`,
		o.containerLogShouldContainThumbprintOfFixtureWithin)
	// (.*) rather than [^"]* — the expected substring is itself a quoted JSON
	// field fragment (e.g. `\"peerSubj\":\"CN=client-valid\"`), and godog does
	// not interpret `\"` as an escape, so the captured text can carry literal
	// embedded quote characters that [^"]* would stop at (see
	// unescapeGherkinQuotes in steps_metrics.go for why this also needs
	// unescaping before use).
	ctx.Step(`^the "([^"]*)" container log should contain "(.*)" within (\d+) seconds$`,
		o.containerLogShouldContainWithin)

	ctx.Step(`^the latest analytics event should have the user id of fixture "([^"]*)"$`,
		o.latestAnalyticsEventShouldHaveUserIDOfFixture)
	ctx.Step(`^the latest analytics event should have no metadata field "([^"]*)"$`,
		o.latestAnalyticsEventShouldHaveNoMetadataField)
}

// containerLogShouldContainWithin polls `service`'s container log (since
// this scenario started) until it contains substr, or fails once seconds
// elapses. Exact, case-sensitive substring match — the feature's expected
// strings are byte-exact JSON field fragments (e.g. `"peerSubj":"CN=..."`).
func (o *mtlsObservabilitySteps) containerLogShouldContainWithin(service, substr string, seconds int) error {
	substr = unescapeGherkinQuotes(substr)
	return o.pollLogs(service, seconds, func(logs string) bool {
		return strings.Contains(logs, substr)
	}, fmt.Sprintf("%q", substr))
}

// containerLogShouldContainThumbprintOfFixtureWithin polls `service`'s
// container log for fixture's SHA-256 thumbprint, matched case-insensitively
// since Envoy's own %DOWNSTREAM_PEER_FINGERPRINT_256% rendering case isn't
// guaranteed to match thumbprintOf's lowercase-hex convention.
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

// pollLogs polls composeManager.ServiceLogs(service, o.scenarioStart) every
// 500ms until match returns true or seconds elapses, at which point it fails
// with a message naming what it was looking for (describeWant).
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

// mtlsAuthSubjectIdentity mirrors mtls-auth's own subject derivation (see
// dev-policies/mtls-auth's sanNarrowedSubject): a certificate's first URI
// SAN wins if it carries one, else its first DNS SAN, else its Subject DN —
// this is what ends up as AuthContext.Subject and, downstream, the
// analytics event's user_id, regardless of whether the accept entry itself
// narrows by SAN.
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
// analytics event's user_id equals the identity mtls-auth derived for
// fixture's certificate (see mtlsAuthSubjectIdentity).
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
