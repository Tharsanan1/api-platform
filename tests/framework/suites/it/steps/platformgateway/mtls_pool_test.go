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

package platformgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/cucumber/godog"
	"github.com/stretchr/testify/require"

	"github.com/wso2/api-platform/tests/framework/core/cleanup"
	"github.com/wso2/api-platform/tests/framework/core/util/httpx"
	"github.com/wso2/api-platform/tests/framework/core/util/tcontext"
	stepscommon "github.com/wso2/api-platform/tests/framework/suites/it/steps/common"
)

// fakeCertificateStore serves the controller's certificate collection.
type fakeCertificateStore struct {
	mu          sync.Mutex
	listing     []map[string]any
	references  []int // referencedByApis served on successive listings; the last repeats
	listings    int
	postStatus  int
	postBodies  [][]byte
	deleteCode  int
	deletedIDs  []string
	deleteAuths []string
}

func (f *fakeCertificateStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	const collection = "/api/management/v1/certificates"
	switch {
	case r.URL.Path == collection && r.Method == http.MethodPost:
		body, _ := io.ReadAll(r.Body)
		f.postBodies = append(f.postBodies, body)
		w.WriteHeader(f.postStatus)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": fmt.Sprintf("cert-%d", len(f.postBodies))})
	case r.URL.Path == collection:
		listing := f.listing
		if len(f.references) > 0 {
			i := min(f.listings, len(f.references)-1)
			listing = []map[string]any{{"id": "cert-1", "name": "named", "referencedByApis": f.references[i]}}
		}
		f.listings++
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": listing})
	case strings.HasPrefix(r.URL.Path, collection+"/") && r.Method == http.MethodDelete:
		f.deletedIDs = append(f.deletedIDs, strings.TrimPrefix(r.URL.Path, collection+"/"))
		f.deleteAuths = append(f.deleteAuths, r.Header.Get("Authorization"))
		w.WriteHeader(f.deleteCode)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// adminOnly rejects reads that are not the admin's, as the lookup must always be one.
func adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.Header.Get("Authorization") != BasicAuthHeader("admin", "secret") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func publish(t *testing.T, ctx context.Context, body string) {
	t.Helper()
	require.NoError(t, tcontext.Set(ctx, httpx.ResponseKey, &httpx.Response{StatusCode: http.StatusOK, Body: []byte(body)}))
}

// taggedScenario builds a scenario carrying the given tags.
func taggedScenario(t *testing.T, tags ...string) *godog.Scenario {
	t.Helper()
	var doc struct {
		Tags []map[string]string `json:"tags"`
	}
	for _, tag := range tags {
		doc.Tags = append(doc.Tags, map[string]string{"name": tag})
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	var sc godog.Scenario
	require.NoError(t, json.Unmarshal(raw, &sc))
	return &sc
}

func pendingCertificates(t *testing.T, ctx context.Context) []string {
	t.Helper()
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	var ids []string
	for _, r := range registry.Pending() {
		if r.Kind.Name == cleanup.KindCertificate.Name {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func TestPublishFixtureMaterialOnlyForMTLSScenarios(t *testing.T) {
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("runner"))
	_, err := publishFixtureMaterial(ctx, taggedScenario(t, "@other"))
	require.NoError(t, err)
	_, ok := tcontext.Get(ctx, fixturePEMKey("ca-a"))
	require.False(t, ok)
	_, err = publishFixtureMaterial(ctx, nil)
	require.NoError(t, err)

	_, err = publishFixtureMaterial(ctx, taggedScenario(t, "@other", tagMTLS))
	require.NoError(t, err)
	caA := mtlsFixture(t, "ca-a")
	body, err := stepscommon.Expand(ctx, `{"certificate":"${CTX:fixture.ca-a.pem}\n${CTX:fixture.ca-a.key}"}`)
	require.NoError(t, err)
	var decoded struct{ Certificate string }
	require.NoError(t, json.Unmarshal([]byte(body), &decoded))
	require.Equal(t, string(caA.CertPEM)+"\n"+string(caA.KeyPEM), decoded.Certificate)
	subject, err := stepscommon.Expand(ctx, "${CTX:fixture.ca-a-intermediate.subject}")
	require.NoError(t, err)
	require.Equal(t, "CN=Partner A Issuing CA 1,O=Partner A", subject)
	_, err = stepscommon.Expand(ctx, "${CTX:fixture.backend-ca.pem}")
	require.NoError(t, err)
}

func TestJSONEscaped(t *testing.T) {
	require.Equal(t, `a\nb\"c\\`, jsonEscaped([]byte("a\nb\"c\\")))
	require.Equal(t, "", jsonEscaped(nil))
}

func TestUploadFixtureSendsUsageRoleAndNarrowing(t *testing.T) {
	store := &fakeCertificateStore{postStatus: http.StatusCreated}
	g, ctx := mtlsGatewayUnderTest(t, store, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "relay", "relay"))

	require.ErrorContains(t, g.uploadFixtureWithRole(ctx, "edge-lb-ca", "literal", "downstream", "relay", ""), "is not generated")
	require.NoError(t, g.uploadFixtureWithRole(ctx, "edge-lb-ca", "${CTX:relay}", "downstream", "relay", ""))
	require.NoError(t, g.uploadFixtureWithRole(ctx, "edge-lb-ca", "${CTX:relay}", "downstream", "relay", "lb.corp.test"))
	require.NoError(t, g.uploadUpstreamFixture(ctx, "backend-ca", "${CTX:relay}"))

	var plain, narrowed, upstream map[string]any
	require.NoError(t, json.Unmarshal(store.postBodies[0], &plain))
	require.NoError(t, json.Unmarshal(store.postBodies[1], &narrowed))
	require.NoError(t, json.Unmarshal(store.postBodies[2], &upstream))
	require.Equal(t, "relay", plain["role"])
	require.Equal(t, "downstream", plain["usage"])
	require.NotContains(t, plain, "match")
	require.Equal(t, map[string]any{"dnsSANs": []any{"lb.corp.test"}}, narrowed["match"])
	require.NotContains(t, upstream, "usage")
	require.NotContains(t, upstream, "role")
	require.Equal(t, string(mtlsFixture(t, "backend-ca").CertPEM), upstream["certificate"])
	require.ElementsMatch(t, []string{"cert-1", "cert-2", "cert-3"}, pendingCertificates(t, ctx))
}

func TestPoolUpstreamFixtureRequiresCreated(t *testing.T) {
	store := &fakeCertificateStore{postStatus: http.StatusConflict}
	g, ctx := mtlsGatewayUnderTest(t, store, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "trust", "trust"))
	require.ErrorContains(t, g.poolUpstreamFixture(ctx, "ca-a", "${CTX:trust}"), "status 201")
	require.ErrorContains(t, g.poolUpstreamFixture(ctx, "no-such-fixture", "${CTX:trust}"), "unknown fixture")
	require.Empty(t, pendingCertificates(t, ctx))
}

func TestUploadCertificateBodyRegistersOnlyAnAcceptedUpload(t *testing.T) {
	store := &fakeCertificateStore{postStatus: http.StatusBadRequest}
	g, ctx := mtlsGatewayUnderTest(t, store, nil)
	require.NoError(t, tcontext.Set(ctx, "certName", "body-cert"))

	require.NoError(t, g.uploadCertificateBody(ctx, &godog.DocString{Content: `{"name":"${CTX:certName}","usage":"downstream"}`}))
	require.JSONEq(t, `{"name":"body-cert","usage":"downstream"}`, string(store.postBodies[0]))
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, published.StatusCode)
	require.Empty(t, pendingCertificates(t, ctx))

	store.postStatus = http.StatusCreated
	require.NoError(t, g.uploadCertificateBody(ctx, &godog.DocString{Content: `not json`}))
	require.Equal(t, "not json", string(store.postBodies[1]))
	require.Equal(t, []string{"cert-2"}, pendingCertificates(t, ctx))
	require.Error(t, g.uploadCertificateBody(ctx, &godog.DocString{Content: `${CTX:missing}`}))
}

func TestUploadOversizedCertificateExceedsTheLimitByATenth(t *testing.T) {
	store := &fakeCertificateStore{postStatus: http.StatusRequestEntityTooLarge}
	g, ctx := mtlsGatewayUnderTest(t, store, nil)
	require.NoError(t, stepscommon.GenerateResourceAndStore(ctx, "big", "big"))
	require.NoError(t, g.uploadOversizedCertificate(ctx, "${CTX:big}", "downstream"))
	var body map[string]string
	require.NoError(t, json.Unmarshal(store.postBodies[0], &body))
	require.Len(t, body["certificate"], certificateUploadLimitBytes+certificateUploadLimitBytes/10)
	require.Equal(t, "downstream", body["usage"])
	require.ErrorContains(t, g.uploadOversizedCertificate(ctx, "literal", "downstream"), "is not generated")
}

func TestDeleteCertificateNamedLooksUpAsAdminAndDeletesAsTheCaller(t *testing.T) {
	store := &fakeCertificateStore{
		listing:    []map[string]any{{"id": "id-a", "name": "pool-a"}, {"id": "id-b", "name": "pool-b"}},
		deleteCode: http.StatusForbidden,
	}
	g, ctx := mtlsGatewayUnderTest(t, adminOnly(store), nil)
	registry, err := cleanup.Of(ctx)
	require.NoError(t, err)
	require.NoError(t, registry.Register(cleanup.Resource{Kind: cleanup.KindCertificate, ID: "id-b", Actor: "admin"}))
	require.NoError(t, tcontext.Set(ctx, "b", "pool-b"))

	require.NoError(t, g.deleteCertificateNamed(ctx, "${CTX:b}"))
	require.Equal(t, []string{"id-b"}, store.deletedIDs)
	published, err := httpx.Published(ctx)
	require.NoError(t, err)
	require.Equal(t, http.StatusForbidden, published.StatusCode)
	require.Equal(t, []string{"id-b"}, pendingCertificates(t, ctx), "a refused delete stays registered")

	store.deleteCode = http.StatusNoContent
	require.NoError(t, g.deleteCertificateNamed(ctx, "pool-b"))
	require.Empty(t, pendingCertificates(t, ctx))
	require.ErrorContains(t, g.deleteCertificateNamed(ctx, "pool-c"), `no certificate named "pool-c"`)
}

func TestDeleteCertificateOnceUnreferenced(t *testing.T) {
	store := &fakeCertificateStore{references: []int{1, 0}, deleteCode: http.StatusOK}
	g, ctx := mtlsGatewayUnderTest(t, store, nil)
	require.NoError(t, g.deleteCertificateOnceUnreferenced(ctx, "named"))
	require.Equal(t, 2, store.listings)
	require.Equal(t, []string{"cert-1"}, store.deletedIDs)

	uncounted := &fakeCertificateStore{listing: []map[string]any{{"id": "x", "name": "named"}}}
	g, ctx = mtlsGatewayUnderTest(t, uncounted, nil)
	require.ErrorContains(t, g.deleteCertificateOnceUnreferenced(ctx, "named"), "without a referencedByApis count")
	require.Equal(t, 1, uncounted.listings, "a listing without a count fails at once")
	require.ErrorContains(t, g.deleteCertificateOnceUnreferenced(ctx, "absent"), `no certificate named "absent"`)
	require.Empty(t, uncounted.deletedIDs)
}

func TestCertificateListAssertions(t *testing.T) {
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("runner"))
	require.NoError(t, tcontext.Set(ctx, "a", "pool-a"))
	publish(t, ctx, `{"certificates":[
		{"name":"pool-a","usage":"downstream","referencedByApis":0,"isLeaf":true,
		 "warnings":[{"code":"CERT_EXPIRES_SOON","field":"notAfter"}]},
		{"name":"pool-b","usage":"upstream","warnings":[]}]}`)

	require.NoError(t, certificateListContains(ctx, "contain", "${CTX:a}"))
	require.NoError(t, certificateListContains(ctx, "not contain", "pool-c"))
	require.Error(t, certificateListContains(ctx, "contain", "pool-c"))
	require.Error(t, certificateListContains(ctx, "not contain", "pool-a"))

	require.NoError(t, listedCertificateFieldEquals(ctx, "${CTX:a}", "usage", `"downstream"`))
	require.NoError(t, listedCertificateFieldEquals(ctx, "pool-a", "referencedByApis", "0"))
	require.NoError(t, listedCertificateFieldEquals(ctx, "pool-a", "isLeaf", "true"))
	require.ErrorContains(t, listedCertificateFieldEquals(ctx, "pool-a", "referencedByApis", `"0"`), "expected 0 (string)")
	require.Error(t, listedCertificateFieldEquals(ctx, "pool-a", "isLeaf", "false"))
	require.Error(t, listedCertificateFieldEquals(ctx, "pool-a", "isLeaf", `"true"`))
	require.ErrorContains(t, listedCertificateFieldEquals(ctx, "pool-b", "referencedByApis", "0"), "without field")
	require.ErrorContains(t, listedCertificateFieldEquals(ctx, "pool-c", "usage", `"upstream"`), "not in the listing")

	require.NoError(t, listedCertificateLacksField(ctx, "pool-b", "referencedByApis"))
	require.Error(t, listedCertificateLacksField(ctx, "pool-a", "referencedByApis"))

	require.NoError(t, listedCertificateHasWarning(ctx, "pool-a", "code", "CERT_EXPIRES_SOON"))
	require.NoError(t, listedCertificateHasWarning(ctx, "pool-a", "field", "notAfter"))
	require.Error(t, listedCertificateHasWarning(ctx, "pool-a", "code", "notAfter"))
	require.Error(t, listedCertificateHasWarning(ctx, "pool-b", "code", "CERT_EXPIRES_SOON"))
	require.NoError(t, listedCertificateHasNoWarnings(ctx, "pool-b"))
	require.Error(t, listedCertificateHasNoWarnings(ctx, "pool-a"))

	publish(t, ctx, `{"status":"error"}`)
	require.ErrorContains(t, certificateListContains(ctx, "not contain", "pool-a"), "not a certificate listing")
	httpx.ClearPublished(ctx)
	require.Error(t, certificateListContains(ctx, "not contain", "pool-a"))
}

func TestValidationErrorListed(t *testing.T) {
	ctx := tcontext.WithLocal(context.Background(), tcontext.NewLocal("runner"))
	require.NoError(t, tcontext.Set(ctx, "api", "ref-api-1"))
	publish(t, ctx, `{"status":"error","errors":[
		{"field":"name","message":"name may contain only letters"},
		{"field":"spec.policies[0]","message":"named by ref-api-1"}]}`)

	require.NoError(t, validationErrorListed(ctx, "name", "with message", "name may contain only letters"))
	require.Error(t, validationErrorListed(ctx, "name", "with message", "name may contain"))
	require.NoError(t, validationErrorListed(ctx, "name", "containing", "may contain"))
	require.NoError(t, validationErrorListed(ctx, "spec.policies[0]", "containing", "${CTX:api}"))
	require.NoError(t, validationErrorListed(ctx, "name", "", ""))
	require.Error(t, validationErrorListed(ctx, "role", "", ""))
	require.Error(t, validationErrorListed(ctx, "spec.policies[0]", "with message", "name may contain only letters"))

	publish(t, ctx, `not json`)
	require.ErrorContains(t, validationErrorListed(ctx, "name", "", ""), "not a JSON error response")
}
