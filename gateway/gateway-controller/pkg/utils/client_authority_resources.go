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

package utils

import (
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/lazyresourcexds"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/storage"
)

// ClientAuthorityPublisher publishes the gateway's client certificate
// authority pool to the policy engine as shared lazy resources, one
// LazyResourceTypeClientCertificateAuthority resource per usage: client row:
//
//	ID:       the row's name
//	Resource: {"certificates": ["<PEM>", ...], "role": "client" | "relay",
//	           "match": {"uriSANs": [...], "dnsSANs": [...]}}
//
// "certificates" holds one PEM string per certificate in the row. "match" is
// present only for a relay row stored with narrowing, and carries only the
// lists that row has. The mtls-auth policy reads these resources on the
// engine side; a policy chain carries only an API's own accept names and
// narrowing, so a pool change reaches every API through this one push.
type ClientAuthorityPublisher struct {
	certificates config.MtlsAuthCertificateStore
	resources    *lazyresourcexds.LazyResourceStateManager

	// mu serialises Publish so that two certificate writes finishing close
	// together cannot interleave their reads and writes: the last Publish to
	// run always reads the latest committed pool and leaves exactly that
	// published.
	mu sync.Mutex
}

// NewClientAuthorityPublisher creates a publisher reading the pool from
// certificates and publishing it through resources.
func NewClientAuthorityPublisher(certificates config.MtlsAuthCertificateStore, resources *lazyresourcexds.LazyResourceStateManager) *ClientAuthorityPublisher {
	return &ClientAuthorityPublisher{certificates: certificates, resources: resources}
}

// Publish makes the published client authority resources match the usage:
// client rows currently in the database: every row is stored (a row whose
// resource is already published unchanged is left alone), then every
// published resource with no row left is removed. Storing before removing
// means no intermediate snapshot lacks a row that still exists.
func (p *ClientAuthorityPublisher) Publish(correlationID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	rows, err := p.certificates.ListCertificatesByUsage(models.CertificateUsageClient)
	if err != nil {
		return fmt.Errorf("listing client certificate authorities: %w", err)
	}

	published := p.resources.GetResourcesByType(LazyResourceTypeClientCertificateAuthority)
	current := make(map[string]struct{}, len(rows))
	for _, row := range rows {
		current[row.Name] = struct{}{}
		resource := clientAuthorityResource(row)
		if existing, ok := published[row.Name]; ok && reflect.DeepEqual(existing.Resource, resource.Resource) {
			continue
		}
		if err := p.resources.StoreResource(resource, correlationID); err != nil {
			return fmt.Errorf("publishing client certificate authority %q: %w", row.Name, err)
		}
	}

	for name := range published {
		if _, ok := current[name]; ok {
			continue
		}
		if err := p.resources.RemoveResourceByIDAndType(name, LazyResourceTypeClientCertificateAuthority, correlationID); err != nil {
			return fmt.Errorf("removing client certificate authority %q: %w", name, err)
		}
	}
	return nil
}

// clientAuthorityResource builds the published resource for one usage:
// client row, in the shape documented on ClientAuthorityPublisher.
func clientAuthorityResource(row *models.StoredCertificate) *storage.LazyResource {
	role := row.Role
	if role == "" {
		role = models.CertificateRoleClient
	}
	body := map[string]interface{}{
		"certificates": splitCertificatePEMs(row.Certificate),
		"role":         role,
	}
	if role == models.CertificateRoleRelay && row.Match != nil {
		match := map[string]interface{}{}
		if len(row.Match.URISANs) > 0 {
			match["uriSANs"] = row.Match.URISANs
		}
		if len(row.Match.DNSSANs) > 0 {
			match["dnsSANs"] = row.Match.DNSSANs
		}
		if len(match) > 0 {
			body["match"] = match
		}
	}
	return &storage.LazyResource{
		ID:           row.Name,
		ResourceType: LazyResourceTypeClientCertificateAuthority,
		Resource:     body,
	}
}

// splitCertificatePEMs decodes every CERTIFICATE PEM block in data, in
// order, re-encoding each one individually so the result holds exactly one
// certificate per string (dropping any other block type and any stray bytes
// between or around blocks). Certificate material only; never logged.
func splitCertificatePEMs(data []byte) []string {
	out := []string{}
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return out
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		out = append(out, strings.TrimRight(string(pem.EncodeToMemory(block)), "\n"))
	}
}
