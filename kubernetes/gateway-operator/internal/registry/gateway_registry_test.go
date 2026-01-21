/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package registry

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apiv1 "github.com/wso2/api-platform/kubernetes/gateway-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetGatewayRegistry_Singleton(t *testing.T) {
	registry1 := GetGatewayRegistry()
	registry2 := GetGatewayRegistry()

	assert.Same(t, registry1, registry2, "GetGatewayRegistry should return the same instance")
}

func TestGatewayRegistry_RegisterAndGet(t *testing.T) {
	// Create a new registry for testing (bypassing singleton)
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	info := &GatewayInfo{
		Name:             "test-gateway",
		Namespace:        "default",
		GatewayClassName: "production",
		ServiceName:      "test-gateway-svc",
		ServicePort:      8080,
		ControlPlaneHost: "control-plane:443",
	}

	// Register gateway
	registry.Register(info)

	// Get gateway
	retrieved, exists := registry.Get("default", "test-gateway")
	require.True(t, exists)
	assert.Equal(t, "test-gateway", retrieved.Name)
	assert.Equal(t, "default", retrieved.Namespace)
	assert.Equal(t, "production", retrieved.GatewayClassName)
	assert.Equal(t, "test-gateway-svc", retrieved.ServiceName)
	assert.Equal(t, int32(8080), retrieved.ServicePort)
}

func TestGatewayRegistry_GetNonExistent(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	_, exists := registry.Get("default", "non-existent")
	assert.False(t, exists)
}

func TestGatewayRegistry_Unregister(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	info := &GatewayInfo{
		Name:      "test-gateway",
		Namespace: "default",
	}

	registry.Register(info)

	// Verify it's registered
	_, exists := registry.Get("default", "test-gateway")
	require.True(t, exists)

	// Unregister
	registry.Unregister("default", "test-gateway")

	// Verify it's gone
	_, exists = registry.Get("default", "test-gateway")
	assert.False(t, exists)
}

func TestGatewayRegistry_ListAll(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	// Register multiple gateways
	registry.Register(&GatewayInfo{Name: "gateway-1", Namespace: "ns1"})
	registry.Register(&GatewayInfo{Name: "gateway-2", Namespace: "ns1"})
	registry.Register(&GatewayInfo{Name: "gateway-3", Namespace: "ns2"})

	all := registry.ListAll()
	assert.Len(t, all, 3)
}

func TestGatewayRegistry_ListAllEmpty(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	all := registry.ListAll()
	assert.Empty(t, all)
}

func TestGatewayRegistry_Update(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	info := &GatewayInfo{
		Name:        "test-gateway",
		Namespace:   "default",
		ServicePort: 8080,
	}
	registry.Register(info)

	// Update
	updatedInfo := &GatewayInfo{
		Name:        "test-gateway",
		Namespace:   "default",
		ServicePort: 9090,
	}
	registry.Register(updatedInfo)

	retrieved, exists := registry.Get("default", "test-gateway")
	require.True(t, exists)
	assert.Equal(t, int32(9090), retrieved.ServicePort)
}

func TestGatewayInfo_GetGatewayServiceEndpoint(t *testing.T) {
	info := &GatewayInfo{
		Name:        "my-gateway",
		Namespace:   "api-system",
		ServiceName: "my-gateway-controller",
		ServicePort: 8443,
	}

	endpoint := info.GetGatewayServiceEndpoint()
	assert.Equal(t, "http://my-gateway-controller.api-system.svc.cluster.local:8443", endpoint)
}

func TestGatewayRegistry_FindMatchingGateways_ClusterScope(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "cluster-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.ClusterScope,
		},
	})

	// Cluster-scoped gateway should match any API
	matching := registry.FindMatchingGateways("other-namespace", map[string]string{"app": "test"})
	assert.Len(t, matching, 1)
	assert.Equal(t, "cluster-gateway", matching[0].Name)
}

func TestGatewayRegistry_FindMatchingGateways_NamespacedScope(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "namespaced-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope:      apiv1.NamespacedScope,
			Namespaces: []string{"ns1", "ns2"},
		},
	})

	// Should match API in ns1
	matching := registry.FindMatchingGateways("ns1", nil)
	assert.Len(t, matching, 1)

	// Should match API in ns2
	matching = registry.FindMatchingGateways("ns2", nil)
	assert.Len(t, matching, 1)

	// Should not match API in ns3
	matching = registry.FindMatchingGateways("ns3", nil)
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_NamespacedScope_EmptyNamespaces(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "namespaced-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope:      apiv1.NamespacedScope,
			Namespaces: nil, // No namespaces specified
		},
	})

	// Should not match any API when no namespaces are specified
	matching := registry.FindMatchingGateways("default", nil)
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_LabelSelector_MatchLabels(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "label-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchLabels: map[string]string{
				"env":  "production",
				"team": "api",
			},
		},
	})

	// API with matching labels
	matching := registry.FindMatchingGateways("any-ns", map[string]string{
		"env":  "production",
		"team": "api",
	})
	assert.Len(t, matching, 1)

	// API with partial labels (missing 'team')
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "production",
	})
	assert.Empty(t, matching)

	// API with wrong label value
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"env":  "development",
		"team": "api",
	})
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_LabelSelector_In(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "label-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "env",
					Operator: "In",
					Values:   []string{"production", "staging"},
				},
			},
		},
	})

	// API with label value in the set
	matching := registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "production",
	})
	assert.Len(t, matching, 1)

	// API with another value in the set
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "staging",
	})
	assert.Len(t, matching, 1)

	// API with value not in the set
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "development",
	})
	assert.Empty(t, matching)

	// API without the label
	matching = registry.FindMatchingGateways("any-ns", map[string]string{})
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_LabelSelector_NotIn(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "label-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "env",
					Operator: "NotIn",
					Values:   []string{"development", "test"},
				},
			},
		},
	})

	// API with label value not in the excluded set
	matching := registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "production",
	})
	assert.Len(t, matching, 1)

	// API with excluded value
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "development",
	})
	assert.Empty(t, matching)

	// API without the label (NotIn matches when label doesn't exist)
	matching = registry.FindMatchingGateways("any-ns", map[string]string{})
	assert.Len(t, matching, 1)
}

func TestGatewayRegistry_FindMatchingGateways_LabelSelector_Exists(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "label-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "managed",
					Operator: "Exists",
				},
			},
		},
	})

	// API with the label
	matching := registry.FindMatchingGateways("any-ns", map[string]string{
		"managed": "true",
	})
	assert.Len(t, matching, 1)

	// API with the label (any value)
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"managed": "",
	})
	assert.Len(t, matching, 1)

	// API without the label
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"other": "value",
	})
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_LabelSelector_DoesNotExist(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "label-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "deprecated",
					Operator: "DoesNotExist",
				},
			},
		},
	})

	// API without the label
	matching := registry.FindMatchingGateways("any-ns", map[string]string{
		"other": "value",
	})
	assert.Len(t, matching, 1)

	// API with the label
	matching = registry.FindMatchingGateways("any-ns", map[string]string{
		"deprecated": "true",
	})
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_NilSelector(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:        "no-selector-gateway",
		Namespace:   "default",
		APISelector: nil,
	})

	// Gateway with nil selector should not match any API
	matching := registry.FindMatchingGateways("any-ns", nil)
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_UnknownScope(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "unknown-scope-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.APISelectorScope("Unknown"),
		},
	})

	// Gateway with unknown scope should not match any API
	matching := registry.FindMatchingGateways("any-ns", nil)
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_EmptyRegistry(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	// Empty registry should return empty slice
	matching := registry.FindMatchingGateways("any-ns", nil)
	assert.Empty(t, matching)
}

func TestGatewayRegistry_FindMatchingGateways_MultipleGateways(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	// Register multiple gateways with different selectors
	registry.Register(&GatewayInfo{
		Name:      "cluster-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.ClusterScope,
		},
	})

	registry.Register(&GatewayInfo{
		Name:      "ns1-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope:      apiv1.NamespacedScope,
			Namespaces: []string{"ns1"},
		},
	})

	registry.Register(&GatewayInfo{
		Name:      "prod-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchLabels: map[string]string{
				"env": "production",
			},
		},
	})

	// API in ns1 with production label should match 3 gateways
	matching := registry.FindMatchingGateways("ns1", map[string]string{
		"env": "production",
	})
	assert.Len(t, matching, 3)

	// API in ns2 with production label should match 2 gateways (cluster + prod)
	matching = registry.FindMatchingGateways("ns2", map[string]string{
		"env": "production",
	})
	assert.Len(t, matching, 2)

	// API in ns1 without labels should match 2 gateways (cluster + ns1)
	matching = registry.FindMatchingGateways("ns1", nil)
	assert.Len(t, matching, 2)
}

func TestGatewayRegistry_FindMatchingGateways_UnknownOperator(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	registry.Register(&GatewayInfo{
		Name:      "label-gateway",
		Namespace: "default",
		APISelector: &apiv1.APISelector{
			Scope: apiv1.LabelSelectorScope,
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "env",
					Operator: "UnknownOperator",
				},
			},
		},
	})

	// Unknown operator should cause no match
	matching := registry.FindMatchingGateways("any-ns", map[string]string{
		"env": "production",
	})
	assert.Empty(t, matching)
}

func TestGatewayRegistry_ConcurrentAccess(t *testing.T) {
	registry := &GatewayRegistry{
		gateways: make(map[string]*GatewayInfo),
	}

	done := make(chan bool)

	// Concurrent writes
	go func() {
		for i := 0; i < 100; i++ {
			registry.Register(&GatewayInfo{
				Name:      "gateway",
				Namespace: "default",
			})
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			registry.Get("default", "gateway")
		}
		done <- true
	}()

	// Concurrent deletes
	go func() {
		for i := 0; i < 100; i++ {
			registry.Unregister("default", "gateway")
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}
