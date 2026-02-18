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

package k8sutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
)

func TestNewGatewayManifestTemplateData(t *testing.T) {
	data := NewGatewayManifestTemplateData("my-gateway")

	assert.Equal(t, "my-gateway", data.GatewayName)
	assert.Equal(t, int32(1), data.Replicas)
	assert.Equal(t, "wso2/gateway-controller:latest", data.GatewayImage)
	assert.Equal(t, "wso2/gateway-router:latest", data.RouterImage)
	assert.Equal(t, "host.docker.internal:8443", data.ControlPlaneHost)
	assert.Equal(t, "info", data.LogLevel)
	assert.Equal(t, "sqlite", data.StorageType)
	assert.Equal(t, "/app/data/gateway.db", data.StorageSQLitePath)

	// Optional fields should be nil
	assert.Nil(t, data.ControlPlaneTokenSecret)
	assert.Nil(t, data.Resources)
	assert.Nil(t, data.NodeSelector)
	assert.Nil(t, data.Tolerations)
	assert.Nil(t, data.Affinity)
}

func TestNewGatewayManifestTemplateData_DifferentNames(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"simple", "simple"},
		{"production-gateway", "production-gateway"},
		{"test-env-1", "test-env-1"},
		{"a", "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := NewGatewayManifestTemplateData(tt.name)
			assert.Equal(t, tt.expected, data.GatewayName)
		})
	}
}

func TestGatewayManifestTemplateData_WithSecretReference(t *testing.T) {
	data := NewGatewayManifestTemplateData("my-gateway")

	data.ControlPlaneTokenSecret = &SecretReference{
		Name: "control-plane-token",
		Key:  "token",
	}

	require.NotNil(t, data.ControlPlaneTokenSecret)
	assert.Equal(t, "control-plane-token", data.ControlPlaneTokenSecret.Name)
	assert.Equal(t, "token", data.ControlPlaneTokenSecret.Key)
}

func TestGatewayManifestTemplateData_WithResources(t *testing.T) {
	data := NewGatewayManifestTemplateData("my-gateway")

	data.Resources = &ResourceRequirements{
		Requests: &ResourceList{
			CPU:    "100m",
			Memory: "256Mi",
		},
		Limits: &ResourceList{
			CPU:    "500m",
			Memory: "512Mi",
		},
	}

	require.NotNil(t, data.Resources)
	require.NotNil(t, data.Resources.Requests)
	require.NotNil(t, data.Resources.Limits)

	assert.Equal(t, "100m", data.Resources.Requests.CPU)
	assert.Equal(t, "256Mi", data.Resources.Requests.Memory)
	assert.Equal(t, "500m", data.Resources.Limits.CPU)
	assert.Equal(t, "512Mi", data.Resources.Limits.Memory)
}

func TestGatewayManifestTemplateData_WithNodeSelector(t *testing.T) {
	data := NewGatewayManifestTemplateData("my-gateway")

	data.NodeSelector = map[string]string{
		"kubernetes.io/os":    "linux",
		"node-type":           "api-gateway",
		"topology.kubernetes.io/zone": "us-east-1a",
	}

	assert.Len(t, data.NodeSelector, 3)
	assert.Equal(t, "linux", data.NodeSelector["kubernetes.io/os"])
	assert.Equal(t, "api-gateway", data.NodeSelector["node-type"])
	assert.Equal(t, "us-east-1a", data.NodeSelector["topology.kubernetes.io/zone"])
}

func TestGatewayManifestTemplateData_WithTolerations(t *testing.T) {
	data := NewGatewayManifestTemplateData("my-gateway")

	data.Tolerations = []corev1.Toleration{
		{
			Key:      "dedicated",
			Operator: corev1.TolerationOpEqual,
			Value:    "api-gateway",
			Effect:   corev1.TaintEffectNoSchedule,
		},
		{
			Key:      "node.kubernetes.io/not-ready",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoExecute,
		},
	}

	assert.Len(t, data.Tolerations, 2)
	assert.Equal(t, "dedicated", data.Tolerations[0].Key)
	assert.Equal(t, corev1.TolerationOpEqual, data.Tolerations[0].Operator)
	assert.Equal(t, "api-gateway", data.Tolerations[0].Value)
	assert.Equal(t, corev1.TaintEffectNoSchedule, data.Tolerations[0].Effect)
}

func TestGatewayManifestTemplateData_WithAffinity(t *testing.T) {
	data := NewGatewayManifestTemplateData("my-gateway")

	data.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
				{
					Weight: 100,
					PodAffinityTerm: corev1.PodAffinityTerm{
						TopologyKey: "kubernetes.io/hostname",
					},
				},
			},
		},
	}

	require.NotNil(t, data.Affinity)
	require.NotNil(t, data.Affinity.PodAntiAffinity)
	assert.Len(t, data.Affinity.PodAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution, 1)
}

func TestGatewayManifestTemplateData_CustomValues(t *testing.T) {
	data := NewGatewayManifestTemplateData("custom-gateway")

	// Override default values
	data.Replicas = 3
	data.GatewayImage = "custom/gateway:v2.0.0"
	data.RouterImage = "custom/router:v2.0.0"
	data.ControlPlaneHost = "control-plane.example.com:443"
	data.LogLevel = "debug"
	data.StorageType = "postgres"
	data.StorageSQLitePath = ""

	assert.Equal(t, "custom-gateway", data.GatewayName)
	assert.Equal(t, int32(3), data.Replicas)
	assert.Equal(t, "custom/gateway:v2.0.0", data.GatewayImage)
	assert.Equal(t, "custom/router:v2.0.0", data.RouterImage)
	assert.Equal(t, "control-plane.example.com:443", data.ControlPlaneHost)
	assert.Equal(t, "debug", data.LogLevel)
	assert.Equal(t, "postgres", data.StorageType)
	assert.Empty(t, data.StorageSQLitePath)
}

func TestSecretReference_Struct(t *testing.T) {
	ref := &SecretReference{
		Name: "my-secret",
		Key:  "my-key",
	}

	assert.Equal(t, "my-secret", ref.Name)
	assert.Equal(t, "my-key", ref.Key)
}

func TestResourceRequirements_Struct(t *testing.T) {
	req := &ResourceRequirements{
		Requests: &ResourceList{
			CPU:    "100m",
			Memory: "128Mi",
		},
		Limits: &ResourceList{
			CPU:    "1000m",
			Memory: "1Gi",
		},
	}

	assert.Equal(t, "100m", req.Requests.CPU)
	assert.Equal(t, "128Mi", req.Requests.Memory)
	assert.Equal(t, "1000m", req.Limits.CPU)
	assert.Equal(t, "1Gi", req.Limits.Memory)
}

func TestResourceList_Struct(t *testing.T) {
	list := &ResourceList{
		CPU:    "500m",
		Memory: "512Mi",
	}

	assert.Equal(t, "500m", list.CPU)
	assert.Equal(t, "512Mi", list.Memory)
}

func TestGatewayManifestTemplateData_AllFieldsPopulated(t *testing.T) {
	data := &GatewayManifestTemplateData{
		GatewayName:      "full-gateway",
		Replicas:         5,
		GatewayImage:     "custom/gateway:latest",
		RouterImage:      "custom/router:latest",
		ControlPlaneHost: "cp.example.com:443",
		ControlPlaneTokenSecret: &SecretReference{
			Name: "cp-token",
			Key:  "token",
		},
		LogLevel:          "debug",
		StorageType:       "postgres",
		StorageSQLitePath: "",
		Resources: &ResourceRequirements{
			Requests: &ResourceList{
				CPU:    "200m",
				Memory: "256Mi",
			},
			Limits: &ResourceList{
				CPU:    "2000m",
				Memory: "2Gi",
			},
		},
		NodeSelector: map[string]string{
			"env": "production",
		},
		Tolerations: []corev1.Toleration{
			{
				Key:      "dedicated",
				Operator: corev1.TolerationOpEqual,
				Value:    "gateway",
				Effect:   corev1.TaintEffectNoSchedule,
			},
		},
		Affinity: &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{},
		},
	}

	// Verify all fields
	assert.Equal(t, "full-gateway", data.GatewayName)
	assert.Equal(t, int32(5), data.Replicas)
	assert.Equal(t, "custom/gateway:latest", data.GatewayImage)
	assert.Equal(t, "custom/router:latest", data.RouterImage)
	assert.Equal(t, "cp.example.com:443", data.ControlPlaneHost)
	require.NotNil(t, data.ControlPlaneTokenSecret)
	assert.Equal(t, "cp-token", data.ControlPlaneTokenSecret.Name)
	assert.Equal(t, "debug", data.LogLevel)
	assert.Equal(t, "postgres", data.StorageType)
	assert.Empty(t, data.StorageSQLitePath)
	require.NotNil(t, data.Resources)
	assert.NotNil(t, data.NodeSelector)
	assert.Len(t, data.Tolerations, 1)
	assert.NotNil(t, data.Affinity)
}
