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

package controller

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGatewayTracker(t *testing.T) {
	tracker := NewGatewayTracker()
	assert.NotNil(t, tracker)
	assert.NotNil(t, tracker.entries)
}

func TestGatewayTracker_SetAndGet(t *testing.T) {
	tracker := NewGatewayTracker()

	entry := &GatewayTrackingEntry{
		Generation:    1,
		Status:        GatewayTrackingStatusProcessing,
		RetryCount:    0,
		LastRetryTime: time.Now(),
	}

	tracker.Set("default/my-gateway", entry)

	retrieved, exists := tracker.Get("default/my-gateway")
	require.True(t, exists)
	assert.Equal(t, int64(1), retrieved.Generation)
	assert.Equal(t, GatewayTrackingStatusProcessing, retrieved.Status)
	assert.Equal(t, 0, retrieved.RetryCount)
}

func TestGatewayTracker_GetNonExistent(t *testing.T) {
	tracker := NewGatewayTracker()

	_, exists := tracker.Get("default/non-existent")
	assert.False(t, exists)
}

func TestGatewayTracker_Delete(t *testing.T) {
	tracker := NewGatewayTracker()

	entry := &GatewayTrackingEntry{
		Generation: 1,
		Status:     GatewayTrackingStatusDeployed,
	}

	tracker.Set("default/my-gateway", entry)

	// Verify it exists
	_, exists := tracker.Get("default/my-gateway")
	require.True(t, exists)

	// Delete it
	tracker.Delete("default/my-gateway")

	// Verify it's gone
	_, exists = tracker.Get("default/my-gateway")
	assert.False(t, exists)
}

func TestGatewayTracker_DeleteNonExistent(t *testing.T) {
	tracker := NewGatewayTracker()

	// Should not panic
	tracker.Delete("default/non-existent")
}

func TestGatewayTracker_Update(t *testing.T) {
	tracker := NewGatewayTracker()

	// Initial entry
	entry1 := &GatewayTrackingEntry{
		Generation: 1,
		Status:     GatewayTrackingStatusProcessing,
		RetryCount: 0,
	}
	tracker.Set("default/my-gateway", entry1)

	// Update entry
	entry2 := &GatewayTrackingEntry{
		Generation: 1,
		Status:     GatewayTrackingStatusDeployed,
		RetryCount: 0,
	}
	tracker.Set("default/my-gateway", entry2)

	retrieved, exists := tracker.Get("default/my-gateway")
	require.True(t, exists)
	assert.Equal(t, GatewayTrackingStatusDeployed, retrieved.Status)
}

func TestGatewayTracker_MultipleEntries(t *testing.T) {
	tracker := NewGatewayTracker()

	entries := map[string]*GatewayTrackingEntry{
		"default/gateway-1": {Generation: 1, Status: GatewayTrackingStatusDeployed},
		"default/gateway-2": {Generation: 2, Status: GatewayTrackingStatusProcessing},
		"kube-system/gateway-3": {Generation: 1, Status: GatewayTrackingStatusRetrying, RetryCount: 3},
	}

	for key, entry := range entries {
		tracker.Set(key, entry)
	}

	// Verify all entries
	for key, expected := range entries {
		retrieved, exists := tracker.Get(key)
		require.True(t, exists, "Entry %s should exist", key)
		assert.Equal(t, expected.Generation, retrieved.Generation)
		assert.Equal(t, expected.Status, retrieved.Status)
		assert.Equal(t, expected.RetryCount, retrieved.RetryCount)
	}
}

func TestGatewayTracker_GetReturnsCopy(t *testing.T) {
	tracker := NewGatewayTracker()

	entry := &GatewayTrackingEntry{
		Generation: 1,
		Status:     GatewayTrackingStatusProcessing,
		RetryCount: 0,
	}
	tracker.Set("default/my-gateway", entry)

	// Get a copy
	retrieved, _ := tracker.Get("default/my-gateway")

	// Modify the copy
	retrieved.Status = GatewayTrackingStatusDeployed
	retrieved.RetryCount = 5

	// Original should be unchanged
	original, _ := tracker.Get("default/my-gateway")
	assert.Equal(t, GatewayTrackingStatusProcessing, original.Status)
	assert.Equal(t, 0, original.RetryCount)
}

func TestGatewayTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewGatewayTracker()

	done := make(chan bool)

	// Concurrent writes
	go func() {
		for i := 0; i < 100; i++ {
			tracker.Set("default/gateway", &GatewayTrackingEntry{
				Generation: int64(i),
				Status:     GatewayTrackingStatusProcessing,
			})
		}
		done <- true
	}()

	// Concurrent reads
	go func() {
		for i := 0; i < 100; i++ {
			tracker.Get("default/gateway")
		}
		done <- true
	}()

	// Concurrent deletes on different key
	go func() {
		for i := 0; i < 100; i++ {
			tracker.Delete("default/other-gateway")
		}
		done <- true
	}()

	// Wait for all goroutines
	<-done
	<-done
	<-done
}

func TestGatewayTrackingStatus_Values(t *testing.T) {
	assert.Equal(t, GatewayTrackingStatus("Processing"), GatewayTrackingStatusProcessing)
	assert.Equal(t, GatewayTrackingStatus("Retrying"), GatewayTrackingStatusRetrying)
	assert.Equal(t, GatewayTrackingStatus("Deployed"), GatewayTrackingStatusDeployed)
	assert.Equal(t, GatewayTrackingStatus("ConfigChanged"), GatewayTrackingStatusConfigChanged)
}

func TestGatewayTrackingEntry_AllFields(t *testing.T) {
	now := time.Now()
	later := now.Add(5 * time.Minute)

	entry := &GatewayTrackingEntry{
		Generation:    5,
		Status:        GatewayTrackingStatusRetrying,
		RetryCount:    3,
		LastRetryTime: now,
		NextRetryTime: later,
	}

	assert.Equal(t, int64(5), entry.Generation)
	assert.Equal(t, GatewayTrackingStatusRetrying, entry.Status)
	assert.Equal(t, 3, entry.RetryCount)
	assert.Equal(t, now, entry.LastRetryTime)
	assert.Equal(t, later, entry.NextRetryTime)
}

func TestGatewayTrackingEntry_DefaultValues(t *testing.T) {
	entry := &GatewayTrackingEntry{}

	assert.Equal(t, int64(0), entry.Generation)
	assert.Equal(t, GatewayTrackingStatus(""), entry.Status)
	assert.Equal(t, 0, entry.RetryCount)
	assert.True(t, entry.LastRetryTime.IsZero())
	assert.True(t, entry.NextRetryTime.IsZero())
}

func TestGatewayTracker_KeyFormat(t *testing.T) {
	tracker := NewGatewayTracker()

	// Keys are typically "namespace/name"
	keys := []string{
		"default/my-gateway",
		"kube-system/system-gateway",
		"api-system/production-gateway",
		"ns-with-dash/gw-with-dash",
	}

	for _, key := range keys {
		entry := &GatewayTrackingEntry{
			Generation: 1,
			Status:     GatewayTrackingStatusDeployed,
		}
		tracker.Set(key, entry)

		retrieved, exists := tracker.Get(key)
		require.True(t, exists, "Key %s should exist", key)
		assert.Equal(t, int64(1), retrieved.Generation)
	}
}
