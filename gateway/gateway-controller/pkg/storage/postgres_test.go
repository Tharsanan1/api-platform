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

package storage

import (
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/metrics"
	"gotest.tools/v3/assert"
)

func setupTestPostgresStorage(t *testing.T) *PostgresStorage {
	t.Helper()

	dsn := os.Getenv("POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_TEST_DSN is not set; skipping postgres integration tests")
	}

	metrics.SetEnabled(false)
	metrics.Init()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pg, err := NewPostgresStorage(PostgresConnectionConfig{DSN: dsn}, logger)
	assert.NilError(t, err)
	return pg
}

func TestNewPostgresStorage_Success(t *testing.T) {
	pg := setupTestPostgresStorage(t)
	defer pg.Close()
	assert.Assert(t, pg != nil)
}

func TestPostgresStorage_ConfigCRUD(t *testing.T) {
	pg := setupTestPostgresStorage(t)
	defer pg.Close()

	cfg := createTestStoredConfig()
	assert.NilError(t, pg.SaveConfig(cfg))
	defer pg.DeleteConfig(cfg.ID)

	stored, err := pg.GetConfig(cfg.ID)
	assert.NilError(t, err)
	assert.Equal(t, stored.ID, cfg.ID)
	assert.Equal(t, stored.GetHandle(), cfg.GetHandle())

	assert.NilError(t, pg.DeleteConfig(cfg.ID))
	_, err = pg.GetConfig(cfg.ID)
	assert.Assert(t, err != nil)
	assert.Assert(t, IsNotFoundError(err))
}

func TestPostgresStorage_TemplateAndAPIKeyCRUD(t *testing.T) {
	pg := setupTestPostgresStorage(t)
	defer pg.Close()

	tmpl := createTestLLMProviderTemplate()
	assert.NilError(t, pg.SaveLLMProviderTemplate(tmpl))
	defer pg.DeleteLLMProviderTemplate(tmpl.ID)

	loadedTemplate, err := pg.GetLLMProviderTemplate(tmpl.ID)
	assert.NilError(t, err)
	assert.Equal(t, loadedTemplate.ID, tmpl.ID)
	assert.Equal(t, loadedTemplate.GetHandle(), tmpl.GetHandle())

	cfg := createTestStoredConfig()
	assert.NilError(t, pg.SaveConfig(cfg))
	defer pg.DeleteConfig(cfg.ID)

	apiKey := createTestAPIKey()
	apiKey.APIId = cfg.ID
	apiKey.Source = "local"
	assert.NilError(t, pg.SaveAPIKey(apiKey))
	defer pg.RemoveAPIKeyAPIAndName(apiKey.APIId, apiKey.Name)

	loadedKey, err := pg.GetAPIKeyByID(apiKey.ID)
	assert.NilError(t, err)
	assert.Equal(t, loadedKey.ID, apiKey.ID)
	assert.Equal(t, loadedKey.APIId, apiKey.APIId)

	count, err := pg.CountActiveAPIKeysByUserAndAPI(apiKey.APIId, apiKey.CreatedBy)
	assert.NilError(t, err)
	assert.Assert(t, count >= 1)
}
