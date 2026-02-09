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

import "fmt"

// LoadFromDatabase loads all configurations from database into the in-memory cache.
func LoadFromDatabase(storage Storage, cache *ConfigStore) error {
	configs, err := storage.GetAllConfigs()
	if err != nil {
		return fmt.Errorf("failed to load configurations from database: %w", err)
	}

	for _, cfg := range configs {
		if err := cache.Add(cfg); err != nil {
			return fmt.Errorf("failed to load config %s into cache: %w", cfg.ID, err)
		}
	}

	return nil
}

// LoadLLMProviderTemplatesFromDatabase loads all LLM Provider templates from database into in-memory store.
func LoadLLMProviderTemplatesFromDatabase(storage Storage, cache *ConfigStore) error {
	templates, err := storage.GetAllLLMProviderTemplates()
	if err != nil {
		return fmt.Errorf("failed to load templates from database: %w", err)
	}

	for _, template := range templates {
		if err := cache.AddTemplate(template); err != nil {
			return fmt.Errorf("failed to load llm provider template %s into cache: %w", template.GetHandle(), err)
		}
	}

	return nil
}

// LoadAPIKeysFromDatabase loads all API keys from database into both the ConfigStore and APIKeyStore.
func LoadAPIKeysFromDatabase(storage Storage, configStore *ConfigStore, apiKeyStore *APIKeyStore) error {
	apiKeys, err := storage.GetAllAPIKeys()
	if err != nil {
		return fmt.Errorf("failed to load API keys from database: %w", err)
	}

	for _, apiKey := range apiKeys {
		if err := configStore.StoreAPIKey(apiKey); err != nil {
			return fmt.Errorf("failed to load API key %s into ConfigStore: %w", apiKey.ID, err)
		}

		if err := apiKeyStore.Store(apiKey); err != nil {
			return fmt.Errorf("failed to load API key %s into APIKeyStore: %w", apiKey.ID, err)
		}
	}

	return nil
}
