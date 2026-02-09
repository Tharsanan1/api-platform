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
	"database/sql"
	_ "embed"
	"fmt"
	"log/slog"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed gateway-controller-db.sql
var schemaSQL string

const (
	sqliteUniqueDeploymentsNameVersion = "UNIQUE constraint failed: deployments.display_name, deployments.version"
	sqliteUniqueDeploymentsID          = "UNIQUE constraint failed: deployments.id"
	sqliteUniqueDeploymentsHandle      = "UNIQUE constraint failed: deployments.handle"
	sqliteUniqueCertificatesName       = "UNIQUE constraint failed: certificates.name"
	sqliteUniqueCertificatesID         = "UNIQUE constraint failed: certificates.id"
	sqliteUniqueTemplatesHandle        = "UNIQUE constraint failed: llm_provider_templates.handle"
	sqliteUniqueAPIKeysKey             = "UNIQUE constraint failed: api_keys.api_key"
	sqliteUniqueAPIKeysID              = "UNIQUE constraint failed: api_keys.id"
	sqliteUniqueAPIKeysExternalIndex   = "UNIQUE constraint failed: index 'idx_unique_external_api_key'"
)

// SQLiteStorage implements the Storage interface using SQLite
type SQLiteStorage struct {
	db     *sql.DB
	logger *slog.Logger
}

// newSQLiteStorage creates a new SQLite storage instance.
func newSQLiteStorage(dbPath string, logger *slog.Logger) (*SQLiteStorage, error) {
	// Build connection string with SQLite pragmas for optimal performance
	dsn := fmt.Sprintf("file:%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_cache_size=2000&_foreign_keys=ON", dbPath)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// CRITICAL: Prevents "database is locked" errors with concurrent access
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	storage := &SQLiteStorage{
		db:     db,
		logger: logger,
	}

	// Initialize schema if needed
	if err := storage.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logger.Info("SQLite storage initialized",
		slog.String("database_path", dbPath),
		slog.String("journal_mode", "WAL"))

	return storage, nil
}

// initSchema creates the database schema if it doesn't exist
func (s *SQLiteStorage) initSchema() error {
	// Check schema version
	var version int
	err := s.db.QueryRow("PRAGMA user_version").Scan(&version)
	if err != nil {
		return fmt.Errorf("failed to query schema version: %w", err)
	}

	if version == 0 {
		s.logger.Info("Initializing database schema (version 6)")
		s.logger.Debug("Creating schema with SQL", slog.String("schema_sql", schemaSQL))

		// Execute schema creation SQL
		if _, err := s.db.Exec(schemaSQL); err != nil {
			return fmt.Errorf("failed to create schema: %w", err)
		}

		s.logger.Info("Database schema initialized successfully")
	} else {
		// Migrations
		if version == 1 {
			// Add policy_definitions table (idempotent due to IF NOT EXISTS in embedded schema)
			if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS policy_definitions (
				name TEXT NOT NULL,
				version TEXT NOT NULL,
				provider TEXT NOT NULL,
				description TEXT,
				flows_request_require_header INTEGER,
				flows_request_require_body INTEGER,
				flows_response_require_header INTEGER,
				flows_response_require_body INTEGER,
				parameters_schema TEXT,
				PRIMARY KEY (name, version)
			);`); err != nil {
				return fmt.Errorf("failed to migrate schema to version 2: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_policy_provider ON policy_definitions(provider);`); err != nil {
				return fmt.Errorf("failed to create policy_definitions index: %w", err)
			}
			if _, err := s.db.Exec("PRAGMA user_version = 2"); err != nil {
				return fmt.Errorf("failed to set schema version to 2: %w", err)
			}
			s.logger.Info("Schema migrated to version 2 (policy_definitions)")
			version = 2
		}

		if version == 2 {
			// Add certificates table
			if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS certificates (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL UNIQUE,
				certificate BLOB NOT NULL,
				subject TEXT NOT NULL,
				issuer TEXT NOT NULL,
				not_before TIMESTAMP NOT NULL,
				not_after TIMESTAMP NOT NULL,
				cert_count INTEGER NOT NULL DEFAULT 1,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			);`); err != nil {
				return fmt.Errorf("failed to migrate schema to version 3 (certificates): %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_cert_name ON certificates(name);`); err != nil {
				return fmt.Errorf("failed to create certificates name index: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_cert_expiry ON certificates(not_after);`); err != nil {
				return fmt.Errorf("failed to create certificates expiry index: %w", err)
			}
			if _, err := s.db.Exec("PRAGMA user_version = 3"); err != nil {
				return fmt.Errorf("failed to set schema version to 3: %w", err)
			}
			s.logger.Info("Schema migrated to version 3 (certificates table)")
			version = 3
		}

		if version == 3 {
			// Add llm_provider_templates table
			if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS llm_provider_templates (
				id TEXT PRIMARY KEY,
				handle TEXT NOT NULL UNIQUE,
				configuration TEXT NOT NULL,
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
			);`); err != nil {
				return fmt.Errorf("failed to migrate schema to version 4: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_template_handle ON llm_provider_templates(handle);`); err != nil {
				return fmt.Errorf("failed to create llm_provider_templates index: %w", err)
			}
			if _, err := s.db.Exec("PRAGMA user_version = 4"); err != nil {
				return fmt.Errorf("failed to set schema version to 4: %w", err)
			}

			s.logger.Info("Schema migrated to version 4 (llm_provider_templates)")

			version = 4
		}

		if version == 4 {
			// Add API keys table with masked_api_key column
			if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS api_keys (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				api_key TEXT NOT NULL UNIQUE,
				masked_api_key TEXT NOT NULL,
				apiId TEXT NOT NULL,
				operations TEXT NOT NULL DEFAULT '*',
				status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'expired')) DEFAULT 'active',
				created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				created_by TEXT NOT NULL DEFAULT 'system',
				updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
				expires_at TIMESTAMP NULL,
				expires_in_unit TEXT NULL,
				expires_in_duration INTEGER NULL,
				FOREIGN KEY (apiId) REFERENCES deployments(id) ON DELETE CASCADE,
				UNIQUE (apiId, name)
			);`); err != nil {
				return fmt.Errorf("failed to migrate schema to version 5 (api_keys): %w", err)
			}

			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key ON api_keys(api_key);`); err != nil {
				return fmt.Errorf("failed to create api_keys key index: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key_api ON api_keys(apiId);`); err != nil {
				return fmt.Errorf("failed to create api_keys handle index: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key_status ON api_keys(status);`); err != nil {
				return fmt.Errorf("failed to create api_keys status index: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key_expiry ON api_keys(expires_at);`); err != nil {
				return fmt.Errorf("failed to create api_keys expiry index: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_created_by ON api_keys(created_by);`); err != nil {
				return fmt.Errorf("failed to create api_keys created_by index: %w", err)
			}
			if _, err := s.db.Exec("PRAGMA user_version = 5"); err != nil {
				return fmt.Errorf("failed to set schema version to 5: %w", err)
			}
			s.logger.Info("Schema migrated to version 5 (api_keys table with masked_api_key)")
			version = 5
		}

		if version == 5 {
			// Check if masked_api_key column exists, if not add it (for existing tables)
			var columnExists int
			err := s.db.QueryRow(`
				SELECT COUNT(*) FROM pragma_table_info('api_keys') 
				WHERE name = 'masked_api_key'
			`).Scan(&columnExists)
			if err == nil && columnExists == 0 {
				// Column doesn't exist, add it (as nullable first, then update)
				if _, err := s.db.Exec(`ALTER TABLE api_keys ADD COLUMN masked_api_key TEXT`); err != nil {
					return fmt.Errorf("failed to add masked_api_key column: %w", err)
				}
				// Update existing rows to have a masked version of their api_key
				if _, err := s.db.Exec(`
					UPDATE api_keys 
					SET masked_api_key = CASE 
						WHEN length(api_key) > 12 THEN substr(api_key, 1, 8) || '...' || substr(api_key, -4)
						ELSE api_key
					END
					WHERE masked_api_key IS NULL
				`); err != nil {
					s.logger.Warn("Failed to update existing masked_api_key values", slog.Any("error", err))
				}
			}

			// Add external API key support columns (only if missing; fresh DBs may already have them)
			err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = 'source'`).Scan(&columnExists)
			if err == nil && columnExists == 0 {
				if _, err := s.db.Exec(`ALTER TABLE api_keys ADD COLUMN source TEXT NOT NULL DEFAULT 'local'`); err != nil {
					return fmt.Errorf("failed to add source column to api_keys: %w", err)
				}
			}
			err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = 'external_ref_id'`).Scan(&columnExists)
			if err == nil && columnExists == 0 {
				if _, err := s.db.Exec(`ALTER TABLE api_keys ADD COLUMN external_ref_id TEXT NULL`); err != nil {
					return fmt.Errorf("failed to add external_ref_id column to api_keys: %w", err)
				}
			}
			// Backfill legacy keys: treat NULL, empty, or 'null' source as 'local' (DB + local cache consistency)
			if _, err := s.db.Exec(`
				UPDATE api_keys
				SET source = 'local'
				WHERE
					source IS NULL
					OR trim(source) = ''
					OR lower(trim(source)) = 'null'
			`); err != nil {
				s.logger.Warn("Failed to backfill api_keys.source for legacy keys", slog.Any("error", err))
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key_source ON api_keys(source);`); err != nil {
				return fmt.Errorf("failed to create api_keys source index: %w", err)
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key_external_ref ON api_keys(external_ref_id);`); err != nil {
				return fmt.Errorf("failed to create api_keys external_ref_id index: %w", err)
			}
			// Add index_key column for O(1) external API key lookup optimization
			err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = 'index_key'`).Scan(&columnExists)
			if err == nil && columnExists == 0 {
				if _, err := s.db.Exec(`ALTER TABLE api_keys ADD COLUMN index_key TEXT NULL`); err != nil {
					return fmt.Errorf("failed to add index_key column to api_keys: %w", err)
				}
			}
			if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_api_key_index_key ON api_keys(index_key);`); err != nil {
				return fmt.Errorf("failed to create api_keys index_key index: %w", err)
			}
			// Add display_name column for human-readable API key names
			err = s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('api_keys') WHERE name = 'display_name'`).Scan(&columnExists)
			if err == nil && columnExists == 0 {
				if _, err := s.db.Exec(`ALTER TABLE api_keys ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`); err != nil {
					return fmt.Errorf("failed to add display_name column to api_keys: %w", err)
				}
				// Backfill existing rows: set display_name = name for existing API keys
				if _, err := s.db.Exec(`UPDATE api_keys SET display_name = name WHERE display_name = ''`); err != nil {
					s.logger.Warn("Failed to backfill api_keys.display_name", slog.Any("error", err))
				}
			}
			if _, err := s.db.Exec("PRAGMA user_version = 6"); err != nil {
				return fmt.Errorf("failed to set schema version to 6: %w", err)
			}
			s.logger.Info("Schema migrated to version 6 (api_keys: external ref, index_key, display_name)")
			version = 6
		}

		s.logger.Info("Database schema up to date", slog.Int("version", version))
	}

	return nil
}

func isUniqueConstraintError(err error) bool {
	// SQLite error code 19 is CONSTRAINT error
	// Error message contains "UNIQUE constraint failed"
	return err != nil && (err.Error() == sqliteUniqueDeploymentsNameVersion ||
		err.Error() == sqliteUniqueDeploymentsID ||
		err.Error() == sqliteUniqueDeploymentsHandle)
}

// isCertificateUniqueConstraintError checks if the error is a UNIQUE constraint violation for certificates
func isCertificateUniqueConstraintError(err error) bool {
	// SQLite error code 19 is CONSTRAINT error
	// Error message contains "UNIQUE constraint failed"
	return err != nil && (err.Error() == sqliteUniqueCertificatesName ||
		err.Error() == sqliteUniqueCertificatesID)
}

func isTemplateUniqueConstraintError(err error) bool {
	return err != nil && err.Error() == sqliteUniqueTemplatesHandle
}

// Helper function to check for API key unique constraint errors
func isAPIKeyUniqueConstraintError(err error) bool {
	return err != nil &&
		(err.Error() == sqliteUniqueAPIKeysKey ||
			err.Error() == sqliteUniqueAPIKeysID ||
			err.Error() == sqliteUniqueAPIKeysExternalIndex)
}
