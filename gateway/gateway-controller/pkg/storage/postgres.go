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
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/metrics"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

//go:embed gateway-controller-db.postgres.sql
var postgresSchemaSQL string

const (
	postgresSchemaVersion = 6
	postgresSchemaLockID  = int64(749251473)
)

// PostgresConnectionConfig holds PostgreSQL-specific connection settings.
type PostgresConnectionConfig struct {
	DSN             string
	Host            string
	Port            int
	Database        string
	User            string
	Password        string
	SSLMode         string
	ConnectTimeout  time.Duration
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
	ApplicationName string
}

// PostgresStorage implements the Storage interface using PostgreSQL.
type PostgresStorage struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewPostgresStorage creates a new PostgreSQL storage instance.
func NewPostgresStorage(cfg PostgresConnectionConfig, logger *slog.Logger) (*PostgresStorage, error) {
	cfg = withDefaultPostgresConfig(cfg)
	dsn, err := buildPostgresDSN(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to build postgres dsn: %w", err)
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open postgres database: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	storage := &PostgresStorage{
		db:     db,
		logger: logger,
	}

	pingTimeout := cfg.ConnectTimeout
	if pingTimeout <= 0 {
		pingTimeout = 5 * time.Second
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping postgres database: %w", err)
	}

	if err := storage.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logger.Info("PostgreSQL storage initialized",
		slog.String("host", cfg.Host),
		slog.Int("port", cfg.Port),
		slog.String("database", cfg.Database),
		slog.String("sslmode", cfg.SSLMode),
		slog.Int("max_open_conns", cfg.MaxOpenConns),
		slog.Int("max_idle_conns", cfg.MaxIdleConns),
		slog.Duration("conn_max_lifetime", cfg.ConnMaxLifetime),
		slog.Duration("conn_max_idle_time", cfg.ConnMaxIdleTime),
		slog.String("dsn", sanitizePostgresDSN(dsn)))

	return storage, nil
}

// initSchema creates the database schema if it doesn't exist.
func (s *PostgresStorage) initSchema() error {
	if _, err := s.exec(`SELECT pg_advisory_lock(?)`, postgresSchemaLockID); err != nil {
		return fmt.Errorf("failed to acquire schema migration lock: %w", err)
	}
	defer func() {
		if _, err := s.exec(`SELECT pg_advisory_unlock(?)`, postgresSchemaLockID); err != nil {
			s.logger.Warn("Failed to release schema migration lock", slog.Any("error", err))
		}
	}()

	if _, err := s.exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			id INTEGER PRIMARY KEY,
			version INTEGER NOT NULL,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		return fmt.Errorf("failed to ensure schema_migrations table: %w", err)
	}
	if _, err := s.exec(`
		INSERT INTO schema_migrations (id, version)
		VALUES (1, 0)
		ON CONFLICT (id) DO NOTHING
	`); err != nil {
		return fmt.Errorf("failed to initialize schema_migrations row: %w", err)
	}

	var version int
	if err := s.queryRow(`SELECT version FROM schema_migrations WHERE id = 1`).Scan(&version); err != nil {
		return fmt.Errorf("failed to query schema version: %w", err)
	}

	if version < postgresSchemaVersion {
		s.logger.Info("Initializing PostgreSQL schema", slog.Int("target_version", postgresSchemaVersion))
		if err := s.execSchemaStatements(postgresSchemaSQL); err != nil {
			return fmt.Errorf("failed to execute postgres schema: %w", err)
		}
		if _, err := s.exec(`
			UPDATE schema_migrations
			SET version = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = 1
		`, postgresSchemaVersion); err != nil {
			return fmt.Errorf("failed to update schema_migrations: %w", err)
		}
		version = postgresSchemaVersion
	}

	s.logger.Info("PostgreSQL schema up to date", slog.Int("version", version))
	return nil
}

func (s *PostgresStorage) execSchemaStatements(schema string) error {
	for _, stmt := range strings.Split(schema, ";") {
		sqlStmt := strings.TrimSpace(stmt)
		if sqlStmt == "" {
			continue
		}
		if _, err := s.db.Exec(sqlStmt); err != nil {
			return err
		}
	}
	return nil
}

func withDefaultPostgresConfig(cfg PostgresConnectionConfig) PostgresConnectionConfig {
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "require"
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 5 * time.Second
	}
	if cfg.MaxOpenConns == 0 {
		cfg.MaxOpenConns = 25
	}
	if cfg.MaxIdleConns == 0 {
		cfg.MaxIdleConns = 5
	}
	if cfg.ConnMaxLifetime == 0 {
		cfg.ConnMaxLifetime = 30 * time.Minute
	}
	if cfg.ConnMaxIdleTime == 0 {
		cfg.ConnMaxIdleTime = 5 * time.Minute
	}
	if cfg.ApplicationName == "" {
		cfg.ApplicationName = "gateway-controller"
	}
	return cfg
}

func buildPostgresDSN(cfg PostgresConnectionConfig) (string, error) {
	if strings.TrimSpace(cfg.DSN) != "" {
		return cfg.DSN, nil
	}
	if cfg.Host == "" || cfg.Database == "" || cfg.User == "" {
		return "", fmt.Errorf("host, database and user are required when dsn is not provided")
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, cfg.Password),
		Host:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Path:   cfg.Database,
	}
	q := u.Query()
	q.Set("sslmode", cfg.SSLMode)
	timeoutSec := int(cfg.ConnectTimeout.Seconds())
	if timeoutSec <= 0 {
		timeoutSec = 5
	}
	q.Set("connect_timeout", strconv.Itoa(timeoutSec))
	if cfg.ApplicationName != "" {
		q.Set("application_name", cfg.ApplicationName)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func sanitizePostgresDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<redacted>"
	}
	if u.User != nil {
		username := u.User.Username()
		if username != "" {
			u.User = url.UserPassword(username, "****")
		}
	}
	return u.String()
}

// SaveConfig persists a new deployment configuration
func (s *PostgresStorage) SaveConfig(cfg *models.StoredConfig) error {
	// Extract fields for indexed columns
	displayName := cfg.GetDisplayName()
	version := cfg.GetVersion()
	context := cfg.GetContext()
	handle := cfg.GetHandle()

	if handle == "" {
		return fmt.Errorf("handle (metadata.name) is required and cannot be empty")
	}

	query := `
		INSERT INTO deployments (
			id, display_name, version, context, kind, handle,
			status, created_at, updated_at, deployed_version
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := s.prepare(query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	now := time.Now()
	_, err = stmt.Exec(
		cfg.ID,
		displayName,
		version,
		context,
		cfg.Kind,
		handle,
		cfg.Status,
		now,
		now,
		cfg.DeployedVersion,
	)

	if err != nil {
		// Check for unique constraint violation
		if isPostgresUniqueConstraintError(err) {
			return fmt.Errorf("%w: configuration with displayName '%s' and version '%s' already exists", ErrConflict, displayName, version)
		}
		return fmt.Errorf("failed to insert configuration: %w", err)
	}

	_, err = s.addDeploymentConfigs(cfg)
	if err != nil {
		return fmt.Errorf("failed to add deployment configurations: %w", err)
	}

	s.logger.Info("Configuration saved",
		slog.String("id", cfg.ID),
		slog.String("displayName", displayName),
		slog.String("version", version))

	return nil
}

// UpdateConfig updates an existing deployment configuration
func (s *PostgresStorage) UpdateConfig(cfg *models.StoredConfig) error {
	startTime := time.Now()
	table := "deployments"

	// Check if configuration exists
	_, err := s.GetConfig(cfg.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
			metrics.StorageErrorsTotal.WithLabelValues("update", "not_found").Inc()
			return fmt.Errorf("cannot update non-existent configuration: %w", err)
		}
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "database_error").Inc()
		return err
	}

	// Extract fields for indexed columns
	displayName := cfg.GetDisplayName()
	version := cfg.GetVersion()
	context := cfg.GetContext()
	handle := cfg.GetHandle()

	if handle == "" {
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "validation_error").Inc()
		return fmt.Errorf("handle (metadata.name) is required and cannot be empty")
	}

	query := `
		UPDATE deployments
		SET display_name = ?, version = ?, context = ?, kind = ?, handle = ?,
			status = ?, updated_at = ?,
			deployed_version = ?
		WHERE id = ?
	`

	stmt, err := s.prepare(query)
	if err != nil {
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "prepare_error").Inc()
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	result, err := stmt.Exec(
		displayName,
		version,
		context,
		cfg.Kind,
		handle,
		cfg.Status,
		time.Now(),
		cfg.DeployedVersion,
		cfg.ID,
	)

	if err != nil {
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "exec_error").Inc()
		return fmt.Errorf("failed to update configuration: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "rows_affected_error").Inc()
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "not_found").Inc()
		return fmt.Errorf("%w: id=%s", ErrNotFound, cfg.ID)
	}

	_, err = s.updateDeploymentConfigs(cfg)
	if err != nil {
		metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("update", "deployment_config_error").Inc()
		return fmt.Errorf("failed to update deployment configurations: %w", err)
	}

	// Record successful metrics
	metrics.DatabaseOperationsTotal.WithLabelValues("update", table, "success").Inc()
	metrics.DatabaseOperationDurationSeconds.WithLabelValues("update", table).Observe(time.Since(startTime).Seconds())

	s.logger.Info("Configuration updated",
		slog.String("id", cfg.ID),
		slog.String("displayName", displayName),
		slog.String("version", version))

	return nil
}

// DeleteConfig removes an deployment configuration by ID
func (s *PostgresStorage) DeleteConfig(id string) error {
	startTime := time.Now()
	table := "deployments"
	query := `DELETE FROM deployments WHERE id = ?`

	result, err := s.exec(query, id)
	if err != nil {
		metrics.DatabaseOperationsTotal.WithLabelValues("delete", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("delete", "exec_error").Inc()
		return fmt.Errorf("failed to delete configuration: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		metrics.DatabaseOperationsTotal.WithLabelValues("delete", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("delete", "rows_affected_error").Inc()
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		metrics.DatabaseOperationsTotal.WithLabelValues("delete", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("delete", "not_found").Inc()
		return fmt.Errorf("%w: id=%s", ErrNotFound, id)
	}

	// Record successful metrics
	metrics.DatabaseOperationsTotal.WithLabelValues("delete", table, "success").Inc()
	metrics.DatabaseOperationDurationSeconds.WithLabelValues("delete", table).Observe(time.Since(startTime).Seconds())

	s.logger.Info("Configuration deleted", slog.String("id", id))

	return nil
}

// GetConfig retrieves an deployment configuration by ID
func (s *PostgresStorage) GetConfig(id string) (*models.StoredConfig, error) {
	startTime := time.Now()
	table := "deployments"
	query := `
		SELECT d.id, d.kind, dc.configuration, dc.source_configuration, d.status, d.created_at,
		d.updated_at, d.deployed_at, d.deployed_version
		FROM deployments d
		LEFT JOIN deployment_configs dc ON d.id = dc.id
		WHERE d.id = ?
	`

	var cfg models.StoredConfig
	var configJSON string
	var sourceConfigJSON string
	var deployedAt sql.NullTime

	err := s.queryRow(query, id).Scan(
		&cfg.ID,
		&cfg.Kind,
		&configJSON,
		&sourceConfigJSON,
		&cfg.Status,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
		&deployedAt,
		&cfg.DeployedVersion,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			metrics.DatabaseOperationsTotal.WithLabelValues("read", table, "error").Inc()
			metrics.StorageErrorsTotal.WithLabelValues("read", "not_found").Inc()
			return nil, fmt.Errorf("%w: id=%s", ErrNotFound, id)
		}
		metrics.DatabaseOperationsTotal.WithLabelValues("read", table, "error").Inc()
		metrics.StorageErrorsTotal.WithLabelValues("read", "query_error").Inc()
		return nil, fmt.Errorf("failed to query configuration: %w", err)
	}

	// Parse deployed_at (nullable field)
	if deployedAt.Valid {
		cfg.DeployedAt = &deployedAt.Time
	}

	// Deserialize JSON configuration
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &cfg.Configuration); err != nil {
			metrics.DatabaseOperationsTotal.WithLabelValues("read", table, "error").Inc()
			metrics.StorageErrorsTotal.WithLabelValues("read", "unmarshal_error").Inc()
			return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
		}
	}
	if sourceConfigJSON != "" {
		if err := json.Unmarshal([]byte(sourceConfigJSON), &cfg.SourceConfiguration); err != nil {
			metrics.DatabaseOperationsTotal.WithLabelValues("read", table, "error").Inc()
			metrics.StorageErrorsTotal.WithLabelValues("read", "unmarshal_error").Inc()
			return nil, fmt.Errorf("failed to unmarshal source configuration: %w", err)
		}
	}

	// Record successful metrics
	metrics.DatabaseOperationsTotal.WithLabelValues("read", table, "success").Inc()
	metrics.DatabaseOperationDurationSeconds.WithLabelValues("read", table).Observe(time.Since(startTime).Seconds())

	return &cfg, nil
}

// GetConfigByNameVersion retrieves an deployment configuration by displayName and version
func (s *PostgresStorage) GetConfigByNameVersion(name, version string) (*models.StoredConfig, error) {
	query := `
		SELECT d.id, d.kind, dc.configuration, dc.source_configuration, d.status, d.created_at, d.updated_at,
			   d.deployed_at, d.deployed_version
		FROM deployments d
		LEFT JOIN deployment_configs dc ON d.id = dc.id
		WHERE d.display_name = ? AND d.version = ?
	`

	var cfg models.StoredConfig
	var configJSON string
	var sourceConfigJSON string
	var deployedAt sql.NullTime

	err := s.queryRow(query, name, version).Scan(
		&cfg.ID,
		&cfg.Kind,
		&configJSON,
		&sourceConfigJSON,
		&cfg.Status,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
		&deployedAt,
		&cfg.DeployedVersion,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: name=%s, version=%s", ErrNotFound, name, version)
		}
		return nil, fmt.Errorf("failed to query configuration: %w", err)
	}

	// Parse deployed_at (nullable field)
	if deployedAt.Valid {
		cfg.DeployedAt = &deployedAt.Time
	}

	// Deserialize JSON configuration
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &cfg.Configuration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
		}
	}
	if sourceConfigJSON != "" {
		if err := json.Unmarshal([]byte(sourceConfigJSON), &cfg.SourceConfiguration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal source configuration: %w", err)
		}
	}

	return &cfg, nil
}

// GetConfigByHandle retrieves a deployment configuration by handle (metadata.name)
func (s *PostgresStorage) GetConfigByHandle(handle string) (*models.StoredConfig, error) {
	query := `
		SELECT d.id, d.kind, dc.configuration, dc.source_configuration, d.status, d.created_at, d.updated_at,
			   d.deployed_at, d.deployed_version
		FROM deployments d
		LEFT JOIN deployment_configs dc ON d.id = dc.id
		WHERE d.handle = ?
	`

	var cfg models.StoredConfig
	var configJSON string
	var sourceConfigJSON string
	var deployedAt sql.NullTime

	err := s.queryRow(query, handle).Scan(
		&cfg.ID,
		&cfg.Kind,
		&configJSON,
		&sourceConfigJSON,
		&cfg.Status,
		&cfg.CreatedAt,
		&cfg.UpdatedAt,
		&deployedAt,
		&cfg.DeployedVersion,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: handle=%s", ErrNotFound, handle)
		}
		return nil, fmt.Errorf("failed to query configuration: %w", err)
	}

	// Parse deployed_at (nullable field)
	if deployedAt.Valid {
		cfg.DeployedAt = &deployedAt.Time
	}

	// Deserialize JSON configuration
	if configJSON != "" {
		if err := json.Unmarshal([]byte(configJSON), &cfg.Configuration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
		}
	}
	if sourceConfigJSON != "" {
		if err := json.Unmarshal([]byte(sourceConfigJSON), &cfg.SourceConfiguration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal source configuration: %w", err)
		}
	}

	return &cfg, nil
}

// GetAllConfigs retrieves all deployment configurations
func (s *PostgresStorage) GetAllConfigs() ([]*models.StoredConfig, error) {
	query := `
			SELECT d.id, d.kind, dc.configuration, dc.source_configuration, d.status, 
			d.created_at, d.updated_at, d.deployed_at, d.deployed_version
			FROM deployments d
			LEFT JOIN deployment_configs dc ON d.id = dc.id
			ORDER BY d.created_at DESC
		`

	rows, err := s.query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query configurations: %w", err)
	}
	defer rows.Close()

	var configs []*models.StoredConfig

	for rows.Next() {
		var cfg models.StoredConfig
		var configJSON string
		var sourceConfigJSON string
		var deployedAt sql.NullTime

		err := rows.Scan(
			&cfg.ID,
			&cfg.Kind,
			&configJSON,
			&sourceConfigJSON,
			&cfg.Status,
			&cfg.CreatedAt,
			&cfg.UpdatedAt,
			&deployedAt,
			&cfg.DeployedVersion,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Parse deployed_at (nullable field)
		if deployedAt.Valid {
			cfg.DeployedAt = &deployedAt.Time
		}

		// Deserialize JSON configuration
		if configJSON != "" {
			if err := json.Unmarshal([]byte(configJSON), &cfg.Configuration); err != nil {
				return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
			}
		}
		if sourceConfigJSON != "" {
			if err := json.Unmarshal([]byte(sourceConfigJSON), &cfg.SourceConfiguration); err != nil {
				return nil, fmt.Errorf("failed to unmarshal source configuration: %w", err)
			}
		}

		configs = append(configs, &cfg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return configs, nil
}

// GetAllConfigsByKind retrieves all deployment configurations of a specific kind
func (s *PostgresStorage) GetAllConfigsByKind(kind string) ([]*models.StoredConfig, error) {
	query := `
			SELECT d.id, d.kind, dc.configuration, dc.source_configuration, d.status, 
			d.created_at, d.updated_at, d.deployed_at, d.deployed_version
			FROM deployments d
			LEFT JOIN deployment_configs dc ON d.id = dc.id 
			WHERE d.kind = ?
			ORDER BY d.created_at DESC
		`

	rows, err := s.query(query, kind)
	if err != nil {
		return nil, fmt.Errorf("failed to query configurations: %w", err)
	}
	defer rows.Close()

	var configs []*models.StoredConfig

	for rows.Next() {
		var cfg models.StoredConfig
		var configJSON string
		var sourceConfigJSON string
		var deployedAt sql.NullTime

		err := rows.Scan(
			&cfg.ID,
			&cfg.Kind,
			&configJSON,
			&sourceConfigJSON,
			&cfg.Status,
			&cfg.CreatedAt,
			&cfg.UpdatedAt,
			&deployedAt,
			&cfg.DeployedVersion,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Parse deployed_at (nullable field)
		if deployedAt.Valid {
			cfg.DeployedAt = &deployedAt.Time
		}

		// Deserialize JSON configuration
		if configJSON != "" {
			if err := json.Unmarshal([]byte(configJSON), &cfg.Configuration); err != nil {
				return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
			}
		}
		if sourceConfigJSON != "" {
			if err := json.Unmarshal([]byte(sourceConfigJSON), &cfg.SourceConfiguration); err != nil {
				return nil, fmt.Errorf("failed to unmarshal source configuration: %w", err)
			}
		}

		configs = append(configs, &cfg)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return configs, nil
}

// SaveLLMProviderTemplate persists a new LLM provider template
func (s *PostgresStorage) SaveLLMProviderTemplate(template *models.StoredLLMProviderTemplate) error {
	// Serialize configuration to JSON
	configJSON, err := json.Marshal(template.Configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal template configuration: %w", err)
	}

	handle := template.GetHandle()

	query := `
		INSERT INTO llm_provider_templates (
			id, handle, configuration, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?)
	`

	now := time.Now()
	_, err = s.exec(query,
		template.ID,
		handle,
		string(configJSON),
		now,
		now,
	)

	if err != nil {
		// Check for unique constraint violation
		if err.Error() == "UNIQUE constraint failed: llm_provider_templates.handle" {
			return fmt.Errorf("%w: template with handle '%s' already exists", ErrConflict, handle)
		}
		return fmt.Errorf("failed to insert template: %w", err)
	}

	s.logger.Info("LLM provider template saved",
		slog.String("uuid", template.ID),
		slog.String("handle", handle))

	return nil
}

// UpdateLLMProviderTemplate updates an existing LLM provider template
func (s *PostgresStorage) UpdateLLMProviderTemplate(template *models.StoredLLMProviderTemplate) error {
	// Check if template exists
	_, err := s.GetLLMProviderTemplate(template.ID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return fmt.Errorf("cannot update non-existent template: %w", err)
		}
		return err
	}

	// Serialize configuration to JSON
	configJSON, err := json.Marshal(template.Configuration)
	if err != nil {
		return fmt.Errorf("failed to marshal template configuration: %w", err)
	}

	handle := template.GetHandle()

	query := `
		UPDATE llm_provider_templates
		SET handle = ?, configuration = ?, updated_at = ?
		WHERE id = ?
	`

	result, err := s.exec(query,
		handle,
		string(configJSON),
		time.Now(),
		template.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update template: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("%w: uuid=%s", ErrNotFound, template.ID)
	}

	s.logger.Info("LLM provider template updated",
		slog.String("uuid", template.ID),
		slog.String("handle", handle))

	return nil
}

// DeleteLLMProviderTemplate removes an LLM provider template by ID
func (s *PostgresStorage) DeleteLLMProviderTemplate(id string) error {
	query := `DELETE FROM llm_provider_templates WHERE id = ?`

	result, err := s.exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("%w: uuid=%s", ErrNotFound, id)
	}

	s.logger.Info("LLM provider template deleted", slog.String("uuid", id))

	return nil
}

// GetLLMProviderTemplate retrieves an LLM provider template by ID
func (s *PostgresStorage) GetLLMProviderTemplate(id string) (*models.StoredLLMProviderTemplate, error) {
	query := `
		SELECT id, configuration, created_at, updated_at
		FROM llm_provider_templates
		WHERE id = ?
	`

	var template models.StoredLLMProviderTemplate
	var configJSON string

	err := s.queryRow(query, id).Scan(
		&template.ID,
		&configJSON,
		&template.CreatedAt,
		&template.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: uuid=%s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("failed to query template: %w", err)
	}

	// Deserialize JSON configuration
	if err := json.Unmarshal([]byte(configJSON), &template.Configuration); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template configuration: %w", err)
	}

	return &template, nil
}

// GetAllLLMProviderTemplates retrieves all LLM provider templates
func (s *PostgresStorage) GetAllLLMProviderTemplates() ([]*models.StoredLLMProviderTemplate, error) {
	query := `
		SELECT id, configuration, created_at, updated_at
		FROM llm_provider_templates
		ORDER BY created_at DESC
	`

	rows, err := s.query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query templates: %w", err)
	}
	defer rows.Close()

	var templates []*models.StoredLLMProviderTemplate

	for rows.Next() {
		var template models.StoredLLMProviderTemplate
		var configJSON string

		err := rows.Scan(
			&template.ID,
			&configJSON,
			&template.CreatedAt,
			&template.UpdatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Deserialize JSON configuration
		if err := json.Unmarshal([]byte(configJSON), &template.Configuration); err != nil {
			return nil, fmt.Errorf("failed to unmarshal template configuration: %w", err)
		}

		templates = append(templates, &template)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	return templates, nil
}

// SaveCertificate persists a certificate to the database
func (s *PostgresStorage) SaveCertificate(cert *models.StoredCertificate) error {
	query := `
		INSERT INTO certificates (
			id, name, certificate, subject, issuer,
			not_before, not_after, cert_count, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := s.exec(query,
		cert.ID,
		cert.Name,
		cert.Certificate,
		cert.Subject,
		cert.Issuer,
		cert.NotBefore,
		cert.NotAfter,
		cert.CertCount,
		cert.CreatedAt,
		cert.UpdatedAt,
	)

	if err != nil {
		// Check for unique constraint violation
		if isPostgresCertificateUniqueConstraintError(err) {
			return fmt.Errorf("%w: certificate with name '%s' already exists", ErrConflict, cert.Name)
		}
		return fmt.Errorf("failed to save certificate: %w", err)
	}

	return nil
}

// GetCertificate retrieves a certificate by ID
func (s *PostgresStorage) GetCertificate(id string) (*models.StoredCertificate, error) {
	query := `
		SELECT id, name, certificate, subject, issuer,
		       not_before, not_after, cert_count, created_at, updated_at
		FROM certificates
		WHERE id = ?
	`

	var cert models.StoredCertificate
	err := s.queryRow(query, id).Scan(
		&cert.ID,
		&cert.Name,
		&cert.Certificate,
		&cert.Subject,
		&cert.Issuer,
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.CertCount,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: id=%s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &cert, nil
}

// GetCertificateByName retrieves a certificate by name
func (s *PostgresStorage) GetCertificateByName(name string) (*models.StoredCertificate, error) {
	query := `
		SELECT id, name, certificate, subject, issuer,
		       not_before, not_after, cert_count, created_at, updated_at
		FROM certificates
		WHERE name = ?
	`

	var cert models.StoredCertificate
	err := s.queryRow(query, name).Scan(
		&cert.ID,
		&cert.Name,
		&cert.Certificate,
		&cert.Subject,
		&cert.Issuer,
		&cert.NotBefore,
		&cert.NotAfter,
		&cert.CertCount,
		&cert.CreatedAt,
		&cert.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate by name: %w", err)
	}

	return &cert, nil
}

// ListCertificates retrieves all certificates
func (s *PostgresStorage) ListCertificates() ([]*models.StoredCertificate, error) {
	query := `
		SELECT id, name, certificate, subject, issuer,
		       not_before, not_after, cert_count, created_at, updated_at
		FROM certificates
		ORDER BY created_at DESC
	`

	rows, err := s.query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to list certificates: %w", err)
	}
	defer rows.Close()

	var certs []*models.StoredCertificate
	for rows.Next() {
		var cert models.StoredCertificate
		if err := rows.Scan(
			&cert.ID,
			&cert.Name,
			&cert.Certificate,
			&cert.Subject,
			&cert.Issuer,
			&cert.NotBefore,
			&cert.NotAfter,
			&cert.CertCount,
			&cert.CreatedAt,
			&cert.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan certificate: %w", err)
		}
		certs = append(certs, &cert)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating certificate rows: %w", err)
	}

	return certs, nil
}

// DeleteCertificate deletes a certificate by ID
func (s *PostgresStorage) DeleteCertificate(id string) error {
	query := `DELETE FROM certificates WHERE id = ?`

	result, err := s.exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete certificate: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		s.logger.Debug("Certificate not found for deletion", slog.String("id", id))
		return ErrNotFound
	}

	s.logger.Info("Certificate deleted", slog.String("id", id))

	return nil
}

// API Key Storage Methods

// SaveAPIKey persists a new API key to the database or updates existing one
// if an API key with the same apiId and name already exists
func (s *PostgresStorage) SaveAPIKey(apiKey *models.APIKey) error {

	// Begin transaction to ensure atomicity
	tx, err := s.begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is properly handled
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-throw panic after rollback
		}
	}()

	// Before inserting, check for duplicates if this is an external key
	if apiKey.Source == "external" && apiKey.IndexKey != nil {
		var count int
		checkQuery := `SELECT COUNT(*) FROM api_keys                                                  
						WHERE apiId = ? AND index_key = ? AND source = 'external'`
		err := tx.QueryRowQ(checkQuery, apiKey.APIId, apiKey.IndexKey).Scan(&count)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to check for duplicate API key: %w", err)
		}
		if count > 0 {
			tx.Rollback()
			return fmt.Errorf("%w: API key value already exists for this API", ErrConflict)
		}
	}

	// First, check if an API key with the same apiId and name exists
	checkQuery := `SELECT id FROM api_keys WHERE apiId = ? AND name = ?`
	var existingID string
	err = tx.QueryRowQ(checkQuery, apiKey.APIId, apiKey.Name).Scan(&existingID)

	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		tx.Rollback()
		return fmt.Errorf("failed to check existing API key: %w", err)
	}

	if errors.Is(err, sql.ErrNoRows) {
		// No existing record, insert new API key
		insertQuery := `
			INSERT INTO api_keys (
				id, name, display_name, api_key, masked_api_key, apiId, operations, status,
				created_at, created_by, updated_at, expires_at, expires_in_unit, expires_in_duration,
				source, external_ref_id, index_key
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`

		_, err := tx.ExecQ(insertQuery,
			apiKey.ID,
			apiKey.Name,
			apiKey.DisplayName,
			apiKey.APIKey,
			apiKey.MaskedAPIKey,
			apiKey.APIId,
			apiKey.Operations,
			apiKey.Status,
			apiKey.CreatedAt,
			apiKey.CreatedBy,
			apiKey.UpdatedAt,
			apiKey.ExpiresAt,
			apiKey.Unit,
			apiKey.Duration,
			apiKey.Source,
			apiKey.ExternalRefId,
			apiKey.IndexKey,
		)

		if err != nil {
			tx.Rollback()
			// Check for unique constraint violation on api_key field
			if isPostgresAPIKeyUniqueConstraintError(err) {
				return fmt.Errorf("%w: API key value already exists", ErrConflict)
			}
			return fmt.Errorf("failed to insert API key: %w", err)
		}

		s.logger.Info("API key inserted successfully",
			slog.String("id", apiKey.ID),
			slog.String("name", apiKey.Name),
			slog.String("apiId", apiKey.APIId),
			slog.String("created_by", apiKey.CreatedBy))
	} else {
		// Existing record found, return conflict error that API Key name already exists
		tx.Rollback()
		s.logger.Error("API key name already exists for the API",
			slog.String("name", apiKey.Name),
			slog.String("apiId", apiKey.APIId),
			slog.Any("error", ErrConflict))
		return fmt.Errorf("%w: API key name already exists for the API: %s", ErrConflict, apiKey.Name)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetAPIKeyByID retrieves an API key by its ID
func (s *PostgresStorage) GetAPIKeyByID(id string) (*models.APIKey, error) {
	query := `
		SELECT id, name, display_name, api_key, masked_api_key, apiId, operations, status,
		       created_at, created_by, updated_at, expires_at, source, external_ref_id, index_key
		FROM api_keys
		WHERE id = ?
	`

	var apiKey models.APIKey
	var expiresAt sql.NullTime
	var externalRefId sql.NullString
	var indexKey sql.NullString

	err := s.queryRow(query, id).Scan(
		&apiKey.ID,
		&apiKey.Name,
		&apiKey.DisplayName,
		&apiKey.APIKey,
		&apiKey.MaskedAPIKey,
		&apiKey.APIId,
		&apiKey.Operations,
		&apiKey.Status,
		&apiKey.CreatedAt,
		&apiKey.CreatedBy,
		&apiKey.UpdatedAt,
		&expiresAt,
		&apiKey.Source,
		&externalRefId,
		&indexKey,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: key not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query API key: %w", err)
	}

	// Handle nullable fields
	if expiresAt.Valid {
		apiKey.ExpiresAt = &expiresAt.Time
	}
	if externalRefId.Valid {
		apiKey.ExternalRefId = &externalRefId.String
	}
	if indexKey.Valid {
		apiKey.IndexKey = &indexKey.String
	}

	return &apiKey, nil
}

// GetAPIKeyByKey retrieves an API key by its key value
func (s *PostgresStorage) GetAPIKeyByKey(key string) (*models.APIKey, error) {
	query := `
		SELECT id, name, display_name, api_key, masked_api_key, apiId, operations, status,
		       created_at, created_by, updated_at, expires_at, source, external_ref_id, index_key
		FROM api_keys
		WHERE api_key = ?
	`

	var apiKey models.APIKey
	var expiresAt sql.NullTime
	var externalRefId sql.NullString
	var indexKey sql.NullString

	err := s.queryRow(query, key).Scan(
		&apiKey.ID,
		&apiKey.Name,
		&apiKey.DisplayName,
		&apiKey.APIKey,
		&apiKey.MaskedAPIKey,
		&apiKey.APIId,
		&apiKey.Operations,
		&apiKey.Status,
		&apiKey.CreatedAt,
		&apiKey.CreatedBy,
		&apiKey.UpdatedAt,
		&expiresAt,
		&apiKey.Source,
		&externalRefId,
		&indexKey,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: key not found", ErrNotFound)
		}
		return nil, fmt.Errorf("failed to query API key: %w", err)
	}

	// Handle nullable fields
	if expiresAt.Valid {
		apiKey.ExpiresAt = &expiresAt.Time
	}
	if externalRefId.Valid {
		apiKey.ExternalRefId = &externalRefId.String
	}
	if indexKey.Valid {
		apiKey.IndexKey = &indexKey.String
	}

	return &apiKey, nil
}

// GetAPIKeysByAPI retrieves all API keys for a specific API
func (s *PostgresStorage) GetAPIKeysByAPI(apiId string) ([]*models.APIKey, error) {
	query := `
		SELECT id, name, display_name, api_key, masked_api_key, apiId, operations, status,
		       created_at, created_by, updated_at, expires_at, source, external_ref_id, index_key
		FROM api_keys
		WHERE apiId = ?
		ORDER BY created_at DESC
	`

	rows, err := s.query(query, apiId)
	if err != nil {
		return nil, fmt.Errorf("failed to query API keys: %w", err)
	}
	defer rows.Close()

	var apiKeys []*models.APIKey

	for rows.Next() {
		var apiKey models.APIKey
		var expiresAt sql.NullTime
		var externalRefId sql.NullString
		var indexKey sql.NullString

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.Name,
			&apiKey.DisplayName,
			&apiKey.APIKey,
			&apiKey.MaskedAPIKey,
			&apiKey.APIId,
			&apiKey.Operations,
			&apiKey.Status,
			&apiKey.CreatedAt,
			&apiKey.CreatedBy,
			&apiKey.UpdatedAt,
			&expiresAt,
			&apiKey.Source,
			&externalRefId,
			&indexKey,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan API key row: %w", err)
		}

		// Handle nullable fields
		if expiresAt.Valid {
			apiKey.ExpiresAt = &expiresAt.Time
		}
		if externalRefId.Valid {
			apiKey.ExternalRefId = &externalRefId.String
		}
		if indexKey.Valid {
			apiKey.IndexKey = &indexKey.String
		}

		apiKeys = append(apiKeys, &apiKey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating API key rows: %w", err)
	}

	return apiKeys, nil
}

// GetAPIKeysByAPIAndName retrieves an API key by its apiId and name
func (s *PostgresStorage) GetAPIKeysByAPIAndName(apiId, name string) (*models.APIKey, error) {
	query := `
		SELECT id, name, display_name, api_key, masked_api_key, apiId, operations, status,
		       created_at, created_by, updated_at, expires_at, source, external_ref_id, index_key
		FROM api_keys
		WHERE apiId = ? AND name = ?
		LIMIT 1
	`

	var apiKey models.APIKey
	var expiresAt sql.NullTime
	var externalRefId sql.NullString
	var indexKey sql.NullString

	err := s.queryRow(query, apiId, name).Scan(
		&apiKey.ID,
		&apiKey.Name,
		&apiKey.DisplayName,
		&apiKey.APIKey,
		&apiKey.MaskedAPIKey,
		&apiKey.APIId,
		&apiKey.Operations,
		&apiKey.Status,
		&apiKey.CreatedAt,
		&apiKey.CreatedBy,
		&apiKey.UpdatedAt,
		&expiresAt,
		&apiKey.Source,
		&externalRefId,
		&indexKey,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("failed to query API key by name: %w", err)
	}

	// Handle nullable fields
	if expiresAt.Valid {
		apiKey.ExpiresAt = &expiresAt.Time
	}
	if externalRefId.Valid {
		apiKey.ExternalRefId = &externalRefId.String
	}
	if indexKey.Valid {
		apiKey.IndexKey = &indexKey.String
	}

	return &apiKey, nil
}

// UpdateAPIKey updates an existing API key
func (s *PostgresStorage) UpdateAPIKey(apiKey *models.APIKey) error {

	// Begin transaction to ensure atomicity
	tx, err := s.begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	// Ensure transaction is properly handled
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-throw panic after rollback
		}
	}()

	if apiKey.Source == "external" && apiKey.IndexKey != nil {
		// Check for duplicate API key value within the same API (same value, different name)
		duplicateCheckQuery := `
			SELECT id, name FROM api_keys
			WHERE apiId = ? AND index_key = ? AND name != ?
			LIMIT 1
		`
		var duplicateID, duplicateName string
		err := tx.QueryRowQ(duplicateCheckQuery, apiKey.APIId, apiKey.IndexKey, apiKey.Name).Scan(&duplicateID, &duplicateName)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			tx.Rollback()
			return fmt.Errorf("failed to check for duplicate API key: %w", err)
		}
		if err == nil {
			// Row found: same key value already exists for this API under a different name
			tx.Rollback()
			return fmt.Errorf("%w: API key value already exists for this API", ErrConflict)
		}
	}

	updateQuery := `
			UPDATE api_keys
			SET api_key = ?, masked_api_key = ?, display_name = ?, operations = ?, status = ?, created_by = ?, updated_at = ?, expires_at = ?, expires_in_unit = ?, expires_in_duration = ?,
			    source = ?, external_ref_id = ?, index_key = ?
			WHERE apiId = ? AND name = ?
		`

	_, err = tx.ExecQ(updateQuery,
		apiKey.APIKey,
		apiKey.MaskedAPIKey,
		apiKey.DisplayName,
		apiKey.Operations,
		apiKey.Status,
		apiKey.CreatedBy,
		apiKey.UpdatedAt,
		apiKey.ExpiresAt,
		apiKey.Unit,
		apiKey.Duration,
		apiKey.Source,
		apiKey.ExternalRefId,
		apiKey.IndexKey,
		apiKey.APIId,
		apiKey.Name,
	)

	if err != nil {
		tx.Rollback()
		// Check for unique constraint violation on api_key field
		if isPostgresAPIKeyUniqueConstraintError(err) {
			return fmt.Errorf("%w: API key value already exists", ErrConflict)
		}
		return fmt.Errorf("failed to update API key: %w", err)
	}

	s.logger.Info("API key updated successfully",
		slog.String("name", apiKey.Name),
		slog.String("apiId", apiKey.APIId),
		slog.String("created_by", apiKey.CreatedBy))

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// DeleteAPIKey removes an API key by its key value
func (s *PostgresStorage) DeleteAPIKey(key string) error {
	query := `DELETE FROM api_keys WHERE api_key = ?`

	result, err := s.exec(query, key)
	if err != nil {
		return fmt.Errorf("failed to delete API key: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("%w: API key not found", ErrNotFound)
	}

	s.logger.Info("API key deleted successfully", slog.String("key_prefix", key[:min(8, len(key))]+"***"))

	return nil
}

// RemoveAPIKeysAPI removes an API keys by apiId
func (s *PostgresStorage) RemoveAPIKeysAPI(apiId string) error {
	query := `DELETE FROM api_keys WHERE apiId = ?`

	_, err := s.exec(query, apiId)
	if err != nil {
		return fmt.Errorf("failed to remove API keys for API: %w", err)
	}

	s.logger.Info("API keys removed successfully",
		slog.String("apiId", apiId))

	return nil
}

// RemoveAPIKeyAPIAndName removes an API key by its apiId and name
func (s *PostgresStorage) RemoveAPIKeyAPIAndName(apiId, name string) error {
	query := `DELETE FROM api_keys WHERE apiId = ? AND name = ?`

	result, err := s.exec(query, apiId, name)
	if err != nil {
		return fmt.Errorf("failed to remove API key: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("%w: API key not found", ErrNotFound)
	}

	s.logger.Info("API key removed successfully",
		slog.String("apiId", apiId),
		slog.String("name", name))

	return nil
}

// Close closes the database connection
func (s *PostgresStorage) Close() error {
	s.logger.Info("Closing PostgreSQL storage")
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}
	return nil
}

// addDeploymentConfigs adds deployment configuration details to the database
func (s *PostgresStorage) addDeploymentConfigs(cfg *models.StoredConfig) (bool, error) {
	query := `INSERT INTO deployment_configs (id, configuration, source_configuration) VALUES (?, ?, ?)`

	stmt, err := s.prepare(query)
	if err != nil {
		return false, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	configJSON, err := json.Marshal(cfg.Configuration)
	if err != nil {
		return false, fmt.Errorf("failed to marshal configuration: %w", err)
	}
	sourceConfigJSON, err := json.Marshal(cfg.SourceConfiguration)
	if err != nil {
		return false, fmt.Errorf("failed to marshal source configuration: %w", err)
	}

	_, err = stmt.Exec(
		cfg.ID,
		string(configJSON),
		string(sourceConfigJSON),
	)

	if err != nil {
		return false, fmt.Errorf("failed to insert deployment configuration: %w", err)
	}

	return true, nil
}

// updateDeploymentConfigs updates deployment configuration details in the database
func (s *PostgresStorage) updateDeploymentConfigs(cfg *models.StoredConfig) (bool, error) {
	query := `UPDATE deployment_configs SET configuration = ?, source_configuration = ? WHERE id = ?`

	stmt, err := s.prepare(query)
	if err != nil {
		return false, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	configJSON, err := json.Marshal(cfg.Configuration)
	if err != nil {
		return false, fmt.Errorf("failed to marshal configuration: %w", err)
	}
	sourceConfigJSON, err := json.Marshal(cfg.SourceConfiguration)
	if err != nil {
		return false, fmt.Errorf("failed to marshal source configuration: %w", err)
	}

	result, err := stmt.Exec(
		string(configJSON),
		string(sourceConfigJSON),
		cfg.ID,
	)
	if err != nil {
		return false, fmt.Errorf("failed to update deployment configuration: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return false, fmt.Errorf("no deployment config found for id=%s", cfg.ID)
	}

	return true, nil
}

// isPostgresUniqueConstraintError checks if the error is a UNIQUE constraint violation.
func isPostgresUniqueConstraintError(err error) bool {
	pgErr := extractPgError(err)
	return pgErr != nil && pgErr.Code == "23505"
}

// isPostgresCertificateUniqueConstraintError checks if the error is a UNIQUE constraint violation for certificates.
func isPostgresCertificateUniqueConstraintError(err error) bool {
	pgErr := extractPgError(err)
	return pgErr != nil && pgErr.Code == "23505"
}

// isPostgresAPIKeyUniqueConstraintError checks if the error is an API key uniqueness violation.
func isPostgresAPIKeyUniqueConstraintError(err error) bool {
	pgErr := extractPgError(err)
	if pgErr == nil || pgErr.Code != "23505" {
		return false
	}
	// Keep this specific to API key uniqueness in case other unique constraints appear.
	switch pgErr.ConstraintName {
	case "api_keys_api_key_key", "api_keys_pkey", "idx_unique_external_api_key":
		return true
	default:
		return strings.Contains(pgErr.TableName, "api_keys")
	}
}

func extractPgError(err error) *pgconn.PgError {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr
	}
	return nil
}

// GetAllAPIKeys retrieves all API keys from the database
func (s *PostgresStorage) GetAllAPIKeys() ([]*models.APIKey, error) {
	query := `
		SELECT id, name, display_name, api_key, masked_api_key, apiId, operations, status,
		       created_at, created_by, updated_at, expires_at, source, external_ref_id, index_key
		FROM api_keys
		WHERE status = 'active'
		ORDER BY created_at DESC
	`

	rows, err := s.query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all API keys: %w", err)
	}
	defer rows.Close()

	var apiKeys []*models.APIKey

	for rows.Next() {
		var apiKey models.APIKey
		var expiresAt sql.NullTime
		var externalRefId sql.NullString
		var indexKey sql.NullString

		err := rows.Scan(
			&apiKey.ID,
			&apiKey.Name,
			&apiKey.DisplayName,
			&apiKey.APIKey,
			&apiKey.MaskedAPIKey,
			&apiKey.APIId,
			&apiKey.Operations,
			&apiKey.Status,
			&apiKey.CreatedAt,
			&apiKey.CreatedBy,
			&apiKey.UpdatedAt,
			&expiresAt,
			&apiKey.Source,
			&externalRefId,
			&indexKey,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan API key row: %w", err)
		}

		// Handle nullable fields
		if expiresAt.Valid {
			apiKey.ExpiresAt = &expiresAt.Time
		}
		if externalRefId.Valid {
			apiKey.ExternalRefId = &externalRefId.String
		}
		if indexKey.Valid {
			apiKey.IndexKey = &indexKey.String
		}

		apiKeys = append(apiKeys, &apiKey)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating API key rows: %w", err)
	}

	return apiKeys, nil
}

// CountActiveAPIKeysByUserAndAPI counts active API keys for a specific user and API
func (s *PostgresStorage) CountActiveAPIKeysByUserAndAPI(apiId, userID string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM api_keys
		WHERE apiId = ? AND created_by = ? AND status = ?
	`

	var count int
	err := s.queryRow(query, apiId, userID, models.APIKeyStatusActive).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active API keys for user %s and API %s: %w", userID, apiId, err)
	}

	return count, nil
}

func (s *PostgresStorage) rebind(query string) string {
	return sqlx.Rebind(sqlx.DOLLAR, query)
}

func (s *PostgresStorage) exec(query string, args ...interface{}) (sql.Result, error) {
	return s.db.Exec(s.rebind(query), args...)
}

func (s *PostgresStorage) queryRow(query string, args ...interface{}) *sql.Row {
	return s.db.QueryRow(s.rebind(query), args...)
}

func (s *PostgresStorage) query(query string, args ...interface{}) (*sql.Rows, error) {
	return s.db.Query(s.rebind(query), args...)
}

func (s *PostgresStorage) prepare(query string) (*sql.Stmt, error) {
	return s.db.Prepare(s.rebind(query))
}

func (s *PostgresStorage) begin() (*postgresTx, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	return &postgresTx{tx: tx, store: s}, nil
}

type postgresTx struct {
	tx    *sql.Tx
	store *PostgresStorage
}

func (t *postgresTx) ExecQ(query string, args ...interface{}) (sql.Result, error) {
	return t.tx.Exec(t.store.rebind(query), args...)
}

func (t *postgresTx) QueryRowQ(query string, args ...interface{}) *sql.Row {
	return t.tx.QueryRow(t.store.rebind(query), args...)
}

func (t *postgresTx) QueryQ(query string, args ...interface{}) (*sql.Rows, error) {
	return t.tx.Query(t.store.rebind(query), args...)
}

func (t *postgresTx) Commit() error {
	return t.tx.Commit()
}

func (t *postgresTx) Rollback() error {
	return t.tx.Rollback()
}
