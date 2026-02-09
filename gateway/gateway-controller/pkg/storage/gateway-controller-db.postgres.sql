-- PostgreSQL Schema for Gateway-Controller API Configurations
-- Version: 6

-- Main table for deployments
CREATE TABLE IF NOT EXISTS deployments (
    id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    version TEXT NOT NULL,
    context TEXT NOT NULL,
    kind TEXT NOT NULL,
    handle TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK(status IN ('pending', 'deployed', 'failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deployed_at TIMESTAMPTZ,
    deployed_version BIGINT NOT NULL DEFAULT 0,
    UNIQUE(display_name, version)
);

CREATE INDEX IF NOT EXISTS idx_name_version ON deployments(display_name, version);
CREATE INDEX IF NOT EXISTS idx_status ON deployments(status);
CREATE INDEX IF NOT EXISTS idx_context ON deployments(context);
CREATE INDEX IF NOT EXISTS idx_kind ON deployments(kind);

-- Table for custom TLS certificates
CREATE TABLE IF NOT EXISTS certificates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    certificate BYTEA NOT NULL,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    cert_count INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cert_name ON certificates(name);
CREATE INDEX IF NOT EXISTS idx_cert_expiry ON certificates(not_after);

-- Table for deployment-specific configurations
CREATE TABLE IF NOT EXISTS deployment_configs (
    id TEXT PRIMARY KEY,
    configuration TEXT NOT NULL,
    source_configuration TEXT,
    FOREIGN KEY(id) REFERENCES deployments(id) ON DELETE CASCADE
);

-- LLM Provider Templates table
CREATE TABLE IF NOT EXISTS llm_provider_templates (
    id TEXT PRIMARY KEY,
    handle TEXT NOT NULL UNIQUE,
    configuration TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_template_handle ON llm_provider_templates(handle);

-- Table for API keys
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL UNIQUE,
    masked_api_key TEXT NOT NULL,
    apiId TEXT NOT NULL,
    operations TEXT NOT NULL DEFAULT '[*]',
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked', 'expired')) DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL DEFAULT 'system',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NULL,
    expires_in_unit TEXT NULL,
    expires_in_duration INTEGER NULL,
    source TEXT NOT NULL DEFAULT 'local',
    external_ref_id TEXT NULL,
    index_key TEXT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (apiId) REFERENCES deployments(id) ON DELETE CASCADE,
    UNIQUE (apiId, name)
);

CREATE INDEX IF NOT EXISTS idx_api_key ON api_keys(api_key);
CREATE INDEX IF NOT EXISTS idx_api_key_api ON api_keys(apiId);
CREATE INDEX IF NOT EXISTS idx_api_key_status ON api_keys(status);
CREATE INDEX IF NOT EXISTS idx_api_key_expiry ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_created_by ON api_keys(created_by);
CREATE INDEX IF NOT EXISTS idx_api_key_source ON api_keys(source);
CREATE INDEX IF NOT EXISTS idx_api_key_external_ref ON api_keys(external_ref_id);
CREATE INDEX IF NOT EXISTS idx_api_key_index_key ON api_keys(index_key);
CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_external_api_key
    ON api_keys(apiId, index_key)
    WHERE source = 'external' AND index_key IS NOT NULL;

-- Schema migration metadata
CREATE TABLE IF NOT EXISTS schema_migrations (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
