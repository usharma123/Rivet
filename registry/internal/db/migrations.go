package db

import (
	"context"
	"database/sql"
)

func Migrate(ctx context.Context, conn *sql.DB) error {
	_, err := conn.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS packages (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  source TEXT NOT NULL,
  publisher TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS package_versions (
  id TEXT PRIMARY KEY,
  package_id TEXT REFERENCES packages(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  source TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'active',
  manifest JSONB NOT NULL,
  artifact_hash TEXT NOT NULL,
  artifact_url TEXT NOT NULL,
  source_metadata JSONB,
  risk_score INTEGER DEFAULT 0,
  published_at TIMESTAMPTZ DEFAULT now(),
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT,
  replacement_version TEXT,
  UNIQUE(package_id, version)
);

ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS artifact_size BIGINT DEFAULT 0;
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS download_count BIGINT DEFAULT 0;
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS last_published_by TEXT;
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS source_repo TEXT;
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS source_visibility TEXT DEFAULT 'unknown';
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS has_native_binaries BOOLEAN DEFAULT false;
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS has_install_scripts BOOLEAN DEFAULT false;
ALTER TABLE package_versions ADD COLUMN IF NOT EXISTS latest_verified_audit_id TEXT;

CREATE TABLE IF NOT EXISTS executables (
  id TEXT PRIMARY KEY,
  package_version_id TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
  command TEXT NOT NULL,
  entry TEXT NOT NULL,
  summary TEXT,
  permissions JSONB,
  risk_score INTEGER DEFAULT 0,
  metadata JSONB
);

CREATE INDEX IF NOT EXISTS executables_command_idx ON executables(command);

CREATE TABLE IF NOT EXISTS evals (
  id TEXT PRIMARY KEY,
  package_version_id TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  model TEXT,
  verdict TEXT NOT NULL,
  risk_score INTEGER DEFAULT 0,
  reasons JSONB NOT NULL,
  suggested_actions JSONB,
  privacy_summary JSONB,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audits (
  id TEXT PRIMARY KEY,
  package_version_id TEXT REFERENCES package_versions(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  sandbox_runtime TEXT NOT NULL,
  agent_image TEXT NOT NULL,
  agent_image_digest TEXT,
  evidence JSONB NOT NULL,
  verdict TEXT NOT NULL,
  risk_score INTEGER NOT NULL,
  reasons JSONB NOT NULL,
  suggested_actions JSONB,
  signature TEXT NOT NULL,
  cost_cents INTEGER NOT NULL DEFAULT 50,
  release_state_applied TEXT,
  started_at TIMESTAMPTZ DEFAULT now(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS audits_package_version_started_idx ON audits(package_version_id, started_at DESC);
`)
	return err
}
