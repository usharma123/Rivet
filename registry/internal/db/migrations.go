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
`)
	return err
}
