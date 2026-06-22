package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/usharma123/rivet/registry/internal/registry"
)

type PostgresStore struct {
	conn *sql.DB
	now  func() time.Time
}

func NewPostgresStore(conn *sql.DB) *PostgresStore {
	return &PostgresStore{conn: conn, now: time.Now}
}

func (s *PostgresStore) GetPackage(ctx context.Context, name string) (registry.PackageRecord, error) {
	var pkg registry.PackageRecord
	err := s.conn.QueryRowContext(ctx, `
SELECT name, source, COALESCE(publisher, ''), created_at
FROM packages
WHERE name = $1`, name).Scan(&pkg.Name, &pkg.Source, &pkg.Publisher, &pkg.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.PackageRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.PackageRecord{}, err
	}
	versions, err := s.listVersions(ctx, name)
	if err != nil {
		return registry.PackageRecord{}, err
	}
	pkg.Versions = versions
	return pkg, nil
}

func (s *PostgresStore) GetVersion(ctx context.Context, name, version string) (registry.VersionRecord, error) {
	return s.getVersion(ctx, name, version)
}

func (s *PostgresStore) FindExecutable(ctx context.Context, command string) (registry.VersionRecord, error) {
	var name, version string
	err := s.conn.QueryRowContext(ctx, `
SELECT p.name, pv.version
FROM executables e
JOIN package_versions pv ON pv.id = e.package_version_id
JOIN packages p ON p.id = pv.package_id
WHERE e.command = $1
ORDER BY pv.published_at DESC
LIMIT 1`, command).Scan(&name, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.VersionRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.VersionRecord{}, err
	}
	return s.getVersion(ctx, name, version)
}

func (s *PostgresStore) Search(ctx context.Context, query string) ([]registry.PackageRecord, error) {
	rows, err := s.conn.QueryContext(ctx, `
SELECT name, source, COALESCE(publisher, ''), created_at
FROM packages
WHERE $1 = '' OR name ILIKE '%' || $1 || '%'
ORDER BY name
LIMIT 50`, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []registry.PackageRecord
	for rows.Next() {
		var pkg registry.PackageRecord
		if err := rows.Scan(&pkg.Name, &pkg.Source, &pkg.Publisher, &pkg.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, pkg)
	}
	return out, rows.Err()
}

func (s *PostgresStore) UpsertVersion(ctx context.Context, version registry.VersionRecord) (registry.VersionRecord, error) {
	version.State = registry.NormalizeState(version.State)
	if err := registry.ValidateReleaseState(version.State); err != nil {
		return registry.VersionRecord{}, err
	}
	if len(version.Manifest) == 0 {
		return registry.VersionRecord{}, fmt.Errorf("%w: manifest is required", registry.ErrInvalidRequest)
	}
	if version.ArtifactHash == "" {
		return registry.VersionRecord{}, fmt.Errorf("%w: artifact_hash is required", registry.ErrInvalidRequest)
	}
	if version.ArtifactURL == "" {
		version.ArtifactURL = "/v1/artifacts/" + version.ArtifactHash
	}
	if len(version.SourceMetadata) == 0 {
		version.SourceMetadata = json.RawMessage(`{}`)
	}

	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	defer tx.Rollback()

	packageID := newID()
	err = tx.QueryRowContext(ctx, `
INSERT INTO packages (id, name, source, publisher)
VALUES ($1, $2, $3, $4)
ON CONFLICT (name)
DO UPDATE SET source = EXCLUDED.source, publisher = EXCLUDED.publisher
RETURNING id`, packageID, version.Name, version.Source, nullString(version.Publisher)).
		Scan(&packageID)
	if err != nil {
		return registry.VersionRecord{}, err
	}

	versionID := newID()
	err = tx.QueryRowContext(ctx, `
INSERT INTO package_versions (
  id, package_id, version, source, state, manifest, artifact_hash, artifact_url,
  source_metadata, risk_score, published_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
ON CONFLICT (package_id, version)
DO UPDATE SET
  source = EXCLUDED.source,
  state = EXCLUDED.state,
  manifest = EXCLUDED.manifest,
  artifact_hash = EXCLUDED.artifact_hash,
  artifact_url = EXCLUDED.artifact_url,
  source_metadata = EXCLUDED.source_metadata,
  risk_score = EXCLUDED.risk_score,
  published_at = package_versions.published_at
RETURNING id`, versionID, packageID, version.Version, version.Source, string(version.State), version.Manifest,
		version.ArtifactHash, version.ArtifactURL, version.SourceMetadata, version.RiskScore).
		Scan(&versionID)
	if err != nil {
		return registry.VersionRecord{}, err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM executables WHERE package_version_id = $1`, versionID); err != nil {
		return registry.VersionRecord{}, err
	}
	for _, executable := range version.Executables {
		if len(executable.Permissions) == 0 {
			executable.Permissions = json.RawMessage(`{}`)
		}
		if len(executable.Metadata) == 0 {
			executable.Metadata = json.RawMessage(`{}`)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO executables (id, package_version_id, command, entry, summary, permissions, risk_score, metadata)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			newID(), versionID, executable.Command, executable.Entry, nullString(executable.Summary),
			executable.Permissions, executable.RiskScore, executable.Metadata); err != nil {
			return registry.VersionRecord{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return registry.VersionRecord{}, err
	}
	return s.getVersion(ctx, version.Name, version.Version)
}

func (s *PostgresStore) SetReleaseState(ctx context.Context, name, version string, state registry.ReleaseState, req registry.StateChangeRequest) (registry.VersionRecord, error) {
	current, err := s.getVersion(ctx, name, version)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	if err := registry.AllowStateChange(current, state, req, s.now()); err != nil {
		return registry.VersionRecord{}, err
	}

	var revokedAt any
	if state == registry.StateRevoked {
		revokedAt = s.now()
	}
	_, err = s.conn.ExecContext(ctx, `
UPDATE package_versions pv
SET state = $1, revoked_at = COALESCE($2, revoked_at), revoke_reason = $3, replacement_version = $4
FROM packages p
WHERE pv.package_id = p.id AND p.name = $5 AND pv.version = $6`,
		string(state), revokedAt, nullString(req.Reason), nullString(req.ReplacementVersion), name, version)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	return s.getVersion(ctx, name, version)
}

func (s *PostgresStore) CreateEval(ctx context.Context, eval registry.EvalRecord) (registry.EvalRecord, error) {
	if len(eval.Reasons) == 0 {
		eval.Reasons = json.RawMessage(`[]`)
	}
	if len(eval.Suggested) == 0 {
		eval.Suggested = json.RawMessage(`[]`)
	}
	if len(eval.PrivacySummary) == 0 {
		eval.PrivacySummary = json.RawMessage(`{}`)
	}

	var versionID string
	err := s.conn.QueryRowContext(ctx, `
SELECT pv.id
FROM package_versions pv
JOIN packages p ON p.id = pv.package_id
WHERE p.name = $1 AND pv.version = $2`, eval.PackageName, eval.Version).Scan(&versionID)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.EvalRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.EvalRecord{}, err
	}

	err = s.conn.QueryRowContext(ctx, `
INSERT INTO evals (id, package_version_id, provider, model, verdict, risk_score, reasons, suggested_actions, privacy_summary)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING created_at`,
		newID(), versionID, eval.Provider, nullString(eval.Model), eval.Verdict, eval.RiskScore,
		eval.Reasons, eval.Suggested, eval.PrivacySummary).Scan(&eval.CreatedAt)
	if err != nil {
		return registry.EvalRecord{}, err
	}
	return eval, nil
}

func (s *PostgresStore) listVersions(ctx context.Context, name string) ([]registry.VersionRecord, error) {
	rows, err := s.conn.QueryContext(ctx, `
SELECT pv.version
FROM package_versions pv
JOIN packages p ON p.id = pv.package_id
WHERE p.name = $1
ORDER BY pv.published_at DESC`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []registry.VersionRecord
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		record, err := s.getVersion(ctx, name, version)
		if err != nil {
			return nil, err
		}
		versions = append(versions, record)
	}
	return versions, rows.Err()
}

func (s *PostgresStore) getVersion(ctx context.Context, name, version string) (registry.VersionRecord, error) {
	var record registry.VersionRecord
	var state string
	var sourceMetadata []byte
	err := s.conn.QueryRowContext(ctx, `
SELECT
  p.name, pv.version, pv.source, pv.state, pv.manifest, pv.artifact_hash, pv.artifact_url,
  COALESCE(p.publisher, ''), COALESCE(pv.source_metadata, '{}'::jsonb), pv.published_at,
  pv.revoked_at, COALESCE(pv.revoke_reason, ''), COALESCE(pv.replacement_version, ''), pv.risk_score
FROM package_versions pv
JOIN packages p ON p.id = pv.package_id
WHERE p.name = $1 AND pv.version = $2`, name, version).
		Scan(&record.Name, &record.Version, &record.Source, &state, &record.Manifest,
			&record.ArtifactHash, &record.ArtifactURL, &record.Publisher, &sourceMetadata,
			&record.PublishedAt, &record.RevokedAt, &record.RevokeReason, &record.ReplacementVersion,
			&record.RiskScore)
	if errors.Is(err, sql.ErrNoRows) {
		return registry.VersionRecord{}, registry.ErrNotFound
	}
	if err != nil {
		return registry.VersionRecord{}, err
	}
	record.State = registry.ReleaseState(state)
	record.SourceMetadata = json.RawMessage(sourceMetadata)

	executables, err := s.executables(ctx, name, version)
	if err != nil {
		return registry.VersionRecord{}, err
	}
	record.Executables = executables
	return record, nil
}

func (s *PostgresStore) executables(ctx context.Context, name, version string) ([]registry.Executable, error) {
	rows, err := s.conn.QueryContext(ctx, `
SELECT e.command, e.entry, COALESCE(e.summary, ''), COALESCE(e.permissions, '{}'::jsonb), e.risk_score, COALESCE(e.metadata, '{}'::jsonb)
FROM executables e
JOIN package_versions pv ON pv.id = e.package_version_id
JOIN packages p ON p.id = pv.package_id
WHERE p.name = $1 AND pv.version = $2
ORDER BY e.command`, name, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []registry.Executable
	for rows.Next() {
		var executable registry.Executable
		var permissions, metadata []byte
		if err := rows.Scan(&executable.Command, &executable.Entry, &executable.Summary, &permissions, &executable.RiskScore, &metadata); err != nil {
			return nil, err
		}
		executable.Permissions = json.RawMessage(permissions)
		executable.Metadata = json.RawMessage(metadata)
		out = append(out, executable)
	}
	return out, rows.Err()
}

func nullString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: value != ""}
}
