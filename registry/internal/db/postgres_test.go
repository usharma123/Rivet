package db

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/registry/storetest"
)

// TestPostgresStoreContract runs the store contract against a real database.
// Set RIVET_TEST_DATABASE_URL to a disposable database to enable it.
func TestPostgresStoreContract(t *testing.T) {
	url := os.Getenv("RIVET_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set RIVET_TEST_DATABASE_URL to run")
	}
	conn, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ctx := context.Background()
	if err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	// Migrations must be re-runnable.
	if err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	storetest.Run(t, func(t *testing.T) registry.Store {
		if _, err := conn.ExecContext(ctx, `TRUNCATE packages, package_versions, executables, evals, audits CASCADE`); err != nil {
			t.Fatal(err)
		}
		return NewPostgresStore(conn)
	})
}

func TestLegacyReleaseWithoutDigestBlocksStartup(t *testing.T) {
	url := os.Getenv("RIVET_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("set RIVET_TEST_DATABASE_URL to run")
	}
	conn, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	if err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `TRUNCATE packages, package_versions, executables, evals, audits CASCADE`); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(ctx, `TRUNCATE packages, package_versions, executables, evals, audits CASCADE`)
	if _, err := conn.ExecContext(ctx, `INSERT INTO packages (id,name,source) VALUES ('legacy-pkg','legacy-demo','native')`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO package_versions (id,package_id,version,source,state,manifest,artifact_hash,artifact_url) VALUES ('legacy-version','legacy-pkg','1.0.0','native','active','{}','sha512-legacy','/artifact')`); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyReleases(ctx, conn); err == nil {
		t.Fatal("legacy release was served without a digest migration")
	}
	if _, err := conn.ExecContext(ctx, `UPDATE package_versions SET tree_digest = 'rivet-tree-v1:sha256:verified' WHERE id = 'legacy-version'`); err != nil {
		t.Fatal(err)
	}
	if err := CheckLegacyReleases(ctx, conn); err != nil {
		t.Fatalf("verified migrated release rejected: %v", err)
	}
}
