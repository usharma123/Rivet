package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/usharma123/rivet/registry/internal/api"
	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/db"
	"github.com/usharma123/rivet/registry/internal/mirror"
	"github.com/usharma123/rivet/registry/internal/npm"
	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "registry failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	production := env("RIVET_ENV", "development") == "production"
	dataDir := env("RIVET_DATA_DIR", "./data")

	store, closeStore, err := openStore(production)
	if err != nil {
		return err
	}
	defer closeStore()

	artifactStore, err := artifacts.NewFileStore(env("RIVET_ARTIFACT_DIR", filepath.Join(dataDir, "artifacts")))
	if err != nil {
		return err
	}

	// Production deployments must supply their key; development generates
	// one on first start and keeps it in the data directory.
	signer, generated, err := signing.LoadSigner(
		os.Getenv("RIVET_SIGNING_KEY"),
		env("RIVET_SIGNING_KEY_FILE", filepath.Join(dataDir, "signing.key")),
		!production,
	)
	if err != nil {
		return fmt.Errorf("load signing key: %w", err)
	}
	if generated {
		fmt.Fprintf(os.Stderr, "generated new registry signing key %s\n", signer.KeyID())
	}

	pipeline := &audit.Pipeline{Signer: signer}
	switch mode := env("RIVET_AUDIT_MODE", "static"); mode {
	case "static":
	case "gvisor":
		pipeline.Sandbox = audit.NewDockerRunner(env("RIVET_AUDIT_AGENT_IMAGE", "rivet-audit-agent:local"))
	default:
		return fmt.Errorf("unknown RIVET_AUDIT_MODE %q (want static or gvisor)", mode)
	}

	npmClient, err := npm.NewClient(env("RIVET_NPM_UPSTREAM", npm.DefaultRegistry))
	if err != nil {
		return err
	}
	var provenance *npm.ProvenanceVerifier
	if env("RIVET_VERIFY_PROVENANCE", "true") == "true" {
		provenance = npm.NewProvenanceVerifier(npmClient)
	}
	ttlHours, err := strconv.Atoi(env("RIVET_ATTESTATION_TTL_HOURS", "168"))
	if err != nil || ttlHours <= 0 {
		return errors.New("RIVET_ATTESTATION_TTL_HOURS must be a positive integer")
	}

	token := os.Getenv("RIVET_REGISTRY_TOKEN")
	if production && len(token) < 32 {
		return errors.New("RIVET_REGISTRY_TOKEN must be at least 32 characters in production")
	}
	handler := api.NewServer(api.Config{
		Store:     store,
		Artifacts: artifactStore,
		Pipeline:  pipeline,
		Mirror: &mirror.Service{
			Store:      store,
			Artifacts:  artifactStore,
			NPM:        npmClient,
			Provenance: provenance,
			Pipeline:   pipeline,
		},
		Signer:         signer,
		Token:          token,
		AdminToken:     os.Getenv("RIVET_ADMIN_TOKEN"),
		PublicMirror:   env("RIVET_PUBLIC_MIRROR", "false") == "true",
		AttestationTTL: time.Duration(ttlHours) * time.Hour,
	})

	server := &http.Server{
		Addr:              env("RIVET_ADDR", ":8080"),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("rivet registry listening on %s (signing key %s)\n", server.Addr, signer.KeyID())
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "registry listen failed: %v\n", err)
			os.Exit(1)
		}
	}()

	<-done
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return server.Shutdown(shutdownCtx)
}

func openStore(production bool) (registry.Store, func(), error) {
	if env("RIVET_STORE", "postgres") == "memory" {
		if production {
			return nil, nil, errors.New("RIVET_STORE=memory is not allowed in production")
		}
		fmt.Fprintln(os.Stderr, "using in-memory store; all registry state is lost on exit")
		return registry.NewMemoryStore(), func() {}, nil
	}
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, nil, errors.New("DATABASE_URL is required (or set RIVET_STORE=memory for development)")
	}
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := db.Migrate(ctx, conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	if err := db.CheckLegacyReleases(ctx, conn); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return db.NewPostgresStore(conn), func() { conn.Close() }, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
