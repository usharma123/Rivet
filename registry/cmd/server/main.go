package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/usharma123/rivet/registry/internal/api"
	"github.com/usharma123/rivet/registry/internal/artifacts"
	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/db"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "registry failed: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := env("DATABASE_URL", "")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}

	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		return err
	}
	if err := db.Migrate(ctx, conn); err != nil {
		return err
	}

	store := db.NewPostgresStore(conn)
	artifactStore, err := artifacts.NewFileStore(env("RIVET_ARTIFACT_DIR", "./artifacts"))
	if err != nil {
		return err
	}
	auditor := audit.NewDockerRunner(
		env("RIVET_AUDIT_AGENT_IMAGE", "rivet-audit-agent:local"),
		env("RIVET_AUDIT_PROXY_URL", "http://host.docker.internal:8080/v1/audit-proxy/model"),
		env("RIVET_AUDIT_SIGNING_KEY", "dev-audit-signing-key"),
	)

	server := &http.Server{
		Addr:              env("RIVET_ADDR", ":8080"),
		Handler:           api.NewServerWithAuditor(store, artifactStore, env("RIVET_REGISTRY_TOKEN", ""), auditor),
		ReadHeaderTimeout: 10 * time.Second,
	}

	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		fmt.Printf("rivet registry listening on %s\n", server.Addr)
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

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
