// Package storetest is a contract suite every registry.Store must pass, so
// the in-memory and Postgres stores cannot drift apart.
package storetest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/usharma123/rivet/registry/internal/registry"
)

func version(name, v, hash string) registry.VersionRecord {
	return registry.VersionRecord{
		Name:         name,
		Version:      v,
		Source:       "npm",
		Manifest:     json.RawMessage(`{"name":"` + name + `"}`),
		ArtifactHash: hash,
		TreeDigest:   "rivet-tree-v1:sha256:" + hash,
		Executables:  []registry.Executable{{Command: "cmd-" + v, Entry: "bin.js", Permissions: json.RawMessage(`{"network":false}`)}},
	}
}

func auditFor(name, v string, verdict registry.AuditVerdict) registry.AuditRecord {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return registry.AuditRecord{
		PackageName:    name,
		Version:        v,
		Status:         registry.AuditPassed,
		SandboxRuntime: registry.SandboxStatic,
		AgentImage:     "in-process",
		Evidence:       json.RawMessage(`{"static":{}}`),
		Verdict:        verdict,
		RiskScore:      10,
		Reasons:        json.RawMessage(`["x"]`),
		Signature:      "keyid|sig",
		CompletedAt:    &now,
	}
}

// Run executes the contract. reset must return an empty store.
func Run(t *testing.T, reset func(t *testing.T) registry.Store) {
	ctx := context.Background()

	t.Run("new versions are pending and immutable", func(t *testing.T) {
		store := reset(t)
		stored, err := store.UpsertVersion(ctx, version("@scope/pkg", "1.0.0", "sha512-a"))
		if err != nil {
			t.Fatal(err)
		}
		if stored.State != registry.StatePending || stored.TreeDigest != "rivet-tree-v1:sha256:sha512-a" {
			t.Fatalf("unexpected stored version %+v", stored)
		}
		if _, err := store.UpsertVersion(ctx, version("@scope/pkg", "1.0.0", "sha512-a")); err != nil {
			t.Fatalf("same content must be idempotent: %v", err)
		}
		if _, err := store.UpsertVersion(ctx, version("@scope/pkg", "1.0.0", "sha512-b")); !errors.Is(err, registry.ErrConflict) {
			t.Fatalf("different content must conflict, got %v", err)
		}
		missing := version("x", "1.0.0", "sha512-c")
		missing.TreeDigest = ""
		if _, err := store.UpsertVersion(ctx, missing); !errors.Is(err, registry.ErrInvalidRequest) {
			t.Fatalf("tree digest must be required, got %v", err)
		}
	})

	t.Run("audits drive state but never undo revocation", func(t *testing.T) {
		store := reset(t)
		if _, err := store.UpsertVersion(ctx, version("pkg", "1.0.0", "sha512-a")); err != nil {
			t.Fatal(err)
		}
		created, err := store.CreateAudit(ctx, auditFor("pkg", "1.0.0", registry.VerdictMedium))
		if err != nil {
			t.Fatal(err)
		}
		if created.ReleaseStateApplied != registry.StateWarned {
			t.Fatalf("medium should warn, got %s", created.ReleaseStateApplied)
		}
		got, err := store.GetVersion(ctx, "pkg", "1.0.0")
		if err != nil || got.State != registry.StateWarned || got.LatestAudit == nil || got.LatestAudit.ID != created.ID {
			t.Fatalf("version not updated by audit: %+v %v", got, err)
		}
		if _, err := store.SetReleaseState(ctx, "pkg", "1.0.0", registry.StateRevoked, registry.StateChangeRequest{Reason: "malware"}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.CreateAudit(ctx, auditFor("pkg", "1.0.0", registry.VerdictLow)); err != nil {
			t.Fatal(err)
		}
		got, _ = store.GetVersion(ctx, "pkg", "1.0.0")
		if got.State != registry.StateRevoked || got.RevokeReason != "malware" {
			t.Fatalf("re-audit must not undo revocation: %s", got.State)
		}
		latest, err := store.GetLatestAudit(ctx, "pkg", "1.0.0")
		if err != nil || latest.Verdict != registry.VerdictLow {
			t.Fatalf("latest audit: %+v %v", latest, err)
		}
		if _, err := store.GetAudit(ctx, created.ID); err != nil {
			t.Fatalf("earlier audit must remain readable: %v", err)
		}
	})

	t.Run("packages list versions and executables", func(t *testing.T) {
		store := reset(t)
		for _, v := range []string{"1.0.0", "1.1.0"} {
			record := version("tool", v, "sha512-"+v)
			record.Source = "native"
			if _, err := store.UpsertVersion(ctx, record); err != nil {
				t.Fatal(err)
			}
		}
		pkg, err := store.GetPackage(ctx, "tool")
		if err != nil || pkg.Source != "native" || len(pkg.Versions) != 2 {
			t.Fatalf("unexpected package %+v %v", pkg, err)
		}
		found, err := store.FindExecutable(ctx, "cmd-1.1.0")
		if err != nil || found.Version != "1.1.0" {
			t.Fatalf("executable lookup: %+v %v", found, err)
		}
		if _, err := store.GetVersion(ctx, "tool", "9.9.9"); !errors.Is(err, registry.ErrNotFound) {
			t.Fatalf("missing version should be not found, got %v", err)
		}
	})
}
