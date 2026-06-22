package audit

import (
	"context"

	"github.com/usharma123/rivet/registry/internal/registry"
)

type Runner interface {
	Audit(ctx context.Context, version registry.VersionRecord, artifactPath string) (registry.AuditRecord, error)
}
