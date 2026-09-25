// Package attest builds the signed release statements clients rely on. A
// statement binds a package name and version to its artifact hash, canonical
// tree digest, normalized manifest, provenance, audit verdict and current
// release state. Statements are re-signed on every request and expire, so a
// client holding a fresh statement knows the release was not revoked since.
package attest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/usharma123/rivet/registry/internal/audit"
	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

const (
	PayloadType   = "application/vnd.rivet.release+json"
	StatementType = "https://rivet.dev/attestation/release/v1"
	DefaultTTL    = 7 * 24 * time.Hour
)

type Statement struct {
	Type               string                    `json:"_type"`
	Name               string                    `json:"name"`
	Version            string                    `json:"version"`
	Source             string                    `json:"source"`
	State              registry.ReleaseState     `json:"state"`
	Artifact           Artifact                  `json:"artifact"`
	Manifest           registry.PackageManifest  `json:"manifest"`
	Executables        []Executable              `json:"executables,omitempty"`
	Publisher          string                    `json:"publisher,omitempty"`
	PublishedAt        time.Time                 `json:"published_at"`
	Upstream           *audit.UpstreamEvidence   `json:"upstream,omitempty"`
	Provenance         *audit.ProvenanceEvidence `json:"provenance,omitempty"`
	Audit              *AuditSummary             `json:"audit,omitempty"`
	RevokeReason       string                    `json:"revoke_reason,omitempty"`
	ReplacementVersion string                    `json:"replacement_version,omitempty"`
	IssuedAt           time.Time                 `json:"issued_at"`
	ExpiresAt          time.Time                 `json:"expires_at"`
}

type Artifact struct {
	Hash       string `json:"hash"`
	Size       int64  `json:"size"`
	TreeDigest string `json:"tree_digest"`
}

type Executable struct {
	Command     string          `json:"command"`
	Entry       string          `json:"entry"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
}

type AuditSummary struct {
	ID             string                `json:"id"`
	Status         registry.AuditStatus  `json:"status"`
	Verdict        registry.AuditVerdict `json:"verdict"`
	RiskScore      int                   `json:"risk_score"`
	Reasons        []string              `json:"reasons"`
	SandboxRuntime string                `json:"sandbox_runtime"`
	AgentImage     string                `json:"agent_image"`
	Capabilities   []string              `json:"capabilities,omitempty"`
	Diff           *audit.DiffEvidence   `json:"diff,omitempty"`
	CompletedAt    *time.Time            `json:"completed_at,omitempty"`
}

// Build assembles a statement from stored registry state.
func Build(version registry.VersionRecord, now time.Time, ttl time.Duration) (Statement, error) {
	if version.TreeDigest == "" {
		return Statement{}, fmt.Errorf("%s@%s has no tree digest", version.Name, version.Version)
	}
	var manifest registry.PackageManifest
	if err := json.Unmarshal(version.Manifest, &manifest); err != nil {
		return Statement{}, fmt.Errorf("decode stored manifest: %w", err)
	}
	statement := Statement{
		Type:     StatementType,
		Name:     version.Name,
		Version:  version.Version,
		Source:   version.Source,
		State:    version.State,
		Manifest: manifest,
		Artifact: Artifact{
			Hash:       version.ArtifactHash,
			Size:       version.ArtifactSize,
			TreeDigest: version.TreeDigest,
		},
		Publisher:          version.Publisher,
		PublishedAt:        version.PublishedAt.UTC(),
		RevokeReason:       version.RevokeReason,
		ReplacementVersion: version.ReplacementVersion,
		IssuedAt:           now.UTC(),
		ExpiresAt:          now.UTC().Add(ttl),
	}
	for _, executable := range version.Executables {
		statement.Executables = append(statement.Executables, Executable{
			Command:     executable.Command,
			Entry:       executable.Entry,
			Permissions: executable.Permissions,
		})
	}
	if version.LatestAudit != nil {
		a := version.LatestAudit
		var evidence audit.Evidence
		_ = json.Unmarshal(a.Evidence, &evidence)
		var reasons []string
		_ = json.Unmarshal(a.Reasons, &reasons)
		statement.Audit = &AuditSummary{
			ID:             a.ID,
			Status:         a.Status,
			Verdict:        a.Verdict,
			RiskScore:      a.RiskScore,
			Reasons:        reasons,
			SandboxRuntime: a.SandboxRuntime,
			AgentImage:     a.AgentImage,
			Capabilities:   evidence.Static.CapabilityNames(),
			Diff:           evidence.Diff,
			CompletedAt:    a.CompletedAt,
		}
		statement.Upstream = evidence.Upstream
		statement.Provenance = evidence.Provenance
	}
	return statement, nil
}

// Sign serializes and signs a statement.
func Sign(signer *signing.Signer, statement Statement) (signing.Envelope, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return signing.Envelope{}, err
	}
	return signer.Seal(PayloadType, payload), nil
}
