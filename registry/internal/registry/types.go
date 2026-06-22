package registry

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type ReleaseState string

const (
	StateActive      ReleaseState = "active"
	StateWarned      ReleaseState = "warned"
	StateQuarantined ReleaseState = "quarantined"
	StateYanked      ReleaseState = "yanked"
	StateRevoked     ReleaseState = "revoked"
	StateBlocked     ReleaseState = "blocked"
	StateArchived    ReleaseState = "archived"
)

var (
	ErrNotFound       = errors.New("not found")
	ErrPolicy         = errors.New("release policy denied")
	ErrInvalidRequest = errors.New("invalid request")
)

type PackageRecord struct {
	Name      string          `json:"name"`
	Source    string          `json:"source"`
	Publisher string          `json:"publisher,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	Versions  []VersionRecord `json:"versions,omitempty"`
}

type VersionRecord struct {
	Name               string          `json:"name"`
	Version            string          `json:"version"`
	Source             string          `json:"source"`
	State              ReleaseState    `json:"state"`
	Manifest           json.RawMessage `json:"manifest"`
	ArtifactHash       string          `json:"artifact_hash"`
	ArtifactURL        string          `json:"artifact_url"`
	Publisher          string          `json:"publisher,omitempty"`
	SourceMetadata     json.RawMessage `json:"source_metadata,omitempty"`
	PublishedAt        time.Time       `json:"published_at"`
	RevokedAt          *time.Time      `json:"revoked_at,omitempty"`
	RevokeReason       string          `json:"revoke_reason,omitempty"`
	ReplacementVersion string          `json:"replacement_version,omitempty"`
	Executables        []Executable    `json:"executables,omitempty"`
	RiskScore          int             `json:"risk_score"`
}

type Executable struct {
	Command     string          `json:"command"`
	Entry       string          `json:"entry"`
	Summary     string          `json:"summary,omitempty"`
	Permissions json.RawMessage `json:"permissions,omitempty"`
	RiskScore   int             `json:"risk_score"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
}

type EvalRecord struct {
	PackageName    string          `json:"package"`
	Version        string          `json:"version"`
	Provider       string          `json:"provider"`
	Model          string          `json:"model,omitempty"`
	Verdict        string          `json:"verdict"`
	RiskScore      int             `json:"risk_score"`
	Reasons        json.RawMessage `json:"reasons"`
	Suggested      json.RawMessage `json:"suggested_actions,omitempty"`
	PrivacySummary json.RawMessage `json:"privacy_summary,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type PublishRequest struct {
	Source         string          `json:"source"`
	Publisher      string          `json:"publisher,omitempty"`
	State          ReleaseState    `json:"state,omitempty"`
	Manifest       json.RawMessage `json:"manifest"`
	ArtifactHash   string          `json:"artifact_hash"`
	ArtifactURL    string          `json:"artifact_url,omitempty"`
	SourceMetadata json.RawMessage `json:"source_metadata,omitempty"`
	Executables    []Executable    `json:"executables,omitempty"`
	RiskScore      int             `json:"risk_score"`
}

type StateChangeRequest struct {
	Reason             string `json:"reason"`
	ReplacementVersion string `json:"replacement_version,omitempty"`
	RegistryApproved   bool   `json:"registry_approved,omitempty"`
	SecurityEvidence   bool   `json:"security_evidence,omitempty"`
}

type Store interface {
	GetPackage(ctx context.Context, name string) (PackageRecord, error)
	GetVersion(ctx context.Context, name, version string) (VersionRecord, error)
	FindExecutable(ctx context.Context, command string) (VersionRecord, error)
	Search(ctx context.Context, query string) ([]PackageRecord, error)
	UpsertVersion(ctx context.Context, version VersionRecord) (VersionRecord, error)
	SetReleaseState(ctx context.Context, name, version string, state ReleaseState, req StateChangeRequest) (VersionRecord, error)
	CreateEval(ctx context.Context, eval EvalRecord) (EvalRecord, error)
}

func NormalizeState(state ReleaseState) ReleaseState {
	if state == "" {
		return StateActive
	}
	return state
}
