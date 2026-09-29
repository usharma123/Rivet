package audit

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/usharma123/rivet/registry/internal/canon"
	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

// Sandbox runs a package inside an isolated runtime and reports what it did.
// Only the dynamic parts of the returned evidence (probes, egress,
// honeytokens) are used; static facts always come from the registry itself.
type Sandbox interface {
	Runtime() string
	Image() string
	Run(ctx context.Context, version registry.VersionRecord, artifactPath string) (Evidence, error)
}

// PreviousRelease describes the release a new version is diffed against.
type PreviousRelease struct {
	Version       string
	Static        StaticEvidence
	Dependencies  map[string]string
	Publisher     string
	HadProvenance bool
}

type Input struct {
	Version      registry.VersionRecord
	Package      *canon.Package
	ArtifactPath string
	Dependencies map[string]string
	Upstream     *UpstreamEvidence
	Provenance   *ProvenanceEvidence
	Previous     *PreviousRelease
	// WeeklyDownloads, when known, suppresses namesquat warnings for
	// packages that are established in their own right.
	WeeklyDownloads *int64
}

// EstablishedDownloads is the weekly download count above which a package is
// treated as established rather than as a possible namesquat.
const EstablishedDownloads = 50_000

// Pipeline produces signed audit records. Static analysis always runs in
// process; a Sandbox adds dynamic evidence and fails closed when configured.
type Pipeline struct {
	Signer  *signing.Signer
	Sandbox Sandbox
	Now     func() time.Time
}

func (p *Pipeline) Audit(ctx context.Context, in Input) (registry.AuditRecord, error) {
	if p.Signer == nil {
		return registry.AuditRecord{}, fmt.Errorf("audit pipeline has no signing key")
	}
	clock := time.Now
	if p.Now != nil {
		clock = p.Now
	}
	now := func() time.Time { return clock().UTC().Truncate(time.Microsecond) }
	started := now()
	var normalized *registry.PackageManifest
	if len(in.Version.Manifest) != 0 {
		var parsed registry.PackageManifest
		if err := json.Unmarshal(in.Version.Manifest, &parsed); err != nil {
			return registry.AuditRecord{}, fmt.Errorf("decode authoritative audit manifest: %w", err)
		}
		if parsed.Name != in.Version.Name || parsed.Version != in.Version.Version {
			return registry.AuditRecord{}, fmt.Errorf("authoritative audit manifest identity mismatch")
		}
		normalized = &parsed
	}
	evidence := Evidence{
		Static:     AnalyzeStaticWithManifest(in.Package, normalized),
		Upstream:   in.Upstream,
		Provenance: in.Provenance,
		Privacy: map[string][]string{
			"will_send":     {},
			"will_not_send": {"package contents never leave the registry"},
		},
		Sandbox: map[string]string{"runtime": registry.SandboxStatic},
		Agent:   map[string]string{"name": "rivet-registry-static-analyzer", "version": "2"},
	}
	if in.WeeklyDownloads != nil {
		evidence.Static.WeeklyDownloads = in.WeeklyDownloads
		if *in.WeeklyDownloads >= EstablishedDownloads {
			evidence.Static.NamesquatWarning = ""
		}
	}
	if in.Provenance != nil && in.Provenance.Status == "verified" && in.Provenance.SourceRepo != "" {
		evidence.Static.SourceRepo = in.Provenance.SourceRepo
		evidence.Static.SourceVisibility = "verified"
	}
	if in.Previous != nil {
		evidence.Diff = Diff(in.Previous.Version, in.Previous.Static, evidence.Static, in.Previous.Dependencies, in.Dependencies)
		if in.Upstream != nil && in.Previous.Publisher != "" && in.Upstream.Publisher != "" && in.Previous.Publisher != in.Upstream.Publisher {
			evidence.Diff.PublisherChanged = true
			evidence.Diff.PreviousPublisher = in.Previous.Publisher
		}
		evidence.Diff.PreviousProvenance = in.Previous.HadProvenance
		if in.Previous.HadProvenance && (in.Provenance == nil || in.Provenance.Status == "absent" || in.Provenance.Status == "invalid") {
			evidence.Diff.ProvenanceRegressed = true
		}
	}

	// Probe results are advisory. Only DockerRunner's private collector can
	// provide validated kernel observations and certify the sandbox run.
	image := "in-process"
	trustedSandbox := false
	if p.Sandbox != nil {
		dynamic, err := p.Sandbox.Run(ctx, in.Version, in.ArtifactPath)
		if err != nil {
			return registry.AuditRecord{}, fmt.Errorf("sandbox audit failed closed: %w", err)
		}
		evidence.SafeProbes = dynamic.SafeProbes
		evidence.Adversarial = dynamic.Adversarial
		evidence.Egress = dynamic.Egress
		evidence.Honeytokens = dynamic.Honeytokens
		image = p.Sandbox.Image()
		evidence.Sandbox = map[string]string{"runtime": registry.SandboxStatic, "attempted_runtime": p.Sandbox.Runtime(), "network": "none", "observations": "package-tamperable"}
		evidence.Agent = dynamic.Agent
		if dynamic.validatedTrace != nil {
			if err := validateTrustedInput(dynamic.validatedTrace, in); err != nil {
				return registry.AuditRecord{}, fmt.Errorf("sandbox trace input mismatch: %w", err)
			}
			trustedSandbox = true
			evidence.Sandbox = map[string]string{"runtime": registry.SandboxGVisor, "network": "none", "observations": "gvisor-kernel-trace", "trace_container_id": dynamic.validatedTrace.containerID, "artifact_hash": dynamic.validatedTrace.artifactHash, "tree_digest": dynamic.validatedTrace.treeDigest, "manifest_sha512": dynamic.validatedTrace.manifestHash}
		}
	}

	trustedForScore := evidence
	trustedForScore.SafeProbes = nil
	trustedForScore.Adversarial = nil
	if !trustedSandbox {
		trustedForScore.Egress = nil
		trustedForScore.Honeytokens = nil
	}
	score := ScoreEvidence(trustedForScore)
	completed := now()
	record := registry.AuditRecord{
		PackageName:    in.Version.Name,
		Version:        in.Version.Version,
		Status:         registry.AuditPassed,
		SandboxRuntime: registry.SandboxStatic,
		AgentImage:     image,
		Evidence:       EvidenceJSON(evidence),
		Verdict:        score.Verdict,
		RiskScore:      score.RiskScore,
		Reasons:        mustJSON(score.Reasons),
		Suggested:      mustJSON(score.SuggestedActions),
		CostCents:      costCents(p.Sandbox != nil),
		StartedAt:      started,
		CompletedAt:    &completed,
	}
	if trustedSandbox {
		record.SandboxRuntime = registry.SandboxGVisor
	}
	signature, err := SignAudit(record, p.Signer)
	if err != nil {
		return registry.AuditRecord{}, err
	}
	record.Signature = signature
	return record, nil
}

func validateTrustedInput(trace *validatedTrace, in Input) error {
	if trace == nil || trace.containerID == "" || trace.nonce == "" || trace.packageName != in.Version.Name || trace.version != in.Version.Version || trace.treeDigest == "" || trace.manifestHash != sha512Hex(in.Version.Manifest) {
		return fmt.Errorf("identity or manifest differs from trace")
	}
	if in.Package == nil || trace.treeDigest != in.Package.TreeDigest || (in.Version.TreeDigest != "" && trace.treeDigest != in.Version.TreeDigest) {
		return fmt.Errorf("package tree differs from trace")
	}
	file, err := os.Open(in.ArtifactPath)
	if err != nil {
		return err
	}
	defer file.Close()
	h := sha512.New()
	if _, err := io.Copy(h, file); err != nil {
		return err
	}
	artifactHash := "sha512-" + hex.EncodeToString(h.Sum(nil))
	if trace.artifactHash != artifactHash || (in.Version.ArtifactHash != "" && in.Version.ArtifactHash != artifactHash) {
		return fmt.Errorf("artifact differs from trace")
	}
	return nil
}

func costCents(dynamic bool) int {
	if dynamic {
		return 50
	}
	return 1
}
