package audit

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/usharma123/rivet/registry/internal/registry"
)

// Evidence is the signed record of everything an audit observed. Its JSON
// shape is part of the public audit contract (docs/adr/0005).
type Evidence struct {
	Static      StaticEvidence      `json:"static"`
	Upstream    *UpstreamEvidence   `json:"upstream,omitempty"`
	Provenance  *ProvenanceEvidence `json:"provenance,omitempty"`
	Diff        *DiffEvidence       `json:"diff,omitempty"`
	SafeProbes  []ProbeEvidence     `json:"safe_probes,omitempty"`
	Adversarial []ProbeEvidence     `json:"adversarial_probes,omitempty"`
	Egress      []EgressEvidence    `json:"egress,omitempty"`
	Honeytokens []HoneytokenAccess  `json:"honeytokens,omitempty"`
	Privacy     map[string][]string `json:"privacy,omitempty"`
	Sandbox     map[string]string   `json:"sandbox,omitempty"`
	Agent       map[string]string   `json:"agent,omitempty"`
}

type StaticEvidence struct {
	ArtifactSize          int64               `json:"artifact_size"`
	FileCount             int                 `json:"file_count,omitempty"`
	TreeDigest            string              `json:"tree_digest,omitempty"`
	HasInstallScripts     bool                `json:"has_install_scripts"`
	InstallScripts        []string            `json:"install_scripts,omitempty"`
	InstallScriptCommands map[string]string   `json:"install_script_commands,omitempty"`
	SuspiciousScripts     []string            `json:"suspicious_scripts,omitempty"`
	HasNativeBinaries     bool                `json:"has_native_binaries"`
	NativeBinaries        []string            `json:"native_binaries,omitempty"`
	MinifiedFiles         []string            `json:"minified_files,omitempty"`
	ObfuscatedFiles       []string            `json:"obfuscated_files,omitempty"`
	Capabilities          map[string][]string `json:"capabilities,omitempty"`
	SourceVisibility      string              `json:"source_visibility"`
	SourceRepo            string              `json:"source_repo,omitempty"`
	NamesquatWarning      string              `json:"namesquat_warning,omitempty"`
	WeeklyDownloads       *int64              `json:"weekly_downloads,omitempty"`
}

type UpstreamEvidence struct {
	Registry           string   `json:"registry"`
	Tarball            string   `json:"tarball"`
	Integrity          string   `json:"integrity,omitempty"`
	IntegrityAlgorithm string   `json:"integrity_algorithm"`
	Publisher          string   `json:"publisher,omitempty"`
	PublishedAt        string   `json:"published_at,omitempty"`
	Deprecated         bool     `json:"deprecated,omitempty"`
	ManifestMismatch   []string `json:"manifest_mismatch,omitempty"`
}

type ProvenanceEvidence struct {
	Status       string `json:"status"`
	SourceRepo   string `json:"source_repo,omitempty"`
	SourceCommit string `json:"source_commit,omitempty"`
	SourceRef    string `json:"source_ref,omitempty"`
	BuildSigner  string `json:"build_signer,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	DeclaredRepo string `json:"declared_repo,omitempty"`
	RepoMatches  *bool  `json:"repo_matches,omitempty"`
	Detail       string `json:"detail,omitempty"`
}

type DiffEvidence struct {
	PreviousVersion     string   `json:"previous_version"`
	NewCapabilities     []string `json:"new_capabilities,omitempty"`
	NewInstallScripts   []string `json:"new_install_scripts,omitempty"`
	AddedDependencies   []string `json:"added_dependencies,omitempty"`
	RemovedDependencies []string `json:"removed_dependencies,omitempty"`
	PreviousPublisher   string   `json:"previous_publisher,omitempty"`
	PublisherChanged    bool     `json:"publisher_changed,omitempty"`
	PreviousProvenance  bool     `json:"previous_provenance,omitempty"`
	ProvenanceRegressed bool     `json:"provenance_regressed,omitempty"`
}

type ProbeEvidence struct {
	Name     string `json:"name"`
	Command  string `json:"command,omitempty"`
	ExitCode int    `json:"exit_code"`
	Timeout  bool   `json:"timeout"`
	Output   string `json:"output,omitempty"`
}

type EgressEvidence struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Bytes    int64  `json:"bytes"`
	Decision string `json:"decision"`
	Probe    string `json:"probe,omitempty"`
}

type HoneytokenAccess struct {
	Token string `json:"token"`
	Probe string `json:"probe,omitempty"`
	How   string `json:"how,omitempty"`
}

type Score struct {
	Verdict          registry.AuditVerdict `json:"verdict"`
	RiskScore        int                   `json:"risk_score"`
	Reasons          []string              `json:"reasons"`
	SuggestedActions []string              `json:"suggested_actions"`
}

// ScoreEvidence converts evidence into a verdict. Weights favour changes and
// behaviour over static capabilities, because most legitimate packages use the
// network or child processes somewhere while compromised releases usually
// show up as a sudden change.
func ScoreEvidence(evidence Evidence) Score {
	s := &scorer{}
	static := evidence.Static
	has := func(capability string) bool { return len(static.Capabilities[capability]) > 0 }

	if static.HasInstallScripts {
		s.add(20, "install lifecycle script present: "+strings.Join(static.InstallScripts, ", "))
	}
	if len(static.SuspiciousScripts) > 0 {
		s.add(25, "install script downloads or evaluates code: "+static.SuspiciousScripts[0])
	}
	if static.HasNativeBinaries {
		s.add(10, "native binary shipped")
	}
	if has(CapObfuscation) {
		s.add(25, "obfuscated code detected")
	}
	if has(CapExfilEndpoint) {
		if sameFile(static, CapExfilEndpoint, CapNetwork) {
			s.add(35, "sends data to a known exfiltration endpoint")
		} else {
			s.add(5, "mentions a known exfiltration endpoint")
		}
	}
	if has(CapExfilPattern) {
		s.add(30, "same file reads credentials or environment and uses the network")
	} else {
		if has(CapSensitivePaths) {
			s.add(10, "references credential file paths")
		}
		if has(CapEnvHarvest) {
			s.add(10, "reads sensitive environment variables")
		}
	}
	if static.NamesquatWarning != "" {
		s.add(30, static.NamesquatWarning)
	}
	if static.SourceRepo == "" {
		s.add(5, "no source repository declared")
	}

	if p := evidence.Provenance; p != nil {
		switch p.Status {
		case "invalid":
			s.add(60, "provenance is advertised but does not verify: "+p.Detail)
		case "verified":
			if p.RepoMatches != nil && !*p.RepoMatches {
				s.add(40, fmt.Sprintf("provenance source %s does not match declared repository %s", p.SourceRepo, p.DeclaredRepo))
			}
		}
	}
	if u := evidence.Upstream; u != nil {
		if u.IntegrityAlgorithm == "sha1" {
			s.add(5, "upstream only publishes a sha1 digest")
		}
		if len(u.ManifestMismatch) > 0 {
			s.add(30, "registry metadata disagrees with the tarball: "+strings.Join(u.ManifestMismatch, "; "))
		}
	}

	if d := evidence.Diff; d != nil {
		if d.ProvenanceRegressed {
			s.add(40, "previous release "+d.PreviousVersion+" had provenance; this release does not")
		}
		if len(d.NewInstallScripts) > 0 {
			s.add(30, "install script added since "+d.PreviousVersion+": "+strings.Join(d.NewInstallScripts, ", "))
		}
		risky := 0
		for _, capability := range d.NewCapabilities {
			switch capability {
			case CapNetwork, CapChildProcess, CapDynamicCode, CapEnvHarvest, CapSensitivePaths, CapExfilPattern, CapExfilEndpoint, CapObfuscation, CapEmbeddedBlob:
				risky++
			}
		}
		if risky > 0 {
			s.add(min(15*risky, 45), "new capabilities since "+d.PreviousVersion+": "+strings.Join(d.NewCapabilities, ", "))
		}
		if d.PublisherChanged {
			s.add(10, fmt.Sprintf("published by %q; previous release by %q", evidencePublisher(evidence), d.PreviousPublisher))
		}
		if n := len(d.AddedDependencies); n > 0 {
			s.add(min(5*n, 15), "dependencies added since "+d.PreviousVersion+": "+strings.Join(d.AddedDependencies, ", "))
		}
	}

	egress := 0
	for _, e := range evidence.Egress {
		if !strings.EqualFold(e.Decision, "allowed") {
			egress++
			if egress <= 3 {
				s.reasons = append(s.reasons, fmt.Sprintf("network egress attempted during %s: %s:%d", e.Probe, e.Host, e.Port))
			}
		}
	}
	if egress > 0 {
		s.score += min(25*egress, 50)
	}
	for _, h := range evidence.Honeytokens {
		s.add(60, fmt.Sprintf("honeytoken %s accessed during %s", h.Token, h.Probe))
	}
	for _, probe := range append(append([]ProbeEvidence{}, evidence.SafeProbes...), evidence.Adversarial...) {
		if probe.Timeout {
			s.add(5, "probe timed out: "+probe.Name)
		}
	}

	if s.score > 100 {
		s.score = 100
	}
	verdict := registry.VerdictLow
	switch {
	case s.score >= 80:
		verdict = registry.VerdictCritical
	case s.score >= 60:
		verdict = registry.VerdictHigh
	case s.score >= 30:
		verdict = registry.VerdictMedium
	}
	if len(s.reasons) == 0 {
		s.reasons = append(s.reasons, "no risk indicators found")
	}
	return Score{
		Verdict:          verdict,
		RiskScore:        s.score,
		Reasons:          s.reasons,
		SuggestedActions: suggestedActions(verdict),
	}
}

// sameFile reports whether some file has both capabilities.
func sameFile(static StaticEvidence, a, b string) bool {
	files := map[string]bool{}
	for _, path := range static.Capabilities[a] {
		files[path] = true
	}
	for _, path := range static.Capabilities[b] {
		if files[path] {
			return true
		}
	}
	return false
}

type scorer struct {
	score   int
	reasons []string
}

func (s *scorer) add(points int, reason string) {
	s.score += points
	s.reasons = append(s.reasons, reason)
}

func evidencePublisher(e Evidence) string {
	if e.Upstream == nil {
		return ""
	}
	return e.Upstream.Publisher
}

// Diff compares this release's evidence with the previous release's.
func Diff(previousVersion string, previous, current StaticEvidence, previousDeps, currentDeps map[string]string) *DiffEvidence {
	diff := &DiffEvidence{PreviousVersion: previousVersion}
	for _, capability := range current.CapabilityNames() {
		if len(previous.Capabilities[capability]) == 0 {
			diff.NewCapabilities = append(diff.NewCapabilities, capability)
		}
	}
	prevScripts := map[string]bool{}
	for _, name := range previous.InstallScripts {
		prevScripts[name] = true
	}
	for _, name := range current.InstallScripts {
		if !prevScripts[name] {
			diff.NewInstallScripts = append(diff.NewInstallScripts, name)
		}
	}
	for name := range currentDeps {
		if _, ok := previousDeps[name]; !ok {
			diff.AddedDependencies = append(diff.AddedDependencies, name)
		}
	}
	for name := range previousDeps {
		if _, ok := currentDeps[name]; !ok {
			diff.RemovedDependencies = append(diff.RemovedDependencies, name)
		}
	}
	sort.Strings(diff.AddedDependencies)
	sort.Strings(diff.RemovedDependencies)
	return diff
}

func EvidenceJSON(evidence Evidence) json.RawMessage {
	data, _ := json.Marshal(evidence)
	return data
}

func suggestedActions(verdict registry.AuditVerdict) []string {
	switch verdict {
	case registry.VerdictLow:
		return []string{"allow_install"}
	case registry.VerdictMedium:
		return []string{"warn_user", "request_audit"}
	case registry.VerdictHigh:
		return []string{"quarantine_release", "request_human_review"}
	case registry.VerdictCritical:
		return []string{"block_install", "escalate_security_review"}
	default:
		return []string{"request_human_review"}
	}
}
