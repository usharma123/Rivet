package audit

import (
	"encoding/json"
	"strings"

	"github.com/usharma123/rivet/registry/internal/registry"
)

type Evidence struct {
	Static      StaticEvidence      `json:"static"`
	SafeProbes  []ProbeEvidence     `json:"safe_probes,omitempty"`
	Adversarial []ProbeEvidence     `json:"adversarial_probes,omitempty"`
	Egress      []EgressEvidence    `json:"egress,omitempty"`
	Privacy     map[string][]string `json:"privacy,omitempty"`
	Sandbox     map[string]string   `json:"sandbox,omitempty"`
	Agent       map[string]string   `json:"agent,omitempty"`
}

type StaticEvidence struct {
	ArtifactSize      int64    `json:"artifact_size"`
	HasInstallScripts bool     `json:"has_install_scripts"`
	InstallScripts    []string `json:"install_scripts,omitempty"`
	HasNativeBinaries bool     `json:"has_native_binaries"`
	NativeBinaries    []string `json:"native_binaries,omitempty"`
	MinifiedFiles     []string `json:"minified_files,omitempty"`
	ObfuscatedFiles   []string `json:"obfuscated_files,omitempty"`
	SourceVisibility  string   `json:"source_visibility"`
	SourceRepo        string   `json:"source_repo,omitempty"`
	NamesquatWarning  string   `json:"namesquat_warning,omitempty"`
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
}

type Score struct {
	Verdict          registry.AuditVerdict `json:"verdict"`
	RiskScore        int                   `json:"risk_score"`
	Reasons          []string              `json:"reasons"`
	SuggestedActions []string              `json:"suggested_actions"`
}

func ScoreEvidence(evidence Evidence) Score {
	score := 0
	var reasons []string
	if evidence.Static.HasInstallScripts {
		score += 25
		reasons = append(reasons, "install lifecycle script present")
	}
	if evidence.Static.HasNativeBinaries {
		score += 25
		reasons = append(reasons, "native binary detected")
	}
	if len(evidence.Static.MinifiedFiles) > 0 || len(evidence.Static.ObfuscatedFiles) > 0 {
		score += 15
		reasons = append(reasons, "minified or obfuscated files detected")
	}
	if evidence.Static.SourceVisibility == "" || evidence.Static.SourceVisibility == "unknown" || evidence.Static.SourceVisibility == "closed" {
		score += 10
		reasons = append(reasons, "source visibility is not verified open source")
	}
	if evidence.Static.NamesquatWarning != "" {
		score += 30
		reasons = append(reasons, evidence.Static.NamesquatWarning)
	}
	for _, probe := range append(evidence.SafeProbes, evidence.Adversarial...) {
		if probe.Timeout {
			score += 10
			reasons = append(reasons, "probe timed out: "+probe.Name)
		} else if probe.ExitCode != 0 {
			score += 5
			reasons = append(reasons, "probe failed: "+probe.Name)
		}
	}
	for _, egress := range evidence.Egress {
		if strings.EqualFold(egress.Decision, "blocked") || strings.EqualFold(egress.Decision, "unknown") {
			score += 20
			reasons = append(reasons, "unknown egress attempted: "+egress.Host)
		}
	}
	if score > 100 {
		score = 100
	}
	verdict := registry.VerdictLow
	switch {
	case score >= 80:
		verdict = registry.VerdictCritical
	case score >= 60:
		verdict = registry.VerdictHigh
	case score >= 30:
		verdict = registry.VerdictMedium
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no suspicious behavior detected in sandbox probes")
	}
	return Score{
		Verdict:          verdict,
		RiskScore:        score,
		Reasons:          reasons,
		SuggestedActions: suggestedActions(verdict),
	}
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
