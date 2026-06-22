package audit

import (
	"testing"

	"github.com/usharma123/rivet/registry/internal/registry"
)

func TestScoreEvidenceLowRisk(t *testing.T) {
	score := ScoreEvidence(Evidence{Static: StaticEvidence{SourceVisibility: "open"}})
	if score.Verdict != registry.VerdictLow {
		t.Fatalf("expected low, got %s", score.Verdict)
	}
}

func TestScoreEvidenceCriticalRisk(t *testing.T) {
	score := ScoreEvidence(Evidence{
		Static: StaticEvidence{
			HasInstallScripts: true,
			HasNativeBinaries: true,
			SourceVisibility:  "unknown",
			NamesquatWarning:  "possible namesquat",
			MinifiedFiles:     []string{"index.js"},
		},
		Egress: []EgressEvidence{{Host: "unknown.example", Decision: "blocked"}},
	})
	if score.Verdict != registry.VerdictCritical {
		t.Fatalf("expected critical, got %s score=%d reasons=%v", score.Verdict, score.RiskScore, score.Reasons)
	}
}
