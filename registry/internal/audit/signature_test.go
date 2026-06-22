package audit

import (
	"encoding/json"
	"testing"

	"github.com/usharma123/rivet/registry/internal/registry"
)

func TestAuditSignatureRoundTrip(t *testing.T) {
	audit := registry.AuditRecord{
		PackageName:    "demo",
		Version:        "0.1.0",
		Status:         registry.AuditPassed,
		SandboxRuntime: "gvisor/runsc",
		AgentImage:     "rivet-audit-agent:local",
		Evidence:       json.RawMessage(`{}`),
		Verdict:        registry.VerdictLow,
		RiskScore:      12,
		Reasons:        json.RawMessage(`[]`),
	}
	signature, err := SignAudit(audit, "secret")
	if err != nil {
		t.Fatal(err)
	}
	audit.Signature = signature
	if !VerifyAuditSignature(audit, "secret") {
		t.Fatal("signature did not verify")
	}
	audit.RiskScore = 99
	if VerifyAuditSignature(audit, "secret") {
		t.Fatal("tampered audit verified")
	}
}
