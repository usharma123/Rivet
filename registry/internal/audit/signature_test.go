package audit

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

func testSigner(t *testing.T, fill byte) *signing.Signer {
	t.Helper()
	signer, err := signing.NewSigner(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestAuditSignatureRoundTrip(t *testing.T) {
	signer := testSigner(t, 1)
	audit := registry.AuditRecord{
		PackageName:    "demo",
		Version:        "0.1.0",
		Status:         registry.AuditPassed,
		SandboxRuntime: registry.SandboxStatic,
		AgentImage:     "in-process",
		Evidence:       json.RawMessage(`{}`),
		Verdict:        registry.VerdictLow,
		RiskScore:      12,
		Reasons:        json.RawMessage(`[]`),
	}
	signature, err := SignAudit(audit, signer)
	if err != nil {
		t.Fatal(err)
	}
	audit.Signature = signature
	if !VerifyAuditSignature(audit, signer) {
		t.Fatal("signature did not verify")
	}
	tampered := audit
	tampered.RiskScore = 0
	if VerifyAuditSignature(tampered, signer) {
		t.Fatal("tampered audit verified")
	}
	if VerifyAuditSignature(audit, testSigner(t, 2)) {
		t.Fatal("audit verified under a different key")
	}
	forged := audit
	forged.Signature = "hmac-sha256:test"
	if VerifyAuditSignature(forged, signer) {
		t.Fatal("forged signature string verified")
	}
}
