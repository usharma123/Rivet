package audit

import (
	"encoding/json"
	"strings"

	"github.com/usharma123/rivet/registry/internal/registry"
	"github.com/usharma123/rivet/registry/internal/signing"
)

// SignAudit signs the audit record (minus its signature) with the registry's
// Ed25519 key. The result is "<keyid>|<base64 signature>".
func SignAudit(audit registry.AuditRecord, signer *signing.Signer) (string, error) {
	payload, err := auditPayload(audit)
	if err != nil {
		return "", err
	}
	return signer.KeyID() + "|" + signer.SignBytes(payload), nil
}

// VerifyAuditSignature checks that the audit was signed by signer and has not
// been modified since.
func VerifyAuditSignature(audit registry.AuditRecord, signer *signing.Signer) bool {
	keyID, signature, ok := strings.Cut(audit.Signature, "|")
	if !ok || keyID != signer.KeyID() {
		return false
	}
	payload, err := auditPayload(audit)
	if err != nil {
		return false
	}
	return signer.VerifyBytes(payload, signature)
}

func auditPayload(audit registry.AuditRecord) ([]byte, error) {
	clone := audit
	clone.Signature = ""
	clone.ID = ""
	clone.ReleaseStateApplied = ""
	return json.Marshal(clone)
}
