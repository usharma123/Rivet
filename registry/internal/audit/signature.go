package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/usharma123/rivet/registry/internal/registry"
)

func SignAudit(audit registry.AuditRecord, secret string) (string, error) {
	clone := audit
	clone.Signature = ""
	payload, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyAuditSignature(audit registry.AuditRecord, secret string) bool {
	if audit.Signature == "" {
		return false
	}
	expected, err := SignAudit(audit, secret)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(audit.Signature))
}
