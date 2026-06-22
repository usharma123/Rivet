package registry

import (
	"fmt"
	"time"
)

const (
	PublisherRevokeDownloadThreshold = 100
	PublisherRevokeWindow            = 5 * time.Hour
)

func ValidateReleaseState(state ReleaseState) error {
	switch state {
	case StateActive, StateWarned, StateQuarantined, StateYanked, StateRevoked, StateBlocked, StateArchived:
		return nil
	default:
		return fmt.Errorf("%w: unknown release state %q", ErrInvalidRequest, state)
	}
}

func AllowStateChange(current VersionRecord, target ReleaseState, req StateChangeRequest, now time.Time) error {
	if err := ValidateReleaseState(target); err != nil {
		return err
	}
	if target != StateRevoked && target != StateYanked {
		return nil
	}
	if req.Reason == "" {
		return fmt.Errorf("%w: reason is required", ErrInvalidRequest)
	}

	if PublisherSelfRevokeAllowed(current, now) {
		return nil
	}

	if target == StateYanked && req.RegistryApproved {
		return nil
	}
	if target == StateRevoked && req.SecurityEvidence {
		return nil
	}
	return fmt.Errorf("%w: release is older than 5 hours and has at least 100 downloads", ErrPolicy)
}

func PublisherSelfRevokeAllowed(current VersionRecord, now time.Time) bool {
	age := now.Sub(current.PublishedAt)
	return current.DownloadCount < PublisherRevokeDownloadThreshold || age <= PublisherRevokeWindow
}

func StateForVerdict(verdict AuditVerdict) ReleaseState {
	switch verdict {
	case VerdictLow:
		return StateActive
	case VerdictMedium:
		return StateWarned
	case VerdictHigh:
		return StateQuarantined
	case VerdictCritical:
		return StateBlocked
	default:
		return StateQuarantined
	}
}

func ValidateAudit(audit AuditRecord) error {
	switch audit.Status {
	case AuditPending, AuditRunning, AuditPassed, AuditFailed:
	default:
		return fmt.Errorf("%w: unknown audit status %q", ErrInvalidRequest, audit.Status)
	}
	switch audit.Verdict {
	case VerdictLow, VerdictMedium, VerdictHigh, VerdictCritical:
	default:
		return fmt.Errorf("%w: unknown audit verdict %q", ErrInvalidRequest, audit.Verdict)
	}
	if audit.PackageName == "" || audit.Version == "" {
		return fmt.Errorf("%w: package and version are required", ErrInvalidRequest)
	}
	if audit.SandboxRuntime != "gvisor/runsc" {
		return fmt.Errorf("%w: sandbox runtime must be gvisor/runsc", ErrInvalidRequest)
	}
	if audit.Signature == "" {
		return fmt.Errorf("%w: registry audit signature is required", ErrInvalidRequest)
	}
	if audit.CostCents == 0 {
		audit.CostCents = 50
	}
	return nil
}
