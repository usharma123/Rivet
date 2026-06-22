package registry

import (
	"fmt"
	"time"
)

const PublisherRevokeWindow = 100 * 24 * time.Hour

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

	age := now.Sub(current.PublishedAt)
	if age <= PublisherRevokeWindow {
		return nil
	}

	if target == StateYanked && req.RegistryApproved {
		return nil
	}
	if target == StateRevoked && req.SecurityEvidence {
		return nil
	}
	return fmt.Errorf("%w: release is older than 100 days", ErrPolicy)
}
