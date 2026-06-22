package registry

import (
	"testing"
	"time"
)

func TestAllowStateChangeWithinPublisherWindow(t *testing.T) {
	record := VersionRecord{PublishedAt: time.Now().Add(-4 * time.Hour), DownloadCount: 500}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "bad build"}, time.Now())
	if err != nil {
		t.Fatalf("expected revoke inside 5 hours to pass: %v", err)
	}
}

func TestAllowStateChangeWithinDownloadThreshold(t *testing.T) {
	now := time.Now()
	record := VersionRecord{PublishedAt: now.Add(-24 * time.Hour), DownloadCount: 99}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "bad build"}, now)
	if err != nil {
		t.Fatalf("expected low-download revoke to pass: %v", err)
	}
}

func TestAllowStateChangeBlocksWideImpactPublisherRevoke(t *testing.T) {
	now := time.Now()
	record := VersionRecord{PublishedAt: now.Add(-6 * time.Hour), DownloadCount: 100}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "bad build"}, now)
	if err == nil {
		t.Fatal("expected wide-impact publisher revoke to be denied")
	}
}

func TestAllowStateChangePermitsOldSecurityRevoke(t *testing.T) {
	now := time.Now()
	record := VersionRecord{PublishedAt: now.Add(-6 * time.Hour), DownloadCount: 100}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "malware", SecurityEvidence: true}, now)
	if err != nil {
		t.Fatalf("expected security revoke to pass: %v", err)
	}
}

func TestStateForVerdict(t *testing.T) {
	if got := StateForVerdict(VerdictMedium); got != StateWarned {
		t.Fatalf("medium should warn, got %s", got)
	}
	if got := StateForVerdict(VerdictHigh); got != StateQuarantined {
		t.Fatalf("high should quarantine, got %s", got)
	}
	if got := StateForVerdict(VerdictCritical); got != StateBlocked {
		t.Fatalf("critical should block, got %s", got)
	}
}
