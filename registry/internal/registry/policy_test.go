package registry

import (
	"testing"
	"time"
)

func TestAllowStateChangeWithinPublisherWindow(t *testing.T) {
	record := VersionRecord{PublishedAt: time.Now().Add(-10 * 24 * time.Hour)}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "bad build"}, time.Now())
	if err != nil {
		t.Fatalf("expected revoke inside 100 days to pass: %v", err)
	}
}

func TestAllowStateChangeBlocksOldPublisherRevoke(t *testing.T) {
	now := time.Now()
	record := VersionRecord{PublishedAt: now.Add(-101 * 24 * time.Hour)}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "bad build"}, now)
	if err == nil {
		t.Fatal("expected old publisher revoke to be denied")
	}
}

func TestAllowStateChangePermitsOldSecurityRevoke(t *testing.T) {
	now := time.Now()
	record := VersionRecord{PublishedAt: now.Add(-101 * 24 * time.Hour)}
	err := AllowStateChange(record, StateRevoked, StateChangeRequest{Reason: "malware", SecurityEvidence: true}, now)
	if err != nil {
		t.Fatalf("expected security revoke to pass: %v", err)
	}
}
