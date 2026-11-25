package test

// Requirement: service-platform service gets foreign data only from the broker.
// audit keeps no projection; its only foreign data are the consumed audit
// messages, applied once per (publisher, publisher_seq).

import (
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048ServicePlatformForeignDataOnlyFromBroker(t *testing.T) {
	t.Run("Replayed message is applied once", func(t *testing.T) {
		h := newHarness(t)
		for i := 0; i < 3; i++ {
			h.handle(t, delivery(t, "admin", adminMsg("team-registry", 900, "team_archived", 3)))
		}
		if n := len(h.store.Entries()); n != 1 {
			t.Fatalf("entries = %d, want 1", n)
		}
		_ = audit.ResultDuplicate
	})
}
