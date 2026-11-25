package test

// Requirement: service-platform service returns non-revealing not-found for
// foreign resources (audit's only resource is the audit entry; audit has no
// write operation).

import (
	"bytes"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048ServicePlatformNonRevealingNotFound(t *testing.T) {
	t.Run("Operator reads a foreign audit entry", func(t *testing.T) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 4, 3, "flow_updated")
		foreign := h.store.Entries()[2].AuditID
		before := len(h.store.Entries())
		unknown := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 1010})
		got := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": foreign})
		expectError(t, got, 404, "resource_not_found")
		if !bytes.Equal(got.Body, unknown.Body) {
			t.Fatalf("foreign reply %s differs from unknown reply %s", got.Body, unknown.Body)
		}
		if len(h.store.Entries()) != before || len(h.store.RejectedMessages()) != 0 {
			t.Fatal("a rejected read changed audit data")
		}
	})
}
