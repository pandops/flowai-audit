package test

// Requirement: service-platform service stores team ownership in normalized
// form. Immutability of the stored team_id is proven against PostgreSQL in
// v0048_audit_store_integration_test.go; audit has no child records.

import (
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048ServicePlatformTeamOwnership(t *testing.T) {
	t.Run("Display metadata never authorizes", func(t *testing.T) {
		h := newHarness(t)
		update := adminMsg("team-registry", 1, "team_updated", 3)
		update["changes"] = map[string]any{"default_image": map[string]any{"old": "registry.example/flowai/runtime:1.0.0", "new": "registry.example/flowai/runtime:1.1.0"}}
		h.handle(t, delivery(t, "admin", update))
		h.seed(t, "flow-registry", 1, 3, 2, "flow_updated")
		h.seed(t, "flow-registry", 10, 4, 2, "flow_updated")
		hdr := uiHeaders(4)
		hdr["team_name"] = "beta"
		p := decodePage(t, h.call(t, audit.OperationList, hdr, map[string]any{"team_id": 4}))
		for _, it := range p.Items {
			if e := entryByID(t, h, int64(it["audit_id"].(float64))); *e.TeamID != 4 {
				t.Fatalf("team_name beta granted access to team %d", *e.TeamID)
			}
		}
		if len(p.Items) != 2 {
			t.Fatalf("items = %d, want team 4's 2", len(p.Items))
		}
	})
}
