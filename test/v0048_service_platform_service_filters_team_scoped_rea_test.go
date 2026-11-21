package test

// Requirement: service-platform service filters team-scoped reads before shaping.

import (
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048ServicePlatformFiltersTeamScopedReads(t *testing.T) {
	t.Run("Teams share filter values", func(t *testing.T) {
		h := newHarness(t)
		// Team 4 has newer matching entries than team 3; a filter applied
		// after pagination would fill team 3's page with them.
		h.seed(t, "flow-registry", 1, 3, 10, "flow_updated")
		h.seed(t, "flow-registry", 1000, 4, 40, "flow_updated")
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow_updated"}))
		if len(p.Items) != 10 {
			t.Fatalf("page length = %d, want 10", len(p.Items))
		}
		if p.NextCursor != nil {
			t.Fatal("next_cursor issued although team 3 has exactly 10 matches")
		}
		for _, it := range p.Items {
			if e := entryByID(t, h, int64(it["audit_id"].(float64))); e.TeamID == nil || *e.TeamID != 3 {
				t.Fatalf("page holds a foreign entry %v", it["audit_id"])
			}
		}
		empty := decodePage(t, h.call(t, audit.OperationList, uiHeaders(5), map[string]any{"team_id": 5, "search": "flow_updated"}))
		if len(empty.Items) != 0 || empty.NextCursor != nil {
			t.Fatalf("team 5 page = %+v, want empty", empty)
		}
	})
}
