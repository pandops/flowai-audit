//go:build integration

package test

// The team predicate, search, ordering and keyset pagination run in SQL;
// these checks repeat the read scenarios against PostgreSQL.

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048AuditReadsIntegration(t *testing.T) {
	_, s := migratedStore(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := &harness{consumer: audit.NewConsumer(s, logger), reader: audit.NewReader(s, testKeyring(t), logger)}
	ctx := context.Background()
	handle := func(team string, f fields) {
		if got := h.consumer.Handle(ctx, delivery(t, team, f)); got != audit.ResultStored {
			t.Fatalf("store %v: %s", f["publisher_seq"], got)
		}
	}
	for i := int64(1); i <= 12; i++ {
		f := operatorMsg("flow-registry", i, 3, "flow_updated")
		f["occurred_at"] = "2026-11-07T10:00:00.000Z" // equal times: audit_id breaks ties
		handle("3", f)
	}
	for i := int64(100); i < 130; i++ {
		handle("4", operatorMsg("flow-registry", i, 4, "flow_updated"))
	}
	handle("admin", adminMsg("team-registry", 1, "team_updated", 3))
	handle("admin", adminMsg("admin-panel", 1762500000000001, "team-get", 3))
	sec := operatorMsg("env-registry", 1, 3, "secret_created")
	sec["actor_id"] = 555
	sec["resource_id"] = 9876
	handle("3", sec)
	nullRes := operatorMsg("env-registry", 2, 3, "secret_versions_listed")
	nullRes["resource_id"] = nil
	handle("3", nullRes)

	t.Run("Teams share filter values", func(t *testing.T) {
		var all []float64
		cur := ""
		for {
			params := map[string]any{"team_id": 3, "search": "flow"}
			if cur != "" {
				params["cursor"] = cur
			}
			p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), params))
			for _, it := range p.Items {
				all = append(all, it["audit_id"].(float64))
			}
			if p.NextCursor == nil {
				break
			}
			cur = *p.NextCursor
		}
		if len(all) != 12 {
			t.Fatalf("team 3 flow entries = %d, want 12", len(all))
		}
		for i := 1; i < len(all); i++ {
			if all[i] >= all[i-1] {
				t.Fatalf("order %v is not audit_id DESC at equal occurred_at", all)
			}
		}
		if all[0] != 12 {
			t.Fatalf("first entry %v, want audit_id 12", all[0])
		}
	})

	t.Run("search by actor and resource identifier", func(t *testing.T) {
		// "e_r" occurs in no stored action; an unescaped "_" wildcard would
		// match "secret" and return the secret entries.
		for search, want := range map[string]int{"555": 1, "9876": 1, "SECRET": 2, "team_updated": 0, "%": 0, "e_r": 0} {
			p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": search}))
			if len(p.Items) != want {
				t.Errorf("search %q = %d, want %d", search, len(p.Items), want)
			}
		}
	})

	t.Run("administrator and foreign entries are not found", func(t *testing.T) {
		unknown := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 999999})
		expectError(t, unknown, 404, "resource_not_found")
		for _, id := range []int64{13, 43, 44} { // a team 4 entry and both administrator entries
			r := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": id})
			if r.Status != 404 || string(r.Body) != string(unknown.Body) {
				t.Errorf("audit_id %d: %d %s, want the unknown-id 404", id, r.Status, r.Body)
			}
		}
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "limit": 100}))
		if len(p.Items) != 14 {
			t.Fatalf("team 3 list = %d entries, want its 14 (no administrator entry)", len(p.Items))
		}
	})

	t.Run("null resource_id reads back as null", func(t *testing.T) {
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "versions"}))
		if len(p.Items) != 1 {
			t.Fatalf("items = %d", len(p.Items))
		}
		if v, ok := p.Items[0]["resource_id"]; !ok || v != nil {
			t.Fatalf("resource_id = %v", v)
		}
	})
}
