package test

// Requirement: audit serves team-filtered reads to API Gateway.

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048AuditServesTeamFilteredReads(t *testing.T) {
	t.Run("Teams share filter values", func(t *testing.T) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 12, "flow_updated")
		h.seed(t, "flow-registry", 100, 4, 30, "flow_updated")
		h.seed(t, "env-registry", 1, 3, 5, "secret_created")

		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow"}))
		if len(p.Items) != 10 {
			t.Fatalf("first page length = %d, want default limit 10 of team 3's 12 matches", len(p.Items))
		}
		if p.NextCursor == nil {
			t.Fatal("first page has no next_cursor although team 3 has 12 matches")
		}
		seen := map[float64]bool{}
		check := func(items []map[string]any) {
			for _, it := range items {
				id := it["audit_id"].(float64)
				e := entryByID(t, h, int64(id))
				if e.TeamID == nil || *e.TeamID != 3 || e.Action != "flow_updated" {
					t.Fatalf("page holds entry %v of team %v action %s", id, e.TeamID, e.Action)
				}
				if seen[id] {
					t.Fatalf("entry %v appears twice", id)
				}
				seen[id] = true
			}
		}
		check(p.Items)
		p2 := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow", "cursor": *p.NextCursor}))
		check(p2.Items)
		if len(p2.Items) != 2 || p2.NextCursor != nil {
			t.Fatalf("second page = %d items, cursor %v; want the remaining 2 team 3 entries and no cursor", len(p2.Items), p2.NextCursor)
		}
	})

	t.Run("order is occurred_at DESC then audit_id DESC", func(t *testing.T) {
		h := newHarness(t)
		at := "2026-11-07T10:00:00Z"
		for i := int64(1); i <= 3; i++ {
			f := operatorMsg("flow-registry", i, 3, "flow_updated")
			f["occurred_at"] = at
			h.handle(t, delivery(t, "3", f))
		}
		later := operatorMsg("flow-registry", 4, 3, "flow_updated")
		later["occurred_at"] = "2026-11-07T09:00:00Z"
		h.handle(t, delivery(t, "3", later))
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3}))
		var got []int64
		for _, it := range p.Items {
			got = append(got, int64(it["audit_id"].(float64)))
		}
		if len(got) != 4 || got[0] != 3 || got[1] != 2 || got[2] != 1 || got[3] != 4 {
			t.Fatalf("order = %v, want [3 2 1 4]", got)
		}
	})

	t.Run("search matches action, actor and resource identifier", func(t *testing.T) {
		h := newHarness(t)
		a := operatorMsg("flow-registry", 1, 3, "flow_updated")
		b := operatorMsg("env-registry", 1, 3, "secret_created")
		b["actor_id"] = 555
		b["resource_id"] = 9876
		h.handle(t, delivery(t, "3", a))
		h.handle(t, delivery(t, "3", b))
		for search, want := range map[string]int{"secret": 1, "555": 1, "9876": 1, "FLOW": 1, "nothing": 0} {
			p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": search}))
			if len(p.Items) != want {
				t.Errorf("search %q returned %d, want %d", search, len(p.Items), want)
			}
		}
	})

	t.Run("limit values 10, 25, 50 and 100 are accepted", func(t *testing.T) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 120, "flow_updated")
		for _, limit := range []int{10, 25, 50, 100} {
			p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "limit": limit}))
			if len(p.Items) != limit || p.NextCursor == nil {
				t.Errorf("limit %d returned %d items cursor %v", limit, len(p.Items), p.NextCursor)
			}
		}
	})

	t.Run("Operator reads a foreign or system entry", func(t *testing.T) {
		h := newHarness(t)
		h.handle(t, delivery(t, "4", operatorMsg("flow-registry", 1, 4, "flow_updated")))
		h.handle(t, delivery(t, "admin", adminMsg("team-registry", 1, "team_updated", 3)))
		foreign := h.store.Entries()[0].AuditID
		system := h.store.Entries()[1].AuditID
		unknown := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 5120})
		expectError(t, unknown, 404, "resource_not_found")
		for name, id := range map[string]int64{"team 4 entry": foreign, "administrator entry": system} {
			r := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": id})
			if r.Status != unknown.Status || !bytes.Equal(r.Body, unknown.Body) {
				t.Errorf("%s reply = %d %s, want the unknown-id reply %d %s", name, r.Status, r.Body, unknown.Status, unknown.Body)
			}
		}
	})

	t.Run("Non-integer audit identifier is rejected", func(t *testing.T) {
		for name, raw := range map[string]string{
			"abc":            `"abc"`,
			"zero":           `0`,
			"negative":       `-1`,
			"uuid":           `"3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f"`,
			"fraction":       `1.5`,
			"exponent":       `1e3`,
			"above int64":    `9223372036854775808`,
			"decimal string": `"5"`,
			"null":           `null`,
		} {
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				h.handle(t, delivery(t, "3", operatorMsg("flow-registry", 1, 3, "flow_updated")))
				before := h.store.Reads
				body := []byte(`{"params":{"team_id":3,"audit_id":` + raw + `}}`)
				expectError(t, h.callRaw(t, audit.OperationGet, uiHeaders(3), body), 400, "invalid_request")
				if h.store.Reads != before {
					t.Fatalf("store read %d times, want none", h.store.Reads-before)
				}
			})
		}
		h := newHarness(t)
		expectError(t, h.callRaw(t, audit.OperationGet, uiHeaders(3), []byte(`{"params":{"team_id":3}}`)), 400, "invalid_request")
		if h.store.Reads != 0 {
			t.Fatal("missing audit_id read the store")
		}
	})

	t.Run("admin-panel rejection naming a team stays out of that team's reads", func(t *testing.T) {
		h := newHarness(t)
		rej := adminMsg("admin-panel", 1762500000000001, "insufficient_admin_role", 3)
		rej["outcome"] = "rejected"
		h.handle(t, delivery(t, "admin", rej))
		h.handle(t, delivery(t, "admin", adminMsg("team-registry", 7, "team_updated", 3)))
		entries := h.store.Entries()
		if len(entries) != 2 {
			t.Fatalf("entries = %d, want 2", len(entries))
		}
		unknown := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 999999})
		for _, e := range entries {
			if e.TeamID != nil {
				t.Fatalf("administrator entry has team %d", *e.TeamID)
			}
			r := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": e.AuditID})
			if r.Status != 404 || !bytes.Equal(r.Body, unknown.Body) {
				t.Fatalf("team 3 get of administrator entry = %d %s, want the unknown-id 404", r.Status, r.Body)
			}
		}
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3}))
		if len(p.Items) != 0 || p.NextCursor != nil {
			t.Fatalf("team 3 list = %+v, want empty", p)
		}
	})

	t.Run("Cursor is reused in another team", func(t *testing.T) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 15, "flow_updated")
		h.seed(t, "flow-registry", 100, 4, 15, "flow_updated")
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3}))
		before := h.store.Reads
		expectError(t, h.call(t, audit.OperationList, uiHeaders(4), map[string]any{"team_id": 4, "cursor": *p.NextCursor}), 400, "invalid_pagination")
		if h.store.Reads != before {
			t.Fatal("store was read for a foreign-team cursor")
		}
	})

	t.Run("replies validate against the audit schemas", func(t *testing.T) {
		s := loadSchemas(t)
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 12, "flow_updated")
		list := h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3})
		if err := s.validate("ui.list.reply.schema.json", list.Body); err != nil {
			t.Fatalf("list reply violates its schema: %v\n%s", err, list.Body)
		}
		get := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 1})
		if err := s.validate("ui.get.reply.schema.json", get.Body); err != nil {
			t.Fatalf("get reply violates its schema: %v\n%s", err, get.Body)
		}
		var item map[string]any
		_ = json.Unmarshal(get.Body, &item)
		if ts, _ := item["occurred_at"].(string); ts == "" {
			t.Fatal("occurred_at missing")
		} else if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			t.Fatalf("occurred_at %q: %v", ts, err)
		}
		bad := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 0})
		if err := s.validate("error.reply.schema.json", bad.Body); err != nil {
			t.Fatalf("error reply violates its schema: %v\n%s", err, bad.Body)
		}
	})
}

func entryByID(t *testing.T, h *harness, id int64) audit.Entry {
	t.Helper()
	for _, e := range h.store.Entries() {
		if e.AuditID == id {
			return e
		}
	}
	t.Fatalf("no entry %d", id)
	return audit.Entry{}
}
