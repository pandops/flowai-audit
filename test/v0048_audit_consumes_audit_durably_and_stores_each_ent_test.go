package test

// Requirement: audit consumes ALL_AUDIT durably and stores each entry once.

import (
	"errors"
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048AuditConsumesAllAuditDurably(t *testing.T) {
	t.Run("Message is redelivered", func(t *testing.T) {
		h := newHarness(t)
		first := delivery(t, "3", operatorMsg("flow-registry", 120, 3, "flow_updated"))
		first.AckError = errors.New("connection lost before ack")
		h.handle(t, first)
		if n := len(h.store.Entries()); n != 1 {
			t.Fatalf("entries after first delivery = %d, want 1", n)
		}
		stored := h.store.Entries()[0]

		redelivered := delivery(t, "3", operatorMsg("flow-registry", 120, 3, "flow_updated"))
		if got := h.handle(t, redelivered); got != audit.ResultDuplicate {
			t.Fatalf("redelivery result = %s, want duplicate", got)
		}
		if redelivered.Acked != 1 || redelivered.Termed != 0 {
			t.Fatalf("redelivery acked=%d termed=%d, want ack only", redelivered.Acked, redelivered.Termed)
		}
		entries := h.store.Entries()
		if len(entries) != 1 || entries[0].AuditID != stored.AuditID {
			t.Fatalf("entries = %+v, want the one first entry with audit_id %d", entries, stored.AuditID)
		}
		if entries[0].Publisher != "flow-registry" || entries[0].PublisherSeq != 120 {
			t.Fatalf("stored pair = (%s, %d), want (flow-registry, 120)", entries[0].Publisher, entries[0].PublisherSeq)
		}
	})

	t.Run("audit_id comes from the commit sequence, never from the message", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 1, 3, "flow_updated")
		f["audit_id"] = 999
		h.handle(t, delivery(t, "3", f))
		h.handle(t, delivery(t, "3", operatorMsg("flow-registry", 2, 3, "flow_updated")))
		e := h.store.Entries()
		if len(e) != 2 || e[0].AuditID == 999 || e[0].AuditID < 1 || e[1].AuditID <= e[0].AuditID {
			t.Fatalf("audit_ids = %+v, want positive strictly increasing ids not taken from the message", e)
		}
	})

	t.Run("Administrator actions arrive from the handling service", func(t *testing.T) {
		h := newHarness(t)
		update := adminMsg("team-registry", 10, "team_updated", 3)
		update["changes"] = map[string]any{"default_image": map[string]any{"old": "registry.example/flowai/runtime:1.0.0", "new": "registry.example/flowai/runtime:1.1.0"}}
		rejection := adminMsg("admin-panel", 1762500000000000, "insufficient_admin_role", 0)
		rejection["actor_subject"] = "admin-sub-2"
		rejection["outcome"] = "rejected"
		rejection["resource_type"] = "admin_route"
		rejection["resource_id"] = 1
		if got := h.handle(t, delivery(t, "admin", update)); got != audit.ResultStored {
			t.Fatalf("update result = %s", got)
		}
		if got := h.handle(t, delivery(t, "admin", rejection)); got != audit.ResultStored {
			t.Fatalf("rejection result = %s", got)
		}
		entries := h.store.Entries()
		if len(entries) != 2 {
			t.Fatalf("entries = %d, want 2", len(entries))
		}
		want := map[string]string{"team-registry": "admin-sub-1", "admin-panel": "admin-sub-2"}
		for _, e := range entries {
			if e.TeamID != nil {
				t.Errorf("%s entry team = %d, want none", e.SourceService, *e.TeamID)
			}
			if e.ActorType != audit.ActorAdministrator || e.ActorID != nil {
				t.Errorf("%s entry actor = %s/%v, want administrator without actor_id", e.SourceService, e.ActorType, e.ActorID)
			}
			if e.ActorSubject == nil || *e.ActorSubject != want[e.SourceService] {
				t.Errorf("%s entry actor_subject = %v, want %s", e.SourceService, e.ActorSubject, want[e.SourceService])
			}
			delete(want, e.SourceService)
		}
		if len(want) != 0 {
			t.Fatalf("missing source_service entries: %v", want)
		}
	})

	t.Run("source_service comes from the subject", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 5, 3, "flow_updated")
		f["source_service"] = "task-manager"
		h.handle(t, delivery(t, "3", f))
		if e := h.store.Entries(); len(e) != 1 || e[0].SourceService != "flow-registry" {
			t.Fatalf("entries = %+v, want source_service flow-registry", e)
		}
	})

	t.Run("Payload names another team", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 30, 4, "flow_updated")
		d := deliveryOn(t, "flow-registry.audit.flow_updated.sub", "3", f)
		if got := h.handle(t, d); got != audit.ResultRejected {
			t.Fatalf("result = %s, want rejected", got)
		}
		if d.Acked != 1 || d.Termed != 0 {
			t.Fatalf("acked=%d termed=%d, want acknowledged", d.Acked, d.Termed)
		}
		if n := len(h.store.Entries()); n != 0 {
			t.Fatalf("entries = %d, want none", n)
		}
		rej := h.store.RejectedMessages()
		if len(rej) != 1 || rej[0].Publisher != "flow-registry" || rej[0].Seq != 30 {
			t.Fatalf("rejected = %+v, want (flow-registry, 30)", rej)
		}
		for _, tm := range []int64{3, 4} {
			p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(tm), map[string]any{"team_id": tm}))
			if len(p.Items) != 0 {
				t.Fatalf("team %d read returns %d entries, want none", tm, len(p.Items))
			}
		}
		// A redelivery of the rejected message is acknowledged without effect.
		again := deliveryOn(t, "flow-registry.audit.flow_updated.sub", "3", f)
		if got := h.handle(t, again); got != audit.ResultDuplicate || again.Acked != 1 {
			t.Fatalf("redelivered rejected message: result %s acked %d, want duplicate ack", got, again.Acked)
		}
	})

	t.Run("team header and actor type must agree", func(t *testing.T) {
		for name, tc := range map[string]struct {
			team string
			f    fields
		}{
			"operator message with team admin":  {"admin", operatorMsg("flow-registry", 40, 3, "flow_updated")},
			"administrator message with team 3": {"3", adminMsg("team-registry", 41, "team_updated", 3)},
			"missing team header":               {"", operatorMsg("flow-registry", 42, 3, "flow_updated")},
			"non-decimal team header":           {"03", operatorMsg("flow-registry", 43, 3, "flow_updated")},
			"publisher differs from subject service": {"3", func() fields {
				f := operatorMsg("flow-registry", 44, 3, "x")
				f["publisher"] = "task-manager"
				return f
			}()},
		} {
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				d := deliveryOn(t, "flow-registry.audit."+tc.f["action"].(string)+".sub", tc.team, tc.f)
				got := h.handle(t, d)
				if got != audit.ResultTerminated || d.Termed != 1 || d.Acked != 0 {
					t.Fatalf("result=%s termed=%d acked=%d, want terminated", got, d.Termed, d.Acked)
				}
				if n := len(h.store.Entries()); n != 0 {
					t.Fatalf("entries = %d, want none", n)
				}
			})
		}
	})

	t.Run("message outside the audit subjects is not stored", func(t *testing.T) {
		h := newHarness(t)
		d := deliveryOn(t, "executor.event.7.running.sub", "3", operatorMsg("executor", 1, 3, "running"))
		if got := h.handle(t, d); got != audit.ResultTerminated {
			t.Fatalf("result = %s, want terminated", got)
		}
		if n := len(h.store.Entries()); n != 0 {
			t.Fatalf("entries = %d, want none", n)
		}
		if !strings.Contains(h.logs.String(), "executor.event.7.running.sub") {
			t.Fatalf("log does not name the subject: %s", h.logs.String())
		}
	})
}
