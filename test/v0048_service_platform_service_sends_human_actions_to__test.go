package test

// Requirement: service-platform service sends human actions to audit and
// others to journal (audit's side: what it stores).

import (
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048ServicePlatformHumanActionsReachAudit(t *testing.T) {
	t.Run("Operator cancels a task", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("task-manager", 77, 3, "task_cancel_requested")
		f["resource_type"] = "task"
		f["resource_id"] = 1010
		if got := h.handle(t, delivery(t, "3", f)); got != audit.ResultStored {
			t.Fatalf("result = %s", got)
		}
		e := h.store.Entries()
		if len(e) != 1 || e[0].SourceService != "task-manager" || e[0].ResourceID == nil || *e[0].ResourceID != 1010 || *e[0].TeamID != 3 {
			t.Fatalf("entries = %+v", e)
		}
	})

	t.Run("Forwarded administrator action is audited by its owner", func(t *testing.T) {
		h := newHarness(t)
		h.handle(t, delivery(t, "admin", adminMsg("team-registry", 5, "team_archived", 3)))
		e := h.store.Entries()
		if len(e) != 1 || e[0].SourceService != "team-registry" || e[0].TeamID != nil || e[0].ActorType != audit.ActorAdministrator {
			t.Fatalf("entries = %+v, want one administrator entry from team-registry with no team", e)
		}
	})

	t.Run("Rejected human action is audited", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 6, 3, "flow_update_rejected")
		f["outcome"] = "rejected"
		h.handle(t, delivery(t, "3", f))
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3}))
		if len(p.Items) != 1 || p.Items[0]["outcome"] != "rejected" {
			t.Fatalf("items = %+v, want the rejected action", p.Items)
		}
	})

	t.Run("Executor event goes to journal", func(t *testing.T) {
		h := newHarness(t)
		for _, subject := range []string{"executor.event.7.running.sub", "task-manager.event.queued.sub"} {
			d := deliveryOn(t, subject, "3", operatorMsg("task-manager", 8, 3, "running"))
			if got := h.handle(t, d); got == audit.ResultStored {
				t.Fatalf("%s stored as audit", subject)
			}
		}
		if n := len(h.store.Entries()); n != 0 {
			t.Fatalf("entries = %d, want none", n)
		}
	})
}
