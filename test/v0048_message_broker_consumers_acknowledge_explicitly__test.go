package test

// Requirement: message-broker consumers acknowledge explicitly and receive
// redelivery (audit's code: acknowledge only after commit).

import (
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
)

func TestV0048MessageBrokerConsumersAcknowledgeExplicitly(t *testing.T) {
	t.Run("Consumer crashes before acknowledging", func(t *testing.T) {
		h := newHarness(t)
		h.store.FailInsert = 1 // the process dies before the entry commits
		first := delivery(t, "3", operatorMsg("flow-registry", 9, 3, "flow_updated"))
		if got := h.handle(t, first); got != audit.ResultRetry {
			t.Fatalf("result = %s, want retry", got)
		}
		if first.Acked != 0 || first.Termed != 0 {
			t.Fatalf("acked=%d termed=%d, want neither before commit", first.Acked, first.Termed)
		}
		if n := len(h.store.Entries()); n != 0 {
			t.Fatalf("entries = %d before redelivery", n)
		}
		again := delivery(t, "3", operatorMsg("flow-registry", 9, 3, "flow_updated"))
		if got := h.handle(t, again); got != audit.ResultStored || again.Acked != 1 {
			t.Fatalf("redelivery result %s acked %d, want stored and acknowledged", got, again.Acked)
		}
		if n := len(h.store.Entries()); n != 1 {
			t.Fatalf("entries = %d, want exactly 1", n)
		}
	})

}
