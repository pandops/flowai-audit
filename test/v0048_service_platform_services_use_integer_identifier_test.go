package test

// Requirement: service-platform services use integer identifiers.
// audit_id is global (audit's commit sequence); audit owns no per-team
// counter. Concurrency and rollback of the real sequence are proven in
// v0048_audit_store_integration_test.go.

import (
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/ids"
)

func TestV0048ServicePlatformUsesIntegerIdentifiers(t *testing.T) {
	t.Run("Invalid identifier is rejected", func(t *testing.T) {
		for _, raw := range []string{`"abc"`, `0`, `-1`, `1.5`, `9223372036854775808`, `"3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f"`} {
			for _, field := range []string{"team_id", "audit_id"} {
				h := newHarness(t)
				var params string
				if field == "team_id" {
					params = `"team_id":` + raw + `,"audit_id":1`
				} else {
					params = `"team_id":3,"audit_id":` + raw
				}
				expectError(t, h.callRaw(t, audit.OperationGet, uiHeaders(3), []byte(`{"params":{`+params+`}}`)), 400, "invalid_request")
				if h.store.Reads != 0 {
					t.Fatalf("%s=%s read the store", field, raw)
				}
			}
		}
	})

	t.Run("decimal and JSON identifier parsing", func(t *testing.T) {
		for _, s := range []string{"1", "42", "9223372036854775807"} {
			if _, err := ids.ParseDecimal(s); err != nil {
				t.Errorf("ParseDecimal(%q) = %v, want ok", s, err)
			}
		}
		for _, s := range []string{"", "0", "-1", "+1", "01", "1.5", "abc", "9223372036854775808", " 1", "1e3"} {
			if _, err := ids.ParseDecimal(s); err == nil {
				t.Errorf("ParseDecimal(%q) accepted", s)
			}
		}
		for _, s := range []string{"1", "9223372036854775807"} {
			if v, err := ids.ParseJSON([]byte(s)); err != nil || v < 1 {
				t.Errorf("ParseJSON(%s) = %d %v", s, v, err)
			}
		}
		for _, s := range []string{`"1"`, "0", "-1", "1.5", "1e3", "1.0", "null", "true", "9223372036854775808", `"3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f"`} {
			if _, err := ids.ParseJSON([]byte(s)); err == nil {
				t.Errorf("ParseJSON(%s) accepted", s)
			}
		}
	})

	t.Run("Redelivered message is deduplicated by publisher sequence", func(t *testing.T) {
		h := newHarness(t)
		h.handle(t, delivery(t, "3", operatorMsg("flow-registry", 120, 3, "flow_updated")))
		d := delivery(t, "3", operatorMsg("flow-registry", 120, 3, "flow_updated"))
		if got := h.handle(t, d); got != audit.ResultDuplicate || d.Acked != 1 {
			t.Fatalf("result %s acked %d, want duplicate acknowledged", got, d.Acked)
		}
		if n := len(h.store.Entries()); n != 1 {
			t.Fatalf("entries = %d, want 1", n)
		}
	})

	t.Run("Equal sequence numbers of two publishers are distinct messages", func(t *testing.T) {
		h := newHarness(t)
		h.handle(t, delivery(t, "3", operatorMsg("task-manager", 40, 3, "task_cancelled")))
		h.handle(t, delivery(t, "3", operatorMsg("flow-registry", 40, 3, "flow_updated")))
		if n := len(h.store.Entries()); n != 2 {
			t.Fatalf("entries = %d, want 2", n)
		}
	})
}
