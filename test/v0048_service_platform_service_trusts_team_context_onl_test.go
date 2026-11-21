package test

// Requirement: service-platform service trusts team context only from ui requests.

import (
	"encoding/json"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/ids"
)

// hasRequestID reports whether an error reply body carries request_id.
func hasRequestID(t *testing.T, body []byte) bool {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode error body: %v %s", err, body)
	}
	_, has := m["request_id"]
	return has
}

func TestV0048ServicePlatformTrustsTeamContextOnlyFromUI(t *testing.T) {
	t.Run("Gateway forwards verified operator context", func(t *testing.T) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 2, "flow_updated")
		h.seed(t, "flow-registry", 10, 4, 3, "flow_updated")
		with := uiHeaders(3)
		without := uiHeaders(3)
		delete(without, "team_name")
		misleading := uiHeaders(3)
		misleading["team_name"] = "team4"
		for name, hdr := range map[string]headers{"with team_name": with, "without team_name": without, "team_name of team 4": misleading} {
			p := decodePage(t, h.call(t, audit.OperationList, hdr, map[string]any{"team_id": 3}))
			if len(p.Items) != 2 {
				t.Errorf("%s: %d items, want team 3's 2", name, len(p.Items))
			}
		}
	})

	t.Run("Payload names another team", func(t *testing.T) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 10, 4, 3, "flow_updated")
		for _, op := range []struct {
			name   string
			params map[string]any
		}{
			{audit.OperationList, map[string]any{"team_id": 4}},
			{audit.OperationGet, map[string]any{"team_id": 4, "audit_id": 1}},
		} {
			r := h.call(t, op.name, uiHeaders(3), op.params)
			if r.Status == 200 {
				t.Fatalf("%s with header team 3 and params team 4 answered 200 %s", op.name, r.Body)
			}
			expectError(t, r, 400, "invalid_request")
		}
		if h.store.Reads != 0 {
			t.Fatalf("store read %d times for a request naming team 4", h.store.Reads)
		}
	})

	t.Run("Context is missing", func(t *testing.T) {
		cases := map[string]func(h headers){
			"no team":                func(h headers) { delete(h, "team") },
			"team admin":             func(h headers) { h["team"] = "admin" },
			"no operator_id":         func(h headers) { delete(h, "operator_id") },
			"no request_id":          func(h headers) { delete(h, "request_id") },
			"team not decimal":       func(h headers) { h["team"] = "abc" },
			"team zero":              func(h headers) { h["team"] = "0" },
			"team leading zero":      func(h headers) { h["team"] = "03" },
			"team signed":            func(h headers) { h["team"] = "+3" },
			"operator_id negative":   func(h headers) { h["operator_id"] = "-1" },
			"request_id above int64": func(h headers) { h["request_id"] = "9223372036854775808" },
			"request_id zero":        func(h headers) { h["request_id"] = "0" },
			"request_id not decimal": func(h headers) { h["request_id"] = "r-1" },
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				h.seed(t, "flow-registry", 1, 3, 1, "flow_updated")
				hdr := uiHeaders(3)
				mutate(hdr)
				for _, op := range []string{audit.OperationList, audit.OperationGet} {
					params := map[string]any{"team_id": 3}
					if op == audit.OperationGet {
						params["audit_id"] = 1
					}
					r := h.call(t, op, hdr, params)
					e := expectError(t, r, 400, "invalid_request")
					// D12 owner decision 2026-11-09: no valid request_id, no
					// request_id field; every other error keeps it.
					_, perr := ids.ParseDecimal(hdr["request_id"])
					switch has := hasRequestID(t, r.Body); {
					case perr == nil && (!has || e.RequestID != 7001):
						t.Fatalf("%s: body %s, want request_id 7001", op, r.Body)
					case perr != nil && has:
						t.Fatalf("%s: body %s, want no request_id field", op, r.Body)
					}
				}
				if h.store.Reads != 0 {
					t.Fatalf("store read %d times without valid context", h.store.Reads)
				}
			})
		}
	})

	t.Run("unknown operation and malformed body are rejected", func(t *testing.T) {
		h := newHarness(t)
		expectError(t, h.call(t, "delete", uiHeaders(3), map[string]any{"team_id": 3}), 400, "invalid_request")
		expectError(t, h.callRaw(t, audit.OperationList, uiHeaders(3), []byte("{")), 400, "invalid_request")
		expectError(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "resource_type": "flow"}), 400, "invalid_request")
		expectError(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": 5}), 400, "invalid_request")
		if h.store.Reads != 0 {
			t.Fatal("store read for a rejected request")
		}
	})

	t.Run("error reply echoes the request_id", func(t *testing.T) {
		h := newHarness(t)
		e := expectError(t, h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": 0}), 400, "invalid_request")
		if e.RequestID != 7001 || e.Message == "" {
			t.Fatalf("error body = %+v, want request_id 7001 and a message", e)
		}
	})
}
