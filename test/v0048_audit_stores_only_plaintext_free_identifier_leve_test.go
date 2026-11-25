package test

// Requirement: audit stores only plaintext-free identifier-level fields.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/mocks"
)

// secretMaterial is what an audit message must never leak into storage,
// logs or replies.
var secretMaterial = map[string]string{
	"value":          "plaintext-secret-value-123",
	"ciphertext":     "Y2lwaGVydGV4dC1ieXRlcw==",
	"nonce":          "bm9uY2UtYnl0ZXM=",
	"key":            "ZGF0YS1rZXktbWF0ZXJpYWw=",
	"auth_tag":       "dGFnLWJ5dGVz",
	"litellm_key":    "sk-litellm-virtual-key",
	"jwt":            "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln",
	"decrypted_env":  "DB_PASSWORD=hunter2",
	"claim_token":    "claim-token-opaque",
	"operator_email": "operator@example.com",
}

func TestV0048AuditStoresOnlyPlaintextFreeFields(t *testing.T) {
	t.Run("Authorized secret write is audited", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("env-registry", 300, 3, "secret_created")
		f["resource_type"] = "secret"
		f["resource_id"] = 17
		for k, v := range secretMaterial {
			f[k] = v
		}
		if got := h.handle(t, delivery(t, "3", f)); got != audit.ResultStored {
			t.Fatalf("result = %s, want stored", got)
		}
		e := h.store.Entries()
		if len(e) != 1 {
			t.Fatalf("entries = %d, want 1", len(e))
		}
		got := e[0]
		if got.TeamID == nil || *got.TeamID != 3 || got.ActorID == nil || *got.ActorID != 12 ||
			got.Action != "secret_created" || got.ResourceType != "secret" || got.ResourceID == nil || *got.ResourceID != 17 ||
			got.RequestID != 7001 || got.Outcome != "succeeded" || got.SourceService != "env-registry" ||
			got.ActorType != audit.ActorOperator {
			t.Fatalf("stored entry = %+v, want team 3, operator 12, secret_created on secret 17, request 7001, succeeded", got)
		}
		stored, _ := json.Marshal(got)
		reply := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": got.AuditID})
		list := h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3})
		for k, v := range secretMaterial {
			for where, text := range map[string]string{"entry": string(stored), "get reply": string(reply.Body), "list reply": string(list.Body), "logs": h.logs.String()} {
				if strings.Contains(text, v) {
					t.Errorf("%s contains %s material", where, k)
				}
			}
		}
	})

	t.Run("Message carries an unexpected field", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 301, 3, "flow_updated")
		f["value"] = "unexpected-display-value"
		h.handle(t, delivery(t, "3", f))
		e := h.store.Entries()
		if len(e) != 1 {
			t.Fatalf("entries = %d, want 1", len(e))
		}
		raw, _ := json.Marshal(e[0])
		if strings.Contains(string(raw), "unexpected-display-value") {
			t.Fatalf("stored entry keeps the extra field: %s", raw)
		}
		for _, r := range []audit.Reply{
			h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3}),
			h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": e[0].AuditID}),
		} {
			if r.Status != 200 || strings.Contains(string(r.Body), "unexpected-display-value") || strings.Contains(string(r.Body), `"value"`) {
				t.Fatalf("read returns the extra field or failed: %d %s", r.Status, r.Body)
			}
		}
	})

	t.Run("changes keep only non-secret display values", func(t *testing.T) {
		h := newHarness(t)
		f := adminMsg("team-registry", 302, "team_updated", 3)
		f["changes"] = map[string]any{"default_image": map[string]any{"old": "registry.example/flowai/runtime:1.0.0", "new": "registry.example/flowai/runtime:1.1.0"}}
		h.handle(t, delivery(t, "admin", f))
		e := h.store.Entries()
		if len(e) != 1 || !strings.Contains(string(e[0].Changes), "registry.example/flowai/runtime:1.1.0") ||
			!strings.Contains(string(e[0].Changes), "registry.example/flowai/runtime:1.0.0") {
			t.Fatalf("entries = %+v, want changes with the old and new default_image", e)
		}
	})

	t.Run("Message is malformed", func(t *testing.T) {
		cases := map[string]func(f fields){
			"lacks actor_id":              func(f fields) { delete(f, "actor_id") },
			"actor_id is text":            func(f fields) { f["actor_id"] = "op-1" },
			"actor_id is zero":            func(f fields) { f["actor_id"] = 0 },
			"resource_id is negative":     func(f fields) { f["resource_id"] = -1 },
			"resource_id is fractional":   func(f fields) { f["resource_id"] = 1.5 },
			"request_id is a UUID":        func(f fields) { f["request_id"] = "3f2c8a10-6b1e-4d2a-9c3e-5a7b8c9d0e1f" },
			"request_id above int64":      func(f fields) { f["request_id"] = json.Number("9223372036854775808") },
			"lacks outcome":               func(f fields) { delete(f, "outcome") },
			"lacks occurred_at":           func(f fields) { delete(f, "occurred_at") },
			"occurred_at is not a time":   func(f fields) { f["occurred_at"] = "yesterday" },
			"lacks resource_type":         func(f fields) { delete(f, "resource_type") },
			"lacks team_id":               func(f fields) { delete(f, "team_id") },
			"unknown actor_type":          func(f fields) { f["actor_type"] = "executor" },
			"action differs from subject": func(f fields) { f["action"] = "flow_deleted" },
		}
		for name, mutate := range cases {
			t.Run(name, func(t *testing.T) {
				h := newHarness(t)
				f := operatorMsg("flow-registry", 400, 3, "flow_updated")
				f["value"] = "never-logged-value"
				mutate(f)
				d := deliveryOn(t, "flow-registry.audit.flow_updated.sub", "3", f)
				if got := h.handle(t, d); got != audit.ResultTerminated {
					t.Fatalf("result = %s, want terminated", got)
				}
				if d.Termed != 1 || d.Acked != 0 {
					t.Fatalf("termed=%d acked=%d, want terminated only", d.Termed, d.Acked)
				}
				if n := len(h.store.Entries()); n != 0 {
					t.Fatalf("entries = %d, want none", n)
				}
				if n := len(h.store.RejectedMessages()); n != 0 {
					t.Fatalf("rejected rows = %d, want none (stored nowhere)", n)
				}
				logs := h.logs.String()
				for _, want := range []string{`"publisher":"flow-registry"`, `"publisher_seq":400`, `"subject":"flow-registry.audit.flow_updated.sub"`} {
					if !strings.Contains(logs, want) {
						t.Errorf("log lacks %s: %s", want, logs)
					}
				}
				for _, leak := range []string{"never-logged-value", "op-1", "7001", "admin-sub"} {
					if strings.Contains(logs, leak) {
						t.Errorf("log contains payload value %q: %s", leak, logs)
					}
				}
			})
		}
	})

	t.Run("message without a usable publisher pair is terminated and logged by subject", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 401, 3, "flow_updated")
		delete(f, "publisher_seq")
		d := deliveryOn(t, "flow-registry.audit.flow_updated.sub", "3", f)
		if got := h.handle(t, d); got != audit.ResultTerminated {
			t.Fatalf("result = %s, want terminated", got)
		}
		d2 := mocks.NewDelivery("flow-registry.audit.flow_updated.sub", map[string]string{"team": "3"}, []byte("{not json"))
		if got := h.handle(t, d2); got != audit.ResultTerminated {
			t.Fatalf("invalid JSON result = %s, want terminated", got)
		}
		if !strings.Contains(h.logs.String(), "flow-registry.audit.flow_updated.sub") {
			t.Fatalf("log lacks subject: %s", h.logs.String())
		}
	})
}

// Deviation D3: publishers send resource_id = null for actions without a
// target; the key itself stays required.
func TestV0048AuditNullResourceID(t *testing.T) {
	t.Run("null resource_id is stored and read back as null", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("env-registry", 500, 3, "secret_versions_listed")
		f["resource_id"] = nil
		if got := h.handle(t, delivery(t, "3", f)); got != audit.ResultStored {
			t.Fatalf("result = %s, want stored", got)
		}
		e := h.store.Entries()
		if len(e) != 1 || e[0].ResourceID != nil {
			t.Fatalf("entries = %+v, want one entry with no resource_id", e)
		}
		r := h.call(t, audit.OperationGet, uiHeaders(3), map[string]any{"team_id": 3, "audit_id": e[0].AuditID})
		var item map[string]any
		if err := json.Unmarshal(r.Body, &item); err != nil || r.Status != 200 {
			t.Fatalf("get = %d %s", r.Status, r.Body)
		}
		if v, ok := item["resource_id"]; !ok || v != nil {
			t.Fatalf("resource_id = %v (present %v), want null", v, ok)
		}
		if err := loadSchemas(t).validate("ui.get.reply.schema.json", r.Body); err != nil {
			t.Fatalf("reply violates schema: %v", err)
		}
	})
	t.Run("missing resource_id key is malformed", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("env-registry", 501, 3, "secret_created")
		delete(f, "resource_id")
		if got := h.handle(t, delivery(t, "3", f)); got != audit.ResultTerminated {
			t.Fatalf("result = %s, want terminated", got)
		}
	})
	t.Run("reason is dropped", func(t *testing.T) {
		h := newHarness(t)
		f := operatorMsg("flow-registry", 502, 3, "flow_updated")
		f["outcome"] = "rejected"
		f["reason"] = "precondition_failed"
		h.handle(t, delivery(t, "3", f))
		raw, _ := json.Marshal(h.store.Entries())
		if strings.Contains(string(raw), "precondition_failed") {
			t.Fatalf("reason stored: %s", raw)
		}
	})
}
