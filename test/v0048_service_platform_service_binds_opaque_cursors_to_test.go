package test

// Requirement: service-platform service binds opaque cursors to their read
// (audit list; limits per the audit capability: 10, 25, 50, 100).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/pandops/flowai-audit/internal/audit"
	"github.com/pandops/flowai-audit/internal/cursor"
)

// signCursor builds a cursor in the documented token format with secret.
func signCursor(t *testing.T, payload map[string]any, secret []byte) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return body + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// decodeCursorPayload returns the JSON payload of a token.
func decodeCursorPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	body, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("cursor %q has no signature part", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("cursor payload: %v", err)
	}
	p := map[string]any{}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("cursor payload json: %v", err)
	}
	return p
}

func TestV0048ServicePlatformBindsOpaqueCursors(t *testing.T) {
	setup := func(t *testing.T) (*harness, string) {
		h := newHarness(t)
		h.seed(t, "flow-registry", 1, 3, 25, "flow_updated")
		p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow"}))
		if p.NextCursor == nil {
			t.Fatal("no next_cursor")
		}
		return h, *p.NextCursor
	}

	t.Run("Forward page advances", func(t *testing.T) {
		h, next := setup(t)
		seen := map[float64]bool{}
		var last float64 = 1 << 62
		cur := ""
		pages := 0
		for {
			params := map[string]any{"team_id": 3, "search": "flow"}
			if cur != "" {
				params["cursor"] = cur
			}
			p := decodePage(t, h.call(t, audit.OperationList, uiHeaders(3), params))
			pages++
			for _, it := range p.Items {
				id := it["audit_id"].(float64)
				if seen[id] || id >= last {
					t.Fatalf("entry %v overlaps or breaks DESC order (last %v)", id, last)
				}
				seen[id], last = true, id
			}
			if p.NextCursor == nil {
				break
			}
			cur = *p.NextCursor
		}
		if len(seen) != 25 || pages != 3 {
			t.Fatalf("paged %d entries in %d pages, want 25 in 3", len(seen), pages)
		}
		pl := decodeCursorPayload(t, next)
		if k, ok := pl["k"].(float64); !ok || k != 1 {
			t.Fatalf("cursor key_id = %v, want integer 1 (the active key)", pl["k"])
		}
	})

	t.Run("Tampered cursor", func(t *testing.T) {
		h, next := setup(t)
		raw := []byte(next)
		i := len(raw) / 3
		raw[i] ^= 0x01
		before := h.store.Reads
		for _, token := range []string{string(raw), next + "x", "garbage", next[:len(next)-2], "." + next} {
			expectError(t, h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow", "cursor": token}), 400, "invalid_pagination")
		}
		if h.store.Reads != before {
			t.Fatal("store read for a tampered cursor")
		}
	})

	t.Run("Cursor reused for another operation or team", func(t *testing.T) {
		h, next := setup(t)
		pl := decodeCursorPayload(t, next)
		otherOp := map[string]any{}
		for k, v := range pl {
			otherOp[k] = v
		}
		otherOp["op"] = "admin.list"
		otherOperator := uiHeaders(3)
		otherOperator["operator_id"] = "13"
		before := h.store.Reads
		for name, tc := range map[string]struct {
			hdr    headers
			params map[string]any
		}{
			"team 4":            {uiHeaders(4), map[string]any{"team_id": 4, "search": "flow", "cursor": next}},
			"another operator":  {otherOperator, map[string]any{"team_id": 3, "search": "flow", "cursor": next}},
			"another operation": {uiHeaders(3), map[string]any{"team_id": 3, "search": "flow", "cursor": signCursor(t, otherOp, testSecret)}},
		} {
			r := h.call(t, audit.OperationList, tc.hdr, tc.params)
			if r.Status != 400 {
				t.Errorf("%s: status %d, want 400 invalid_pagination", name, r.Status)
				continue
			}
			expectError(t, r, 400, "invalid_pagination")
		}
		if h.store.Reads != before {
			t.Fatal("store read for a cursor of another context")
		}
	})

	t.Run("Changed filter", func(t *testing.T) {
		h, next := setup(t)
		before := h.store.Reads
		for _, params := range []map[string]any{
			{"team_id": 3, "search": "secret", "cursor": next},
			{"team_id": 3, "cursor": next},
		} {
			expectError(t, h.call(t, audit.OperationList, uiHeaders(3), params), 400, "invalid_pagination")
		}
		if h.store.Reads != before {
			t.Fatal("store read for a cursor with a changed filter")
		}
	})

	t.Run("Limit out of range", func(t *testing.T) {
		h := newHarness(t)
		for _, raw := range []string{`0`, `201`, `11`, `-10`, `10.5`, `"10"`, `"abc"`, `null`, `200`} {
			body := []byte(`{"params":{"team_id":3,"limit":` + raw + `}}`)
			expectError(t, h.callRaw(t, audit.OperationList, uiHeaders(3), body), 400, "invalid_pagination")
		}
		if h.store.Reads != 0 {
			t.Fatal("store read for an invalid limit")
		}
	})

	t.Run("unknown or non-integer key_id is rejected before any query", func(t *testing.T) {
		h, next := setup(t)
		pl := decodeCursorPayload(t, next)
		before := h.store.Reads
		for name, mutate := range map[string]func(p map[string]any){
			"unknown key_id":    func(p map[string]any) { p["k"] = 99 },
			"text key_id":       func(p map[string]any) { p["k"] = "1" },
			"fractional key_id": func(p map[string]any) { p["k"] = 1.5 },
			"zero key_id":       func(p map[string]any) { p["k"] = 0 },
		} {
			p := map[string]any{}
			for k, v := range pl {
				p[k] = v
			}
			mutate(p)
			r := h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow", "cursor": signCursor(t, p, testSecret)})
			if r.Status != 400 {
				t.Errorf("%s: status %d, want 400", name, r.Status)
				continue
			}
			expectError(t, r, 400, "invalid_pagination")
		}
		// A cursor signed with the second configured key is still verified.
		p := map[string]any{}
		for k, v := range pl {
			p[k] = v
		}
		p["k"] = 2
		r := h.call(t, audit.OperationList, uiHeaders(3), map[string]any{"team_id": 3, "search": "flow", "cursor": signCursor(t, p, []byte(strings.Repeat("\x24", 32)))})
		if r.Status != 200 {
			t.Fatalf("cursor under configured key 2: status %d %s, want 200", r.Status, r.Body)
		}
		if h.store.Reads != before+1 {
			t.Fatalf("store reads = %d, want only the one valid read", h.store.Reads-before)
		}
	})

	t.Run("keyring requires a configured active key", func(t *testing.T) {
		if _, err := cursor.NewKeyring(3, []cursor.Key{{ID: 1, Secret: testSecret}}); err == nil {
			t.Fatal("keyring with an unconfigured active key_id was accepted")
		}
		if _, err := cursor.NewKeyring(1, []cursor.Key{{ID: 1, Secret: []byte("short")}}); err == nil {
			t.Fatal("keyring with a short secret was accepted")
		}
		if _, err := cursor.NewKeyring(1, []cursor.Key{{ID: 1, Secret: testSecret}, {ID: 1, Secret: testSecret}}); err == nil {
			t.Fatal("keyring with a duplicate key_id was accepted")
		}
		if _, err := cursor.NewKeyring(0, []cursor.Key{{ID: 0, Secret: testSecret}}); err == nil {
			t.Fatal("keyring with key_id 0 was accepted")
		}
	})
}
